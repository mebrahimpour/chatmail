package imap

import (
	"bufio"
	"chatmail/internal/database"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// connIdleTimeout is the maximum time a connected but idle (non-IDLE-command)
// client may hold a goroutine open without sending any data.
const connIdleTimeout = 30 * time.Minute

// connWriteTimeout is the maximum time a single conn.Write call may block.
// A client that stops reading responses (slow-loris write variant) would
// otherwise hold the goroutine open indefinitely.
const connWriteTimeout = 60 * time.Second

// writeLine sets a short write deadline and writes the complete byte slice.
// net.Conn.Write is allowed to return a short write with an error; looping here
// prevents silently truncating large literals/responses. Any final error is
// deliberately discarded — the next ReadString will catch the broken connection.
func writeLine(conn net.Conn, data []byte) {
	_ = conn.SetWriteDeadline(time.Now().Add(connWriteTimeout))
	defer conn.SetWriteDeadline(time.Time{})
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return
		}
		if n <= 0 {
			return
		}
		data = data[n:]
	}
}

type Server struct {
	addr     string
	db       *database.BboltDB
	mu       sync.Mutex
	listener net.Listener
}

func NewServer(addr string, db *database.BboltDB) *Server {
	return &Server{addr: addr, db: db}
}

func (s *Server) ListenAndServe() error {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			// Distinguish an intentional Close() from a real network error.
			// After Close() the listener is nil; treat that as a clean exit.
			s.mu.Lock()
			closed := s.listener == nil
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		go s.handleClient(conn)
	}
}

// Close shuts down the IMAP listener, causing ListenAndServe to return.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		_ = s.listener.Close()
		s.listener = nil
	}
}

func (s *Server) handleClient(conn net.Conn) {
	defer conn.Close()

	// 1. Initial Greeting
	writeLine(conn, []byte("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN IDLE UIDPLUS] Minimal Chatmail IMAP Server Ready\r\n"))

	authenticated := false
	selected := false
	currentUser := ""

	reader := bufio.NewReader(conn)

	for {
		// Apply an idle read deadline to prevent goroutine leaks from slow/abandoned clients.
		_ = conn.SetReadDeadline(time.Now().Add(connIdleTimeout))

		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		// Clear deadline while processing the command.
		_ = conn.SetReadDeadline(time.Time{})

		cmdLine := strings.TrimSpace(line)
		if cmdLine == "" {
			continue
		}

		parts := parseIMAPLine(cmdLine)
		if len(parts) < 2 {
			continue
		}

		tag := parts[0]
		cmdName := strings.ToUpper(parts[1])

		// Suspension check: after authentication, terminate the session as soon as
		// the backing account disappears or becomes suspended. Allow LOGOUT and
		// CAPABILITY so clients can still close cleanly or inspect server features,
		// but block all mailbox/authenticated operations immediately. This avoids a
		// stale authenticated IMAP session retaining access after admin revocation.
		if authenticated && cmdName != "LOGOUT" && cmdName != "CAPABILITY" {
			exists, suspended, err := s.db.GetUserStatus(currentUser)
			if err != nil {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Temporary system error\r\n", tag)))
				continue
			}
			if !exists || suspended {
				writeLine(conn, []byte("* BYE [ALERT] Account disabled by administration\r\n"))
				return
			}
		}

		switch cmdName {
		case "CAPABILITY":
			writeLine(conn, []byte(fmt.Sprintf("* CAPABILITY IMAP4rev1 AUTH=PLAIN IDLE UIDPLUS\r\n%s OK CAPABILITY completed\r\n", tag)))

		// RFC 3501 §6.2.2 / RFC 4616 §2 — AUTHENTICATE PLAIN
		// Supports both the two-step challenge form and the single-step inline
		// initial-response form: AUTHENTICATE PLAIN <base64>
		case "AUTHENTICATE":
			if authenticated {
				writeLine(conn, []byte(fmt.Sprintf("%s BAD Already authenticated\r\n", tag)))
				continue
			}
			if len(parts) < 3 || strings.ToUpper(parts[2]) != "PLAIN" {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Unsupported authentication mechanism\r\n", tag)))
				continue
			}
			var b64Payload string
			if len(parts) >= 4 && parts[3] != "" {
				// Inline initial response — credentials already present on the
				// command line; skip the server continuation challenge entirely.
				b64Payload = parts[3]
			} else {
				// Two-step: issue an empty challenge and wait for client response.
				writeLine(conn, []byte("+ \r\n"))
				_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
				b64Line, err := reader.ReadString('\n')
				_ = conn.SetReadDeadline(time.Time{})
				if err != nil {
					return
				}
				b64Payload = strings.TrimSpace(b64Line)
			}
			user, pass, ok := decodePlainAuth(b64Payload)
			if !ok {
				writeLine(conn, []byte(fmt.Sprintf("%s BAD Invalid PLAIN encoding\r\n", tag)))
				continue
			}
			_ = s.authenticateUser(tag, user, pass, &authenticated, &currentUser, conn, conn.RemoteAddr().String())

		case "LOGIN":
			if authenticated {
				writeLine(conn, []byte(fmt.Sprintf("%s BAD Already authenticated\r\n", tag)))
				continue
			}
			if len(parts) < 4 {
				writeLine(conn, []byte(fmt.Sprintf("%s BAD Arguments missing\r\n", tag)))
				continue
			}
			user := strings.ToLower(parts[2])
			pass := parts[3]
			_ = s.authenticateUser(tag, user, pass, &authenticated, &currentUser, conn, conn.RemoteAddr().String())

		case "SELECT":
			if !authenticated {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Authenticate first\r\n", tag)))
				continue
			}
			if len(parts) < 3 {
				writeLine(conn, []byte(fmt.Sprintf("%s BAD SELECT missing mailbox name\r\n", tag)))
				continue
			}
			if strings.ToUpper(parts[2]) != "INBOX" {
				writeLine(conn, []byte(fmt.Sprintf("%s NO [NONEXISTENT] Mailbox does not exist\r\n", tag)))
				continue
			}
			count, uidValidity, nextUID, err := s.db.GetMailboxInfo(currentUser)
			if err != nil {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Select failed\r\n", tag)))
				continue
			}
			if uidValidity == 0 {
				// Generate a stable fallback from the current Unix timestamp
				// rather than emitting a hardcoded magic number.
				uidValidity = uint32(time.Now().Unix())
			}
			if nextUID == 0 {
				nextUID = count + 1
			}

			writeLine(conn, []byte("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n"))
			writeLine(conn, []byte("* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted)] Flags allowed\r\n"))
			writeLine(conn, []byte(fmt.Sprintf("* %d EXISTS\r\n", count)))
			writeLine(conn, []byte(fmt.Sprintf("* OK [UIDVALIDITY %d] UIDs stable\r\n", uidValidity)))
			writeLine(conn, []byte(fmt.Sprintf("* OK [UIDNEXT %d] Predicted UID\r\n", nextUID)))
			writeLine(conn, []byte(fmt.Sprintf("%s OK [READ-WRITE] SELECT completed\r\n", tag)))
			selected = true

		case "IDLE":
			if !authenticated {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Authenticate first\r\n", tag)))
				continue
			}
			if !selected {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Select mailbox first\r\n", tag)))
				continue
			}
			writeLine(conn, []byte("+ idling\r\n"))

			// Register for push notifications from StoreMessage.
			notifyCh := make(chan struct{}, 10)
			s.db.RegisterNotifier(currentUser, notifyCh)

			// A single helper goroutine owns the reader while handleClient is inside
			// IDLE. If the server-side timer ends IDLE first, we set a read deadline
			// and wait for this goroutine to exit before the main loop reads again —
			// preventing both bufio.Reader races and leaked blocked goroutines.
			clientDone := make(chan string, 1)
			clientErr := make(chan error, 1)
			go func() {
				line, err := reader.ReadString('\n')
				if err != nil {
					clientErr <- err
					return
				}
				clientDone <- strings.ToUpper(strings.TrimSpace(line))
			}()

			idleTimer := time.NewTimer(28 * time.Minute)
			idleDone := false
			for !idleDone {
				select {
				case <-notifyCh:
					for len(notifyCh) > 0 {
						<-notifyCh
					}
					count, _, _, err := s.db.GetMailboxInfo(currentUser)
					if err == nil {
						writeLine(conn, []byte(fmt.Sprintf("* %d EXISTS\r\n", count)))
					}

				case <-idleTimer.C:
					writeLine(conn, []byte("* OK Still here\r\n"))
					_ = conn.SetReadDeadline(time.Now())
					select {
					case <-clientDone:
					case <-clientErr:
					case <-time.After(2 * time.Second):
						idleTimer.Stop()
						s.db.DeregisterNotifier(currentUser, notifyCh)
						return
					}
					_ = conn.SetReadDeadline(time.Time{})
					idleDone = true

				case cmd := <-clientDone:
					if cmd == "DONE" {
						idleDone = true
					} else {
						writeLine(conn, []byte("* BAD Expected DONE while idling\r\n"))
						idleDone = true
					}

				case <-clientErr:
					idleTimer.Stop()
					s.db.DeregisterNotifier(currentUser, notifyCh)
					return
				}
			}

			idleTimer.Stop()
			s.db.DeregisterNotifier(currentUser, notifyCh)
			writeLine(conn, []byte(fmt.Sprintf("%s OK IDLE completed\r\n", tag)))

		case "UID":
			if !selected {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Select mailbox first\r\n", tag)))
				continue
			}
			if len(parts) < 3 {
				writeLine(conn, []byte(fmt.Sprintf("%s BAD UID command format error\r\n", tag)))
				continue
			}
			subCmd := strings.ToUpper(parts[2])
			if subCmd == "FETCH" {
				if len(parts) < 4 {
					writeLine(conn, []byte(fmt.Sprintf("%s BAD UID FETCH missing arguments\r\n", tag)))
					continue
				}
				uidRange := parts[3]
				cmdUpper := strings.ToUpper(cmdLine)
				wantBody := strings.Contains(cmdUpper, "BODY") || strings.Contains(cmdUpper, "RFC822")
				var msgsList []database.DBMessage
				var err error
				if wantBody {
					msgsList, err = s.db.FetchMessages(currentUser)
				} else {
					msgsList, err = s.db.FetchMessageHeaders(currentUser)
				}
				if err != nil {
					writeLine(conn, []byte(fmt.Sprintf("%s NO Failed to read mailbox messages\r\n", tag)))
					continue
				}

				// Sequence numbers must be contiguous starting from 1 over the
				// current snapshot — they cannot use raw slice indices.
				maxUID := highestUID(msgsList)
				seqNum := 0
				for _, msg := range msgsList {
					seqNum++
					if matchUID(msg.UID, maxUID, uidRange) {
						flagsStr := formatFlags(msg.Flags)
						if wantBody {
							// IMAP literals must advertise the exact number of bytes that
							// will be sent. Use the copied payload length rather than the
							// persisted Length field so a corrupt legacy row cannot make
							// clients hang waiting for bytes that will never arrive.
							literalSize := len(msg.Payload)
							writeLine(conn, []byte(fmt.Sprintf("* %d FETCH (UID %d FLAGS %s BODY[] {%d}\r\n", seqNum, msg.UID, flagsStr, literalSize)))
							writeLine(conn, msg.Payload)
							// RFC 3501 §4.3: after the literal, exactly one CRLF
							// before the closing ')' regardless of whether the
							// payload itself ends in CRLF.
							if len(msg.Payload) == 0 || msg.Payload[len(msg.Payload)-1] != '\n' {
								writeLine(conn, []byte("\r\n)\r\n"))
							} else {
								writeLine(conn, []byte(")\r\n"))
							}
						} else {
							writeLine(conn, []byte(fmt.Sprintf("* %d FETCH (UID %d FLAGS %s)\r\n", seqNum, msg.UID, flagsStr)))
						}
					}
				}
				writeLine(conn, []byte(fmt.Sprintf("%s OK UID FETCH completed\r\n", tag)))

			} else if subCmd == "STORE" {
				if len(parts) < 5 {
					writeLine(conn, []byte(fmt.Sprintf("%s BAD UID STORE missing arguments\r\n", tag)))
					continue
				}
				uidRange := parts[3]
				// parts[4] is the FLAGS item name (e.g. "+FLAGS", "FLAGS", "-FLAGS",
				// "+FLAGS.SILENT", "FLAGS.SILENT", "-FLAGS.SILENT").
				storeItem := strings.ToUpper(parts[4])

				// RFC 3501 §6.4.6: the .SILENT suffix suppresses the untagged
				// FETCH response. Detect it before inspecting +/- modifiers.
				silent := strings.Contains(storeItem, ".SILENT")

				// Everything after the storeItem token is the flag list.
				// Use the parsed parts rather than slicing the raw command line to
				// avoid index mis-alignment on mixed-case input.
				flagsPart := strings.Join(parts[5:], " ")
				mask := parseFlagsMask(flagsPart)

				isReplace := !strings.Contains(storeItem, "+") && !strings.Contains(storeItem, "-")
				var flagsToSet uint32
				var flagsToClear uint32
				if isReplace {
					flagsToSet = mask
				} else if strings.Contains(storeItem, "+") {
					flagsToSet = mask
				} else {
					flagsToClear = mask
				}

				// Use FetchMessageHeaders — UID STORE only needs UIDs and current
				// flags, never message bodies. This avoids copying all payloads.
				msgsList, err := s.db.FetchMessageHeaders(currentUser)
				if err != nil {
					writeLine(conn, []byte(fmt.Sprintf("%s NO Failed to read mailbox messages\r\n", tag)))
					continue
				}

				var matchingUIDs []uint32
				uidToSeq := make(map[uint32]int)
				maxUID := highestUID(msgsList)
				for i, msg := range msgsList {
					if matchUID(msg.UID, maxUID, uidRange) {
						matchingUIDs = append(matchingUIDs, msg.UID)
						uidToSeq[msg.UID] = i + 1
					}
				}

				if len(matchingUIDs) > 0 {
					updatedFlags, err := s.db.UpdateMessagesFlags(currentUser, matchingUIDs, flagsToSet, flagsToClear, isReplace)
					if err != nil {
						writeLine(conn, []byte(fmt.Sprintf("%s NO Failed to update flags\r\n", tag)))
						continue
					}
					// Only emit untagged FETCH responses when the client did NOT
					// request silent mode (RFC 3501 §6.4.6).
					if !silent {
						for _, msg := range msgsList {
							if newFlags, ok := updatedFlags[msg.UID]; ok {
								flagsStr := formatFlags(newFlags)
								writeLine(conn, []byte(fmt.Sprintf("* %d FETCH (UID %d FLAGS %s)\r\n", uidToSeq[msg.UID], msg.UID, flagsStr)))
							}
						}
					}
				}
				writeLine(conn, []byte(fmt.Sprintf("%s OK UID STORE completed\r\n", tag)))
			} else if subCmd == "EXPUNGE" {
				// RFC 4315: UID EXPUNGE <uid-set> removes only messages that are
				// both already \Deleted and whose UID is in the supplied set. It must
				// not mark messages deleted, and it must not expunge other deleted UIDs.
				if len(parts) < 4 {
					writeLine(conn, []byte(fmt.Sprintf("%s BAD UID EXPUNGE missing uid-set\r\n", tag)))
					continue
				}
				uidSet := parts[3]

				msgsBefore, err := s.db.FetchMessageHeaders(currentUser)
				if err != nil {
					writeLine(conn, []byte(fmt.Sprintf("%s NO Failed to read mailbox\r\n", tag)))
					continue
				}

				allowedUIDs := make(map[uint32]bool)
				maxUID := highestUID(msgsBefore)
				for _, msg := range msgsBefore {
					if matchUID(msg.UID, maxUID, uidSet) {
						allowedUIDs[msg.UID] = true
					}
				}

				expungedUIDs, err := s.db.ExpungeSelectedDeletedMessages(currentUser, allowedUIDs)
				if err != nil {
					writeLine(conn, []byte(fmt.Sprintf("%s NO Expunge failed\r\n", tag)))
					continue
				}
				expungedSet := make(map[uint32]bool, len(expungedUIDs))
				for _, uid := range expungedUIDs {
					expungedSet[uid] = true
				}
				// Emit sequence numbers in descending order (RFC 3501 §7.4.1).
				var seqNums []int
				for i, msg := range msgsBefore {
					if expungedSet[msg.UID] {
						seqNums = append(seqNums, i+1)
					}
				}
				for i, j := 0, len(seqNums)-1; i < j; i, j = i+1, j-1 {
					seqNums[i], seqNums[j] = seqNums[j], seqNums[i]
				}
				for _, seq := range seqNums {
					writeLine(conn, []byte(fmt.Sprintf("* %d EXPUNGE\r\n", seq)))
				}
				writeLine(conn, []byte(fmt.Sprintf("%s OK UID EXPUNGE completed\r\n", tag)))
			} else {
				writeLine(conn, []byte(fmt.Sprintf("%s NO UID subcommand not implemented: %s\r\n", tag, subCmd)))
			}

		// RFC 3501 §6.4.6 — STORE <sequence-set> <message data item> <value>
		// Sequence-number form: sequence numbers map to the ordered FetchMessages
		// snapshot. Delegates to the same flag-update path as UID STORE.
		case "STORE":
			if !selected {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Select mailbox first\r\n", tag)))
				continue
			}
			if len(parts) < 5 {
				writeLine(conn, []byte(fmt.Sprintf("%s BAD STORE missing arguments\r\n", tag)))
				continue
			}
			seqRange := parts[2]
			storeItem := strings.ToUpper(parts[3])
			silent := strings.Contains(storeItem, ".SILENT")
			flagsPart := strings.Join(parts[4:], " ")
			mask := parseFlagsMask(flagsPart)
			isReplace := !strings.Contains(storeItem, "+") && !strings.Contains(storeItem, "-")
			var flagsToSet, flagsToClear uint32
			if isReplace {
				flagsToSet = mask
			} else if strings.Contains(storeItem, "+") {
				flagsToSet = mask
			} else {
				flagsToClear = mask
			}

			msgsList, err := s.db.FetchMessageHeaders(currentUser)
			if err != nil {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Failed to read mailbox\r\n", tag)))
				continue
			}
			var matchingUIDs []uint32
			seqToUID := make(map[uint32]int) // uid → seqNum
			for i, msg := range msgsList {
				sn := i + 1
				if matchSeq(sn, len(msgsList), seqRange) {
					matchingUIDs = append(matchingUIDs, msg.UID)
					seqToUID[msg.UID] = sn
				}
			}
			if len(matchingUIDs) > 0 {
				updatedFlags, err := s.db.UpdateMessagesFlags(currentUser, matchingUIDs, flagsToSet, flagsToClear, isReplace)
				if err != nil {
					writeLine(conn, []byte(fmt.Sprintf("%s NO Failed to update flags\r\n", tag)))
					continue
				}
				if !silent {
					// Emit responses in stable mailbox sequence order. Iterating the
					// updatedFlags map directly would randomise untagged FETCH order,
					// which confuses strict clients tracking sequence-number changes.
					for _, msg := range msgsList {
						if newFlags, ok := updatedFlags[msg.UID]; ok {
							flagsStr := formatFlags(newFlags)
							writeLine(conn, []byte(fmt.Sprintf("* %d FETCH (UID %d FLAGS %s)\r\n", seqToUID[msg.UID], msg.UID, flagsStr)))
						}
					}
				}
			}
			writeLine(conn, []byte(fmt.Sprintf("%s OK STORE completed\r\n", tag)))

		// RFC 3501 §6.4.5 — FETCH <sequence-set> <data items>
		// This is the mandatory sequence-number form. We map sequence numbers
		// directly to the ordered FetchMessages snapshot (seq 1 = first message).
		case "FETCH":
			if !selected {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Select mailbox first\r\n", tag)))
				continue
			}
			if len(parts) < 4 {
				writeLine(conn, []byte(fmt.Sprintf("%s BAD FETCH missing arguments\r\n", tag)))
				continue
			}
			seqRange := parts[2]
			cmdUpper := strings.ToUpper(cmdLine)
			wantBody := strings.Contains(cmdUpper, "BODY") || strings.Contains(cmdUpper, "RFC822")
			var msgsList []database.DBMessage
			var err error
			if wantBody {
				msgsList, err = s.db.FetchMessages(currentUser)
			} else {
				msgsList, err = s.db.FetchMessageHeaders(currentUser)
			}
			if err != nil {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Failed to read mailbox messages\r\n", tag)))
				continue
			}

			for i, msg := range msgsList {
				seqNum := i + 1
				if !matchSeq(seqNum, len(msgsList), seqRange) {
					continue
				}
				flagsStr := formatFlags(msg.Flags)
				if wantBody {
					// IMAP literals must advertise exactly the bytes that follow.
					// Use the copied payload length rather than persisted metadata so
					// corrupt rows cannot desynchronise strict clients.
					literalSize := len(msg.Payload)
					writeLine(conn, []byte(fmt.Sprintf("* %d FETCH (UID %d FLAGS %s BODY[] {%d}\r\n", seqNum, msg.UID, flagsStr, literalSize)))
					writeLine(conn, msg.Payload)
					// RFC 3501 §4.3: after the literal, exactly one CRLF before
					// the closing ')' — avoid a double-blank-line when the
					// payload already ends in \r\n, and ensure ')' is never
					// appended to the last byte of a payload that lacks one.
					if len(msg.Payload) == 0 || msg.Payload[len(msg.Payload)-1] != '\n' {
						writeLine(conn, []byte("\r\n)\r\n"))
					} else {
						writeLine(conn, []byte(")\r\n"))
					}
				} else {
					writeLine(conn, []byte(fmt.Sprintf("* %d FETCH (UID %d FLAGS %s)\r\n", seqNum, msg.UID, flagsStr)))
				}
			}
			writeLine(conn, []byte(fmt.Sprintf("%s OK FETCH completed\r\n", tag)))

		case "EXPUNGE":
			if !selected {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Select mailbox first\r\n", tag)))
				continue
			}
			expungedSeqNums, err := s.expungeAndReport(currentUser)
			if err != nil {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Expunge failed\r\n", tag)))
				continue
			}
			for _, seq := range expungedSeqNums {
				writeLine(conn, []byte(fmt.Sprintf("* %d EXPUNGE\r\n", seq)))
			}
			writeLine(conn, []byte(fmt.Sprintf("%s OK EXPUNGE completed\r\n", tag)))

		case "NOOP":
			// RFC 3501 §6.1.2: server SHOULD send unsolicited mailbox status
			// updates (EXISTS, RECENT) in response to any command when the
			// mailbox has changed. Emit * N EXISTS so NOOP-polling clients
			// (those that do not use IDLE) discover new mail reliably.
			if selected {
				if noopCount, _, _, noopErr := s.db.GetMailboxInfo(currentUser); noopErr == nil {
					writeLine(conn, []byte(fmt.Sprintf("* %d EXISTS\r\n", noopCount)))
				}
			}
			writeLine(conn, []byte(fmt.Sprintf("%s OK NOOP completed\r\n", tag)))

		case "LIST":
			if !authenticated {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Authenticate first\r\n", tag)))
				continue
			}
			writeLine(conn, []byte("* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n"))
			writeLine(conn, []byte(fmt.Sprintf("%s OK LIST completed\r\n", tag)))

		case "LSUB":
			if !authenticated {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Authenticate first\r\n", tag)))
				continue
			}
			writeLine(conn, []byte("* LSUB () \"/\" \"INBOX\"\r\n"))
			writeLine(conn, []byte(fmt.Sprintf("%s OK LSUB completed\r\n", tag)))

		case "STATUS":
			if !authenticated {
				writeLine(conn, []byte(fmt.Sprintf("%s NO Authenticate first\r\n", tag)))
				continue
			}
			// RFC 3501 §6.3.10: STATUS <mailbox> (<data items>)
			// parts[2] = mailbox name, parts[3..] = requested data items.
			// This server only supports INBOX; reject any other mailbox name.
			if len(parts) < 4 {
				writeLine(conn, []byte(fmt.Sprintf("%s BAD STATUS missing arguments\r\n", tag)))
				continue
			}
			mailboxName := strings.ToUpper(parts[2])
			if mailboxName != "INBOX" {
				writeLine(conn, []byte(fmt.Sprintf("%s NO [NONEXISTENT] Mailbox does not exist\r\n", tag)))
				continue
			}

			requestedItems := parseStatusItems(strings.Join(parts[3:], " "))
			if len(requestedItems) == 0 {
				writeLine(conn, []byte(fmt.Sprintf("%s BAD STATUS data item list is empty or malformed\r\n", tag)))
				continue
			}

			count, uidValidity, nextUID, err := s.db.GetMailboxInfo(currentUser)
			if err != nil {
				writeLine(conn, []byte(fmt.Sprintf("%s NO STATUS failed\r\n", tag)))
				continue
			}
			if uidValidity == 0 {
				uidValidity = uint32(time.Now().Unix())
			}
			if nextUID == 0 {
				nextUID = count + 1
			}

			var unseenCount uint32
			if requestedItems["UNSEEN"] {
				// UNSEEN must be the count of messages without \Seen (flag bit 0x01),
				// not the total message count. FetchMessageHeaders avoids copying
				// message payloads — only UID, Flags, and metadata are needed here.
				allMsgs, fetchErr := s.db.FetchMessageHeaders(currentUser)
				if fetchErr != nil {
					writeLine(conn, []byte(fmt.Sprintf("%s NO STATUS failed\r\n", tag)))
					continue
				}
				for _, m := range allMsgs {
					if m.Flags&0x01 == 0 {
						unseenCount++
					}
				}
			}

			var statusPairs []string
			for _, item := range []string{"MESSAGES", "RECENT", "UIDNEXT", "UIDVALIDITY", "UNSEEN"} {
				if !requestedItems[item] {
					continue
				}
				switch item {
				case "MESSAGES":
					statusPairs = append(statusPairs, fmt.Sprintf("MESSAGES %d", count))
				case "RECENT":
					statusPairs = append(statusPairs, "RECENT 0")
				case "UIDNEXT":
					statusPairs = append(statusPairs, fmt.Sprintf("UIDNEXT %d", nextUID))
				case "UIDVALIDITY":
					statusPairs = append(statusPairs, fmt.Sprintf("UIDVALIDITY %d", uidValidity))
				case "UNSEEN":
					statusPairs = append(statusPairs, fmt.Sprintf("UNSEEN %d", unseenCount))
				}
			}
			writeLine(conn, []byte(fmt.Sprintf("* STATUS INBOX (%s)\r\n", strings.Join(statusPairs, " "))))
			writeLine(conn, []byte(fmt.Sprintf("%s OK STATUS completed\r\n", tag)))

		case "CLOSE":
			if !selected {
				writeLine(conn, []byte(fmt.Sprintf("%s BAD No mailbox selected\r\n", tag)))
				continue
			}
			// RFC 3501 §6.4.2: CLOSE must silently expunge \Deleted messages.
			if _, err := s.db.ExpungeDeletedMessages(currentUser); err != nil {
				writeLine(conn, []byte(fmt.Sprintf("%s NO CLOSE failed\r\n", tag)))
				continue
			}
			selected = false
			writeLine(conn, []byte(fmt.Sprintf("%s OK CLOSE completed\r\n", tag)))

		case "LOGOUT":
			// RFC 3501 §6.1.3: server sends untagged BYE, then tagged OK.
			// Two distinct protocol lines — sent as separate writes for clarity
			// and correct per-write deadline enforcement.
			writeLine(conn, []byte("* BYE IMAP Server logging out\r\n"))
			writeLine(conn, []byte(fmt.Sprintf("%s OK LOGOUT completed\r\n", tag)))
			return

		default:
			writeLine(conn, []byte(fmt.Sprintf("%s BAD Unknown command\r\n", tag)))
		}
	}
}

// authenticateUser validates credentials, enforces domain policy, and updates
// session state. It writes the tagged response to conn and returns any error.
// remoteAddr is included in log lines for abuse detection and audit purposes.
func (s *Server) authenticateUser(tag, user, pass string, authenticated *bool, currentUser *string, conn net.Conn, remoteAddr string) error {
	user = cleanAuthUsername(user)
	if user == "" || !strings.HasSuffix(user, "@local.chat") {
		writeLine(conn, []byte(fmt.Sprintf("%s NO [AUTHENTICATIONFAILED] Only well-formed @local.chat accounts are permitted\r\n", tag)))
		log.Printf("IMAP auth rejected — malformed/non-local identity: user=%q remote=%s", user, remoteAddr)
		return fmt.Errorf("identity rejected")
	}
	err := s.db.AuthenticateOrRegister(user, pass)
	if err != nil {
		if errors.Is(err, database.ErrUserSuspended) {
			writeLine(conn, []byte(fmt.Sprintf("%s NO [ALERT] Account suspended by administration\r\n", tag)))
		} else {
			writeLine(conn, []byte(fmt.Sprintf("%s NO [AUTHENTICATIONFAILED] Credentials invalid\r\n", tag)))
		}
		log.Printf("IMAP authentication failed: user=%q remote=%s err=%v", user, remoteAddr, err)
		return err
	}
	*authenticated = true
	*currentUser = user
	log.Printf("IMAP authentication succeeded: user=%s remote=%s", user, remoteAddr)
	writeLine(conn, []byte(fmt.Sprintf("%s OK LOGIN completed\r\n", tag)))
	return nil
}

// expungeAndReport fetches the pre-expunge snapshot, runs the expunge, and
// returns the descending sequence numbers of the expunged messages as required
// by RFC 3501 §7.4.1 (sequence numbers shift downward with each expunge).
func (s *Server) expungeAndReport(username string) ([]int, error) {
	// Snapshot message metadata before expunge to compute correct sequence numbers.
	msgsBefore, err := s.db.FetchMessageHeaders(username)
	if err != nil {
		return nil, err
	}
	expungedUIDs, err := s.db.ExpungeDeletedMessages(username)
	if err != nil {
		return nil, err
	}

	expungedSet := make(map[uint32]bool, len(expungedUIDs))
	for _, uid := range expungedUIDs {
		expungedSet[uid] = true
	}

	// Collect sequence numbers in forward order, then reverse before returning
	// so that clients remove them from highest to lowest (RFC 3501 §7.4.1).
	var seqNums []int
	for i, msg := range msgsBefore {
		if expungedSet[msg.UID] {
			seqNums = append(seqNums, i+1)
		}
	}
	// Reverse so we send highest sequence number first.
	for i, j := 0, len(seqNums)-1; i < j; i, j = i+1, j-1 {
		seqNums[i], seqNums[j] = seqNums[j], seqNums[i]
	}
	return seqNums, nil
}

// cleanAuthUsername validates the mailbox identity used for IMAP LOGIN and
// AUTHENTICATE. Auto-registration is intentionally limited to syntactically
// well-formed local.chat mailboxes to prevent malformed accounts such as
// "@local.chat" or "alice@@local.chat" from being created through auth paths.
func cleanAuthUsername(username string) string {
	if strings.ContainsAny(username, "\r\n\t") {
		return ""
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" || strings.Contains(username, " ") {
		return ""
	}
	if strings.Count(username, "@") != 1 {
		return ""
	}
	parts := strings.SplitN(username, "@", 2)
	if parts[0] == "" || parts[1] == "" {
		return ""
	}
	return username
}

// decodePlainAuth decodes a base64-encoded SASL PLAIN token of the form:
// [authzid NUL] authcid NUL passwd  (RFC 4616)
func decodePlainAuth(encoded string) (user, pass string, ok bool) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Some clients omit padding; try RawStdEncoding as a fallback.
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return "", "", false
		}
	}
	if len(decoded) < 2 {
		return "", "", false
	}
	// Split on NUL bytes: [authzid \x00 authcid \x00 passwd]
	parts := strings.SplitN(string(decoded), "\x00", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	// parts[0] = authzid (ignored), parts[1] = username, parts[2] = password
	return parts[1], parts[2], true
}

// matchSeq reports whether seqNum (1-based) is within the given RFC 3501
// sequence-set string. Sequence-sets may be comma-separated lists of numbers
// and ranges, e.g. "1,3,5:7,*". "*" means the last message (totalMsgs).
func matchSeq(seqNum, totalMsgs int, seqSet string) bool {
	for _, part := range strings.Split(seqSet, ",") {
		part = strings.TrimSpace(part)
		if matchSeqPart(seqNum, totalMsgs, part) {
			return true
		}
	}
	return false
}

func matchSeqPart(seqNum, totalMsgs int, part string) bool {
	resolveSeq := func(s string) int {
		if s == "*" {
			return totalMsgs
		}
		var v int
		if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
			return -1
		}
		return v
	}
	if !strings.Contains(part, ":") {
		return seqNum == resolveSeq(part)
	}
	rangeParts := strings.SplitN(part, ":", 2)
	lo := resolveSeq(rangeParts[0])
	hi := resolveSeq(rangeParts[1])
	if lo > hi {
		lo, hi = hi, lo // RFC 3501 §9: n:m is valid even when n > m
	}
	return seqNum >= lo && seqNum <= hi
}

func highestUID(msgs []database.DBMessage) uint32 {
	var maxUID uint32
	for _, msg := range msgs {
		if msg.UID > maxUID {
			maxUID = msg.UID
		}
	}
	return maxUID
}

// matchUID reports whether uid is within the given RFC 3501 UID set string.
// UID sets use the same comma/range syntax as sequence sets, but "*" means the
// highest UID currently in the mailbox snapshot, not "all UIDs". Passing maxUID
// keeps wildcard handling RFC-correct for FETCH/STORE/EXPUNGE snapshots.
func matchUID(uid, maxUID uint32, seqSet string) bool {
	for _, part := range strings.Split(seqSet, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if matchUIDPart(uid, maxUID, part) {
			return true
		}
	}
	return false
}

func matchUIDPart(uid, maxUID uint32, part string) bool {
	resolveUID := func(s string) (uint32, bool) {
		if s == "*" {
			return maxUID, maxUID != 0
		}
		var val uint32
		if _, err := fmt.Sscanf(s, "%d", &val); err != nil {
			return 0, false
		}
		return val, true
	}

	if !strings.Contains(part, ":") {
		val, ok := resolveUID(part)
		return ok && uid == val
	}
	rangeParts := strings.SplitN(part, ":", 2)
	if len(rangeParts) != 2 {
		return false
	}
	start, ok := resolveUID(rangeParts[0])
	if !ok {
		return false
	}
	end, ok := resolveUID(rangeParts[1])
	if !ok {
		return false
	}
	if start > end {
		start, end = end, start
	}
	return uid >= start && uid <= end
}

func parseStatusItems(raw string) map[string]bool {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "(")
	raw = strings.TrimSuffix(raw, ")")
	items := make(map[string]bool)
	for _, field := range strings.Fields(raw) {
		switch strings.ToUpper(field) {
		case "MESSAGES", "RECENT", "UIDNEXT", "UIDVALIDITY", "UNSEEN":
			items[strings.ToUpper(field)] = true
		}
	}
	return items
}

func formatFlags(flags uint32) string {
	var list []string
	if flags&0x01 != 0 {
		list = append(list, "\\Seen")
	}
	if flags&0x02 != 0 {
		list = append(list, "\\Answered")
	}
	if flags&0x04 != 0 {
		list = append(list, "\\Flagged")
	}
	if flags&0x08 != 0 {
		list = append(list, "\\Deleted")
	}
	if flags&0x10 != 0 {
		list = append(list, "\\Draft")
	}
	return "(" + strings.Join(list, " ") + ")"
}

func parseFlagsMask(s string) uint32 {
	var mask uint32
	upper := strings.ToUpper(s)
	if strings.Contains(upper, "\\SEEN") {
		mask |= 0x01
	}
	if strings.Contains(upper, "\\ANSWERED") {
		mask |= 0x02
	}
	if strings.Contains(upper, "\\FLAGGED") {
		mask |= 0x04
	}
	if strings.Contains(upper, "\\DELETED") {
		mask |= 0x08
	}
	if strings.Contains(upper, "\\DRAFT") {
		mask |= 0x10
	}
	return mask
}

// parseIMAPLine splits an IMAP command line into tokens, honouring double-quoted
// strings and parenthesised groups. Outside quoted strings, backslash is treated
// as a literal character because IMAP flag names like \Seen must be preserved.
// Inside quoted strings, only RFC 3501 quoted-pair escapes for DQUOTE and
// backslash are unescaped; other backslashes are preserved defensively.
func parseIMAPLine(line string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	parenDepth := 0

	flush := func() {
		if current.Len() > 0 {
			parts = append(parts, current.String())
			current.Reset()
		}
	}

	for i := 0; i < len(line); i++ {
		r := line[i]

		if inQuote {
			// RFC 3501 quoted strings use backslash to escape DQUOTE and
			// backslash. Preserve non-standard backslash sequences literally instead
			// of silently dropping the backslash from a password/mailbox name.
			if r == '\\' && i+1 < len(line) {
				next := line[i+1]
				if next == '\\' || next == '"' {
					i++
					current.WriteByte(next)
					continue
				}
			}
			if r == '"' {
				inQuote = false
				continue
			}
			current.WriteByte(r)
			continue
		}

		switch r {
		case '"':
			inQuote = true
			continue
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case ' ':
			if parenDepth == 0 {
				flush()
				continue
			}
		}
		current.WriteByte(r)
	}
	flush()
	return parts
}
