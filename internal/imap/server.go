// Package imap implements the chatmail IMAP engine on top of the
// emersion/go-imap/v2 imapserver framework. The framework owns wire-protocol
// parsing (tagged commands, literals, sequence sets, SASL); this package
// supplies a bbolt-backed Session that exposes a single INBOX per authenticated
// user.
//
// Design notes:
//   - TLS is intentionally absent; encryption is terminated by stunnel4 and
//     the engine speaks plaintext on its loopback port.
//   - InsecureAuth must be enabled so LOGIN/AUTHENTICATE are accepted without
//     an in-process TLS layer.
//   - IMAP LOGIN rejects unknown users; SMTP AUTH performs auto-registration.
//     This asymmetry is intentional: the first interaction is always a
//     submission from a client that already knows its credentials.
//   - The session holds an in-memory snapshot of the mailbox taken at SELECT
//     time. Mutations (STORE, EXPUNGE, APPEND) are written through to bbolt
//     and the snapshot is reloaded so sequence numbers remain stable.
//   - IDLE blocks until the client sends DONE. The engine does not push
//     unsolicited EXISTS/EXPUNGE updates; clients discover new mail by
//     re-SELECTing.
package imap

import (
	"bufio"
	"bytes"
	"log"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/textproto"

	"chatmail/internal/database"
)

const inbox = "INBOX"

// NewServer constructs an imapserver.Server backed by the chatmail database.
func NewServer(db *database.DB, logger *log.Logger) *imapserver.Server {
	opts := &imapserver.Options{
		NewSession: func(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return &session{db: db, logger: logger}, nil, nil
		},
		Caps:         imap.CapSet{imap.CapIMAP4rev1: {}},
		InsecureAuth: true,
	}
	if logger != nil {
		opts.Logger = logger
	}
	return imapserver.New(opts)
}

// session is the per-connection IMAP state.
type session struct {
	db     *database.DB
	logger *log.Logger

	user     string
	selected bool
	msgs     []*database.Message
	uidNext  uint32
	uidValid uint32
}

// Compile-time proof that *session satisfies the framework interface.
var _ imapserver.Session = (*session)(nil)

// ---------------------------------------------------------------------------
// Not-authenticated state
// ---------------------------------------------------------------------------

// Login validates credentials against the Users bucket. Unknown accounts are
// rejected — there is no auto-registration on the IMAP side.
func (s *session) Login(username, password string) error {
	if err := s.db.VerifyCredentials(username, password); err != nil {
		return imapserver.ErrAuthFailed
	}
	s.user = strings.ToLower(username)
	return nil
}

func (s *session) Close() error { return nil }

// ---------------------------------------------------------------------------
// Authenticated state
// ---------------------------------------------------------------------------

func (s *session) Select(mailbox string, _ *imap.SelectOptions) (*imap.SelectData, error) {
	if !strings.EqualFold(mailbox, inbox) {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "No such mailbox",
		}
	}
	if err := s.reload(); err != nil {
		return nil, err
	}
	s.selected = true

	data := &imap.SelectData{
		Flags:          definedFlags(),
		PermanentFlags: append(definedFlags(), imap.FlagWildcard),
		NumMessages:    uint32(len(s.msgs)),
		UIDNext:        imap.UID(s.uidNext),
		UIDValidity:    s.uidValid,
	}
	for i, m := range s.msgs {
		if m.Flags&database.FlagSeen == 0 {
			data.FirstUnseenSeqNum = uint32(i) + 1
			break
		}
	}
	return data, nil
}

func (s *session) Unselect() error {
	s.selected = false
	s.msgs = nil
	return nil
}

func (s *session) Status(mailbox string, options *imap.StatusOptions) (*imap.StatusData, error) {
	if !strings.EqualFold(mailbox, inbox) {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "No such mailbox",
		}
	}
	msgs, err := s.db.LoadMessages(s.user)
	if err != nil && err != database.ErrNoMailbox {
		return nil, err
	}
	uidNext, _ := s.db.NextUID(s.user)
	uidValid, _ := s.db.UIDValidity(s.user)

	data := &imap.StatusData{Mailbox: inbox}
	if options.NumMessages {
		n := uint32(len(msgs))
		data.NumMessages = &n
	}
	if options.UIDNext {
		data.UIDNext = imap.UID(uidNext)
	}
	if options.UIDValidity {
		data.UIDValidity = uidValid
	}
	if options.NumUnseen {
		var n uint32
		for _, m := range msgs {
			if m.Flags&database.FlagSeen == 0 {
				n++
			}
		}
		data.NumUnseen = &n
	}
	if options.NumDeleted {
		var n uint32
		for _, m := range msgs {
			if m.Flags&database.FlagDeleted != 0 {
				n++
			}
		}
		data.NumDeleted = &n
	}
	return data, nil
}

func (s *session) List(w *imapserver.ListWriter, ref string, patterns []string, _ *imap.ListOptions) error {
	if len(patterns) == 0 {
		return w.WriteList(&imap.ListData{Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect}, Delim: '/'})
	}
	for _, pattern := range patterns {
		if imapserver.MatchList(inbox, '/', ref, pattern) {
			return w.WriteList(&imap.ListData{Mailbox: inbox, Delim: '/'})
		}
	}
	return nil
}

func (s *session) Append(mailbox string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	if !strings.EqualFold(mailbox, inbox) {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeTryCreate,
			Text: "No such mailbox",
		}
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, err
	}
	t := options.Time
	if t.IsZero() {
		t = time.Now()
	}
	uid, err := s.db.AppendMessage(s.user, buf.Bytes(), flagsToBitmask(options.Flags), t)
	if err != nil {
		return nil, err
	}
	uidValid, _ := s.db.UIDValidity(s.user)
	return &imap.AppendData{UID: imap.UID(uid), UIDValidity: uidValid}, nil
}

// ---------------------------------------------------------------------------
// Selected state
// ---------------------------------------------------------------------------

func (s *session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	markSeen := false
	for _, bs := range options.BodySection {
		if !bs.Peek {
			markSeen = true
			break
		}
	}

	for i, m := range s.msgs {
		seqNum := uint32(i) + 1
		if !contains(numSet, seqNum, m.UID, s.maxSeq(), s.maxUID()) {
			continue
		}
		if markSeen && m.Flags&database.FlagSeen == 0 {
			m.Flags |= database.FlagSeen
			if err := s.db.SetFlags(s.user, m.UID, m.Flags); err != nil {
				return err
			}
		}
		rw := w.CreateMessage(seqNum)
		if err := writeMessage(rw, m, options); err != nil {
			return err
		}
	}
	return nil
}

func (s *session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, _ *imap.StoreOptions) error {
	for i, m := range s.msgs {
		seqNum := uint32(i) + 1
		if !contains(numSet, seqNum, m.UID, s.maxSeq(), s.maxUID()) {
			continue
		}
		m.Flags = applyStore(m.Flags, flags)
		if err := s.db.SetFlags(s.user, m.UID, m.Flags); err != nil {
			return err
		}
	}
	if flags.Silent {
		return nil
	}
	// Emit updated FLAGS for matched messages via a FETCH response.
	return s.Fetch(w, numSet, &imap.FetchOptions{Flags: true})
}

// Expunge removes messages flagged \Deleted. If uids is non-nil (UID EXPUNGE),
// only the intersection of flagged messages and uids is removed. Responses are
// emitted in descending sequence order so the client's remaining sequence
// numbers stay valid as the list shrinks.
func (s *session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	for i := len(s.msgs) - 1; i >= 0; i-- {
		m := s.msgs[i]
		if uids != nil && !uids.Contains(imap.UID(m.UID)) {
			continue
		}
		if m.Flags&database.FlagDeleted == 0 {
			continue
		}
		if err := s.db.DeleteMessage(s.user, m.UID); err != nil {
			return err
		}
		if err := w.WriteExpunge(uint32(i) + 1); err != nil {
			return err
		}
	}
	return s.reload()
}

// Search implements the criteria subset needed by DeltaChat:
// sequence/UID sets, system flags, and date windows.
func (s *session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, _ *imap.SearchOptions) (*imap.SearchData, error) {
	var (
		data   imap.SearchData
		seqSet imap.SeqSet
		uidSet imap.UIDSet
	)
	for i, m := range s.msgs {
		seqNum := uint32(i) + 1
		if !matchSearch(m, seqNum, criteria, s.maxSeq(), s.maxUID()) {
			continue
		}
		var num uint32
		switch kind {
		case imapserver.NumKindSeq:
			seqSet.AddNum(seqNum)
			num = seqNum
		case imapserver.NumKindUID:
			uidSet.AddNum(imap.UID(m.UID))
			num = m.UID
		}
		if data.Min == 0 || num < data.Min {
			data.Min = num
		}
		if num > data.Max {
			data.Max = num
		}
		data.Count++
	}
	if kind == imapserver.NumKindUID {
		data.All = uidSet
	} else {
		data.All = seqSet
	}
	return &data, nil
}

// Poll is called by the framework for unsolicited updates (new EXISTS, EXPUNGE
// from another session). We do not maintain cross-session state, so this is a
// no-op.
func (s *session) Poll(_ *imapserver.UpdateWriter, _ bool) error { return nil }

// Idle blocks until the client terminates the IDLE command. New mail is not
// pushed; clients observe it by re-SELECTing after DONE.
func (s *session) Idle(_ *imapserver.UpdateWriter, stop <-chan struct{}) error {
	<-stop
	return nil
}

// ---------------------------------------------------------------------------
// Unsupported mutating operations on the fixed INBOX-only namespace
// ---------------------------------------------------------------------------

func (s *session) Create(string, *imap.CreateOptions) error {
	return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Mailbox creation is not supported"}
}
func (s *session) Delete(string) error {
	return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Mailbox deletion is not supported"}
}
func (s *session) Rename(string, string, *imap.RenameOptions) error {
	return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Mailbox rename is not supported"}
}
func (s *session) Subscribe(string) error   { return nil }
func (s *session) Unsubscribe(string) error { return nil }
func (s *session) Copy(imap.NumSet, string) (*imap.CopyData, error) {
	return nil, &imap.Error{
		Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeTryCreate,
		Text: "No such mailbox",
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (s *session) reload() error {
	msgs, err := s.db.LoadMessages(s.user)
	if err != nil && err != database.ErrNoMailbox {
		return err
	}
	s.msgs = msgs
	if s.uidNext, err = s.db.NextUID(s.user); err != nil && err != database.ErrNoMailbox {
		return err
	}
	if s.uidValid, err = s.db.UIDValidity(s.user); err != nil && err != database.ErrNoMailbox {
		return err
	}
	return nil
}

func (s *session) maxSeq() uint32 { return uint32(len(s.msgs)) }

func (s *session) maxUID() uint32 {
	if len(s.msgs) == 0 {
		return 0
	}
	return s.msgs[len(s.msgs)-1].UID
}

// ---------------------------------------------------------------------------
// NumSet matching
// ---------------------------------------------------------------------------

// contains reports whether a message at (seqNum, uid) is selected by numSet.
// Dynamic "*" boundaries are resolved against the current mailbox maxima.
func contains(numSet imap.NumSet, seqNum, uid, maxSeq, maxUID uint32) bool {
	switch set := numSet.(type) {
	case imap.SeqSet:
		return rangeContains(resolveSeqSet(set, maxSeq), seqNum)
	case imap.UIDSet:
		return rangeContains(resolveUIDSet(set, maxUID), uid)
	default:
		return false
	}
}

func rangeContains(ranges [][2]uint32, n uint32) bool {
	for _, r := range ranges {
		if n >= r[0] && n <= r[1] {
			return true
		}
	}
	return false
}

func resolveSeqSet(set imap.SeqSet, max uint32) [][2]uint32 {
	out := make([][2]uint32, 0, len(set))
	for _, r := range set {
		out = append(out, resolveRange(r.Start, r.Stop, max))
	}
	return out
}

func resolveUIDSet(set imap.UIDSet, max uint32) [][2]uint32 {
	out := make([][2]uint32, 0, len(set))
	for _, r := range set {
		out = append(out, resolveRange(uint32(r.Start), uint32(r.Stop), max))
	}
	return out
}

// resolveRange converts a possibly-dynamic IMAP range [start,stop] (where 0
// means "*" = the highest existing num) into a concrete [lo, hi] pair.
func resolveRange(start, stop, max uint32) [2]uint32 {
	if start == 0 {
		start = max
	}
	if stop == 0 {
		stop = max
	}
	if start > stop {
		start, stop = stop, start
	}
	return [2]uint32{start, stop}
}

// ---------------------------------------------------------------------------
// Flag conversion
// ---------------------------------------------------------------------------

// systemFlagBits maps the five system flags to their bitmask values.
var systemFlagBits = []struct {
	flag imap.Flag
	bit  uint32
}{
	{imap.FlagSeen, database.FlagSeen},
	{imap.FlagAnswered, database.FlagAnswered},
	{imap.FlagFlagged, database.FlagFlagged},
	{imap.FlagDeleted, database.FlagDeleted},
	{imap.FlagDraft, database.FlagDraft},
}

func flagsToBitmask(flags []imap.Flag) uint32 {
	var b uint32
	for _, f := range flags {
		for _, sf := range systemFlagBits {
			if strings.EqualFold(string(f), string(sf.flag)) {
				b |= sf.bit
			}
		}
	}
	return b
}

func bitmaskToFlags(b uint32) []imap.Flag {
	var flags []imap.Flag
	for _, sf := range systemFlagBits {
		if b&sf.bit != 0 {
			flags = append(flags, sf.flag)
		}
	}
	return flags
}

func definedFlags() []imap.Flag {
	return []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft}
}

func applyStore(cur uint32, store *imap.StoreFlags) uint32 {
	mask := flagsToBitmask(store.Flags)
	switch store.Op {
	case imap.StoreFlagsSet:
		return mask
	case imap.StoreFlagsAdd:
		return cur | mask
	case imap.StoreFlagsDel:
		return cur &^ mask
	default:
		return cur
	}
}

// ---------------------------------------------------------------------------
// FETCH response assembly
// ---------------------------------------------------------------------------

// writeMessage emits a single FETCH response. Body section extraction and MIME
// structure parsing are delegated to the imapserver framework helpers so the
// implementation stays protocol-correct for nested multipart messages.
func writeMessage(w *imapserver.FetchResponseWriter, m *database.Message, options *imap.FetchOptions) error {
	w.WriteUID(imap.UID(m.UID))

	if options.Flags {
		w.WriteFlags(bitmaskToFlags(m.Flags))
	}
	if options.InternalDate {
		w.WriteInternalDate(time.Unix(m.InternalDate, 0))
	}
	if options.RFC822Size {
		w.WriteRFC822Size(int64(len(m.Body)))
	}
	if options.Envelope {
		w.WriteEnvelope(extractEnvelope(m.Body))
	}
	if options.BodyStructure != nil {
		w.WriteBodyStructure(imapserver.ExtractBodyStructure(bytes.NewReader(m.Body)))
	}

	for _, bs := range options.BodySection {
		buf := imapserver.ExtractBodySection(bytes.NewReader(m.Body), bs)
		wc := w.WriteBodySection(bs, int64(len(buf)))
		_, writeErr := wc.Write(buf)
		closeErr := wc.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}

	for _, bs := range options.BinarySection {
		buf := imapserver.ExtractBinarySection(bytes.NewReader(m.Body), bs)
		wc := w.WriteBinarySection(bs, int64(len(buf)))
		_, writeErr := wc.Write(buf)
		closeErr := wc.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}

	for _, bss := range options.BinarySectionSize {
		n := imapserver.ExtractBinarySectionSize(bytes.NewReader(m.Body), bss)
		w.WriteBinarySectionSize(bss, n)
	}

	return w.Close()
}

func extractEnvelope(body []byte) *imap.Envelope {
	br := bufio.NewReader(bytes.NewReader(body))
	header, err := textproto.ReadHeader(br)
	if err != nil {
		return nil
	}
	return imapserver.ExtractEnvelope(header)
}

// ---------------------------------------------------------------------------
// SEARCH criteria matching
// ---------------------------------------------------------------------------

// matchSearch evaluates the DeltaChat-relevant SEARCH criteria subset:
// sequence/UID set membership, system flags, and date windows.
//
// Text, header, and body searches are not implemented (they would require
// full-text indexing). Unrecognised criteria cause the message to be excluded.
func matchSearch(m *database.Message, seqNum uint32, criteria *imap.SearchCriteria, maxSeq, maxUID uint32) bool {
	for _, set := range criteria.SeqNum {
		if !rangeContains(resolveSeqSet(set, maxSeq), seqNum) {
			return false
		}
	}
	for _, set := range criteria.UID {
		if !rangeContains(resolveUIDSet(set, maxUID), m.UID) {
			return false
		}
	}
	for _, f := range criteria.Flag {
		if m.Flags&flagsToBitmask([]imap.Flag{f}) == 0 {
			return false
		}
	}
	for _, f := range criteria.NotFlag {
		if m.Flags&flagsToBitmask([]imap.Flag{f}) != 0 {
			return false
		}
	}
	t := time.Unix(m.InternalDate, 0)
	if !criteria.Since.IsZero() && t.Before(criteria.Since) {
		return false
	}
	if !criteria.Before.IsZero() && !t.Before(criteria.Before) {
		return false
	}
	return true
}
