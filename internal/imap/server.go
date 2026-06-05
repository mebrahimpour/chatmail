// Package imap implements the chatmail IMAP engine on top of the
// emersion/go-imap/v2 imapserver framework. The framework owns wire-protocol
// parsing (tagged commands, literals, sequence sets); this package supplies a
// bbolt-backed Session that exposes a single INBOX per user.
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

	"github.com/local/chatmail/internal/database"
)

const inbox = "INBOX"

// NewServer constructs an imapserver.Server backed by the chatmail database.
// TLS is intentionally omitted: encryption is terminated by stunnel4 and the
// engine speaks plaintext on its loopback port. InsecureAuth therefore must be
// enabled so LOGIN/AUTHENTICATE are accepted without an in-process TLS layer.
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

// session is the per-connection IMAP state. After SELECT it holds an immutable
// snapshot of the mailbox (sorted by ascending UID); sequence number N maps to
// snapshot index N-1. Mutations (STORE/EXPUNGE/APPEND) are written through to
// bbolt and the snapshot is reloaded so sequence numbers stay consistent.
type session struct {
	db     *database.DB
	logger *log.Logger

	user     string
	selected bool
	msgs     []*database.Message
	uidNext  uint32
	uidValid uint32
}

var _ imapserver.Session = (*session)(nil)

// --- Not authenticated state ---

// Login validates credentials against the Users bucket. Unknown accounts are
// rejected (no auto-registration on the IMAP side).
func (s *session) Login(username, password string) error {
	if err := s.db.VerifyCredentials(username, password); err != nil {
		return imapserver.ErrAuthFailed
	}
	s.user = strings.ToLower(username)
	return nil
}

func (s *session) Close() error { return nil }

// --- Authenticated state ---

func (s *session) Select(mailbox string, _ *imap.SelectOptions) (*imap.SelectData, error) {
	if !strings.EqualFold(mailbox, inbox) {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNonExistent, Text: "No such mailbox"}
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
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNonExistent, Text: "No such mailbox"}
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

func (s *session) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	if len(patterns) == 0 {
		// A nil-pattern LIST is a request for the hierarchy delimiter.
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
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeTryCreate, Text: "No such mailbox"}
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

// --- Selected state ---

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

func (s *session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
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
	return s.Fetch(w, numSet, &imap.FetchOptions{Flags: true})
}

func (s *session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	// Emit EXPUNGE responses in descending sequence order so that the
	// client's remaining sequence numbers stay valid as messages are removed.
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

func (s *session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
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

func (s *session) Poll(_ *imapserver.UpdateWriter, _ bool) error { return nil }

// Idle blocks until the client terminates the IDLE command. The engine does not
// push unsolicited updates; clients observe new mail by re-selecting INBOX.
func (s *session) Idle(_ *imapserver.UpdateWriter, stop <-chan struct{}) error {
	<-stop
	return nil
}

// --- Unsupported mutating operations on the fixed INBOX-only namespace ---

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
	return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeTryCreate, Text: "No such mailbox"}
}

// --- helpers ---

func (s *session) reload() error {
	msgs, err := s.db.LoadMessages(s.user)
	if err != nil && err != database.ErrNoMailbox {
		return err
	}
	s.msgs = msgs
	if s.uidNext, err = s.db.NextUID(s.user); err != nil {
		return err
	}
	if s.uidValid, err = s.db.UIDValidity(s.user); err != nil {
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

// contains reports whether a message identified by (seqNum, uid) is selected by
// numSet. Dynamic "*" ranges are resolved against the mailbox maxima.
func contains(numSet imap.NumSet, seqNum, uid, maxSeq, maxUID uint32) bool {
	switch set := numSet.(type) {
	case imap.SeqSet:
		return rangeContains(staticSeq(set, maxSeq), seqNum)
	case imap.UIDSet:
		return rangeContains(staticUID(set, maxUID), uid)
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

func staticSeq(set imap.SeqSet, max uint32) [][2]uint32 {
	out := make([][2]uint32, 0, len(set))
	for _, r := range set {
		out = append(out, resolveRange(r.Start, r.Stop, max))
	}
	return out
}

func staticUID(set imap.UIDSet, max uint32) [][2]uint32 {
	out := make([][2]uint32, 0, len(set))
	for _, r := range set {
		out = append(out, resolveRange(uint32(r.Start), uint32(r.Stop), max))
	}
	return out
}

// resolveRange converts a possibly-dynamic IMAP range into a concrete [lo,hi]
// pair. The value 0 represents "*", the largest seq/UID in the mailbox.
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

func definedFlags() []imap.Flag {
	return []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft}
}

// systemFlagBits maps the five supported system flags to their bitmask values.
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

// flagsToBitmask converts a list of IMAP flags to the stored bitmask.
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

// bitmaskToFlags converts the stored bitmask to a list of IMAP flags.
func bitmaskToFlags(b uint32) []imap.Flag {
	flags := []imap.Flag{}
	for _, sf := range systemFlagBits {
		if b&sf.bit != 0 {
			flags = append(flags, sf.flag)
		}
	}
	return flags
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

// writeMessage emits a single FETCH response, mirroring the item handling of
// the upstream in-memory server. Body section extraction is delegated to the
// framework so MIME structure parsing stays correct.
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

// matchSearch implements the minimal SEARCH criteria needed by DeltaChat:
// sequence/UID sets, system flags, and date windows.
func matchSearch(m *database.Message, seqNum uint32, criteria *imap.SearchCriteria, maxSeq, maxUID uint32) bool {
	for _, set := range criteria.SeqNum {
		if !rangeContains(staticSeq(set, maxSeq), seqNum) {
			return false
		}
	}
	for _, set := range criteria.UID {
		if !rangeContains(staticUID(set, maxUID), m.UID) {
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
