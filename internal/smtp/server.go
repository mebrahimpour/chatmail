// Package smtp implements the chatmail SMTP submission engine on top of
// emersion/go-smtp. It performs auto-registration on first authentication,
// enforces the local-domain policy, and commits raw MIME payloads to bbolt.
//
// TLS is intentionally absent: transport encryption is terminated by the
// external stunnel4 daemon, so this engine speaks plaintext on its loopback
// port only.
package smtp

import (
	"io"
	"log"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"

	"chatmail/internal/database"
)

// MaxMessageBytes is the maximum accepted DATA payload (10 MiB). Larger
// submissions are rejected with 552 either pre-emptively in MAIL (if the
// client advertises SIZE) or by the framework during DATA.
const MaxMessageBytes int64 = 10 * 1024 * 1024

// Backend adapts the chatmail database to the go-smtp Backend interface.
type Backend struct {
	db     *database.DB
	logger *log.Logger
}

// Compile-time interface check.
var _ gosmtp.Backend = (*Backend)(nil)

// NewServer constructs a configured go-smtp server bound to addr.
func NewServer(db *database.DB, addr string, logger *log.Logger) *gosmtp.Server {
	be := &Backend{db: db, logger: logger}
	s := gosmtp.NewServer(be)
	s.Addr = addr
	s.Domain = db.Domain()
	s.MaxMessageBytes = MaxMessageBytes
	s.MaxRecipients = 50
	// Standard SMTP timeout for submission servers.
	// RFC 5321 §4.5.3.2 recommends 5 minutes for DATA; we use that for all phases.
	s.ReadTimeout = 5 * time.Minute
	s.WriteTimeout = 5 * time.Minute
	// AUTH must be offered on this plain loopback socket because stunnel4 has
	// already terminated TLS on the public-facing port.
	s.AllowInsecureAuth = true
	// Accept UTF-8 in addresses (RFC 6532) for international usernames.
	s.EnableSMTPUTF8 = true
	if logger != nil {
		s.ErrorLog = logger
	}
	return s
}

// NewSession implements gosmtp.Backend.
func (b *Backend) NewSession(_ *gosmtp.Conn) (gosmtp.Session, error) {
	return &session{db: b.db, logger: b.logger}, nil
}

// session carries the state of a single SMTP connection.
type session struct {
	db     *database.DB
	logger *log.Logger

	authUser string // set after successful AUTH PLAIN
	from     string
	rcpts    []string
}

// Compile-time interface check.
var _ gosmtp.AuthSession = (*session)(nil)

// AuthMechanisms advertises supported SASL mechanisms.
func (s *session) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

// Auth returns a SASL PLAIN server that performs credential validation and
// auto-registration via the database layer.
func (s *session) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, username, password string) error {
		created, err := s.db.Authenticate(username, password)
		if err == database.ErrAuthFailed {
			return &gosmtp.SMTPError{
				Code:         535,
				EnhancedCode: gosmtp.EnhancedCode{5, 7, 8},
				Message:      "Authentication credentials invalid",
			}
		}
		if err != nil {
			s.logf("auth error for %q: %v", username, err)
			return &gosmtp.SMTPError{
				Code:         451,
				EnhancedCode: gosmtp.EnhancedCode{4, 0, 0},
				Message:      "Internal authentication error; please retry",
			}
		}
		s.authUser = username
		if created {
			s.logf("auto-registered new account %q", username)
		}
		return nil
	}), nil
}

// Mail validates the envelope sender.
//
// Enforced invariants:
//  1. The client must be authenticated (530).
//  2. The sender domain must match the local server domain (550).
//  3. If the client declared SIZE > MaxMessageBytes in EHLO, reject early (552).
func (s *session) Mail(from string, opts *gosmtp.MailOptions) error {
	if s.authUser == "" {
		// RFC 4954 §4 requires 530 "Authentication required" here.
		return &gosmtp.SMTPError{
			Code:         530,
			EnhancedCode: gosmtp.EnhancedCode{5, 7, 0},
			Message:      "Authentication required",
		}
	}
	if !s.domainMatches(from) {
		return &gosmtp.SMTPError{
			Code:         550,
			EnhancedCode: gosmtp.EnhancedCode{5, 7, 1},
			Message:      "Access denied: sender domain is not local",
		}
	}
	// Pre-emptive SIZE check (RFC 1870): reject before the client wastes
	// bandwidth uploading an oversized message.
	if opts != nil && opts.Size > MaxMessageBytes {
		return &gosmtp.SMTPError{
			Code:         552,
			EnhancedCode: gosmtp.EnhancedCode{5, 3, 4},
			Message:      "Message size exceeds maximum",
		}
	}
	s.from = from
	return nil
}

// Rcpt enforces that the recipient is local. Local recipient mailboxes are
// provisioned on demand so messages can be delivered before the recipient first
// authenticates.
func (s *session) Rcpt(to string, _ *gosmtp.RcptOptions) error {
	if !s.domainMatches(to) {
		return &gosmtp.SMTPError{
			Code:         551,
			EnhancedCode: gosmtp.EnhancedCode{5, 7, 1},
			Message:      "User not local; relaying denied",
		}
	}
	addr := strings.ToLower(to)
	if err := s.db.EnsureMailbox(addr); err != nil {
		s.logf("ensure mailbox %q: %v", addr, err)
		return &gosmtp.SMTPError{Code: 451, Message: "Mailbox provisioning failed; try again"}
	}
	s.rcpts = append(s.rcpts, addr)
	return nil
}

// Data reads the raw MIME payload and commits it to every recipient mailbox.
// The payload is stored unmodified to preserve OpenPGP/Autocrypt signatures
// and DeltaChat group metadata headers.
//
// go-smtp enforces MaxMessageBytes before calling this method (it wraps the
// reader in an io.LimitedReader and returns a 552 if the limit is hit), so we
// do not need to re-check here.
func (s *session) Data(r io.Reader) error {
	if s.authUser == "" {
		// Belt-and-suspenders guard; the framework should prevent this.
		return gosmtp.ErrAuthRequired
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, rcpt := range s.rcpts {
		if _, err := s.db.AppendMessage(rcpt, body, 0, now); err != nil {
			s.logf("store %d-byte message for %q: %v", len(body), rcpt, err)
			// RFC 5321 §4.2.1: transient local failure.
			return &gosmtp.SMTPError{Code: 451, Message: "Message storage failed; try again"}
		}
	}
	s.logf("stored %d-byte message from %q to %v", len(body), s.from, s.rcpts)
	return nil
}

// Reset clears the per-transaction state but preserves authentication.
func (s *session) Reset() {
	s.from = ""
	s.rcpts = nil
}

// Logout releases session resources.
func (s *session) Logout() error { return nil }

// domainMatches reports whether addr belongs to the configured local domain.
// Comparison is case-insensitive per RFC 5321 §2.3.5.
func (s *session) domainMatches(addr string) bool {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return false
	}
	return strings.EqualFold(addr[at+1:], s.db.Domain())
}

func (s *session) logf(format string, args ...interface{}) {
	if s.logger != nil {
		s.logger.Printf("smtp: "+format, args...)
		return
	}
	log.Printf("smtp: "+format, args...)
}
