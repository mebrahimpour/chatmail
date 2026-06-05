// Package smtp implements the chatmail SMTP submission engine on top of
// emersion/go-smtp. It performs auto-registration on first authentication,
// enforces the local-domain policy, and commits raw MIME payloads to bbolt.
package smtp

import (
	"io"
	"log"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"

	"github.com/local/chatmail/internal/database"
)

// MaxMessageBytes is the maximum accepted DATA payload (10 MiB). Larger
// submissions are rejected with a 552 error during the DATA phase.
const MaxMessageBytes int64 = 10 * 1024 * 1024

// Backend adapts the chatmail database to the go-smtp Backend interface.
type Backend struct {
	db     *database.DB
	logger *log.Logger
}

// NewServer constructs a go-smtp server bound to addr. TLS is intentionally not
// configured: transport encryption is terminated by the external stunnel4
// daemon, so the engine speaks plaintext on its loopback port.
func NewServer(db *database.DB, addr string, logger *log.Logger) *gosmtp.Server {
	be := &Backend{db: db, logger: logger}
	s := gosmtp.NewServer(be)
	s.Addr = addr
	s.Domain = db.Domain()
	s.MaxMessageBytes = MaxMessageBytes
	s.MaxRecipients = 50
	s.ReadTimeout = 5 * time.Minute
	s.WriteTimeout = 5 * time.Minute
	// The engine runs behind stunnel4 on a plaintext loopback socket, so AUTH
	// must be offered without an in-process TLS layer.
	s.AllowInsecureAuth = true
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

	authUser string
	from     string
	rcpts    []string
}

var _ gosmtp.AuthSession = (*session)(nil)

// AuthMechanisms advertises the supported SASL mechanisms.
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
				Message:      "Internal authentication error",
			}
		}
		s.authUser = username
		if created {
			s.logf("auto-registered new account %q", username)
		}
		return nil
	}), nil
}

// Mail validates the envelope sender domain against the local server domain.
func (s *session) Mail(from string, _ *gosmtp.MailOptions) error {
	if !s.domainMatches(from) {
		return &gosmtp.SMTPError{
			Code:         550,
			EnhancedCode: gosmtp.EnhancedCode{5, 7, 1},
			Message:      "Access denied: sender domain is not local",
		}
	}
	s.from = from
	return nil
}

// Rcpt enforces that the recipient is local; external relay is refused. Local
// recipient mailboxes are provisioned on demand so messages can be delivered
// even before the recipient first authenticates.
func (s *session) Rcpt(to string, _ *gosmtp.RcptOptions) error {
	if !s.domainMatches(to) {
		return &gosmtp.SMTPError{
			Code:         551,
			EnhancedCode: gosmtp.EnhancedCode{5, 7, 1},
			Message:      "User not local; relaying denied",
		}
	}
	if err := s.db.EnsureMailbox(strings.ToLower(to)); err != nil {
		s.logf("ensure mailbox %q: %v", to, err)
		return &gosmtp.SMTPError{Code: 451, Message: "Mailbox provisioning failed"}
	}
	s.rcpts = append(s.rcpts, strings.ToLower(to))
	return nil
}

// Data reads the raw MIME payload and commits it verbatim to every recipient
// mailbox. The payload is stored unmodified to preserve OpenPGP/Autocrypt
// signatures and DeltaChat group headers.
func (s *session) Data(r io.Reader) error {
	if s.authUser == "" {
		return gosmtp.ErrAuthRequired
	}
	body, err := io.ReadAll(r)
	if err != nil {
		// go-smtp surfaces the 552 size-limit error here when the cap is hit.
		return err
	}
	now := time.Now()
	for _, rcpt := range s.rcpts {
		if _, err := s.db.AppendMessage(rcpt, body, 0, now); err != nil {
			s.logf("store message for %q: %v", rcpt, err)
			return &gosmtp.SMTPError{Code: 451, Message: "Message storage failed"}
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

// domainMatches reports whether addr is within the configured local domain.
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
