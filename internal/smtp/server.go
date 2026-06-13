package smtp

import (
	"bytes"
	"chatmail/internal/database"
	"errors"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

type Server struct {
	addr string
	db   *database.BboltDB
	mu   sync.Mutex
	srv  *smtp.Server
}

func NewServer(addr string, db *database.BboltDB) *Server {
	return &Server{addr: addr, db: db}
}

func (s *Server) ListenAndServe() error {
	srv := smtp.NewServer(&Backend{db: s.db})
	srv.Addr = s.addr
	srv.Domain = "local.chat"
	srv.MaxMessageBytes = 10 * 1024 * 1024 // Strict 10 MB quota per message
	srv.MaxRecipients = 50                 // Cap recipients per envelope to prevent amplification
	srv.AllowInsecureAuth = true           // TLS is handled by stunnel4 upstream
	srv.ReadTimeout = 5 * time.Minute      // Protect against slow-loris read attacks
	srv.WriteTimeout = 5 * time.Minute     // Protect against write-blocked connections

	s.mu.Lock()
	s.srv = srv
	s.mu.Unlock()

	return srv.ListenAndServe()
}

// Close gracefully shuts down the SMTP listener.
func (s *Server) Close() {
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// SMTP Backend Architecture
type Backend struct {
	db *database.BboltDB
}

func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{
		backend:    b,
		remoteAddr: c.Conn().RemoteAddr().String(),
	}, nil
}

type Session struct {
	backend    *Backend
	remoteAddr string // remote IP:port, captured at session creation for logging
	user       string
	to         []string
}

// cleanAddress normalises an RFC 5321 address by stripping angle brackets,
// trimming whitespace, and lowercasing. Returns an empty string if the result
// is structurally invalid (no @, multiple @, empty local part, or whitespace)
// so that all callers can rely on a simple empty-string check.
func cleanAddress(addr string) string {
	addr = strings.TrimSpace(addr)

	// RFC 5321 paths are normally presented as <local@domain>. Be strict about
	// angle brackets: accept a balanced outer pair, but reject unbalanced or
	// nested brackets instead of silently normalising malformed paths such as
	// "alice@local.chat>" into a valid address.
	hasOpen := strings.Contains(addr, "<")
	hasClose := strings.Contains(addr, ">")
	if hasOpen || hasClose {
		if !(strings.HasPrefix(addr, "<") && strings.HasSuffix(addr, ">")) {
			return ""
		}
		addr = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(addr, "<"), ">"))
		if strings.ContainsAny(addr, "<>") {
			return ""
		}
	}

	addr = strings.ToLower(addr)
	return cleanAuthUsername(addr)
}

// cleanAuthUsername validates the address form used as a login identity. SMTP
// authentication should not auto-register malformed local-part values such as
// "@local.chat", "alice@@local.chat", or values containing whitespace/control
// characters. The empty-string return value means invalid.
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

// AuthMechanisms advertises the supported SASL mechanisms in the EHLO response.
// Implements the go-smtp AuthSession add-on interface (go-smtp v0.21.3+).
func (s *Session) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

// Auth returns the sasl.Server for the requested mechanism.
// The returned server's Next() method is called by go-smtp to drive the
// SASL exchange; all credential validation happens inside the PlainAuthenticator
// closure so it runs outside the bbolt write lock.
// Implements the go-smtp AuthSession add-on interface.
func (s *Session) Auth(mech string) (sasl.Server, error) {
	if mech != sasl.Plain {
		return nil, &smtp.SMTPError{
			Code:         504,
			EnhancedCode: smtp.EnhancedCode{5, 7, 4},
			Message:      "Unsupported authentication mechanism",
		}
	}

	return sasl.NewPlainServer(func(identity, username, password string) error {
		// identity (authzid) is deliberately ignored — we only support
		// simple username/password authentication.
		trimmedUser := cleanAuthUsername(username)

		if trimmedUser == "" || !strings.HasSuffix(trimmedUser, "@local.chat") {
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 8},
				Message:      "Access Denied: sender must be a @local.chat account",
			}
		}

		if err := s.backend.db.AuthenticateOrRegister(trimmedUser, password); err != nil {
			if errors.Is(err, database.ErrUserSuspended) {
				log.Printf("SMTP auth rejected — suspended: user=%s remote=%s", trimmedUser, s.remoteAddr)
				return &smtp.SMTPError{
					Code:         550,
					EnhancedCode: smtp.EnhancedCode{5, 7, 8},
					Message:      "Account disabled by administrator",
				}
			}
			log.Printf("SMTP auth failed: user=%s remote=%s err=%v", trimmedUser, s.remoteAddr, err)
			return &smtp.SMTPError{
				Code:         535,
				EnhancedCode: smtp.EnhancedCode{5, 7, 8},
				Message:      "Authentication credentials invalid",
			}
		}

		s.user = trimmedUser
		log.Printf("SMTP auth succeeded: user=%s remote=%s", trimmedUser, s.remoteAddr)
		return nil
	}), nil
}

func (s *Session) ensureAuthenticatedActive() error {
	if s.user == "" {
		return &smtp.SMTPError{
			Code:         530,
			EnhancedCode: smtp.EnhancedCode{5, 7, 0},
			Message:      "Authentication required",
		}
	}
	exists, suspended, err := s.backend.db.GetUserStatus(s.user)
	if err != nil {
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "Temporary system error — please retry",
		}
	}
	if !exists || suspended {
		log.Printf("SMTP command rejected — authenticated account inactive: user=%s remote=%s", s.user, s.remoteAddr)
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 8},
			Message:      "Account disabled by administrator",
		}
	}
	return nil
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	// Require authentication and re-check active sender state before accepting
	// each envelope. This closes the window where an account is suspended after
	// AUTH but before MAIL FROM / DATA.
	if err := s.ensureAuthenticatedActive(); err != nil {
		return err
	}
	trimmedFrom := cleanAddress(from)
	if trimmedFrom == "" {
		return &smtp.SMTPError{
			Code:         501,
			EnhancedCode: smtp.EnhancedCode{5, 1, 3},
			Message:      "Malformed address in MAIL FROM",
		}
	}
	if !strings.HasSuffix(trimmedFrom, "@local.chat") {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "Access Denied: MAIL FROM must be a @local.chat address",
		}
	}
	// Prevent sender spoofing: MAIL FROM must match the authenticated user.
	if trimmedFrom != s.user {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "Access Denied: MAIL FROM does not match authenticated identity",
		}
	}
	s.to = nil
	return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	// Belt-and-suspenders: re-check authenticated sender status on every RCPT so
	// a newly suspended account cannot keep expanding an already-open envelope.
	if err := s.ensureAuthenticatedActive(); err != nil {
		return err
	}
	trimmedTo := cleanAddress(to)
	if trimmedTo == "" {
		return &smtp.SMTPError{
			Code:         501,
			EnhancedCode: smtp.EnhancedCode{5, 1, 3},
			Message:      "Malformed address in RCPT TO",
		}
	}
	if !strings.HasSuffix(trimmedTo, "@local.chat") {
		return &smtp.SMTPError{
			Code:         551,
			EnhancedCode: smtp.EnhancedCode{5, 1, 6},
			Message:      "User not local: Forwarding and external relay blocked",
		}
	}

	// Verify recipient existence and suspension state in a single atomic read
	// transaction — eliminates the TOCTOU window between two sequential calls.
	exists, suspended, err := s.backend.db.GetUserStatus(trimmedTo)
	if err != nil {
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "Temporary system error — please retry",
		}
	}
	if !exists {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 1, 1},
			Message:      "User not found or mailbox deactivated",
		}
	}
	if suspended {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 2, 1},
			Message:      "User account has been suspended by administration",
		}
	}

	s.to = append(s.to, trimmedTo)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	// Re-check the authenticated sender immediately before accepting DATA so an
	// administrator suspension between RCPT and DATA is enforced before storage.
	if err := s.ensureAuthenticatedActive(); err != nil {
		return err
	}
	if len(s.to) == 0 {
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "Bad sequence of commands: no recipients specified",
		}
	}
	// Revalidate every recipient before reading/storing the message. Recipient
	// state may have changed since RCPT TO; checking up front avoids partial
	// multi-recipient delivery where earlier recipients are stored before a later
	// deleted/suspended mailbox fails.
	for _, recipient := range s.to {
		exists, suspended, err := s.backend.db.GetUserStatus(recipient)
		if err != nil {
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 3, 0},
				Message:      "Temporary system error — please retry",
			}
		}
		if !exists || suspended {
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 1, 1},
				Message:      "Recipient mailbox unavailable",
			}
		}
	}

	// Pre-allocate a 512 KiB buffer to avoid repeated heap growth for typical
	// message sizes. go-smtp already enforces MaxMessageBytes at the protocol
	// layer so io.Copy will never deliver more than that limit.
	buf := bytes.NewBuffer(make([]byte, 0, 512*1024))
	if _, err := io.Copy(buf, r); err != nil {
		return err
	}

	payload := buf.Bytes()
	for _, recipient := range s.to {
		log.Printf("Inbound SMTP mail stored for recipient %s (%d bytes)", recipient, len(payload))
		if _, err := s.backend.db.StoreMessage(recipient, payload); err != nil {
			return err
		}
	}
	return nil
}

// Reset clears the entire envelope state (RFC 5321 §4.1.1.5).
// Note: authentication state (s.user) is intentionally preserved across RSET
// because RFC 5321 only resets the mail transaction, not the session auth.
func (s *Session) Reset() {
	s.to = nil
}

func (s *Session) Logout() error {
	s.user = ""
	s.to = nil
	return nil
}
