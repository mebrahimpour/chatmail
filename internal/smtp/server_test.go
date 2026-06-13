package smtp

import (
	"chatmail/internal/database"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanAddressAcceptsValidMailbox(t *testing.T) {
	if got := cleanAddress(" <Alice@LOCAL.CHAT> "); got != "alice@local.chat" {
		t.Fatalf("expected normalised address alice@local.chat, got %q", got)
	}
}

func TestCleanAddressRejectsMalformedAddresses(t *testing.T) {
	cases := []string{
		"",
		"@local.chat",
		"alice@",
		"alice@@local.chat",
		"alice@local.chat@example.com",
		"alice @local.chat",
		"alice@local.chat\r\nBCC: victim@local.chat",
		"alice@local.chat>",
		"<alice@local.chat",
		"<<alice@local.chat>>",
		"<alice@local.chat> extra",
	}
	for _, tc := range cases {
		if got := cleanAddress(tc); got != "" {
			t.Fatalf("cleanAddress(%q) = %q, want empty string", tc, got)
		}
	}
}

func TestCleanAuthUsernameRejectsMalformedIdentities(t *testing.T) {
	cases := []string{
		"",
		"@local.chat",
		"alice@",
		"alice@@local.chat",
		"alice @local.chat",
		"alice@local.chat\n",
	}
	for _, tc := range cases {
		if got := cleanAuthUsername(tc); got != "" {
			t.Fatalf("cleanAuthUsername(%q) = %q, want empty string", tc, got)
		}
	}
	if got := cleanAuthUsername(" Alice@LOCAL.CHAT "); got != "alice@local.chat" {
		t.Fatalf("cleanAuthUsername normalisation failed: got %q", got)
	}
}

func TestDataRejectsSuspendedAuthenticatedSender(t *testing.T) {
	db, err := database.NewBboltDB(filepath.Join(t.TempDir(), "smtp-sender-suspended.db"))
	if err != nil {
		t.Fatalf("NewBboltDB failed: %v", err)
	}
	defer db.Close()

	sender := "sender@local.chat"
	recipient := "recipient@local.chat"
	if err := db.CreateUser(sender, "pw"); err != nil {
		t.Fatalf("CreateUser sender failed: %v", err)
	}
	if err := db.CreateUser(recipient, "pw"); err != nil {
		t.Fatalf("CreateUser recipient failed: %v", err)
	}
	if err := db.SuspendUser(sender); err != nil {
		t.Fatalf("SuspendUser sender failed: %v", err)
	}

	sess := &Session{backend: &Backend{db: db}, user: sender, to: []string{recipient}}
	if err := sess.Data(strings.NewReader("Subject: blocked\r\n\r\nbody")); err == nil {
		t.Fatalf("expected DATA to reject a sender suspended after authentication")
	}
}

func TestDataRevalidatesRecipientsBeforeStoring(t *testing.T) {
	db, err := database.NewBboltDB(filepath.Join(t.TempDir(), "smtp-recipient-suspended.db"))
	if err != nil {
		t.Fatalf("NewBboltDB failed: %v", err)
	}
	defer db.Close()

	sender := "sender@local.chat"
	recipientOK := "ok@local.chat"
	recipientSuspended := "suspended@local.chat"
	for _, user := range []string{sender, recipientOK, recipientSuspended} {
		if err := db.CreateUser(user, "pw"); err != nil {
			t.Fatalf("CreateUser(%s) failed: %v", user, err)
		}
	}
	if err := db.SuspendUser(recipientSuspended); err != nil {
		t.Fatalf("SuspendUser recipient failed: %v", err)
	}

	sess := &Session{backend: &Backend{db: db}, user: sender, to: []string{recipientOK, recipientSuspended}}
	if err := sess.Data(strings.NewReader("Subject: no partial\r\n\r\nbody")); err == nil {
		t.Fatalf("expected DATA to fail before partial delivery when any recipient is unavailable")
	}
	msgs, err := db.FetchMessageHeaders(recipientOK)
	if err != nil {
		t.Fatalf("FetchMessageHeaders failed: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("expected no partial delivery to first recipient, got %d messages", len(msgs))
	}
}
