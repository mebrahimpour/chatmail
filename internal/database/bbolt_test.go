package database

import (
	"path/filepath"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"), "local.chat")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSerializeRoundTrip(t *testing.T) {
	orig := &Message{UID: 42, Flags: FlagSeen | FlagDeleted, InternalDate: 1700000000, Body: []byte("Subject: hi\r\n\r\nbody")}
	got, err := deserialize(serialize(orig))
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.UID != orig.UID || got.Flags != orig.Flags || got.InternalDate != orig.InternalDate {
		t.Fatalf("header mismatch: %+v vs %+v", got, orig)
	}
	if string(got.Body) != string(orig.Body) {
		t.Fatalf("body mismatch: %q vs %q", got.Body, orig.Body)
	}
}

func TestAuthenticateAutoRegisterAndVerify(t *testing.T) {
	db := openTestDB(t)

	created, err := db.Authenticate("alice@local.chat", "pw")
	if err != nil || !created {
		t.Fatalf("first auth should auto-register: created=%v err=%v", created, err)
	}

	created, err = db.Authenticate("alice@local.chat", "pw")
	if err != nil || created {
		t.Fatalf("second auth should verify existing user: created=%v err=%v", created, err)
	}

	if _, err := db.Authenticate("alice@local.chat", "wrong"); err != ErrAuthFailed {
		t.Fatalf("expected ErrAuthFailed on mismatch, got %v", err)
	}

	if err := db.VerifyCredentials("alice@local.chat", "pw"); err != nil {
		t.Fatalf("VerifyCredentials should succeed: %v", err)
	}
	if err := db.VerifyCredentials("ghost@local.chat", "pw"); err != ErrAuthFailed {
		t.Fatalf("VerifyCredentials should fail for unknown user, got %v", err)
	}
}

func TestAppendAssignsSequentialUIDs(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Authenticate("bob@local.chat", "pw"); err != nil {
		t.Fatalf("auth: %v", err)
	}

	for want := uint32(1); want <= 3; want++ {
		uid, err := db.AppendMessage("bob@local.chat", []byte("m"), 0, time.Now())
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		if uid != want {
			t.Fatalf("expected UID %d, got %d", want, uid)
		}
	}

	// Deleting a message must not rewind NextUID (UID stability).
	if err := db.DeleteMessage("bob@local.chat", 2); err != nil {
		t.Fatalf("delete: %v", err)
	}
	uid, err := db.AppendMessage("bob@local.chat", []byte("m"), 0, time.Now())
	if err != nil {
		t.Fatalf("append after delete: %v", err)
	}
	if uid != 4 {
		t.Fatalf("expected UID 4 after delete (no reuse), got %d", uid)
	}

	msgs, err := db.LoadMessages("bob@local.chat")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages after delete, got %d", len(msgs))
	}
	for i := 1; i < len(msgs); i++ {
		if msgs[i-1].UID >= msgs[i].UID {
			t.Fatalf("messages not sorted ascending by UID: %v", msgs)
		}
	}
}

func TestUIDValidityStable(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Authenticate("carol@local.chat", "pw"); err != nil {
		t.Fatalf("auth: %v", err)
	}
	first, err := db.UIDValidity("carol@local.chat")
	if err != nil {
		t.Fatalf("uidvalidity: %v", err)
	}
	if first == 0 {
		t.Fatal("UIDVALIDITY must be non-zero")
	}
	// Re-authenticating must not change UIDVALIDITY.
	if _, err := db.Authenticate("carol@local.chat", "pw"); err != nil {
		t.Fatalf("re-auth: %v", err)
	}
	second, _ := db.UIDValidity("carol@local.chat")
	if first != second {
		t.Fatalf("UIDVALIDITY changed: %d -> %d", first, second)
	}
}

func TestSweepRetentionFlagsOldMessages(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Authenticate("dave@local.chat", "pw"); err != nil {
		t.Fatalf("auth: %v", err)
	}
	old := time.Now().Add(-48 * time.Hour)
	recent := time.Now()
	if _, err := db.AppendMessage("dave@local.chat", []byte("old"), 0, old); err != nil {
		t.Fatalf("append old: %v", err)
	}
	if _, err := db.AppendMessage("dave@local.chat", []byte("new"), 0, recent); err != nil {
		t.Fatalf("append new: %v", err)
	}

	n, err := db.SweepRetention(24 * time.Hour)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 message flagged, got %d", n)
	}

	msgs, _ := db.LoadMessages("dave@local.chat")
	for _, m := range msgs {
		if m.InternalDate == old.Unix() && m.Flags&FlagDeleted == 0 {
			t.Fatal("old message should be flagged \\Deleted")
		}
		if m.InternalDate == recent.Unix() && m.Flags&FlagDeleted != 0 {
			t.Fatal("recent message should not be flagged")
		}
	}
}
