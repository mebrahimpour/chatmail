package database

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// openTestDB opens a fresh database in a temp directory and registers cleanup.
func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"), "local.chat")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

func TestSerializeRoundTrip(t *testing.T) {
	orig := &Message{
		UID:          42,
		Flags:        FlagSeen | FlagDeleted,
		InternalDate: 1700000000,
		Body:         []byte("Subject: hi\r\n\r\nbody"),
	}
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

func TestDeserializeRejectsShortBuffer(t *testing.T) {
	cases := [][]byte{nil, {}, make([]byte, 19)}
	for _, c := range cases {
		if _, err := deserialize(c); err == nil {
			t.Fatalf("expected error for %d-byte input", len(c))
		}
	}
}

func TestDeserializeRejectsTruncatedPayload(t *testing.T) {
	// Header says length=100 but only 5 bytes follow.
	buf := make([]byte, 20+5)
	encodeUint32Into(buf[16:20], 100)
	if _, err := deserialize(buf); err == nil {
		t.Fatal("expected error for truncated payload")
	}
}

// FuzzDeserialize exercises the deserialiser against arbitrary inputs.
func FuzzDeserialize(f *testing.F) {
	// Seed corpus: valid message and some short buffers.
	m := &Message{UID: 1, Flags: FlagSeen, InternalDate: 1700000000, Body: []byte("hello")}
	f.Add(serialize(m))
	f.Add([]byte(""))
	f.Add(make([]byte, 19))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic.
		_, _ = deserialize(data)
	})
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

func TestAuthenticateAutoRegisterAndVerify(t *testing.T) {
	db := openTestDB(t)

	created, err := db.Authenticate("alice@local.chat", "pw")
	if err != nil || !created {
		t.Fatalf("first auth should auto-register: created=%v err=%v", created, err)
	}

	created, err = db.Authenticate("alice@local.chat", "pw")
	if err != nil || created {
		t.Fatalf("second auth should verify existing: created=%v err=%v", created, err)
	}

	if _, err := db.Authenticate("alice@local.chat", "wrong"); err != ErrAuthFailed {
		t.Fatalf("expected ErrAuthFailed on mismatch, got %v", err)
	}
}

func TestVerifyCredentials(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Authenticate("alice@local.chat", "pw"); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if err := db.VerifyCredentials("alice@local.chat", "pw"); err != nil {
		t.Fatalf("VerifyCredentials should succeed: %v", err)
	}
	if err := db.VerifyCredentials("ghost@local.chat", "pw"); err != ErrAuthFailed {
		t.Fatalf("VerifyCredentials should fail for unknown user, got %v", err)
	}
	if err := db.VerifyCredentials("alice@local.chat", "bad"); err != ErrAuthFailed {
		t.Fatalf("VerifyCredentials should fail for bad password, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// UID assignment
// ---------------------------------------------------------------------------

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

	// Deleting a message must not rewind NextUID.
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
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}
	for i := 1; i < len(msgs); i++ {
		if msgs[i-1].UID >= msgs[i].UID {
			t.Fatalf("messages not sorted ascending by UID: %v", msgs)
		}
	}
}

// ---------------------------------------------------------------------------
// UIDValidity
// ---------------------------------------------------------------------------

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

func TestRandomUIDValidityNonZero(t *testing.T) {
	for i := 0; i < 1000; i++ {
		if v := randomUIDValidity(); v == 0 {
			t.Fatal("randomUIDValidity returned 0")
		}
	}
}

// ---------------------------------------------------------------------------
// Flag operations
// ---------------------------------------------------------------------------

func TestSetFlagsOperations(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Authenticate("eve@local.chat", "pw"); err != nil {
		t.Fatalf("auth: %v", err)
	}
	uid, _ := db.AppendMessage("eve@local.chat", []byte("body"), 0, time.Now())

	// Add Seen flag.
	if err := db.SetFlags("eve@local.chat", uid, FlagSeen); err != nil {
		t.Fatalf("SetFlags: %v", err)
	}
	msgs, _ := db.LoadMessages("eve@local.chat")
	if msgs[0].Flags != FlagSeen {
		t.Fatalf("expected FlagSeen, got %08x", msgs[0].Flags)
	}

	// Add Deleted flag while preserving Seen.
	combined := msgs[0].Flags | FlagDeleted
	if err := db.SetFlags("eve@local.chat", uid, combined); err != nil {
		t.Fatalf("SetFlags: %v", err)
	}
	msgs, _ = db.LoadMessages("eve@local.chat")
	if msgs[0].Flags != (FlagSeen | FlagDeleted) {
		t.Fatalf("expected Seen|Deleted, got %08x", msgs[0].Flags)
	}

	// Remove Seen, keep Deleted.
	if err := db.SetFlags("eve@local.chat", uid, FlagDeleted); err != nil {
		t.Fatalf("SetFlags: %v", err)
	}
	msgs, _ = db.LoadMessages("eve@local.chat")
	if msgs[0].Flags != FlagDeleted {
		t.Fatalf("expected only FlagDeleted, got %08x", msgs[0].Flags)
	}
}

// SetFlags on a non-existent UID must be a silent no-op, not an error.
func TestSetFlagsNonExistentUID(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Authenticate("noop@local.chat", "pw"); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if err := db.SetFlags("noop@local.chat", 9999, FlagSeen); err != nil {
		t.Fatalf("SetFlags on missing UID should be no-op: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Retention sweep
// ---------------------------------------------------------------------------

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

func TestSweepRetentionDoesNotReflagAlreadyDeleted(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Authenticate("frank@local.chat", "pw"); err != nil {
		t.Fatalf("auth: %v", err)
	}
	old := time.Now().Add(-48 * time.Hour)
	uid, _ := db.AppendMessage("frank@local.chat", []byte("old"), FlagDeleted, old)
	_ = uid

	// Second sweep must not double-count already-flagged messages.
	n, err := db.SweepRetention(24 * time.Hour)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 newly flagged (already deleted), got %d", n)
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// TestConcurrentAppend verifies there are no data races when multiple
// goroutines append messages to different mailboxes simultaneously.
// Run with: go test -race ./internal/database/
func TestConcurrentAppend(t *testing.T) {
	db := openTestDB(t)

	users := []string{"u1@local.chat", "u2@local.chat", "u3@local.chat"}
	for _, u := range users {
		if _, err := db.Authenticate(u, "pw"); err != nil {
			t.Fatalf("auth %s: %v", u, err)
		}
	}

	var wg sync.WaitGroup
	for _, u := range users {
		u := u
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if _, err := db.AppendMessage(u, []byte("body"), 0, time.Now()); err != nil {
					t.Errorf("append %s: %v", u, err)
				}
			}
		}()
	}
	wg.Wait()

	for _, u := range users {
		msgs, err := db.LoadMessages(u)
		if err != nil {
			t.Fatalf("load %s: %v", u, err)
		}
		if len(msgs) != 10 {
			t.Fatalf("%s: expected 10 messages, got %d", u, len(msgs))
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkAppendMessage(b *testing.B) {
	db, err := Open(filepath.Join(b.TempDir(), "bench.db"), "local.chat")
	if err != nil {
		b.Fatalf("open: %v", err)
	}
	defer db.Close()
	if _, err := db.Authenticate("bench@local.chat", "pw"); err != nil {
		b.Fatalf("auth: %v", err)
	}
	body := []byte("Subject: bench\r\n\r\n" + string(make([]byte, 1024)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := db.AppendMessage("bench@local.chat", body, 0, time.Now()); err != nil {
			b.Fatalf("append: %v", err)
		}
	}
}

func BenchmarkLoadMessages1000(b *testing.B) {
	db, err := Open(filepath.Join(b.TempDir(), "bench.db"), "local.chat")
	if err != nil {
		b.Fatalf("open: %v", err)
	}
	defer db.Close()
	if _, err := db.Authenticate("bench@local.chat", "pw"); err != nil {
		b.Fatalf("auth: %v", err)
	}
	body := []byte("Subject: bench\r\n\r\nbody")
	for i := 0; i < 1000; i++ {
		if _, err := db.AppendMessage("bench@local.chat", body, 0, time.Now()); err != nil {
			b.Fatalf("append: %v", err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := db.LoadMessages("bench@local.chat"); err != nil {
			b.Fatalf("load: %v", err)
		}
	}
}

func BenchmarkSerialize(b *testing.B) {
	m := &Message{UID: 1, Flags: FlagSeen, InternalDate: 1700000000, Body: make([]byte, 512)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := serialize(m)
		if _, err := deserialize(buf); err != nil {
			b.Fatalf("deserialize: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func encodeUint32Into(dst []byte, v uint32) {
	dst[0] = byte(v >> 24)
	dst[1] = byte(v >> 16)
	dst[2] = byte(v >> 8)
	dst[3] = byte(v)
}
