package database

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

// Unit and Integration Tests for Bbolt DB setup
func TestAuthenticateAndRegister(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := NewBboltDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BboltDB: %v", err)
	}
	defer db.Close()

	user := "alice@local.chat"
	pass := "supersecure123"

	// 1. First authentication triggers auto-registration
	err = db.AuthenticateOrRegister(user, pass)
	if err != nil {
		t.Fatalf("Expected registration success, got error: %v", err)
	}

	// 2. Subsequent authentication with correct password succeeds
	err = db.AuthenticateOrRegister(user, pass)
	if err != nil {
		t.Fatalf("Expected login success with correct password, got error: %v", err)
	}

	// 3. Authentication with bad password must fail
	err = db.AuthenticateOrRegister(user, "wrongpassword")
	if err == nil {
		t.Fatalf("Expected authentication fail on wrong password, but got success")
	}
}

func TestCreateUser(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_create.db")

	db, err := NewBboltDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BboltDB: %v", err)
	}
	defer db.Close()

	user := "carol@local.chat"
	pass := "supersecure456"

	// 1. First creation succeeds
	err = db.CreateUser(user, pass)
	if err != nil {
		t.Fatalf("Expected CreateUser success, got error: %v", err)
	}

	// 2. Secondary creation fails with ErrUserExists
	err = db.CreateUser(user, pass)
	if err != ErrUserExists {
		t.Fatalf("Expected ErrUserExists during double creation, but got: %v", err)
	}

	// 3. Normal AuthenticateOrRegister still works for created user
	err = db.AuthenticateOrRegister(user, pass)
	if err != nil {
		t.Fatalf("Expected login success with correct password, got error: %v", err)
	}
}

func TestRejectEmptyPasswords(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_empty_password.db")

	db, err := NewBboltDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BboltDB: %v", err)
	}
	defer db.Close()

	user := "empty-password@local.chat"
	if err := db.AuthenticateOrRegister(user, ""); err != ErrEmptyPassword {
		t.Fatalf("expected AuthenticateOrRegister to reject empty passwords with ErrEmptyPassword, got %v", err)
	}
	if err := db.CreateUser(user, ""); err != ErrEmptyPassword {
		t.Fatalf("expected CreateUser to reject empty passwords with ErrEmptyPassword, got %v", err)
	}

	if err := db.CreateUser(user, "nonempty"); err != nil {
		t.Fatalf("CreateUser with non-empty password failed: %v", err)
	}
	if err := db.SetUserPassword(user, ""); err != ErrEmptyPassword {
		t.Fatalf("expected SetUserPassword to reject empty passwords with ErrEmptyPassword, got %v", err)
	}
}

func TestSuspendAndActivate(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := NewBboltDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BboltDB: %v", err)
	}
	defer db.Close()

	user := "bob@local.chat"
	pass := "password123"

	// Register
	_ = db.AuthenticateOrRegister(user, pass)

	// Suspend
	err = db.SuspendUser(user)
	if err != nil {
		t.Fatalf("Failed to suspend user: %v", err)
	}

	// Check status using the canonical single-transaction GetUserStatus path.
	exists, isSuspended, err := db.GetUserStatus(user)
	if err != nil {
		t.Fatalf("GetUserStatus error: %v", err)
	}
	if !exists {
		t.Fatalf("Expected user to exist after registration, but GetUserStatus reports not found")
	}
	if !isSuspended {
		t.Fatalf("Expected user to be suspended, got isSuspended=false")
	}

	// Try login -> must return ErrUserSuspended
	err = db.AuthenticateOrRegister(user, pass)
	if err != ErrUserSuspended {
		t.Fatalf("Expected suspended login error (%v), got: %v", ErrUserSuspended, err)
	}

	// Activate
	err = db.ActivateUser(user)
	if err != nil {
		t.Fatalf("Failed to activate user: %v", err)
	}

	// Try login again -> should succeed
	err = db.AuthenticateOrRegister(user, pass)
	if err != nil {
		t.Fatalf("Expected success login after activation, got: %v", err)
	}
}

func TestSuspendActivateDeleteRequireExistingUser(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_suspend_missing.db")

	db, err := NewBboltDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BboltDB: %v", err)
	}
	defer db.Close()

	missing := "missing@local.chat"
	if err := db.SuspendUser(missing); err == nil {
		t.Fatalf("expected SuspendUser to reject a missing user")
	}
	if err := db.ActivateUser(missing); err == nil {
		t.Fatalf("expected ActivateUser to reject a missing user")
	}
	if err := db.DeleteUser(missing); err == nil {
		t.Fatalf("expected DeleteUser to reject a missing user")
	}

	exists, suspended, err := db.GetUserStatus(missing)
	if err != nil {
		t.Fatalf("GetUserStatus failed: %v", err)
	}
	if exists || suspended {
		t.Fatalf("missing user should not exist or be suspended, got exists=%v suspended=%v", exists, suspended)
	}
}

func TestExpungeSelectedDeletedMessages(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_expunge_selected.db")

	db, err := NewBboltDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BboltDB: %v", err)
	}
	defer db.Close()

	user := "expunge@local.chat"
	if err := db.AuthenticateOrRegister(user, "pw"); err != nil {
		t.Fatalf("AuthenticateOrRegister failed: %v", err)
	}

	uid1, _ := db.StoreMessage(user, []byte("Subject: one\r\n\r\n1"))
	uid2, _ := db.StoreMessage(user, []byte("Subject: two\r\n\r\n2"))
	uid3, _ := db.StoreMessage(user, []byte("Subject: three\r\n\r\n3"))

	if _, err := db.UpdateMessagesFlags(user, []uint32{uid1, uid2, uid3}, 0x08, 0, false); err != nil {
		t.Fatalf("UpdateMessagesFlags failed: %v", err)
	}

	expunged, err := db.ExpungeSelectedDeletedMessages(user, map[uint32]bool{uid2: true})
	if err != nil {
		t.Fatalf("ExpungeSelectedDeletedMessages failed: %v", err)
	}
	if len(expunged) != 1 || expunged[0] != uid2 {
		t.Fatalf("expected only UID %d to be expunged, got %v", uid2, expunged)
	}

	msgs, err := db.FetchMessageHeaders(user)
	if err != nil {
		t.Fatalf("FetchMessageHeaders failed: %v", err)
	}
	remaining := map[uint32]bool{}
	for _, msg := range msgs {
		remaining[msg.UID] = true
	}
	if !remaining[uid1] || remaining[uid2] || !remaining[uid3] {
		t.Fatalf("UID EXPUNGE semantics violated; remaining UID set: %#v", remaining)
	}
}

func TestStoreMessageRejectsExhaustedUIDSpace(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_uid_exhausted.db")

	db, err := NewBboltDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BboltDB: %v", err)
	}
	defer db.Close()

	user := "uidmax@local.chat"
	if err := db.AuthenticateOrRegister(user, "pw"); err != nil {
		t.Fatalf("AuthenticateOrRegister failed: %v", err)
	}

	if err := db.Update(func(tx *bbolt.Tx) error {
		mailboxes := tx.Bucket(MailboxesBucket)
		uMbox := mailboxes.Bucket([]byte(user))
		meta := uMbox.Bucket(MetadataBucket)
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, ^uint32(0))
		return meta.Put(NextUIDKey, buf)
	}); err != nil {
		t.Fatalf("failed to force UID exhaustion: %v", err)
	}

	if _, err := db.StoreMessage(user, []byte("Subject: exhausted\r\n\r\nbody")); err == nil {
		t.Fatalf("expected StoreMessage to reject exhausted UID space")
	}
}

func TestDeleteCascading(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := NewBboltDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BboltDB: %v", err)
	}
	defer db.Close()

	alice := "alice@local.chat"
	bob := "bob@local.chat"

	_ = db.AuthenticateOrRegister(alice, "pw")
	_ = db.AuthenticateOrRegister(bob, "pw")

	// Store message for Alice
	uid, err := db.StoreMessage(alice, []byte("To: alice@local.chat\r\nFrom: bob@local.chat\r\nSubject: Hi\r\n\r\nHello Alice!"))
	if err != nil {
		t.Fatalf("Failed to store message: %v", err)
	}

	// Store message for Bob referencing Alice
	_, err = db.StoreMessage(bob, []byte("To: bob@local.chat\r\nFrom: alice@local.chat\r\nSubject: Hi back\r\n\r\nHello Bob!"))
	if err != nil {
		t.Fatalf("Failed to store message: %v", err)
	}

	// Delete Bob (cascading)
	err = db.DeleteUser(bob)
	if err != nil {
		t.Fatalf("Failed to delete user bob: %v", err)
	}

	// Verify Bob is unregistered using the canonical single-transaction path.
	bobExists, _, statusErr := db.GetUserStatus(bob)
	if statusErr != nil {
		t.Fatalf("GetUserStatus error after deletion: %v", statusErr)
	}
	if bobExists {
		t.Fatalf("Bob should not exist in the database after deletion")
	}

	// Verify Alice's message (which was from Bob) got marked with Deleted Flag (0x08)
	var flagVal uint32
	err = db.View(func(tx *bbolt.Tx) error {
		mailboxes := tx.Bucket(MailboxesBucket)
		uMbox := mailboxes.Bucket([]byte(alice))
		msgs := uMbox.Bucket(MessagesBucket)
		msgKey := fmt.Sprintf("%08d", uid)
		v := msgs.Get([]byte(msgKey))
		if len(v) >= 20 {
			flagVal = binary.BigEndian.Uint32(v[4:8])
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to read message block: %v", err)
	}

	if flagVal&0x08 == 0 {
		t.Fatalf("Expected Alice's message to contain Deleted Flag 0x08 due to cascade, got flag: %d", flagVal)
	}
}

// Concurrency Race Check for "go test -race"
func TestNotifyNewMessageIgnoresClosedStaleNotifier(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_closed_notifier.db")

	db, err := NewBboltDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BboltDB: %v", err)
	}
	defer db.Close()

	user := "notify@local.chat"
	if err := db.AuthenticateOrRegister(user, "pw"); err != nil {
		t.Fatalf("AuthenticateOrRegister failed: %v", err)
	}

	ch := make(chan struct{}, 1)
	db.RegisterNotifier(user, ch)
	close(ch)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NotifyNewMessage should not panic on a stale closed notifier, recovered %v", r)
		}
	}()
	db.NotifyNewMessage(user)
}

func TestRaceConditions(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "race_test.db")

	db, err := NewBboltDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to create DB: %v", err)
	}
	defer db.Close()

	user := "race@local.chat"
	_ = db.AuthenticateOrRegister(user, "pw")

	var wg sync.WaitGroup
	workers := 10
	wg.Add(workers * 3)

	// Goroutine group A: write messages and notify
	for i := 0; i < workers; i++ {
		go func(id int) {
			defer wg.Done()
			payload := []byte(fmt.Sprintf("Concurrent MSG %d", id))
			_, _ = db.StoreMessage(user, payload)
		}(i)
	}

	// Goroutine group B: manage notification channels
	chans := make([]chan struct{}, workers)
	for i := 0; i < workers; i++ {
		chans[i] = make(chan struct{}, 10)
		go func(ch chan struct{}) {
			defer wg.Done()
			db.RegisterNotifier(user, ch)
			time.Sleep(10 * time.Millisecond)
			db.DeregisterNotifier(user, ch)
		}(chans[i])
	}

	// Goroutine group C: suspend/activate toggle
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			_ = db.SuspendUser(user)
			_ = db.ActivateUser(user)
		}()
	}

	wg.Wait()
}

// Benchmark StoreMessage for "go test -bench=."
func BenchmarkStoreMessage(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "bench")
	if err != nil {
		b.Fatalf("Failed to create tempdir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "bench.db")
	db, err := NewBboltDB(dbPath)
	if err != nil {
		b.Fatalf("Failed to create DB: %v", err)
	}
	defer db.Close()

	user := "bench@local.chat"
	_ = db.AuthenticateOrRegister(user, "password")

	payload := []byte("From: sender@local.chat\r\nTo: bench@local.chat\r\nSubject: Benchmark\r\n\r\nThis is benchmark payload data.")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = db.StoreMessage(user, payload)
		if err != nil {
			b.Fatalf("Benchmark error: %v", err)
		}
	}
}

// Fuzz test for "go test -fuzz=."
func FuzzBytesToLower(f *testing.F) {
	// Seed some typical test cases
	f.Add([]byte("Hello WORLD"))
	f.Add([]byte("alice@local.chat"))
	f.Add([]byte("\r\nTo: BOB@LOCAL.CHAT\r\n"))
	f.Add([]byte{0x00, 0x12, 0xff, 'A', 'Z', 'z', 'a'})

	f.Fuzz(func(t *testing.T, orig []byte) {
		lowered := bytesToLower(orig)
		if len(lowered) != len(orig) {
			t.Errorf("Length mismatch: orig=%d lowered=%d", len(orig), len(lowered))
		}
		// Confirm all bytes are indeed lowercase/unchanged
		for i := 0; i < len(orig); i++ {
			c := orig[i]
			if c >= 'A' && c <= 'Z' {
				if lowered[i] != c+32 {
					t.Errorf("Char at %d not properly case-folded: expected %d, got %d", i, c+32, lowered[i])
				}
			} else {
				if lowered[i] != c {
					t.Errorf("Char at %d mutated incorrectly: expected %d, got %d", i, c, lowered[i])
				}
			}
		}
	})
}
