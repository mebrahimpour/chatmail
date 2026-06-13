package database

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

// MessageCountKey is persisted in MetadataBucket to track the mailbox size in O(1).
var MessageCountKey = []byte("MessageCount")

type BboltDB struct {
	*bbolt.DB
	mu       sync.Mutex
	channels map[string][]chan struct{}
}

// Nested hierarchy Keys
var (
	ConfigBucket     = []byte("Configuration")
	UsersBucket      = []byte("Users")
	MailboxesBucket  = []byte("Mailboxes")
	MetadataBucket   = []byte("Metadata")
	MessagesBucket   = []byte("Messages")
	UserStatusBucket = []byte("UserStatus")

	DomainKey      = []byte("ServerDomain")
	NextUIDKey     = []byte("NextUID")
	UIDValidityKey = []byte("UIDValidity")
)

var (
	ErrUserSuspended = errors.New("535 Account disabled by administrator")
	ErrUserExists    = errors.New("user already exists")
	ErrEmptyPassword = errors.New("password cannot be empty")
)

// SerializedMessage represents the packed binary schema
type SerializedMessage struct {
	UID          uint32
	Flags        uint32
	InternalDate int64
	Length       uint32
	Payload      []byte
}

func NewBboltDBWithOptions(path string, readOnly bool) (*BboltDB, error) {
	db, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: 1 * time.Second, ReadOnly: readOnly})
	if err != nil {
		return nil, err
	}

	if !readOnly {
		// Bootstrap schema structures — propagate all bucket creation errors
		err = db.Update(func(tx *bbolt.Tx) error {
			// Boot Configuration
			cfg, err := tx.CreateBucketIfNotExists(ConfigBucket)
			if err != nil {
				return fmt.Errorf("create config bucket: %w", err)
			}
			if cfg.Get(DomainKey) == nil {
				if err := cfg.Put(DomainKey, []byte("local.chat")); err != nil {
					return fmt.Errorf("put domain key: %w", err)
				}
			}

			// Boot top-level buckets
			if _, err := tx.CreateBucketIfNotExists(UsersBucket); err != nil {
				return fmt.Errorf("create users bucket: %w", err)
			}
			if _, err := tx.CreateBucketIfNotExists(MailboxesBucket); err != nil {
				return fmt.Errorf("create mailboxes bucket: %w", err)
			}
			if _, err := tx.CreateBucketIfNotExists(UserStatusBucket); err != nil {
				return fmt.Errorf("create user-status bucket: %w", err)
			}
			return nil
		})

		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("bootstrap schema: %w", err)
		}
	}

	return &BboltDB{
		DB:       db,
		channels: make(map[string][]chan struct{}),
	}, nil
}

func NewBboltDB(path string) (*BboltDB, error) {
	return NewBboltDBWithOptions(path, false)
}

// bootstrapMailbox initialises the per-user mailbox sub-tree inside an active
// write transaction. MailboxesBucket must already exist before calling.
func bootstrapMailbox(mailboxes *bbolt.Bucket, username string) error {
	uMbox, err := mailboxes.CreateBucketIfNotExists([]byte(username))
	if err != nil {
		return fmt.Errorf("create user mailbox bucket: %w", err)
	}
	meta, err := uMbox.CreateBucketIfNotExists(MetadataBucket)
	if err != nil {
		return fmt.Errorf("create metadata bucket: %w", err)
	}

	// Stable UIDValidity derived from creation Unix timestamp
	uidValidityBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(uidValidityBuf, uint32(time.Now().Unix()))
	if err := meta.Put(UIDValidityKey, uidValidityBuf); err != nil {
		return fmt.Errorf("put uidvalidity: %w", err)
	}

	// NextUID starts at 1
	nextUIDBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(nextUIDBuf, 1)
	if err := meta.Put(NextUIDKey, nextUIDBuf); err != nil {
		return fmt.Errorf("put nextuid: %w", err)
	}

	// Message count starts at 0
	countBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(countBuf, 0)
	if err := meta.Put(MessageCountKey, countBuf); err != nil {
		return fmt.Errorf("put message count: %w", err)
	}

	if _, err := uMbox.CreateBucketIfNotExists(MessagesBucket); err != nil {
		return fmt.Errorf("create messages bucket: %w", err)
	}
	return nil
}

// CreateUser registers a new user with strict uniqueness and boots their mailbox structure.
// Returns ErrUserExists if the account already exists.
//
// bcrypt.GenerateFromPassword (~100 ms at DefaultCost) is intentionally run
// before the write transaction opens so the exclusive bbolt write lock is held
// only for the fast key-value writes, not for the CPU-bound hash derivation.
func (db *BboltDB) CreateUser(username, password string) error {
	if password == "" {
		return ErrEmptyPassword
	}

	// Phase 1: quick existence check in a cheap read transaction.
	err := db.View(func(tx *bbolt.Tx) error {
		users := tx.Bucket(UsersBucket)
		if users == nil {
			return nil // bucket absent → user cannot exist yet
		}
		if users.Get([]byte(username)) != nil {
			return ErrUserExists
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Phase 2: CPU-bound bcrypt work outside any transaction.
	newHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	// Phase 3: write transaction — TOCTOU guard re-checks existence so that a
	// concurrent CreateUser for the same username cannot both succeed.
	return db.Update(func(tx *bbolt.Tx) error {
		users := tx.Bucket(UsersBucket)
		if users == nil {
			return errors.New("users bucket not found")
		}
		if users.Get([]byte(username)) != nil {
			return ErrUserExists
		}
		if err := users.Put([]byte(username), newHash); err != nil {
			return fmt.Errorf("store user hash: %w", err)
		}
		mailboxes := tx.Bucket(MailboxesBucket)
		if mailboxes == nil {
			return errors.New("mailboxes bucket not found")
		}
		return bootstrapMailbox(mailboxes, username)
	})
}

// AuthenticateOrRegister auto-registers the user on first connection, or
// verifies their bcrypt password on subsequent connections.
// Returns ErrUserSuspended if the account has been administratively suspended.
//
// Design note: bcrypt operations (both GenerateFromPassword and
// CompareHashAndPassword) take ~100 ms at DefaultCost. Running them inside a
// bbolt write transaction would hold the exclusive write lock for that entire
// duration, blocking every concurrent writer (StoreMessage, SuspendUser, etc.).
// To avoid this, we use a two-phase approach:
//  1. Read-only transaction: fetch the stored hash (or detect new user).
//  2. CPU-bound bcrypt work: performed outside any transaction.
//  3. Write transaction (new users only): store the generated hash and bootstrap
//     the mailbox. A TOCTOU check inside the write transaction prevents double
//     registration if two connections race for the same new username.
func (db *BboltDB) AuthenticateOrRegister(username, password string) error {
	if password == "" {
		return ErrEmptyPassword
	}

	// ── Phase 1: read the stored hash (or determine this is a new user) ──
	var storedHash []byte
	err := db.View(func(tx *bbolt.Tx) error {
		// Suspension check first — fail fast before any crypto work.
		if statusBucket := tx.Bucket(UserStatusBucket); statusBucket != nil {
			if string(statusBucket.Get([]byte(username))) == "suspended" {
				return ErrUserSuspended
			}
		}
		users := tx.Bucket(UsersBucket)
		if users == nil {
			return errors.New("users bucket not found")
		}
		if h := users.Get([]byte(username)); h != nil {
			// Copy the hash out of the mmap'd page — the slice is only valid
			// for the lifetime of the transaction.
			storedHash = make([]byte, len(h))
			copy(storedHash, h)
		}
		return nil
	})
	if err != nil {
		return err
	}

	if storedHash != nil {
		// ── Phase 2a: existing user — verify password outside any lock ──
		if err := bcrypt.CompareHashAndPassword(storedHash, []byte(password)); err != nil {
			return err
		}
		// Re-check suspension after bcrypt. Without this second read, a user
		// suspended while password verification is running could still complete
		// one successful login using the stale Phase 1 status snapshot.
		_, suspended, err := db.GetUserStatus(username)
		if err != nil {
			return err
		}
		if suspended {
			return ErrUserSuspended
		}
		return nil
	}

	// ── Phase 2b: new user — generate hash outside any lock ──
	newHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	// ── Phase 3: write transaction — store hash and bootstrap mailbox ──
	// TOCTOU guard: if another goroutine registered the same user between
	// Phase 1 and now, copy the existing hash out so we can verify it after
	// the transaction closes (bcrypt must never run inside a write tx).
	var racedHash []byte
	writeErr := db.Update(func(tx *bbolt.Tx) error {
		// Re-check suspension inside the write transaction. This closes the race
		// where an administrator suspends an address while bcrypt generation for a
		// first-time auto-registration is still in progress.
		if statusBucket := tx.Bucket(UserStatusBucket); statusBucket != nil {
			if string(statusBucket.Get([]byte(username))) == "suspended" {
				return ErrUserSuspended
			}
		}

		users := tx.Bucket(UsersBucket)
		if users == nil {
			return errors.New("users bucket not found")
		}
		if existing := users.Get([]byte(username)); existing != nil {
			// Another goroutine won the registration race.
			// Copy the stored hash out; the tx will commit cleanly (no write).
			racedHash = make([]byte, len(existing))
			copy(racedHash, existing)
			return nil // commit with no mutation — we just needed to read
		}
		if err := users.Put([]byte(username), newHash); err != nil {
			return fmt.Errorf("store user hash: %w", err)
		}
		mailboxes := tx.Bucket(MailboxesBucket)
		if mailboxes == nil {
			return errors.New("mailboxes bucket not found")
		}
		return bootstrapMailbox(mailboxes, username)
	})
	if writeErr != nil {
		return writeErr
	}
	if racedHash != nil {
		// Verify against the hash written by the winning goroutine, then perform
		// the same post-bcrypt suspension re-check used by the existing-user path.
		// Without this, an account suspended while this losing registration attempt
		// is comparing the raced hash could still complete one successful login.
		if err := bcrypt.CompareHashAndPassword(racedHash, []byte(password)); err != nil {
			return err
		}
		_, suspended, err := db.GetUserStatus(username)
		if err != nil {
			return err
		}
		if suspended {
			return ErrUserSuspended
		}
	}
	return nil
}

// StoreMessage appends a new RFC 822 message to the recipient's mailbox in a
// single atomic write transaction. Returns the assigned UID on success.
func (db *BboltDB) StoreMessage(email string, payload []byte) (uint32, error) {
	// The on-disk format stores payload length as uint32 and prefixes a 20-byte
	// binary header. Reject impossible/hostile sizes before converting to uint32
	// so the allocation length cannot overflow.
	if len(payload) > math.MaxUint32-20 {
		return 0, errors.New("message payload exceeds maximum storable size")
	}

	var finalUID uint32
	err := db.Update(func(tx *bbolt.Tx) error {
		mailboxes := tx.Bucket(MailboxesBucket)
		if mailboxes == nil {
			return errors.New("mailboxes bucket not found")
		}
		uMbox := mailboxes.Bucket([]byte(email))
		if uMbox == nil {
			return fmt.Errorf("mailbox not found for %q", email)
		}
		meta := uMbox.Bucket(MetadataBucket)
		if meta == nil {
			return errors.New("metadata bucket not found")
		}
		msgs := uMbox.Bucket(MessagesBucket)
		if msgs == nil {
			return errors.New("messages bucket not found")
		}

		// 1. Allocate UID
		nextUIDBuf := meta.Get(NextUIDKey)
		uid := uint32(1)
		if len(nextUIDBuf) >= 4 {
			uid = binary.BigEndian.Uint32(nextUIDBuf)
		}
		finalUID = uid
		if uid == math.MaxUint32 {
			return errors.New("mailbox UID space exhausted")
		}

		newNextUIDBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(newNextUIDBuf, uid+1)
		if err := meta.Put(NextUIDKey, newNextUIDBuf); err != nil {
			return fmt.Errorf("update nextuid: %w", err)
		}

		// 2. Increment persisted message count
		countBuf := meta.Get(MessageCountKey)
		count := uint32(0)
		if len(countBuf) >= 4 {
			count = binary.BigEndian.Uint32(countBuf)
		}
		if count == math.MaxUint32 {
			return errors.New("mailbox message count exhausted")
		}
		newCountBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(newCountBuf, count+1)
		if err := meta.Put(MessageCountKey, newCountBuf); err != nil {
			return fmt.Errorf("update message count: %w", err)
		}

		// 3. Serialise to packed binary representation
		// Byte layout (fixed 20-byte header):
		// [0-3]   UID          uint32 big-endian
		// [4-7]   Flags        uint32 big-endian (0x00 = unread)
		// [8-15]  InternalDate int64  big-endian (Unix seconds)
		// [16-19] Length       uint32 big-endian
		// [20+]   Payload      raw RFC 822 bytes
		length := uint32(len(payload))
		binaryPayload := make([]byte, 20+len(payload))
		binary.BigEndian.PutUint32(binaryPayload[0:4], uid)
		binary.BigEndian.PutUint32(binaryPayload[4:8], 0) // flags = unread
		binary.BigEndian.PutUint64(binaryPayload[8:16], uint64(time.Now().Unix()))
		binary.BigEndian.PutUint32(binaryPayload[16:20], length)
		copy(binaryPayload[20:], payload)

		// 4. Key = zero-padded 8-digit UID for lexicographic ordering
		msgKey := fmt.Sprintf("%08d", uid)
		return msgs.Put([]byte(msgKey), binaryPayload)
	})

	if err == nil {
		db.NotifyNewMessage(email)
	}
	return finalUID, err
}

func (db *BboltDB) RegisterNotifier(email string, ch chan struct{}) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.channels[email] = append(db.channels[email], ch)
}

func (db *BboltDB) DeregisterNotifier(email string, ch chan struct{}) {
	db.mu.Lock()
	defer db.mu.Unlock()
	chans := db.channels[email]
	for i, c := range chans {
		if c == ch {
			db.channels[email] = append(chans[:i], chans[i+1:]...)
			break
		}
	}
	if len(db.channels[email]) == 0 {
		delete(db.channels, email)
	}
}

func (db *BboltDB) NotifyNewMessage(email string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	for _, c := range db.channels[email] {
		func(ch chan struct{}) {
			// Defensive guard: callers should deregister without closing notifier
			// channels, but a stale closed channel must not crash the mail store path.
			defer func() { _ = recover() }()
			select {
			case ch <- struct{}{}:
			default:
			}
		}(c)
	}
}

func (db *BboltDB) SuspendUser(username string) error {
	return db.Update(func(tx *bbolt.Tx) error {
		users := tx.Bucket(UsersBucket)
		if users == nil {
			return errors.New("users bucket not found")
		}
		if users.Get([]byte(username)) == nil {
			return errors.New("user not found")
		}
		statusBucket := tx.Bucket(UserStatusBucket)
		if statusBucket == nil {
			return errors.New("user status bucket not found")
		}
		return statusBucket.Put([]byte(username), []byte("suspended"))
	})
}

func (db *BboltDB) ActivateUser(username string) error {
	return db.Update(func(tx *bbolt.Tx) error {
		users := tx.Bucket(UsersBucket)
		if users == nil {
			return errors.New("users bucket not found")
		}
		if users.Get([]byte(username)) == nil {
			return errors.New("user not found")
		}
		statusBucket := tx.Bucket(UserStatusBucket)
		if statusBucket == nil {
			return errors.New("user status bucket not found")
		}
		return statusBucket.Delete([]byte(username))
	})
}

// SetUserPassword replaces the stored bcrypt hash for username.
//
// bcrypt.GenerateFromPassword (~100 ms at DefaultCost) is run outside the
// write transaction so the exclusive bbolt write lock is not held during the
// CPU-intensive hash derivation — preventing all other writers from stalling.
func (db *BboltDB) SetUserPassword(username, newPassword string) error {
	if newPassword == "" {
		return ErrEmptyPassword
	}

	// Phase 1: verify the user exists before doing expensive crypto work.
	err := db.View(func(tx *bbolt.Tx) error {
		users := tx.Bucket(UsersBucket)
		if users == nil {
			return errors.New("users bucket not found")
		}
		if users.Get([]byte(username)) == nil {
			return errors.New("user not found")
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Phase 2: CPU-bound bcrypt work outside any transaction.
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	// Phase 3: short write transaction — just store the new hash.
	return db.Update(func(tx *bbolt.Tx) error {
		users := tx.Bucket(UsersBucket)
		if users == nil {
			return errors.New("users bucket not found")
		}
		// Re-check existence inside the write transaction (TOCTOU guard).
		if users.Get([]byte(username)) == nil {
			return errors.New("user not found")
		}
		return users.Put([]byte(username), newHash)
	})
}

func (db *BboltDB) DeleteUser(username string) error {
	return db.Update(func(tx *bbolt.Tx) error {
		// 1. Remove user registration. Treat a missing user as an error so admin
		// typos do not silently report success or cascade-delete against an address
		// that was never a registered local account.
		users := tx.Bucket(UsersBucket)
		if users == nil {
			return errors.New("users bucket not found")
		}
		if users.Get([]byte(username)) == nil {
			return errors.New("user not found")
		}
		if err := users.Delete([]byte(username)); err != nil {
			return fmt.Errorf("delete user record: %w", err)
		}

		// 2. Remove suspension status
		if statusBucket := tx.Bucket(UserStatusBucket); statusBucket != nil {
			if err := statusBucket.Delete([]byte(username)); err != nil {
				return fmt.Errorf("delete status record: %w", err)
			}
		}

		mailboxes := tx.Bucket(MailboxesBucket)
		if mailboxes == nil {
			return nil
		}

		needle := []byte(username)

		// markDeletedInBucket collects keys whose message payload matches (when
		// checkPayload=true) and then mutates them after the ForEach completes.
		// Collecting first avoids mutating a bucket cursor mid-iteration.
		markDeletedInBucket := func(msgs *bbolt.Bucket, checkPayload bool) error {
			var toMark [][]byte
			if err := msgs.ForEach(func(k, v []byte) error {
				if len(v) < 20 {
					return nil
				}
				if binary.BigEndian.Uint32(v[4:8])&0x08 != 0 {
					return nil // already marked \Deleted
				}
				if checkPayload && !headerContainsIgnoreCase(v[20:], needle) {
					return nil
				}
				keyCopy := make([]byte, len(k))
				copy(keyCopy, k)
				toMark = append(toMark, keyCopy)
				return nil
			}); err != nil {
				return err
			}
			for _, k := range toMark {
				v := msgs.Get(k)
				if len(v) < 20 {
					continue
				}
				vCopy := make([]byte, len(v))
				copy(vCopy, v)
				flags := binary.BigEndian.Uint32(vCopy[4:8])
				flags |= 0x08
				binary.BigEndian.PutUint32(vCopy[4:8], flags)
				if err := msgs.Put(k, vCopy); err != nil {
					return err
				}
			}
			return nil
		}

		// 3. Mark every message in the deleted user's own mailbox as \Deleted,
		//    then permanently remove the entire mailbox bucket to free disk space.
		if uMbox := mailboxes.Bucket(needle); uMbox != nil {
			if msgs := uMbox.Bucket(MessagesBucket); msgs != nil {
				if err := markDeletedInBucket(msgs, false); err != nil {
					return fmt.Errorf("mark own mailbox deleted: %w", err)
				}
			}
		}
		// Remove the bucket unconditionally — DeleteBucket is a no-op if absent.
		if err := mailboxes.DeleteBucket(needle); err != nil && !errors.Is(err, bbolt.ErrBucketNotFound) {
			return fmt.Errorf("delete mailbox bucket: %w", err)
		}

		// 4. Cascade \Deleted to messages in other mailboxes that reference
		//    the deleted user's address in their payload.
		// Collect mailbox keys before mutating nested message buckets. This avoids
		// doing writes beneath the same top-level cursor used by ForEach, which is
		// fragile and can invalidate cursor traversal in bbolt-style B+ trees.
		var otherMailboxKeys [][]byte
		if err := mailboxes.ForEach(func(k, _ []byte) error {
			if bytes.Equal(k, needle) {
				return nil // own mailbox already handled above
			}
			keyCopy := make([]byte, len(k))
			copy(keyCopy, k)
			otherMailboxKeys = append(otherMailboxKeys, keyCopy)
			return nil
		}); err != nil {
			return err
		}

		for _, k := range otherMailboxKeys {
			otherMbox := mailboxes.Bucket(k)
			if otherMbox == nil {
				continue
			}
			msgs := otherMbox.Bucket(MessagesBucket)
			if msgs == nil {
				continue
			}
			if err := markDeletedInBucket(msgs, true); err != nil {
				return err
			}
		}
		return nil
	})
}

// headerContainsIgnoreCase scans only the RFC 822 header portion of a raw
// message (everything before the first blank line "\r\n\r\n" or "\n\n") for
// the needle, case-insensitively. Limiting the search to headers avoids
// scanning potentially large message bodies during cascade deletes.
func headerContainsIgnoreCase(payload, needle []byte) bool {
	// Locate end-of-header: "\r\n\r\n" or "\n\n"
	header := payload
	if idx := bytes.Index(payload, []byte("\r\n\r\n")); idx >= 0 {
		header = payload[:idx]
	} else if idx := bytes.Index(payload, []byte("\n\n")); idx >= 0 {
		header = payload[:idx]
	}
	return bytes.Contains(bytes.ToLower(header), bytes.ToLower(needle))
}

// bytesToLower is retained for the fuzz test in bbolt_test.go.
func bytesToLower(b []byte) []byte {
	res := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			res[i] = c + 32
		} else {
			res[i] = c
		}
	}
	return res
}

// DBMessage represents a retrieved message model from the index database
type DBMessage struct {
	UID          uint32
	Flags        uint32
	InternalDate int64
	Length       uint32
	Payload      []byte
}

// FetchMessages retrieves all messages sequentially for a key mailbox user.
// Each message's Payload is copied out of the bbolt mmap buffer so that the
// returned slice remains valid after the read transaction closes.
func (db *BboltDB) FetchMessages(username string) ([]DBMessage, error) {
	var msgsList []DBMessage
	err := db.View(func(tx *bbolt.Tx) error {
		mailboxes := tx.Bucket(MailboxesBucket)
		if mailboxes == nil {
			return nil
		}
		uMbox := mailboxes.Bucket([]byte(username))
		if uMbox == nil {
			return nil
		}
		msgs := uMbox.Bucket(MessagesBucket)
		if msgs == nil {
			return nil
		}
		return msgs.ForEach(func(k, v []byte) error {
			if len(v) < 20 {
				return nil
			}
			uid := binary.BigEndian.Uint32(v[0:4])
			flags := binary.BigEndian.Uint32(v[4:8])
			internalDate := int64(binary.BigEndian.Uint64(v[8:16]))
			length := binary.BigEndian.Uint32(v[16:20])

			// Copy payload out of the mmap'd page — the slice returned by
			// bbolt is only valid for the lifetime of the transaction.
			rawPayload := v[20:]
			payloadCopy := make([]byte, len(rawPayload))
			copy(payloadCopy, rawPayload)

			msgsList = append(msgsList, DBMessage{
				UID:          uid,
				Flags:        flags,
				InternalDate: internalDate,
				Length:       length,
				Payload:      payloadCopy,
			})
			return nil
		})
	})
	return msgsList, err
}

// FetchMessageHeaders retrieves metadata (UID, Flags, InternalDate, Length) for
// all messages in username's mailbox without copying the message payload.
// Use this for FLAGS-only queries (STORE, flag-only FETCH, STATUS UNSEEN) to
// avoid allocating potentially megabytes of payload that will not be read.
func (db *BboltDB) FetchMessageHeaders(username string) ([]DBMessage, error) {
	var msgsList []DBMessage
	err := db.View(func(tx *bbolt.Tx) error {
		mailboxes := tx.Bucket(MailboxesBucket)
		if mailboxes == nil {
			return nil
		}
		uMbox := mailboxes.Bucket([]byte(username))
		if uMbox == nil {
			return nil
		}
		msgs := uMbox.Bucket(MessagesBucket)
		if msgs == nil {
			return nil
		}
		return msgs.ForEach(func(k, v []byte) error {
			if len(v) < 20 {
				return nil
			}
			msgsList = append(msgsList, DBMessage{
				UID:          binary.BigEndian.Uint32(v[0:4]),
				Flags:        binary.BigEndian.Uint32(v[4:8]),
				InternalDate: int64(binary.BigEndian.Uint64(v[8:16])),
				Length:       binary.BigEndian.Uint32(v[16:20]),
				// Payload intentionally omitted — callers that need the body
				// should use FetchMessages instead.
			})
			return nil
		})
	})
	return msgsList, err
}

// UpdateMessageFlags atomically modifies the flags of a single message identified
// by uid in username's mailbox and returns the resulting flag word.
// Delegates to UpdateMessagesFlags to avoid duplicating transaction logic.
func (db *BboltDB) UpdateMessageFlags(username string, uid uint32, flagsToSet, flagsToClear uint32, isReplace bool) (uint32, error) {
	results, err := db.UpdateMessagesFlags(username, []uint32{uid}, flagsToSet, flagsToClear, isReplace)
	if err != nil {
		return 0, err
	}
	if flags, ok := results[uid]; ok {
		return flags, nil
	}
	return 0, errors.New("message not found")
}

// UpdateMessagesFlags modifies multiple message flags in a single transactional exclusive scope
func (db *BboltDB) UpdateMessagesFlags(username string, uids []uint32, flagsToSet uint32, flagsToClear uint32, isReplace bool) (map[uint32]uint32, error) {
	results := make(map[uint32]uint32)
	err := db.Update(func(tx *bbolt.Tx) error {
		mailboxes := tx.Bucket(MailboxesBucket)
		if mailboxes == nil {
			return errors.New("mailboxes bucket not found")
		}
		uMbox := mailboxes.Bucket([]byte(username))
		if uMbox == nil {
			return errors.New("mailbox not found")
		}
		msgs := uMbox.Bucket(MessagesBucket)
		if msgs == nil {
			return errors.New("messages bucket not found")
		}

		for _, uid := range uids {
			msgKey := fmt.Sprintf("%08d", uid)
			v := msgs.Get([]byte(msgKey))
			if v == nil {
				continue
			}
			if len(v) < 20 {
				continue
			}
			vCopy := make([]byte, len(v))
			copy(vCopy, v)

			currentFlags := binary.BigEndian.Uint32(vCopy[4:8])
			var finalFlags uint32
			if isReplace {
				finalFlags = flagsToSet
			} else {
				finalFlags = (currentFlags | flagsToSet) &^ flagsToClear
			}
			binary.BigEndian.PutUint32(vCopy[4:8], finalFlags)
			if err := msgs.Put([]byte(msgKey), vCopy); err != nil {
				return err
			}
			results[uid] = finalFlags
		}
		return nil
	})
	return results, err
}

// ExpungeDeletedMessages permanently removes all messages flagged \Deleted from
// username's mailbox. Returns the UIDs that were expunged and updates the
// persisted message count.
func (db *BboltDB) ExpungeDeletedMessages(username string) ([]uint32, error) {
	return db.ExpungeSelectedDeletedMessages(username, nil)
}

// ExpungeSelectedDeletedMessages permanently removes messages flagged \Deleted
// from username's mailbox. If allowedUIDs is non-nil, only deleted messages
// whose UID is present in the set are removed (RFC 4315 UID EXPUNGE semantics).
// It returns the UIDs that were expunged and updates the persisted message count.
func (db *BboltDB) ExpungeSelectedDeletedMessages(username string, allowedUIDs map[uint32]bool) ([]uint32, error) {
	var expungedUIDs []uint32
	err := db.Update(func(tx *bbolt.Tx) error {
		mailboxes := tx.Bucket(MailboxesBucket)
		if mailboxes == nil {
			return nil
		}
		uMbox := mailboxes.Bucket([]byte(username))
		if uMbox == nil {
			return nil
		}
		msgs := uMbox.Bucket(MessagesBucket)
		if msgs == nil {
			return nil
		}
		meta := uMbox.Bucket(MetadataBucket)

		// Collect keys first — never mutate a bucket during ForEach iteration.
		var keysToDelete [][]byte
		if err := msgs.ForEach(func(k, v []byte) error {
			if len(v) < 20 || binary.BigEndian.Uint32(v[4:8])&0x08 == 0 {
				return nil
			}
			uid := binary.BigEndian.Uint32(v[0:4])
			if allowedUIDs != nil && !allowedUIDs[uid] {
				return nil
			}
			keyCopy := make([]byte, len(k))
			copy(keyCopy, k)
			keysToDelete = append(keysToDelete, keyCopy)
			expungedUIDs = append(expungedUIDs, uid)
			return nil
		}); err != nil {
			return err
		}

		for _, k := range keysToDelete {
			if err := msgs.Delete(k); err != nil {
				return fmt.Errorf("delete message key %q: %w", k, err)
			}
		}

		// Decrement the persisted message count.
		if meta != nil && len(keysToDelete) > 0 {
			countBuf := meta.Get(MessageCountKey)
			count := uint32(0)
			if len(countBuf) >= 4 {
				count = binary.BigEndian.Uint32(countBuf)
			}
			if uint32(len(keysToDelete)) <= count {
				count -= uint32(len(keysToDelete))
			} else {
				count = 0
			}
			newCountBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(newCountBuf, count)
			if err := meta.Put(MessageCountKey, newCountBuf); err != nil {
				return fmt.Errorf("update message count: %w", err)
			}
		}
		return nil
	})
	return expungedUIDs, err
}

// GetMailboxInfo returns message count, UIDValidity, and predicted NextUID for a
// SELECT or STATUS response. Uses the O(1) persisted counter rather than a full
// B-tree traversal via msgs.Stats().KeyN.
func (db *BboltDB) GetMailboxInfo(username string) (count, uidValidity, nextUID uint32, err error) {
	err = db.View(func(tx *bbolt.Tx) error {
		mailboxes := tx.Bucket(MailboxesBucket)
		if mailboxes == nil {
			return nil
		}
		uMbox := mailboxes.Bucket([]byte(username))
		if uMbox == nil {
			return nil
		}

		meta := uMbox.Bucket(MetadataBucket)
		if meta != nil {
			if buf := meta.Get(UIDValidityKey); len(buf) >= 4 {
				uidValidity = binary.BigEndian.Uint32(buf)
			}
			if buf := meta.Get(NextUIDKey); len(buf) >= 4 {
				nextUID = binary.BigEndian.Uint32(buf)
			}
			if buf := meta.Get(MessageCountKey); len(buf) >= 4 {
				count = binary.BigEndian.Uint32(buf)
			}
		}
		return nil
	})
	return count, uidValidity, nextUID, err
}

// GetUserStatus returns whether the user exists and whether they are suspended
// in a single atomic read transaction, eliminating the TOCTOU window that exists
// when UserExists and IsUserSuspended are called sequentially.
//
// The suspension check is performed regardless of whether the user exists so
// that the function is consistent with AuthenticateOrRegister's fast-fail path
// and so that callers receive correct suspension state even when existence is
// checked separately.
func (db *BboltDB) GetUserStatus(username string) (exists, suspended bool, err error) {
	err = db.View(func(tx *bbolt.Tx) error {
		if users := tx.Bucket(UsersBucket); users != nil {
			exists = users.Get([]byte(username)) != nil
		}
		// Always check suspension — even for non-existent users — so that the
		// return value is always consistent and callers never see a stale false.
		if sb := tx.Bucket(UserStatusBucket); sb != nil {
			suspended = string(sb.Get([]byte(username))) == "suspended"
		}
		return nil
	})
	return exists, suspended, err
}

// UserStatus bundles a username with its suspension state for display purposes.
type UserStatus struct {
	Username  string
	Suspended bool
}

// ListUsersWithStatus returns all registered users together with their
// suspension state in a single read transaction — O(n) vs the previous
// O(n) transactions that ListUsers + n×IsUserSuspended would require.
func (db *BboltDB) ListUsersWithStatus() ([]UserStatus, error) {
	var result []UserStatus
	err := db.View(func(tx *bbolt.Tx) error {
		users := tx.Bucket(UsersBucket)
		if users == nil {
			return nil
		}
		statusBucket := tx.Bucket(UserStatusBucket)

		return users.ForEach(func(k, _ []byte) error {
			suspended := false
			if statusBucket != nil {
				suspended = string(statusBucket.Get(k)) == "suspended"
			}
			result = append(result, UserStatus{
				Username:  string(k),
				Suspended: suspended,
			})
			return nil
		})
	})
	return result, err
}
