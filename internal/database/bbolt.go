// Package database implements the bbolt-backed storage layer for the chatmail
// server. It owns the bucket hierarchy, the binary message serialisation
// format, and all read/write transactions used by the SMTP and IMAP engines.
//
// Bucket hierarchy:
//
//	Configuration/          top-level
//	  ServerDomain          []byte
//	Users/                  top-level
//	  <email>               bcrypt hash
//	Mailboxes/              top-level
//	  <email>/              sub-bucket
//	    Metadata/           sub-bucket
//	      NextUID           uint32 BE
//	      UIDValidity       uint32 BE
//	    Messages/           sub-bucket
//	      <8-digit-key>     serialised Message
//
// Message wire format (20-byte header + payload):
//
//	0x00–0x03  uint32 BE  UID
//	0x04–0x07  uint32 BE  Flags bitmask
//	0x08–0x0F  int64  BE  InternalDate (Unix seconds)
//	0x10–0x13  uint32 BE  Length (N)
//	0x14–..    []byte     RFC 822 payload (N bytes)
package database

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

// Top-level bucket names.
var (
	bucketConfiguration = []byte("Configuration")
	bucketUsers         = []byte("Users")
	bucketMailboxes     = []byte("Mailboxes")

	// Sub-buckets stored under each Mailboxes/<email> bucket.
	bucketMetadata = []byte("Metadata")
	bucketMessages = []byte("Messages")

	keyServerDomain = []byte("ServerDomain")
	keyNextUID      = []byte("NextUID")
	keyUIDValidity  = []byte("UIDValidity")
)

// IMAP flag bitmask values, per the design specification.
const (
	FlagSeen     uint32 = 0x00000001
	FlagAnswered uint32 = 0x00000002
	FlagFlagged  uint32 = 0x00000004
	FlagDeleted  uint32 = 0x00000008
	FlagDraft    uint32 = 0x00000010
)

// ErrAuthFailed is returned when credentials are invalid or the user does not
// exist. It is intentionally opaque to avoid user-enumeration.
var ErrAuthFailed = errors.New("authentication credentials invalid")

// ErrNoMailbox is returned when the requested mailbox does not exist.
var ErrNoMailbox = errors.New("mailbox does not exist")

// Message is the decoded representation of a single stored email.
type Message struct {
	UID          uint32
	Flags        uint32
	InternalDate int64  // Unix seconds
	Body         []byte // Raw RFC 822 payload
}

// DB wraps a bbolt database and exposes chatmail-specific operations.
type DB struct {
	bolt   *bolt.DB
	domain string
}

// Open opens (or creates) the bbolt database at path and ensures the top-level
// bucket hierarchy exists.
//
// If the database was previously created with a different domain, the stored
// domain takes precedence — the caller's flag is ignored and the stored value
// is returned via DB.Domain(). This prevents silent data corruption when the
// binary is restarted with a changed flag.
func Open(path, domain string) (*DB, error) {
	b, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bbolt %q: %w", path, err)
	}

	db := &DB{bolt: b, domain: domain}
	if err := b.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketConfiguration, bucketUsers, bucketMailboxes} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		cfg := tx.Bucket(bucketConfiguration)
		if existing := cfg.Get(keyServerDomain); existing == nil {
			if err := cfg.Put(keyServerDomain, []byte(domain)); err != nil {
				return err
			}
		} else {
			// Honour the stored domain; caller's flag is advisory on first run only.
			db.domain = string(existing)
		}
		return nil
	}); err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("init buckets: %w", err)
	}

	return db, nil
}

// Close closes the underlying bbolt database.
func (db *DB) Close() error { return db.bolt.Close() }

// Domain returns the configured server domain.
func (db *DB) Domain() string { return db.domain }

// ---------------------------------------------------------------------------
// User & mailbox management
// ---------------------------------------------------------------------------

// Authenticate validates the supplied credentials within a single write
// transaction.
//
// If the user does not yet exist, the password is bcrypt-hashed, the user is
// registered, and an empty mailbox is provisioned (auto-registration). The
// returned created value is true in this case.
//
// If the user already exists, the password is verified against the stored hash.
// ErrAuthFailed is returned on mismatch.
func (db *DB) Authenticate(email, password string) (created bool, err error) {
	err = db.bolt.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(bucketUsers)
		if hash := users.Get([]byte(email)); hash != nil {
			if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil {
				return ErrAuthFailed
			}
			// User already exists and password is correct; ensure their mailbox
			// is present (idempotent).
			return ensureMailbox(tx, email)
		}
		// New user — register and provision.
		hash, hErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if hErr != nil {
			return hErr
		}
		if err := users.Put([]byte(email), hash); err != nil {
			return err
		}
		created = true
		return ensureMailbox(tx, email)
	})
	return created, err
}

// VerifyCredentials validates credentials for an existing user without
// performing auto-registration. It is used by the IMAP LOGIN handler, which
// must reject unknown accounts.
//
// Returns ErrAuthFailed if the user does not exist or the password is wrong.
func (db *DB) VerifyCredentials(email, password string) error {
	return db.bolt.View(func(tx *bolt.Tx) error {
		hash := tx.Bucket(bucketUsers).Get([]byte(email))
		if hash == nil {
			return ErrAuthFailed
		}
		if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil {
			return ErrAuthFailed
		}
		return nil
	})
}

// UserExists reports whether a user account has been registered.
func (db *DB) UserExists(email string) bool {
	exists := false
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		exists = tx.Bucket(bucketUsers).Get([]byte(email)) != nil
		return nil
	})
	return exists
}

// EnsureMailbox provisions an empty mailbox for a local recipient that may not
// have authenticated yet (e.g. a message delivered before the recipient's first
// login). It is idempotent.
func (db *DB) EnsureMailbox(email string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		return ensureMailbox(tx, email)
	})
}

// ensureMailbox provisions Mailboxes/<email>/{Metadata,Messages} if they do
// not already exist. NextUID is initialised to 1 and UIDValidity to a
// cryptographically random uint32, generated once at mailbox creation time and
// never changed thereafter (RFC 9051 §2.3.1.1).
func ensureMailbox(tx *bolt.Tx, email string) error {
	mailboxes := tx.Bucket(bucketMailboxes)
	mbox, err := mailboxes.CreateBucketIfNotExists([]byte(email))
	if err != nil {
		return err
	}
	meta, err := mbox.CreateBucketIfNotExists(bucketMetadata)
	if err != nil {
		return err
	}
	if _, err := mbox.CreateBucketIfNotExists(bucketMessages); err != nil {
		return err
	}
	if meta.Get(keyNextUID) == nil {
		if err := meta.Put(keyNextUID, encodeUint32(1)); err != nil {
			return err
		}
	}
	if meta.Get(keyUIDValidity) == nil {
		if err := meta.Put(keyUIDValidity, encodeUint32(randomUIDValidity())); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Mailbox metadata reads
// ---------------------------------------------------------------------------

// UIDValidity returns the persistent UIDVALIDITY value for a mailbox.
func (db *DB) UIDValidity(email string) (uint32, error) {
	var v uint32
	err := db.bolt.View(func(tx *bolt.Tx) error {
		meta, err := metadataBucket(tx, email)
		if err != nil {
			return err
		}
		v = decodeUint32(meta.Get(keyUIDValidity))
		return nil
	})
	return v, err
}

// NextUID returns the UID that will be assigned to the next delivered message.
func (db *DB) NextUID(email string) (uint32, error) {
	var v uint32
	err := db.bolt.View(func(tx *bolt.Tx) error {
		meta, err := metadataBucket(tx, email)
		if err != nil {
			return err
		}
		v = decodeUint32(meta.Get(keyNextUID))
		return nil
	})
	return v, err
}

// ---------------------------------------------------------------------------
// Message CRUD
// ---------------------------------------------------------------------------

// AppendMessage stores a raw RFC 822 payload in the recipient mailbox. The
// message is assigned the current NextUID (which is then incremented) and
// committed under an 8-character zero-padded decimal key. The mailbox is
// auto-provisioned if it does not yet exist.
//
// The flags and internalDate parameters are accepted from the IMAP APPEND
// command; SMTP delivery passes flags=0 and the current time.
func (db *DB) AppendMessage(email string, body []byte, flags uint32, internalDate time.Time) (uint32, error) {
	var uid uint32
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		if err := ensureMailbox(tx, email); err != nil {
			return err
		}
		mbox := tx.Bucket(bucketMailboxes).Bucket([]byte(email))
		meta := mbox.Bucket(bucketMetadata)
		msgs := mbox.Bucket(bucketMessages)

		uid = decodeUint32(meta.Get(keyNextUID))
		if uid == 0 {
			uid = 1
		}
		if err := meta.Put(keyNextUID, encodeUint32(uid+1)); err != nil {
			return err
		}
		m := &Message{UID: uid, Flags: flags, InternalDate: internalDate.Unix(), Body: body}
		return msgs.Put(messageKey(uid), serialize(m))
	})
	if err != nil {
		return 0, err
	}
	return uid, nil
}

// LoadMessages returns every message in the mailbox sorted by ascending UID.
// Returns nil, ErrNoMailbox if the mailbox has not been provisioned.
func (db *DB) LoadMessages(email string) ([]*Message, error) {
	var out []*Message
	err := db.bolt.View(func(tx *bolt.Tx) error {
		mbox := tx.Bucket(bucketMailboxes).Bucket([]byte(email))
		if mbox == nil {
			return ErrNoMailbox
		}
		msgs := mbox.Bucket(bucketMessages)
		if msgs == nil {
			return nil
		}
		return msgs.ForEach(func(_, v []byte) error {
			msg, err := deserialize(v)
			if err != nil {
				return err
			}
			out = append(out, msg)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	// bbolt iterates keys in lexicographic order; our 8-digit zero-padded keys
	// produce ascending UID order up to UID 99,999,999. The explicit sort is a
	// defensive measure.
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out, nil
}

// SetFlags overwrites the flag bitmask of a single message. It is a no-op if
// the message does not exist (uid was already expunged).
func (db *DB) SetFlags(email string, uid, flags uint32) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		msgs, err := messagesBucket(tx, email)
		if err != nil {
			return err
		}
		raw := msgs.Get(messageKey(uid))
		if raw == nil {
			return nil // already gone — treat as no-op
		}
		msg, err := deserialize(raw)
		if err != nil {
			return err
		}
		msg.Flags = flags
		return msgs.Put(messageKey(uid), serialize(msg))
	})
}

// DeleteMessage removes a single message from the mailbox. The NextUID counter
// is never decremented, preserving UID monotonicity across deletions.
func (db *DB) DeleteMessage(email string, uid uint32) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		msgs, err := messagesBucket(tx, email)
		if err != nil {
			return err
		}
		return msgs.Delete(messageKey(uid))
	})
}

// SweepRetention applies the \Deleted flag to every message older than maxAge
// across all mailboxes and returns the number of messages newly flagged.
//
// It uses a two-pass approach within each mailbox (collect then update) to
// avoid modifying the bucket during ForEach iteration.
func (db *DB) SweepRetention(maxAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-maxAge).Unix()
	flagged := 0
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		mailboxes := tx.Bucket(bucketMailboxes)
		return mailboxes.ForEachBucket(func(email []byte) error {
			msgs := mailboxes.Bucket(email).Bucket(bucketMessages)
			if msgs == nil {
				return nil
			}
			type update struct {
				key []byte
				val []byte
			}
			var pending []update
			if err := msgs.ForEach(func(k, v []byte) error {
				msg, err := deserialize(v)
				if err != nil {
					return err
				}
				if msg.InternalDate < cutoff && msg.Flags&FlagDeleted == 0 {
					msg.Flags |= FlagDeleted
					pending = append(pending, update{
						key: append([]byte(nil), k...),
						val: serialize(msg),
					})
				}
				return nil
			}); err != nil {
				return err
			}
			for _, u := range pending {
				if err := msgs.Put(u.key, u.val); err != nil {
					return err
				}
				flagged++
			}
			return nil
		})
	})
	return flagged, err
}

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

// serialize packs a Message into the binary wire format defined above.
func serialize(m *Message) []byte {
	buf := make([]byte, 20+len(m.Body))
	binary.BigEndian.PutUint32(buf[0:4], m.UID)
	binary.BigEndian.PutUint32(buf[4:8], m.Flags)
	binary.BigEndian.PutUint64(buf[8:16], uint64(m.InternalDate))
	binary.BigEndian.PutUint32(buf[16:20], uint32(len(m.Body)))
	copy(buf[20:], m.Body)
	return buf
}

// deserialize unpacks a binary buffer into a Message. The body is always
// copied into a fresh allocation so the returned Message outlives the bbolt
// transaction that supplied the buffer.
func deserialize(buf []byte) (*Message, error) {
	if len(buf) < 20 {
		return nil, fmt.Errorf("message payload too short: %d bytes", len(buf))
	}
	length := binary.BigEndian.Uint32(buf[16:20])
	if int(length) > len(buf)-20 {
		return nil, fmt.Errorf("message length field %d exceeds available payload %d", length, len(buf)-20)
	}
	return &Message{
		UID:          binary.BigEndian.Uint32(buf[0:4]),
		Flags:        binary.BigEndian.Uint32(buf[4:8]),
		InternalDate: int64(binary.BigEndian.Uint64(buf[8:16])),
		Body:         append([]byte(nil), buf[20:20+length]...),
	}, nil
}

// ---------------------------------------------------------------------------
// Internal transaction helpers
// ---------------------------------------------------------------------------

func metadataBucket(tx *bolt.Tx, email string) (*bolt.Bucket, error) {
	mbox := tx.Bucket(bucketMailboxes).Bucket([]byte(email))
	if mbox == nil {
		return nil, ErrNoMailbox
	}
	meta := mbox.Bucket(bucketMetadata)
	if meta == nil {
		return nil, ErrNoMailbox
	}
	return meta, nil
}

func messagesBucket(tx *bolt.Tx, email string) (*bolt.Bucket, error) {
	mbox := tx.Bucket(bucketMailboxes).Bucket([]byte(email))
	if mbox == nil {
		return nil, ErrNoMailbox
	}
	msgs := mbox.Bucket(bucketMessages)
	if msgs == nil {
		return nil, ErrNoMailbox
	}
	return msgs, nil
}

// messageKey returns the 8-character zero-padded decimal key for uid.
// Keys are lexicographically ordered for UIDs in [1, 99_999_999].
func messageKey(uid uint32) []byte { return []byte(fmt.Sprintf("%08d", uid)) }

func encodeUint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func decodeUint32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

// randomUIDValidity generates a non-zero uint32 suitable for use as a
// UIDVALIDITY value. It uses crypto/rand and falls back to the current Unix
// timestamp only if the system RNG fails.
func randomUIDValidity() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().Unix())
	}
	v := binary.BigEndian.Uint32(b[:])
	if v == 0 {
		v = uint32(time.Now().Unix())
	}
	return v
}
