// Package database implements the bbolt-backed storage layer for the chatmail
// server. It owns the bucket hierarchy, the binary message serialization
// format, and all read/write transactions used by the SMTP and IMAP engines.
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

// Top-level bucket names, per the design specification.
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

// ErrAuthFailed is returned when a known user supplies an incorrect password.
var ErrAuthFailed = errors.New("authentication credentials invalid")

// ErrNoMailbox is returned when a mailbox does not exist.
var ErrNoMailbox = errors.New("mailbox does not exist")

// Message is the decoded form of a serialized message stored in a mailbox.
type Message struct {
	UID          uint32
	Flags        uint32
	InternalDate int64
	Body         []byte
}

// DB wraps a bbolt database file and exposes chatmail-specific operations.
type DB struct {
	bolt   *bolt.DB
	domain string
}

// Open opens (or creates) the bbolt database at path and ensures the top-level
// bucket hierarchy exists. The provided domain is written to the Configuration
// bucket on first creation and is used for all subsequent domain-policy checks.
func Open(path, domain string) (*DB, error) {
	b, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bbolt: %w", err)
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
			db.domain = string(existing)
		}
		return nil
	}); err != nil {
		b.Close()
		return nil, err
	}

	return db, nil
}

// Close closes the underlying bbolt database.
func (db *DB) Close() error { return db.bolt.Close() }

// Domain returns the configured server domain.
func (db *DB) Domain() string { return db.domain }

// Authenticate validates the supplied credentials. If the user does not yet
// exist, the password is hashed with bcrypt, the user is registered, and an
// empty mailbox is provisioned (auto-registration). The created return value
// reports whether a new account was provisioned.
//
// If the user already exists, the password is verified against the stored hash
// and ErrAuthFailed is returned on mismatch.
func (db *DB) Authenticate(email, password string) (created bool, err error) {
	err = db.bolt.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(bucketUsers)
		if hash := users.Get([]byte(email)); hash != nil {
			if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil {
				return ErrAuthFailed
			}
			return ensureMailbox(tx, email)
		}

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
// must reject unknown accounts. It returns ErrAuthFailed if the user does not
// exist or the password does not match.
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

// UserExists reports whether a user has been registered.
func (db *DB) UserExists(email string) bool {
	exists := false
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		exists = tx.Bucket(bucketUsers).Get([]byte(email)) != nil
		return nil
	})
	return exists
}

// ensureMailbox provisions the Mailboxes/<email> hierarchy (Metadata and
// Messages sub-buckets) if it does not already exist. NextUID is initialized to
// 1 and UIDValidity to a stable random uint32 generated once at creation time.
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

// MailboxExists reports whether a mailbox has been provisioned for email.
func (db *DB) MailboxExists(email string) bool {
	exists := false
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		if mb := tx.Bucket(bucketMailboxes).Bucket([]byte(email)); mb != nil {
			exists = true
		}
		return nil
	})
	return exists
}

// EnsureMailbox provisions an empty mailbox for a local recipient that may not
// have authenticated yet (e.g. the target of an inbound message).
func (db *DB) EnsureMailbox(email string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		return ensureMailbox(tx, email)
	})
}

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

// AppendMessage stores a raw RFC822 payload in the recipient mailbox. The
// message is assigned the current NextUID, NextUID is then incremented, and the
// message is committed under an 8-character zero-padded key. The mailbox is
// auto-provisioned if necessary.
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

		msg := &Message{UID: uid, Flags: flags, InternalDate: internalDate.Unix(), Body: body}
		return msgs.Put(messageKey(uid), serialize(msg))
	})
	if err != nil {
		return 0, err
	}
	return uid, nil
}

// LoadMessages returns every message in the mailbox sorted by ascending UID.
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
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out, nil
}

// SetFlags overwrites the flag bitmask of a single message.
func (db *DB) SetFlags(email string, uid, flags uint32) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		msgs, err := messagesBucket(tx, email)
		if err != nil {
			return err
		}
		raw := msgs.Get(messageKey(uid))
		if raw == nil {
			return nil
		}
		msg, err := deserialize(raw)
		if err != nil {
			return err
		}
		msg.Flags = flags
		return msgs.Put(messageKey(uid), serialize(msg))
	})
}

// DeleteMessage removes a single message from a mailbox. The NextUID counter is
// never decremented, preserving UID stability across deletions.
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
			type pending struct {
				key []byte
				val []byte
			}
			var updates []pending
			if err := msgs.ForEach(func(k, v []byte) error {
				msg, err := deserialize(v)
				if err != nil {
					return err
				}
				if msg.InternalDate < cutoff && msg.Flags&FlagDeleted == 0 {
					msg.Flags |= FlagDeleted
					updates = append(updates, pending{key: append([]byte(nil), k...), val: serialize(msg)})
				}
				return nil
			}); err != nil {
				return err
			}
			for _, u := range updates {
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

// --- serialization helpers ---

// serialize packs a message into the binary schema defined by the spec:
//
//	0x00-0x03 uint32 BE UID
//	0x04-0x07 uint32 BE Flags
//	0x08-0x0F int64  BE InternalDate
//	0x10-0x13 uint32 BE Length (N)
//	0x14-..   []byte     RFC822 payload
func serialize(m *Message) []byte {
	buf := make([]byte, 20+len(m.Body))
	binary.BigEndian.PutUint32(buf[0:4], m.UID)
	binary.BigEndian.PutUint32(buf[4:8], m.Flags)
	binary.BigEndian.PutUint64(buf[8:16], uint64(m.InternalDate))
	binary.BigEndian.PutUint32(buf[16:20], uint32(len(m.Body)))
	copy(buf[20:], m.Body)
	return buf
}

func deserialize(buf []byte) (*Message, error) {
	if len(buf) < 20 {
		return nil, fmt.Errorf("message payload too short: %d bytes", len(buf))
	}
	length := binary.BigEndian.Uint32(buf[16:20])
	if int(length) > len(buf)-20 {
		return nil, fmt.Errorf("message length field %d exceeds payload %d", length, len(buf)-20)
	}
	return &Message{
		UID:          binary.BigEndian.Uint32(buf[0:4]),
		Flags:        binary.BigEndian.Uint32(buf[4:8]),
		InternalDate: int64(binary.BigEndian.Uint64(buf[8:16])),
		Body:         append([]byte(nil), buf[20:20+length]...),
	}, nil
}

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
