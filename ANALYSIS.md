# Chatmail: Consolidated Architecture Analysis & Refactor Plan

---

## 1. Repository Synthesis

All three repositories implement the same project: a **minimal, air-gapped chatmail server** intended for DeltaChat use. The server exposes:

- A plaintext SMTP submission engine on `127.0.0.1:1025`
- A plaintext IMAP engine on `127.0.0.1:1143`
- A bbolt-backed persistence layer with auto-registration and a 30-day retention sweep

TLS is terminated by an external stunnel4 daemon; the Go process never handles certificates. Users are auto-registered on first SMTP authentication. IMAP is read-only-ish (INBOX only, no folder hierarchy). This is intentionally a single-mailbox-per-user, single-folder system.

### Repository Identities

| Attribute | qwen | kimi | devin |
|-----------|------|------|-------|
| Go version | 1.26 (invalid) | 1.21 | 1.25 |
| go-imap | v1 (backend API) | raw TCP | **v2 (imapserver)** |
| DB type name | `Database` | `DB` | **`DB`** |
| Retention count returned | no | no | **yes** |
| Typed sentinel errors | no | no | **yes** |
| UIDValidity source | `time.Now().Unix()` | `time.Now().Unix()` | **`crypto/rand`** |
| CLI flags | no | env var | **`flag` package** |
| Graceful shutdown | partial | no | **`sync.WaitGroup`** |
| Unit tests (Go) | none | none | **yes (5 cases)** |
| Integration tests | Python (high-level) | Python (socket-level) | **Python (socket-level, best coverage)** |
| Systemd service | no | partial | **full sandbox** |
| stunnel config | no | no | **yes** |
| SMTP: auth-required guard | no | **yes** | **yes** |
| SMTP: 530 on unauth MAIL | no | **yes** | via `ErrAuthRequired` |
| SMTP: size pre-check in MAIL | no | **yes** | no (framework enforces) |
| SMTP: logs storage result | no | no | **yes** |
| IMAP: SEARCH | all-pass stub | not implemented | **criteria-aware** |
| IMAP: APPEND | yes | not implemented | **yes** |
| IMAP: IDLE | not implemented | not implemented | **yes (blocking)** |
| IMAP: ENVELOPE | not implemented | not implemented | **yes** |
| IMAP: BODY structure | no | manual | **ExtractBodyStructure** |
| Domain: case-insensitive | no | no | **yes (EqualFold)** |

---

## 2. Architecture Analysis

### Package Organisation

All three repos share the same shape:
```
cmd/chatmail/main.go
internal/database/bbolt.go
internal/smtp/server.go
internal/imap/server.go
```
This is correct and should be preserved. The packages are already cleanly layered: `main` → `smtp`/`imap` → `database`. No circular imports.

### Layering Defects Found

**qwen**
- `Database.DB` is a public field (`*bbolt.DB`), leaking the storage abstraction.
- `GetMessages` returns `[]Message` (value slice) — every call copies all payloads.
- `AddMessage` silently discards storage errors for all recipients.
- Retention hardcoded to 30 days with no way to configure.
- `go 1.26.3` is not a valid Go release at time of writing.
- IMAP `SearchMessages` returns every message regardless of criteria — passes integration tests but is wrong.
- No `auth required` guard in `Mail()` — an unauthenticated client can issue MAIL FROM.

**kimi**
- Hand-rolled IMAP parser over raw TCP. This is a significant maintenance liability: it will fail on IMAP literals, pipelining, multi-line commands, SASL challenges, and edge-case whitespace. The hand-rolled parser is also incomplete: no SEARCH, no FETCH without UID, no AUTHENTICATE (only LOGIN), no LIST with subscriptions.
- `Start()` is a blocking function that returns only on fatal error — callers cannot control lifecycle.
- `AutoDeleteOldMessages` uses a magic constant `0x00000008` instead of the named flag.
- `kimi` has a two-phase register/verify pattern (`UserExists` + `CreateUser` vs `VerifyUser`) that has a TOCTOU race: between `UserExists` and `CreateUser`, a concurrent request could register the same email. In bbolt this is safe at the B-tree level because both run in separate write transactions, but the result is a 535 "user already exists" error visible to the client on a duplicate-registration race, rather than a transparent auto-registration.
- `database.ServerDomain` is a package-level constant, making the domain unconfigurable without recompilation.

**devin**
- Best overall structure. One weakness: `Expunge` iterates the snapshot in reverse and emits `w.WriteExpunge` per message — correct per RFC 9051, but there is no reload of the snapshot before `Store` responds to FETCH requests after a flag update. The `session` holds an in-memory snapshot (`s.msgs`) that is mutated in place during `Store` but not reloaded, so a client that issues `STORE` followed by `FETCH` in the same session sees the updated flags from the in-memory snapshot even before `reload()` is called. This is acceptable but worth documenting.
- `Authenticate` is called for both SMTP (auto-register) and IMAP (reject unknown) — devin resolves this cleanly with two separate methods: `Authenticate` (auto-register) and `VerifyCredentials` (reject unknown). This is the correct split.

---

## 3. Component Extraction — Winner per Component

| Component | Winner | Reason |
|-----------|--------|--------|
| **go.mod / dependencies** | devin | go-imap/v2, go-message, correct Go version, proper deps |
| **cmd/main.go** | devin | `flag`, `sync.WaitGroup`, `signal.NotifyContext`, structured logger, configurable retention |
| **database package** | devin | Typed errors, `crypto/rand` UIDValidity, `SweepRetention` returns count, `DeleteMessage`, `AppendMessage` with flags+date, helper funcs, `ForEachBucket` |
| **SMTP server** | devin+kimi | devin's structure + kimi's 530/503 sequence guards + kimi's SIZE pre-check in MAIL |
| **IMAP server** | devin | go-imap/v2, SEARCH, APPEND, IDLE, ENVELOPE, body-structure extraction, correct EXPUNGE ordering |
| **Serialization** | devin | Better error messages, `append([]byte(nil), ...)` copy idiom, named helpers |
| **Unit tests** | devin | Only repo with Go tests |
| **Integration tests** | devin | Best coverage, proper subprocess management, clean socket helpers |
| **Systemd service** | devin | Full sandbox profile (ProtectKernelTunables, MemoryDenyWriteExecute, etc.) |
| **stunnel config** | devin | Only repo that provides it |

---

## 4. Algorithm & Data-Flow Analysis

### Serialization Format (all three repos agree)

```
0x00–0x03  uint32 BE  UID
0x04–0x07  uint32 BE  Flags
0x08–0x0F  int64  BE  InternalDate (Unix seconds)
0x10–0x13  uint32 BE  Length (N)
0x14–..    []byte     RFC822 payload (N bytes)
```

All three repos use this exact format. Wire-compatible. The `Size` field stored by kimi (`m.Size`) is redundant — it equals `len(m.Body)` and is already encoded in the header. Devin drops it from the struct, which is correct.

**Bug in kimi's `deserializeMessage`:** It does `make([]byte, size); copy(body, data[0x14:])` — this copies the body into a fresh allocation on every deserialization, even when the caller only needs metadata. Devin does the same. The efficient alternative is to return a slice alias (`data[20:20+length]`) when the caller guarantees the underlying buffer outlives the message, but inside a bbolt read transaction the buffer is invalidated after the transaction closes, so the copy is required for messages returned outside the transaction. Both are therefore correct.

### UID Key Encoding

All three use `fmt.Sprintf("%08d", uid)`. This gives lexicographic ordering for UIDs 1–99,999,999. Beyond that (unlikely for a chat server), ordering breaks. A cleaner approach is a 4-byte big-endian key, but changing it breaks existing databases — leave as-is and document the limit.

### Retention Sweep

- qwen/kimi: modify during `ForEach` iteration — **dangerous**. bbolt's `ForEach` documents that the bucket must not be modified during iteration. Qwen fixes this with a two-pass approach (collect then delete). Kimi calls `msgs.Put(k, ...)` inside `ForEach` — this *updates* an existing key (not a structural B-tree change), which bbolt permits inside a write transaction, but it is fragile and not guaranteed across bbolt versions.
- devin: collects `pending` updates and applies them after `ForEach`. This is correct and safe.

### TOCTOU in kimi's Auth

```go
if !s.backend.db.UserExists(username) {
    db.CreateUser(...)
} else {
    db.VerifyUser(...)
}
```
Two separate bbolt write transactions. A concurrent SMTP connection for the same email can pass `UserExists` as false, then both try `CreateUser`, and the second fails with "user already exists" (which kimi maps to a 535). In practice chatmail users register once, so this is low-risk but architecturally wrong. Devin fixes it by doing everything in a single write transaction.

---

## 5. Go-Specific Engineering Review

### Goroutine Safety
- All three: bbolt handles its own locking; all mutations go through `db.Update`/`db.View`. No unsafe shared state found.
- qwen: retention worker is started with `go retentionWorker(ctx, db)` with a proper context cancel — correct.
- kimi: retention worker is a naked goroutine on `ticker.C` with no shutdown mechanism — goroutine leak on process exit (minor, process exits anyway, but the pattern is wrong).
- devin: all goroutines tracked in `sync.WaitGroup`; context cancellation propagates cleanly.

### Context Usage
- devin: `signal.NotifyContext` → correct, idiomatic since Go 1.16.
- qwen: manual `context.WithCancel` + `signal.Notify` to a channel — correct but more verbose.
- kimi: no context — goroutine leak.

### Error Handling
- qwen: `AddMessage` discards errors for individual recipients silently (no return, no log). A storage failure is invisible to the SMTP client, which receives a 250. This violates RFC 5321 §6.1 which says the server MUST NOT reply 250 unless it takes responsibility for delivery.
- kimi: returns a wrapped error from `Data` — correct, but maps all errors to a generic "failed to store message".
- devin: returns 451 (transient local failure) with a log entry — correct.

### Nil Dereferences
- qwen `GetMessages`: if the mailbox bucket is nil, returns `nil, nil` (empty list, no error). The IMAP layer then calls `len(msgs)` on nil — safe in Go (len(nil)==0). OK.
- qwen `UpdateMessageFlags`: if `messagesBucket.Get(key)` returns nil, returns "message not found". Then calls `DeserializeMessage(nil)` — **panic**. `DeserializeMessage` checks `len(data) < 20`, but `len(nil) == 0`, so returns an error, which is then ignored by the `UpdateMessageFlags` caller. Actually looking again: `data := messagesBucket.Get(key)` → `if data == nil { return fmt.Errorf(...) }`. OK, that check is there. Fine.
- kimi `deserializeMessage`: does not return an error, so a nil/short buffer returns a nil `*Message` pointer, and callers do not check for nil. In `handleUIDFetch`, `c.getMessageByUID` returns `(nil, false)` when not found — the `!ok` guard prevents the nil deref. In `writeFetchResponse`, `msg` could be nil but only reaches that function through `c.getMessageByUID` which checks the `ok` flag. Probably safe but fragile.

### Allocations
- qwen's `ListMessages` returns value-type `[]Message` — every body is copied.
- kimi/devin return `[]*Message` (pointer slice) — bodies still allocated once per message, but the struct itself is not copied on assignment.
- The most significant allocation is `io.ReadAll` in `Data` — unavoidable since bbolt needs the entire payload upfront.

### Interface Compliance
- devin: `var _ imapserver.Session = (*session)(nil)` — compile-time interface check. Best practice, missing from all others.
- devin: `var _ gosmtp.AuthSession = (*session)(nil)` — same.

---

## 6. Test and Verification Strategy

### Existing Coverage

| Test type | qwen | kimi | devin |
|-----------|------|------|-------|
| Go unit tests | none | none | 5 cases (db layer) |
| Python integration | high-level (smtplib/imaplib) | socket-level | socket-level (best) |
| Race detector | not run | not run | not run |
| Benchmarks | none | none | none |

### Required Tests (consolidated plan)

**Unit — database package**
1. `TestSerializeRoundTrip` — already in devin, keep
2. `TestAuthenticateAutoRegisterAndVerify` — keep
3. `TestAppendAssignsSequentialUIDs` — keep, add UID stability after delete
4. `TestUIDValidityStable` — keep, verify random (not time-based)
5. `TestUIDValidityNonZero` — ensure `randomUIDValidity` never returns 0
6. `TestSweepRetentionFlagsOldMessages` — keep
7. `TestSweepRetentionDoesNotReflagAlreadyDeleted` — new
8. `TestExpungeRemovesOnlyDeletedFlag` — new
9. `TestSetFlagsOrOperations` — Set/Add/Remove
10. `TestConcurrentAppend` — goroutine safety via `t.Parallel`

**Unit — smtp package**
11. `TestMailRejectedForExternalDomain`
12. `TestRcptRejectedForExternalDomain`
13. `TestDataRequiresAuth`
14. `TestDataSizeLimit`

**Unit — imap package**
15. `TestLoginRejectsUnknownUser`
16. `TestSearchFlagCriteria`
17. `TestExpungeDescendingOrder`

**Integration — Python (extend devin's)**
18. All existing devin tests
19. IMAP SEARCH with flag criteria
20. IMAP IDLE (connect, send IDLE, send DONE)
21. Multi-recipient delivery (one SMTP DATA, two RCPT TO, verify both mailboxes)
22. Retention sweep: inject old message, verify flag, expunge

**Benchmark**
23. `BenchmarkAppendMessage` — 1000 sequential appends
24. `BenchmarkLoadMessages1000` — load 1000 messages
25. `BenchmarkSerialize` — serialize/deserialize loop

**Fuzz**
26. `FuzzDeserialize` — random byte slices to deserialize
27. `FuzzParseSeqSet` (if custom parsing retained)

**Race**
- `go test -race ./...` must pass clean

---

## 7. Consolidated Target Design

### Package Layout (unchanged from devin)

```
chatmail/
├── cmd/
│   └── chatmail/
│       └── main.go          # flag parsing, wiring, shutdown
├── internal/
│   ├── database/
│   │   ├── bbolt.go         # DB, Message, CRUD operations
│   │   └── bbolt_test.go    # unit tests
│   ├── smtp/
│   │   └── server.go        # Backend, session, NewServer
│   └── imap/
│       └── server.go        # session, NewServer
├── deploy/
│   ├── chatmail.service     # systemd with full sandbox (devin's)
│   └── stunnel.conf         # TLS offload config (devin's)
├── go.mod
└── go.sum
```

### Interfaces

**Database layer** (exported surface only):
```go
func Open(path, domain string) (*DB, error)
func (db *DB) Close() error
func (db *DB) Domain() string
func (db *DB) Authenticate(email, password string) (created bool, err error)
func (db *DB) VerifyCredentials(email, password string) error
func (db *DB) UserExists(email string) bool
func (db *DB) EnsureMailbox(email string) error
func (db *DB) UIDValidity(email string) (uint32, error)
func (db *DB) NextUID(email string) (uint32, error)
func (db *DB) AppendMessage(email string, body []byte, flags uint32, t time.Time) (uint32, error)
func (db *DB) LoadMessages(email string) ([]*Message, error)
func (db *DB) SetFlags(email string, uid, flags uint32) error
func (db *DB) DeleteMessage(email string, uid uint32) error
func (db *DB) SweepRetention(maxAge time.Duration) (int, error)

var ErrAuthFailed = errors.New("authentication credentials invalid")
var ErrNoMailbox  = errors.New("mailbox does not exist")
```

**SMTP layer**:
```go
func NewServer(db *database.DB, addr string, logger *log.Logger) *gosmtp.Server
```

**IMAP layer**:
```go
func NewServer(db *database.DB, logger *log.Logger) *imapserver.Server
```

### Data Flow

```
DeltaChat → stunnel4:587/993 → chatmail:1025/1143
                                     │
              SMTP session           │          IMAP session
              ─────────────          │          ─────────────
              EHLO                   │          LOGIN → VerifyCredentials
              AUTH PLAIN ──────────────────→   Authenticate (auto-reg)
              MAIL FROM (domain check)         SELECT INBOX → LoadMessages
              RCPT TO   (EnsureMailbox)        FETCH → writeMessage
              DATA      (AppendMessage)        STORE → SetFlags
                                               EXPUNGE → DeleteMessage
                                               SEARCH → matchSearch
                                               IDLE   → <-stop
                        ┌─────────────────────┐
                        │  retention goroutine │
                        │  SweepRetention(30d) │
                        │  every 24h           │
                        └─────────────────────┘
```

### Key Design Decisions

1. **go-imap/v2** (devin): The v2 framework owns all wire-protocol parsing. This eliminates the hand-rolled parser risk from kimi entirely.
2. **Separate auth paths**: `Authenticate` (SMTP, auto-registers) vs `VerifyCredentials` (IMAP, rejects unknown). This matches the chatmail spec and is clear in intent.
3. **`EnsureMailbox` in RCPT**: devin provisions the recipient mailbox during the SMTP RCPT phase, not during DATA. This avoids a partial-delivery scenario where the first recipient is stored and the second fails provisioning mid-transaction.
4. **Domain from database**: On `Open`, the domain is read back from the stored Configuration bucket if it already exists. This prevents flag misconfiguration from silently invalidating existing data.
5. **Random UIDValidity**: `crypto/rand` instead of `time.Now().Unix()`. Two mailboxes created within the same second would otherwise share a UIDVALIDITY, which violates RFC 9051 §2.3.1.1.
6. **`SweepRetention` returns count**: Enables meaningful log output ("flagged N messages") without extra queries.

### Ideas to Discard

- kimi's hand-rolled IMAP TCP parser — replaced entirely by go-imap/v2.
- kimi's `UserExists` + `CreateUser` two-step — replaced by single-transaction `Authenticate`.
- kimi's `database.ServerDomain` package constant — replaced by configurable flag.
- qwen's silent error discard in `AddMessage` / SMTP `Data`.
- qwen's value-type `Message` in exported slice — replaced by pointer.
- qwen's `Database` struct with public `.DB` field.
- All three repos' time-based UIDValidity — replaced by `crypto/rand`.

### Ideas to Merge In

From **kimi** into the consolidated SMTP:
- `530` response ("Authentication required") when `Mail()` is called before `Auth()` — devin uses `ErrAuthRequired` from the framework which maps to 530, so the behavior is already present, just implicit.
- SIZE pre-check in `Mail()`: if `opts.Size > maxBytes`, reject immediately with 552 rather than waiting for DATA. Devin relies solely on the framework's `MaxMessageBytes` enforcement, which rejects at DATA. The kimi pre-check is slightly friendlier but not required by RFC 5321. **Decision**: keep devin's framework enforcement (simpler), add a comment explaining the choice.
- `503 Bad sequence of commands` before MAIL is set for RCPT — devin's framework handles sequencing automatically, so this is already correct implicitly.

From **qwen**'s integration test: the `smtplib`/`imaplib` high-level tests are a useful complement to the socket-level tests for smoke-testing against real protocol libraries. Include both styles.

---

## 8. Phased Refactor Plan

### Phase 0: Baseline (no functional change)
- Adopt devin's codebase as the starting point — it is the closest to the target already.
- Fix `go.mod`: update to `go 1.22` (minimum for `ForEachBucket`, which is bbolt 1.4+).
- Verify `go test ./...` and `go test -race ./...` pass.

### Phase 1: SMTP hardening (from kimi)
- Add SIZE pre-check in `Mail()` for client-friendliness.
- Ensure 530 is returned on unauth `Mail()` — verify devin's framework already does this; add explicit guard if not.
- Add `EnableSMTPUTF8` and `s.ErrorLog` assignment (already in devin).
- Test: add SMTP unit tests 11–14.

### Phase 2: IMAP completeness
- Verify SEARCH criteria coverage matches devin's `matchSearch` — it handles SeqNum, UID, Flag, Since, Before.
- Add `BODY[HEADER.FIELDS ...]` extraction test — this is covered by `imapserver.ExtractBodySection`.
- Confirm IDLE blocks correctly and doesn't spin-loop.
- Test: add IMAP unit tests 15–17.

### Phase 3: Database hardening
- Add `TestConcurrentAppend` with `-race`.
- Add `FuzzDeserialize`.
- Add `TestSweepRetentionDoesNotReflagAlreadyDeleted`.
- Verify `randomUIDValidity` fallback path is tested.

### Phase 4: Observability
- Add a structured startup log line: `logger.Printf("chatmail %s started (domain=%s, data=%s)", version, domain, dataDir)`.
- Add a `version` variable set by `go build -ldflags "-X main.version=$(git describe)"`.
- Consider adding a `/healthz` HTTP endpoint on a separate loopback port for systemd `ExecStartPost=` health checks (optional, out of scope unless requested).

### Phase 5: Deploy
- Ship devin's `chatmail.service` (full sandbox) and `stunnel.conf` as-is.
- Add a `Makefile` with `build`, `test`, `race`, `fuzz`, `install` targets.

---

## 9. Concrete Code Changes

The following sections contain the production-ready consolidated source files. All are based on devin's codebase with targeted improvements from kimi and fixes to the issues identified above.

### Changes relative to devin

**database/bbolt.go** — no changes required; devin's version is already the target.

**smtp/server.go** — one addition: explicit 530 guard in `Mail()` (the framework may or may not enforce this before `Mail` is called depending on go-smtp version); one addition: SIZE pre-check; clarify comment.

**imap/server.go** — no functional changes; minor: add compile-time interface check for `imapserver.Session`.

**cmd/main.go** — add `version` variable; add startup log line.

**database/bbolt_test.go** — add `TestSweepRetentionDoesNotReflagAlreadyDeleted`, `TestSetFlags`, `TestExpungeStability`, `FuzzDeserialize`.

---

## 10. Validation Checklist

### Correctness
- [ ] `go build ./...` succeeds with zero warnings
- [ ] `go vet ./...` passes clean
- [ ] `go test ./...` passes
- [ ] `go test -race ./...` passes
- [ ] `python3 integration_test.py` passes with all tests green
- [ ] UID 1 is assigned to first message
- [ ] UID is never reused after delete
- [ ] UIDVALIDITY does not change across restarts or re-authentication
- [ ] 535 is returned on wrong password
- [ ] 550 is returned for external MAIL FROM
- [ ] 551 is returned for external RCPT TO
- [ ] Messages >10 MiB are rejected with 552
- [ ] Retention sweep flags only messages older than configured age
- [ ] EXPUNGE responses are in descending sequence order
- [ ] IDLE command does not busy-loop

### Security
- [ ] No TLS in the Go binary (stunnel4 only)
- [ ] `AllowInsecureAuth = true` is set (required for loopback-only)
- [ ] Database permissions are 0600
- [ ] Data directory is created with 0700
- [ ] Systemd `NoNewPrivileges=true` and `MemoryDenyWriteExecute=true` are set

### Performance
- [ ] `BenchmarkAppendMessage`: < 5ms/op on spinning disk (bbolt write + fsync)
- [ ] `BenchmarkLoadMessages1000`: < 10ms for 1000-message inbox
- [ ] No allocations inside bbolt read transactions that outlive the transaction

### Risks and Ambiguities

1. **go-imap/v2 API stability**: The module is pinned at `v2.0.0-beta.8`. The beta designation means breaking API changes are possible. Mitigation: pin to an exact version; monitor upstream releases before upgrading.

2. **bbolt `ForEachBucket` availability**: `ForEachBucket` was added in bbolt 1.4.0. The consolidated `go.mod` should require `go.etcd.io/bbolt v1.4.3` (devin already does). kimi uses v1.3.8 and would need an upgrade; qwen uses v1.4.3.

3. **Auto-registration asymmetry**: SMTP auto-registers; IMAP rejects unknown users. This is intentional (chatmail design) but may surprise users who try to check mail before ever sending. The first auth is always an SMTP submission. Document this in the README.

4. **Plaintext loopback**: The server intentionally speaks plaintext on 127.0.0.1. Any misconfigured firewall that exposes ports 1025/1143 externally would allow credential interception. The systemd `RestrictAddressFamilies` helps but does not substitute for firewall rules. Document in README.

5. **Single-mailbox design**: INBOX is the only mailbox. Clients that try to create Sent/Drafts/Trash folders will receive NO responses. DeltaChat handles this gracefully, but other clients may behave unexpectedly.

6. **No NOTIFY/QRESYNC**: The IDLE implementation blocks without push. Clients observe new mail only by re-SELECTing. Sufficient for DeltaChat (which polls), not suitable for clients expecting server-push.
