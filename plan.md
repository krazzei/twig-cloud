# Twig Cloud — Backend Plan

Self-hosted personal file sync backend (Dropbox/Nextcloud replacement, personal use).
Web frontend and iOS/Android apps come later; this plan covers the backend only.

Locked decisions:
- **SQLite** for metadata (single file, zero extra infra, trivially backed up)
- **Custom REST sync API** (server-authoritative, Dropbox-style), not WebDAV
- **Version history**: stored cheaply in v1 (revisions table + CAS blobs), endpoints later
- **Conflicts**: Dropbox-style conflict copies — both versions kept as siblings

## Stack

- Go 1.27, stdlib `net/http` (patterned mux, no router dep), `slog`
- `modernc.org/sqlite` (pure Go, no CGO → trivial Docker build), WAL mode
- `argon2id` via `golang.org/x/crypto`
- Migrations: embedded SQL files, tiny homegrown runner (no golang-migrate dep)
- No Redis/Postgres needed — single-node, all state in SQLite + filesystem

Module path: `github.com/twig/twig-cloud` (change easily if you have a vanity domain).

## Architecture

```
cmd/server/main.go          # config, logging, startup, graceful shutdown
internal/
  config/                   # env-driven (PORT, DATA_DIR, TOKEN_TTLS, PART_SIZE, QUOTA_BYTES)
  database/                 # pool, migrate runner, tx helpers
  auth/                     # argon2id, token issue/validate/rotate, middleware
  storage/                  # CAS blob store (Put/Get/Has), GC
  upload/                   # chunked upload lifecycle
  tree/                     # core service: all mutations, conflict rule, sync log
  api/                      # HTTP handlers + middleware (auth, logging, limits)
migrations/NNN_*.sql
docs/openapi.yaml
Dockerfile, Makefile, docker-compose.yml
```

Storage layout on disk:

```
DATA_DIR/
  twig.db
  blobs/ab/cd/<sha256>      # content-addressed, 2/2-hex shard dirs, atomic temp+rename writes
  tmp/                      # in-flight parts, orphaned on crash → cleaned at startup
```

## Data model (full schema written in one migration, up front)

```sql
users(id TEXT PK, email TEXT UNIQUE, password_hash TEXT, created_at INT)
access_tokens(token_hash TEXT PK, user_id, device_name, expires_at, created_at)
refresh_tokens(token_hash TEXT PK, user_id, device_name, expires_at, last_used_at)
  -- opaque 256-bit random tokens, stored hashed; 15-min access / 30-day refresh, rotating
files(hash TEXT PK, size INT, created_at)                 -- CAS metadata
entries(id TEXT PK,            -- client-generated UUID, stable across moves
        user_id, parent_id NULL, name, type CHECK IN('file','folder'),
        file_hash NULL, size, revision INT, created_at, updated_at, deleted_at NULL,
        CONSTRAINT uq_live_name UNIQUE(user_id,parent_id,name) WHERE deleted_at IS NULL)
revisions(id, entry_id, file_hash, size, revision, created_at)  -- appended on each content change → cheap history
sync_log(seq INTEGER PK AUTOINC, user_id, entry_id, op, payload JSON, created_at)
  -- op ∈ created|updated|moved|deleted|conflict; payload = full node snapshot
  -- pruned to last 10k rows; older → client must re-bootstrap (410)
uploads(id, user_id, total_size, part_size, part_count, status, created_at)
upload_parts(upload_id, part_number, hash, size, path, UNIQUE(upload_id,part_number))
```

## Sync protocol (server-authoritative)

Client holds: full node map (id→state) + `last_seq`.

- **Pull:** `GET /sync?since=<seq>` → log rows after `seq` (each with full snapshot) + new `seq`.
  `410` if pruned → client calls `GET /entries?recursive=true` and resets local state.
- **Push:** `POST /sync/changes` with a batch of ops
  `{client_id, parent_id, name, type, file?{hash,size}, expected_revision?}`.
  Applied **atomically in one transaction**. Per-op outcome: `ok` (with server `entry_id` +
  `revision`) or `conflict` — on `expected_revision` mismatch the write is applied as a
  **conflict copy** (`name (conflict).ext` sibling; Dropbox rule) and the response maps
  `client_id → conflict entry_id + new name` so the device can update its local map.
  Batch never fails wholesale; conflicts are reported, not fatal.
- **Content path (uniform for all files):**
  `POST /uploads` → `PUT /uploads/{id}/parts/{n}` (raw bytes, server hashes) →
  `POST /uploads/{id}/complete` → returns `{file_hash, size}` →
  client sends a `file` change op referencing that hash.
  Uploads and tree mutations stay decoupled; dedup is automatic via CAS.
- **Download:** `GET /entries/{id}/content` with `Range` (206/416), `ETag = file_hash`, streamed from CAS.

## API surface (auth: `Authorization: Bearer <access_token>`)

| Endpoint | Purpose |
|---|---|
| `POST /auth/register` · `login` · `refresh` · `logout` · `GET /auth/me` | Auth |
| `POST /uploads` · `PUT /uploads/{id}/parts/{n}` · `POST /uploads/{id}/complete` · `DELETE /uploads/{id}` | Chunked upload |
| `GET /entries` (children) · `GET /entries?recursive=true` | List / bootstrap |
| `GET /entries/{id}/content` | Stream download, Range |
| `POST /sync/changes` | Atomic change-set (the sync primitive) |
| `GET /sync?since=` | Pull deltas |
| `GET /healthz` | Liveness |

Admin tree REST (create folder / rename / delete) is a thin layer over the same tree core
for the future web frontend.

## Tasks (each ≤ 1 agent session, ~150 turns / 2–4 hours)

Copy-paste prompts for each session live in `tasks.md`. Run them in order.

**T1 — Scaffold.** go.mod, dir layout, config from env, slog, `main.go` with graceful
shutdown + `/healthz`, Makefile (`build/run/test/lint`), .gitignore, git init,
multi-stage Dockerfile.
*Done when:* `go test ./...` passes, `make run` serves healthz, `docker build` succeeds.

**T2 — Database layer + migrations.** Embedded SQL runner (ordered, idempotent,
`schema_migrations` table), full schema above, WAL + `busy_timeout`, tx helpers.
*Done when:* migrate test proves idempotency; WAL verified on the file.

**T3 — Auth.** argon2id, opaque token issue/validate (hashed at rest, constant-time),
all `/auth/*` endpoints, refresh rotation with reuse-detection (old-token reuse revokes the
chain), auth middleware.
*Done when:* httptest suite covers register→login→me, wrong password, expired access token,
refresh rotation, reuse revocation.

**T4 — CAS blob store.** `storage` package: `Put(io.Reader)`, `Get`, `Has`, atomic
temp+rename writes, shard layout, crash cleanup of `tmp/`.
*Done when:* round-trip, dedup (same content → one file), concurrent identical puts,
no partial blobs after simulated crash.

**T5 — Chunked upload API.** Upload lifecycle (init/part/complete/cancel), part
validation, size caps, CAS integration, complete→concatenation+final hash.
*Done when:* httptest suite: multi-part round trip, out-of-order parts, bad size 400,
double-complete 409, cancel cleans disk.

**T6 — Tree core service** (the heart; pure Go over DB, no HTTP). Create folder,
move/rename with `expected_revision`, recursive soft-delete, get/list, revision bumps,
`sync_log` append + snapshot payloads, `revisions` rows on content change,
**conflict-copy rule** (naming + parent resolution), sync_log pruning.
*Done when:* table-driven tests on temp-dir SQLite: invariants, live-name uniqueness,
conflict copy appears as sibling with correct name, recursive delete, log ordering,
prune boundary.

**T7 — Sync read + bootstrap.** `GET /sync?since` (incl. 410-after-prune) and
`GET /entries?recursive=true` with the documented JSON shapes.
*Done when:* tests seed a known history and assert exact delta payloads + seq advance +
410 path.

**T8 — Sync write (change-set API).** `POST /sync/changes` batch endpoint over tree core:
atomic transaction, per-op `ok`/`conflict` results, `client_id → entry_id` mapping,
`file` ops validating `files` row exists.
*Done when:* tests: single op, 10-op batch atomicity (verify mid-failure rollback on DB
error), conflict produces copy + correct mapping, file op with unknown hash 400.

**T9 — Admin tree REST endpoints.** Thin authenticated handlers: create folder,
rename/move, delete, single-entry get — over tree core.
*Done when:* httptest suite per endpoint incl. 401/403/404/409 paths.

**T10 — GC + quota.** Startup + periodic scan: delete blobs unreferenced by `entries`,
`revisions`, or live uploads older than 24h (orphans in `tmp/` always); per-user quota
byte accounting, enforced at upload init (413).
*Done when:* tests: orphan deleted, revision-referenced blob survives, in-flight upload
blob survives, quota rejection.

**T11 — Hardening, e2e, packaging.** Request logging + recovery middleware, body size
limits, panic-free guarantee; **e2e test**: register 2 devices → upload on A → B pulls
sync → B edits → A pushes → conflict copy verified on both; README (run, config,
back up = copy `DATA_DIR`); docker-compose with volume; `docs/openapi.yaml` matching the
real API.
*Done when:* full `go test ./...` green, e2e green, compose stack boots and passes healthz.

**Dependency order:** T1→T2→{T3 ∥ T4}→T5, T6 (after T2) → T7→T8→T9; T10 after T6;
T11 last. All serial except T3∥T4.

## Explicit non-goals (later)

- Version history list/restore endpoints (data already retained via `revisions` —
  one small task later)
- WebDAV mount, web frontend, mobile apps, sharing / multi-user isolation hardening,
  encryption at rest, rate limiting beyond basics
