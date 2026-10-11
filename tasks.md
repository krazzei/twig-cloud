# Agent task prompts

One prompt per session, run in order. Each prompt assumes a fresh agent lands in this
repo and reads plan.md first, so the prompts point there instead of repeating the design.
T1 (scaffold) is already done: config, healthz, graceful shutdown, and the Dockerfile
are in place. Everything below builds on top of it.

Each prompt tells the agent to commit at the end. Delete those lines if you want to
review diffs first.

---

## T2. Database layer and migrations

You're in the twig-cloud repo, a Go backend for a personal file sync server. Read
plan.md before touching anything. T1 is done (config package, healthz, Docker), build
on top of it. Your job this session is the database layer.

1. Put SQL files in `migrations/` as `NNN_name.sql`. Write the entire schema from
   plan.md into a single `001_init.sql`, every table, even the ones that only get used
   by later tasks. I want the schema locked in now. One catch: the unique constraint on
   (user_id, parent_id, name) must be a partial index
   (`CREATE UNIQUE INDEX ... WHERE deleted_at IS NULL`). SQLite won't take it as a
   table constraint.
2. In `internal/database/`, write a small runner: embed the migrations with `go:embed`,
   apply unapplied files in numeric order inside one transaction, track applied files
   in a `schema_migrations` table. It has to be idempotent, the server calls it on
   every startup.
3. Open SQLite with WAL mode and a 5 second `busy_timeout`. Use the
   `modernc.org/sqlite` driver (pure Go, add it to go.mod; the pragmas go in the DSN).
   Expose a `DB` type that wraps `*sql.DB` with a `Tx` helper that takes a func and
   handles commit/rollback, so later tasks run one transaction without ceremony.
4. Wire it into `cmd/server/main.go`: open the DB at `cfg.DataDir/twig.db`, run
   migrations, close on shutdown.

Done when `go test ./...` is green, including a test proving migrations run twice
without error and a test that reads `PRAGMA journal_mode` off the file and confirms
WAL. `make lint` clean.

---

## T3. Auth

You're in twig-cloud. Read plan.md. The database layer is in (T2): migrations apply on
startup, `internal/database` has the pool and Tx helper. Now we need auth.

Add `golang.org/x/crypto` for argon2id. It's the only new dependency for this task.

In `internal/auth/`:
- Hash passwords with argon2id. Pick sane parameters as named constants. 64MB of
  memory is fine, we are not running on a Raspberry Pi 0.
- Opaque tokens, not JWT. Access and refresh tokens are random 256-bit strings; the
  server stores only their SHA-256 in `access_tokens` / `refresh_tokens`. TTLs come
  from the existing config package (15 min access, 30 day refresh).
- Refresh rotation: every `/auth/refresh` issues a new refresh token and invalidates
  the old one. Sessions are per-login, not per device name: a `session_id` column
  (UUID, added in a later migration) identifies the login chain, and rotations keep
  it. If a client presents a token that was already rotated, that is a network retry
  of a lost response only if it arrived within 60s of the redemption — re-issue a
  fresh pair. Past the window the token was copied, so revoke that session (not
  every login sharing the device name).

In `internal/api/`, add the handlers and the bearer-token middleware:
- `POST /auth/register` (email, password, device_name): validate, hash, auto-login,
  return both tokens
- `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `GET /auth/me`
- Middleware resolves the Bearer token to a user id in the request context. Bad or
  expired token gets a 401 JSON body.

Keep validation boring and at the boundary: lowercase and trim the email, check basic
format, minimum 8 char password.

Done when the httptest suite covers: register then login then me, wrong password 401,
expired access token 401, refresh rotation works, reusing a rotated refresh token
revokes the chain, logout kills the token. `go test ./...` green, `make lint` clean.


---

## T4. CAS blob store

You're in twig-cloud. Read plan.md. Auth is done (T3). Now the content-addressed blob
store in `internal/storage/`. No HTTP, no database, just the filesystem under
`cfg.DataDir`.

- `Put(io.Reader)` streams to a temp file in `tmp/`, computes the SHA-256 while
  reading, then renames it into `blobs/<first 2 hex>/<next 2 hex>/<full hash>`. The
  rename is atomic, so a crash mid-write never leaves a partial blob. If a blob with
  that hash already exists, delete the temp file and return the existing one. That is
  the dedup.
- `Get(hash)` opens the blob for streaming and returns its size. `Has(hash)` for
  existence checks.
- On startup, sweep `tmp/` and delete everything in it.

Done when tests cover: a round trip, dedup (two Puts of the same content leave one
file on disk), two concurrent Puts of the same content racing, and a crash test (leave
a temp file behind, the startup sweep removes it, and `Get` on a never-completed hash
returns an error instead of a partial file). `go test ./...` green, `make lint` clean.

---

## T5. Chunked upload API

You're in twig-cloud. Read plan.md. The storage layer is in (T4). This session is the
chunked upload API in `internal/upload/` plus its endpoints in `internal/api/`. This
is how all file content reaches the server; every size goes through this same path.

- `POST /uploads`, body `{total_size}`. The server picks the part size from config and
  responds with `{upload_id, part_size, part_count}`. Creates the `uploads` row.
- `PUT /uploads/{id}/parts/{n}`. Stream the body to a temp file, hash it, store it as
  a CAS blob through the storage package (dedup applies to parts too), insert an
  `upload_parts` row. Reject a body larger than the part size. Parts may arrive in any
  order.
- `POST /uploads/{id}/complete`. Verify every part is present, concatenate the parts
  (streaming, not into memory) into the final blob, compute the whole-file SHA-256,
  upsert the `files` row, mark the upload complete, return `{file_hash, size}`. That
  hash is what sync change ops reference later. Completing twice is a 409.
- `DELETE /uploads/{id}` cancels. Delete the rows; leave the blobs, GC in a later task
  reclaims them since parts are shared content.

Everything sits behind the auth middleware.

Done when tests cover: a multi-part round trip with real bytes, out-of-order part
uploads, double complete 409, part body too large 400, part for unknown upload 404,
cancel removes the rows, unauthenticated 401. `go test ./...` green, `make lint`
clean.

---

## T6. Tree core service

This is the big one. You're in twig-cloud. Read plan.md twice if you need to. Uploads
and storage are in (T5). Your job is `internal/tree/`, the core service that owns all
tree mutations. No HTTP in this task; the handlers land later and sit on top of this.

The tree is the `entries` table; a file is an entry pointing at a hash in `files`.
Every mutation runs inside one transaction and does three things:
- bumps `entry.revision`
- appends a `sync_log` row carrying the full JSON snapshot of the entry after the
  change
- on a content update (new `file_hash`), inserts a row in `revisions`. That is how we
  keep version history cheap.

Operations to implement:
- `CreateFolder(parent_id, name)`
- `PutFile(parent_id, name, file_hash, size, expected_revision)`. Creates the entry,
  or updates the hash if an entry with that name already lives there.
  `expected_revision` is the revision the client last saw.
- `Move(entry_id, new_parent_id, new_name, expected_revision)`
- `Delete(entry_id)`. Soft delete: set `deleted_at` on the entry and every
  descendant, each with its own `sync_log` row.
- `Get`, `List(parent_id)`, and `ListAll` for bootstrap.

The conflict rule, this is the part that matters. If a mutation carries an
`expected_revision` and the server-side entry's revision does not match, do not
reject it. Apply the change as a conflict copy instead: same content, renamed
(`report.pdf` becomes `report (conflict).pdf`), placed next to the original, or in
the nearest surviving ancestor if the parent is gone. If that name is taken too,
number it (`conflict 2`, `conflict 3`). Return the new entry so the caller can map
the client id to the server id. A create that lands on an already-taken name takes
the same path.

`sync_log` uses a per-user autoincrement seq. Prune to the last 10k rows per user
after writes; T7 relies on the prune boundary for its 410.

The partial unique index on (user_id, parent_id, name) where deleted_at is null is
your guard against duplicate live names. Trust it, and let the conflict path handle
the collisions that surface anyway.

Done when table-driven tests on a temp-dir SQLite cover: live name uniqueness, moving
across folders, recursive delete freeing the name for reuse, a conflict copy landing
as a sibling with the right name, a conflict whose parent is gone landing in the
nearest surviving ancestor, revision bumps on every op, `sync_log` rows in order with
exact snapshots, a `revisions` row appearing on content change, and pruning dropping
the 10001st-oldest row. `go test ./...` green, `make lint` clean.

---

## T7. Sync read and bootstrap

You're in twig-cloud. Read plan.md. The tree core is in (T6) and all the semantics
live there. This session is the read side: sync pull and bootstrap.

Endpoints in `internal/api/`:
- `GET /sync?since=N`. Returns `sync_log` rows after N for the requesting user, each
  carrying its op and the full entry snapshot, plus the latest seq. If N is older than
  the oldest retained row (pruned), return 410 with a body that says "re-bootstrap,
  here is the current seq". The client contract: on 410 it calls the bootstrap
  endpoint and rebuilds local state.
- `GET /entries?recursive=true` returns the full live tree plus the current seq. That
  is the bootstrap payload.

Document the exact request and response JSON you implement in `docs/api-notes.md`.
T8, T9, and the OpenAPI doc (T11) build on it, so write down the shapes you actually
ship, not the ones you wish you could ship.

Done when tests seed a known history through the tree core and then assert the exact
delta payloads and seq advance, the 410 after pruning below the retained window, and
that bootstrap returns the complete live tree. `go test ./...` green, `make lint`
clean.

---

## T8. Sync write (change-set API)

You're in twig-cloud. Read plan.md and `docs/api-notes.md` from T7. Now the write side
of sync.

`POST /sync/changes` takes a batch of ops and applies the whole batch in one
transaction through the tree core. If any op fails hard, the entire batch rolls back.
Conflicts are not failures: a conflicting op gets applied as a conflict copy and
reported in the response.

Op shape, pin it exactly, the mobile apps get built against this:

    {client_id, kind, name, parent_id, file{hash,size}, expected_revision}

Kinds are `create_folder`, `put_file`, `move`, `delete`. `delete` and `move` identify
the entry by `client_id`. `put_file` requires a `files` row for `file.hash`,
otherwise the whole request is a 400.

Response: `{seq, results: [{client_id, status: ok|conflict, entry_id, name,
revision}]}`. On conflict, `entry_id` and `name` point at the conflict copy so the
client can rebind its local id to it.

Replay idempotency is out of scope for v1. Do not build it.

Done when tests cover: one op of each kind, a 10-op batch, a forced mid-transaction
DB error rolling the whole batch back, a conflicting op producing a copy with the
result mapping the client id to it, `put_file` with an unknown hash 400,
unauthenticated 401. `go test ./...` green, `make lint` clean.

---

## T9. Admin tree REST endpoints

You're in twig-cloud. Read plan.md and `docs/api-notes.md`. The sync API is done on
both sides. This session is the plain tree endpoints the web frontend will use later.
Thin handlers on top of the tree core, no new logic. If you find yourself writing
logic here, push it down into `internal/tree`.

- `GET /entries/{id}`
- `POST /entries`, create folder, body `{name, parent_id}`
- `PATCH /entries/{id}`, rename and/or move, body `{name?, parent_id?,
  expected_revision}`
- `DELETE /entries/{id}`

Error mapping: 401 unauthenticated, 404 not found, 409 on name collision or revision
mismatch with the current server state in the body. Everything behind the auth
middleware.

Done when each endpoint has an httptest pass covering the happy path plus the 401,
404, and 409 cases. `go test ./...` green, `make lint` clean.

---

## T10. GC and quota

You're in twig-cloud. Read plan.md. Every feature is in; this session is housekeeping.

GC runs at startup and on an hourly ticker. Rules:
- Anything in `tmp/` is garbage. Delete it.
- A CAS blob is safe to delete when nothing references it. References are a `files`
  row pointed at by a live entry or a `revisions` row, and parts belonging to
  uploads that are not complete yet.
- When a `files` row exists but nothing references it, do not delete it the moment it
  becomes orphaned. The replace flow writes the new blob before the tree points at
  it. Only reclaim `files` rows (and their blobs) that have been orphaned for more
  than 24 hours.

Quota: `cfg.QuotaBytes`, 0 means unlimited. Usage is the sum of `size` over the user's
live entries. Enforce it at `POST /uploads`; if current plus `total_size` exceeds
the quota, return 413. Also add `GET /status` returning `{quota_bytes, used_bytes}`;
the web frontend will want it.

Done when tests cover: an orphaned blob older than 24 hours gets deleted, a freshly
orphaned one survives, a revision-referenced blob survives, a live upload's part
survives, a completed upload's part gets reclaimed, quota exceeded is 413, and the
`/status` numbers add up. `go test ./...` green, `make lint` clean.

---

## T11. Hardening, e2e, packaging

Last one. You're in twig-cloud. Read plan.md and `docs/api-notes.md`. Everything
works; your job is hardening, the end-to-end test, and packaging.

Middleware in `internal/api/`: request logging to slog (method, path, status,
duration, user id), a recovery handler that logs the panic with its stack and returns
500 JSON, and a `MaxBytesReader` sized to the part size plus slack. The server should
not be able to panic its way to a dead connection.

Concurrency cap in `internal/auth/`: each argon2id verification allocates 64 MiB, so
an unbounded burst of logins can OOM a small box. Bound the number of verifications
running at once with a semaphore (8 in flight is fine); when the cap is reached,
register and login get a 429 rather than queueing. A test fires concurrent logins
past the cap and asserts the excess are rejected.

The e2e test is the important part. Write it as a Go test against the real stack
(in-process server, temp data dir):
1. Register device A and device B.
2. A uploads a file (init, parts, complete, then the sync change op). B pulls via
   `/sync`, downloads the content, and verifies the hash.
3. B edits the file (new upload, `put_file` with the revision B saw). A, now stale,
   pushes its own `put_file` for the same file.
4. Both pull. Both must see the original, the winner, and the conflict copy with the
   expected name.

Then the packaging:
- `README.md`: what this is, quickstart with `make run` and docker compose, the env
  config table, and the backup story (copy `DATA_DIR`, that is all).
- `docker-compose.yml`: the service, a named volume on `/data`, env vars.
- `docs/openapi.yaml`: hand-written, and it must match what the code actually does.

Done when `go test ./...` is green including the e2e, `docker compose up` boots and
passes `/healthz`, and `openapi.yaml` covers every route.
