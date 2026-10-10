-- 001_init.sql: full v1 schema (see plan.md "Data model").
--
-- Conventions:
--   * IDs are TEXT (UUIDs, or hex-encoded hashes for content/tokens).
--   * Timestamps are INTEGER unix seconds (UTC).
--   * Foreign keys are enforced: the connection DSN sets PRAGMA foreign_keys=ON.

CREATE TABLE users (
    id            TEXT    PRIMARY KEY,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    created_at    INTEGER NOT NULL
);

-- Opaque 256-bit random tokens, stored hashed (SHA-256 hex).
-- 15-min access / 30-day refresh, rotating.
CREATE TABLE access_tokens (
    token_hash  TEXT    PRIMARY KEY,
    user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name TEXT    NOT NULL DEFAULT '',
    expires_at  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE INDEX idx_access_tokens_user ON access_tokens(user_id);

CREATE TABLE refresh_tokens (
    token_hash   TEXT    PRIMARY KEY,
    user_id      TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name  TEXT    NOT NULL DEFAULT '',
    expires_at   INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE INDEX idx_refresh_tokens_user_device ON refresh_tokens(user_id, device_name);

-- CAS metadata: one row per blob in DATA_DIR/blobs, keyed by SHA-256 hex.
CREATE TABLE files (
    hash       TEXT    PRIMARY KEY,
    size       INTEGER NOT NULL CHECK (size >= 0),
    created_at INTEGER NOT NULL
);

-- The tree. id is a client-generated UUID, stable across moves.
-- parent_id NULL = user's root. Soft-deleted rows keep their name but leave
-- the live namespace (see uq_entries_live_name).
CREATE TABLE entries (
    id         TEXT    PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES users(id),
    parent_id  TEXT    REFERENCES entries(id),
    name       TEXT    NOT NULL CHECK (name <> ''),
    type       TEXT    NOT NULL CHECK (type IN ('file', 'folder')),
    file_hash  TEXT    REFERENCES files(hash),
    size       INTEGER NOT NULL DEFAULT 0 CHECK (size >= 0),
    revision   INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER,
    CHECK (type = 'file' OR file_hash IS NULL)
);

-- Live-name uniqueness: (user_id, parent_id, name) among non-deleted rows.
-- SQLite rejects WHERE on a table constraint, so this is a partial index.
-- parent_id is wrapped in IFNULL because SQLite treats NULLs as distinct in
-- unique indexes; without it two live root-level entries could share a name.
-- Entry ids are UUIDs, so '' can never collide with a real parent.
CREATE UNIQUE INDEX uq_entries_live_name
    ON entries(user_id, IFNULL(parent_id, ''), name)
    WHERE deleted_at IS NULL;
CREATE INDEX idx_entries_parent ON entries(parent_id);
CREATE INDEX idx_entries_user ON entries(user_id);
CREATE INDEX idx_entries_file_hash ON entries(file_hash) WHERE file_hash IS NOT NULL;

-- Appended on each content change -> cheap version history.
CREATE TABLE revisions (
    id         INTEGER PRIMARY KEY,
    entry_id   TEXT    NOT NULL REFERENCES entries(id),
    file_hash  TEXT    NOT NULL REFERENCES files(hash),
    size       INTEGER NOT NULL CHECK (size >= 0),
    revision   INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (entry_id, revision)
);
CREATE INDEX idx_revisions_file_hash ON revisions(file_hash);

-- Per-user change feed. payload = full node snapshot (JSON).
-- Pruned to the last 10k rows; older cursors get 410 and must re-bootstrap.
-- AUTOINCREMENT guarantees seq is never reused after pruning.
-- entry_id is deliberately not a foreign key: the log is history.
CREATE TABLE sync_log (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT    NOT NULL REFERENCES users(id),
    entry_id   TEXT    NOT NULL,
    op         TEXT    NOT NULL CHECK (op IN ('created', 'updated', 'moved', 'deleted', 'conflict')),
    payload    TEXT    NOT NULL CHECK (json_valid(payload)),
    created_at INTEGER NOT NULL
);
CREATE INDEX idx_sync_log_user_seq ON sync_log(user_id, seq);

-- Chunked upload sessions. status values are owned by the upload package.
CREATE TABLE uploads (
    id         TEXT    PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES users(id),
    total_size INTEGER NOT NULL CHECK (total_size >= 0),
    part_size  INTEGER NOT NULL CHECK (part_size > 0),
    part_count INTEGER NOT NULL CHECK (part_count >= 0),
    status     TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX idx_uploads_user ON uploads(user_id);

CREATE TABLE upload_parts (
    upload_id   TEXT    NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
    part_number INTEGER NOT NULL CHECK (part_number >= 1),
    hash        TEXT    NOT NULL,
    size        INTEGER NOT NULL CHECK (size >= 0),
    path        TEXT    NOT NULL,
    UNIQUE (upload_id, part_number)
);
