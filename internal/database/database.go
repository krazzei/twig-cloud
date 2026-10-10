// Package database owns the SQLite connection pool, schema migrations, and
// transaction helpers.
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// BusyTimeoutMillis is how long a connection waits on a locked database
// before failing with SQLITE_BUSY.
const BusyTimeoutMillis = 5000

// DB wraps *sql.DB. All *sql.DB methods are available directly; Tx adds a
// managed transaction helper.
type DB struct {
	*sql.DB
}

// Open opens (creating if needed) the SQLite database at path in WAL mode
// with a busy timeout and foreign-key enforcement. Pragmas are set in the DSN
// so every pooled connection gets them, not just the first.
//
// Transactions begin with BEGIN IMMEDIATE: the write lock is taken up front,
// so concurrent writers queue on busy_timeout instead of failing with
// SQLITE_BUSY when a deferred read transaction tries to upgrade.
//
// Open does not run migrations; call Migrate.
func Open(ctx context.Context, path string) (*DB, error) {
	dsn, err := buildDSN(path)
	if err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	db := &DB{DB: sqlDB}

	// Force a real connection so a bad path or locked file fails here, then
	// confirm WAL actually took effect (SQLite silently keeps the old mode
	// when it can't switch, e.g. for in-memory databases).
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	if !strings.EqualFold(mode, "wal") {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("open sqlite %s: journal_mode is %q, want wal", path, mode)
	}
	return db, nil
}

func buildDSN(path string) (string, error) {
	if path == "" {
		return "", errors.New("database path must not be empty")
	}
	// The driver splits a non-URI DSN at the first '?', so a '?' in the path
	// would be misread as the start of the parameters.
	if strings.ContainsRune(path, '?') {
		return "", fmt.Errorf("database path %q must not contain '?'", path)
	}
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", BusyTimeoutMillis))
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Set("_txlock", "immediate")
	return path + "?" + q.Encode(), nil
}

// Tx runs fn inside a transaction. It commits if fn returns nil and rolls
// back if fn returns an error or panics (the panic is re-raised after
// rollback). fn must not call Commit or Rollback itself.
func (db *DB) Tx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			// Covers both the error path and a panic unwinding through here.
			// ErrTxDone just means the context already rolled it back.
			_ = tx.Rollback()
		}
	}()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	committed = true
	return nil
}
