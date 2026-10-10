package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

func openTestDB(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "twig.db")
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

func migratedTestDB(t *testing.T) *DB {
	t.Helper()
	db, _ := openTestDB(t)
	if _, err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

func TestMigrateTwice(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)

	applied, err := db.Migrate(ctx)
	if err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	if !slices.Equal(applied, []string{"001_init.sql"}) {
		t.Fatalf("first Migrate applied %v, want [001_init.sql]", applied)
	}

	applied, err = db.Migrate(ctx)
	if err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("second Migrate applied %v, want nothing", applied)
	}

	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if n != 1 {
		t.Fatalf("schema_migrations has %d rows, want 1", n)
	}

	for _, table := range []string{
		"users", "access_tokens", "refresh_tokens", "files", "entries",
		"revisions", "sync_log", "uploads", "upload_parts",
	} {
		var got string
		err := db.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&got)
		if err != nil {
			t.Errorf("table %s missing: %v", table, err)
		}
	}
}

func TestMigrateSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "twig.db")

	for i := range 2 {
		db, err := Open(ctx, path)
		if err != nil {
			t.Fatalf("Open #%d: %v", i, err)
		}
		applied, err := db.Migrate(ctx)
		if err != nil {
			t.Fatalf("Migrate #%d: %v", i, err)
		}
		if i == 1 && len(applied) != 0 {
			t.Fatalf("Migrate after reopen applied %v, want nothing", applied)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i, err)
		}
	}
}

func TestJournalModeIsWALOnFile(t *testing.T) {
	ctx := context.Background()
	db, path := openTestDB(t)
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen with a bare DSN (no pragmas). WAL is persisted in the database
	// file header, so it must still report wal.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer raw.Close()

	var mode string
	if err := raw.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}
}

func TestPragmasOnEveryPooledConnection(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)

	// Hold several connections at once so the pool must open distinct ones.
	const n = 3
	conns := make([]*sql.Conn, 0, n)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for range n {
		c, err := db.Conn(ctx)
		if err != nil {
			t.Fatalf("Conn: %v", err)
		}
		conns = append(conns, c)
	}

	for i, c := range conns {
		var busy, fk int
		var mode string
		if err := c.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busy); err != nil {
			t.Fatalf("conn %d busy_timeout: %v", i, err)
		}
		if err := c.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil {
			t.Fatalf("conn %d foreign_keys: %v", i, err)
		}
		if err := c.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil {
			t.Fatalf("conn %d journal_mode: %v", i, err)
		}
		if busy != BusyTimeoutMillis {
			t.Errorf("conn %d busy_timeout = %d, want %d", i, busy, BusyTimeoutMillis)
		}
		if fk != 1 {
			t.Errorf("conn %d foreign_keys = %d, want 1", i, fk)
		}
		if mode != "wal" {
			t.Errorf("conn %d journal_mode = %q, want wal", i, mode)
		}
	}
}

func TestOpenRejectsBadPaths(t *testing.T) {
	ctx := context.Background()
	for _, p := range []string{"", filepath.Join(t.TempDir(), "a?b.db")} {
		if db, err := Open(ctx, p); err == nil {
			_ = db.Close()
			t.Errorf("Open(%q) succeeded, want error", p)
		}
	}
}

func TestMigrateNumericOrder(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)

	// Lexically "10_..." sorts before "2_...", which would fail here because
	// 10 depends on the table 2 creates.
	fsys := fstest.MapFS{
		"001_a.sql": {Data: []byte(`CREATE TABLE a (x INTEGER);`)},
		"10_c.sql":  {Data: []byte(`INSERT INTO b (x) VALUES (10);`)},
		"2_b.sql":   {Data: []byte(`CREATE TABLE b (x INTEGER); INSERT INTO b (x) VALUES (2);`)},
	}
	applied, err := db.migrate(ctx, fsys)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	want := []string{"001_a.sql", "2_b.sql", "10_c.sql"}
	if !slices.Equal(applied, want) {
		t.Fatalf("applied %v, want %v", applied, want)
	}

	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM b`).Scan(&count); err != nil {
		t.Fatalf("count b: %v", err)
	}
	if count != 2 {
		t.Fatalf("b has %d rows, want 2 (multi-statement file not fully applied?)", count)
	}
}

func TestMigrateFailureRollsBackEverything(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)

	bad := fstest.MapFS{
		"001_a.sql": {Data: []byte(`CREATE TABLE a (x INTEGER);`)},
		"002_b.sql": {Data: []byte(`CREATE TABLE b (x INTEGER); THIS IS NOT SQL;`)},
	}
	_, err := db.migrate(ctx, bad)
	if err == nil {
		t.Fatal("migrate with broken file succeeded, want error")
	}
	if !strings.Contains(err.Error(), "002_b.sql") {
		t.Errorf("error %q does not name the failing file", err)
	}

	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('a', 'b', 'schema_migrations')`).Scan(&n); err != nil {
		t.Fatalf("inspect sqlite_master: %v", err)
	}
	if n != 0 {
		t.Fatalf("%d objects survived a failed migration, want 0", n)
	}

	good := fstest.MapFS{
		"001_a.sql": bad["001_a.sql"],
		"002_b.sql": {Data: []byte(`CREATE TABLE b (x INTEGER);`)},
	}
	applied, err := db.migrate(ctx, good)
	if err != nil {
		t.Fatalf("migrate after fix: %v", err)
	}
	if len(applied) != 2 {
		t.Fatalf("applied %v after fix, want both files", applied)
	}
}

func TestMigrateAppliesOnlyNewFiles(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)

	v1 := fstest.MapFS{"001_a.sql": {Data: []byte(`CREATE TABLE a (x INTEGER);`)}}
	if _, err := db.migrate(ctx, v1); err != nil {
		t.Fatalf("migrate v1: %v", err)
	}

	v2 := fstest.MapFS{
		"001_a.sql": v1["001_a.sql"],
		"002_b.sql": {Data: []byte(`CREATE TABLE b (x INTEGER);`)},
	}
	applied, err := db.migrate(ctx, v2)
	if err != nil {
		t.Fatalf("migrate v2: %v", err)
	}
	if !slices.Equal(applied, []string{"002_b.sql"}) {
		t.Fatalf("applied %v, want [002_b.sql]", applied)
	}
}

func TestMigrateRejectsUnknownAppliedVersion(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)

	newer := fstest.MapFS{
		"001_a.sql": {Data: []byte(`CREATE TABLE a (x INTEGER);`)},
		"002_b.sql": {Data: []byte(`CREATE TABLE b (x INTEGER);`)},
	}
	if _, err := db.migrate(ctx, newer); err != nil {
		t.Fatalf("migrate newer: %v", err)
	}

	older := fstest.MapFS{"001_a.sql": newer["001_a.sql"]}
	if _, err := db.migrate(ctx, older); err == nil {
		t.Fatal("older build migrated a newer database without error")
	}
}

func TestLoadMigrationsValidation(t *testing.T) {
	cases := map[string]fstest.MapFS{
		"no number":         {"init.sql": {}},
		"no name":           {"001.sql": {}},
		"zero version":      {"000_zero.sql": {}},
		"duplicate version": {"1_a.sql": {}, "001_b.sql": {}},
	}
	for name, fsys := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadMigrations(fsys); err == nil {
				t.Fatal("loadMigrations succeeded, want error")
			}
		})
	}

	// Non-.sql files are ignored.
	ms, err := loadMigrations(fstest.MapFS{"README.md": {}, "001_a.sql": {}})
	if err != nil || len(ms) != 1 {
		t.Fatalf("loadMigrations = %v, %v; want one migration", ms, err)
	}
}

func TestTxCommits(t *testing.T) {
	ctx := context.Background()
	db := migratedTestDB(t)

	err := db.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO users (id, email, password_hash, created_at) VALUES ('u1', 'a@b.c', 'h', 0)`)
		return err
	})
	if err != nil {
		t.Fatalf("Tx: %v", err)
	}
	if n := countUsers(t, db); n != 1 {
		t.Fatalf("users = %d after commit, want 1", n)
	}
}

func TestTxRollsBackOnError(t *testing.T) {
	ctx := context.Background()
	db := migratedTestDB(t)
	sentinel := errors.New("boom")

	err := db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO users (id, email, password_hash, created_at) VALUES ('u1', 'a@b.c', 'h', 0)`); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Tx error = %v, want sentinel", err)
	}
	if n := countUsers(t, db); n != 0 {
		t.Fatalf("users = %d after rollback, want 0", n)
	}
}

func TestTxRollsBackOnPanic(t *testing.T) {
	ctx := context.Background()
	db := migratedTestDB(t)

	func() {
		defer func() {
			if r := recover(); r != "kaboom" {
				t.Fatalf("recovered %v, want re-raised panic", r)
			}
		}()
		_ = db.Tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO users (id, email, password_hash, created_at) VALUES ('u1', 'a@b.c', 'h', 0)`); err != nil {
				t.Fatalf("insert: %v", err)
			}
			panic("kaboom")
		})
	}()

	if n := countUsers(t, db); n != 0 {
		t.Fatalf("users = %d after panic, want 0", n)
	}
	// The connection must be back in the pool and usable for writes.
	if err := db.Tx(ctx, func(*sql.Tx) error { return nil }); err != nil {
		t.Fatalf("Tx after panic: %v", err)
	}
}

func countUsers(t *testing.T, db *DB) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n
}
