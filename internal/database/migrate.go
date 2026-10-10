package database

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/twig/twig-cloud/migrations"
)

// migrationFile matches NNN_name.sql. The numeric prefix is the version.
var migrationFile = regexp.MustCompile(`^(\d+)_[A-Za-z0-9_\-]+\.sql$`)

type migration struct {
	version int
	name    string // file name, e.g. "001_init.sql"
	sql     string
}

// Migrate applies every embedded migration that has not been applied yet and
// returns the file names it applied (empty when the schema is current). It is
// safe to call on every startup.
func (db *DB) Migrate(ctx context.Context) ([]string, error) {
	return db.migrate(ctx, migrations.FS)
}

// migrate applies pending migrations from fsys in ascending numeric order,
// all inside a single transaction: either every pending file applies and is
// recorded in schema_migrations, or nothing changes.
//
// Because the transaction is BEGIN IMMEDIATE, two processes migrating the
// same file serialize; the second sees the first one's work and no-ops.
//
// Migration files must not contain statements SQLite refuses inside a
// transaction (VACUUM, PRAGMA foreign_keys, ...).
func (db *DB) migrate(ctx context.Context, fsys fs.FS) ([]string, error) {
	all, err := loadMigrations(fsys)
	if err != nil {
		return nil, err
	}

	var applied []string
	err = db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			CREATE TABLE IF NOT EXISTS schema_migrations (
				version    INTEGER PRIMARY KEY,
				name       TEXT    NOT NULL,
				applied_at INTEGER NOT NULL
			)`); err != nil {
			return fmt.Errorf("create schema_migrations: %w", err)
		}

		done, err := appliedVersions(ctx, tx)
		if err != nil {
			return err
		}

		// Refuse to run against a schema newer than this binary knows about,
		// e.g. after rolling back to an older build.
		known := make(map[int]bool, len(all))
		for _, m := range all {
			known[m.version] = true
		}
		for v, name := range done {
			if !known[v] {
				return fmt.Errorf("database has migration %d (%s) applied that this build does not know about", v, name)
			}
		}

		now := time.Now().Unix()
		for _, m := range all {
			if _, ok := done[m.version]; ok {
				continue
			}
			if _, err := tx.ExecContext(ctx, m.sql); err != nil {
				return fmt.Errorf("apply migration %s: %w", m.name, err)
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
				m.version, m.name, now); err != nil {
				return fmt.Errorf("record migration %s: %w", m.name, err)
			}
			applied = append(applied, m.name)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return applied, nil
}

func appliedVersions(ctx context.Context, tx *sql.Tx) (map[int]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT version, name FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()

	done := make(map[int]string)
	for rows.Next() {
		var (
			v    int
			name string
		)
		if err := rows.Scan(&v, &name); err != nil {
			return nil, fmt.Errorf("read schema_migrations: %w", err)
		}
		done[v] = name
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	return done, nil
}

// loadMigrations reads every *.sql file at the root of fsys, validates the
// names, and returns them sorted by numeric version (so 010 runs after 002
// regardless of zero-padding).
func loadMigrations(fsys fs.FS) ([]migration, error) {
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}

	var out []migration
	seen := make(map[int]string)
	for _, name := range names {
		m := migrationFile.FindStringSubmatch(path.Base(name))
		if m == nil {
			return nil, fmt.Errorf("migration %q: name must match NNN_name.sql", name)
		}
		v, err := strconv.Atoi(m[1])
		if err != nil || v < 1 {
			return nil, fmt.Errorf("migration %q: version must be a positive integer", name)
		}
		if prev, dup := seen[v]; dup {
			return nil, fmt.Errorf("migrations %q and %q share version %d", prev, name, v)
		}
		seen[v] = name

		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", name, err)
		}
		out = append(out, migration{version: v, name: name, sql: string(body)})
	}

	slices.SortFunc(out, func(a, b migration) int { return a.version - b.version })
	return out, nil
}
