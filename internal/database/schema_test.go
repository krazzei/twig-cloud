package database

import (
	"context"
	"testing"
)

// Schema-level invariants from 001_init.sql that later tasks rely on.

func TestSchemaLiveNameUniqueness(t *testing.T) {
	ctx := context.Background()
	db := migratedTestDB(t)

	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	insertEntry := func(id string, parent any, name string) error {
		_, err := db.ExecContext(ctx, `
			INSERT INTO entries (id, user_id, parent_id, name, type, created_at, updated_at)
			VALUES (?, 'u1', ?, ?, 'folder', 0, 0)`, id, parent, name)
		return err
	}

	mustExec(`INSERT INTO users (id, email, password_hash, created_at) VALUES ('u1', 'a@b.c', 'h', 0)`)
	mustExec(`INSERT INTO users (id, email, password_hash, created_at) VALUES ('u2', 'b@b.c', 'h', 0)`)

	// Root level (parent_id NULL): duplicates must be rejected even though
	// SQLite treats NULLs as distinct in plain unique indexes.
	if err := insertEntry("root-a", nil, "Docs"); err != nil {
		t.Fatalf("insert root-a: %v", err)
	}
	if err := insertEntry("root-b", nil, "Docs"); err == nil {
		t.Fatal("duplicate live name at root accepted")
	}

	// Inside a folder.
	if err := insertEntry("child-a", "root-a", "x"); err != nil {
		t.Fatalf("insert child-a: %v", err)
	}
	if err := insertEntry("child-b", "root-a", "x"); err == nil {
		t.Fatal("duplicate live name in folder accepted")
	}

	// Same name under a different parent is fine.
	if err := insertEntry("root-c", nil, "Other"); err != nil {
		t.Fatalf("insert root-c: %v", err)
	}
	if err := insertEntry("child-c", "root-c", "x"); err != nil {
		t.Fatalf("same name under different parent rejected: %v", err)
	}

	// Same name for a different user is fine.
	mustExec(`INSERT INTO entries (id, user_id, parent_id, name, type, created_at, updated_at)
		VALUES ('u2-root', 'u2', NULL, 'Docs', 'folder', 0, 0)`)

	// Soft-deleting frees the name; any number of deleted rows may share it.
	mustExec(`UPDATE entries SET deleted_at = 1 WHERE id = 'child-a'`)
	if err := insertEntry("child-b", "root-a", "x"); err != nil {
		t.Fatalf("name not freed by soft delete: %v", err)
	}
	mustExec(`UPDATE entries SET deleted_at = 2 WHERE id = 'child-b'`)
	if err := insertEntry("child-d", "root-a", "x"); err != nil {
		t.Fatalf("second reuse after soft delete rejected: %v", err)
	}
}

func TestSchemaConstraints(t *testing.T) {
	ctx := context.Background()
	db := migratedTestDB(t)

	if _, err := db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, created_at) VALUES ('u1', 'a@b.c', 'h', 0)`); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	bad := map[string]string{
		"unknown user (foreign key)": `INSERT INTO entries (id, user_id, name, type, created_at, updated_at)
			VALUES ('e1', 'nobody', 'n', 'folder', 0, 0)`,
		"unknown parent (foreign key)": `INSERT INTO entries (id, user_id, parent_id, name, type, created_at, updated_at)
			VALUES ('e1', 'u1', 'ghost', 'n', 'folder', 0, 0)`,
		"unknown file hash (foreign key)": `INSERT INTO entries (id, user_id, name, type, file_hash, created_at, updated_at)
			VALUES ('e1', 'u1', 'n', 'file', 'deadbeef', 0, 0)`,
		"bad entry type": `INSERT INTO entries (id, user_id, name, type, created_at, updated_at)
			VALUES ('e1', 'u1', 'n', 'symlink', 0, 0)`,
		"folder with file_hash": `INSERT INTO entries (id, user_id, name, type, file_hash, created_at, updated_at)
			VALUES ('e1', 'u1', 'n', 'folder', 'deadbeef', 0, 0)`,
		"empty name": `INSERT INTO entries (id, user_id, name, type, created_at, updated_at)
			VALUES ('e1', 'u1', '', 'folder', 0, 0)`,
		"bad sync op": `INSERT INTO sync_log (user_id, entry_id, op, payload, created_at)
			VALUES ('u1', 'e1', 'renamed', '{}', 0)`,
		"invalid json payload": `INSERT INTO sync_log (user_id, entry_id, op, payload, created_at)
			VALUES ('u1', 'e1', 'created', '{not json', 0)`,
		"duplicate email": `INSERT INTO users (id, email, password_hash, created_at)
			VALUES ('u2', 'a@b.c', 'h', 0)`,
	}
	for name, q := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := db.ExecContext(ctx, q); err == nil {
				t.Fatal("constraint violation accepted")
			}
		})
	}
}

func TestSchemaUploadPartsCascade(t *testing.T) {
	ctx := context.Background()
	db := migratedTestDB(t)

	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, created_at) VALUES ('u1', 'a@b.c', 'h', 0)`,
		`INSERT INTO uploads (id, user_id, total_size, part_size, part_count, status, created_at)
			VALUES ('up1', 'u1', 10, 5, 2, 'pending', 0)`,
		`INSERT INTO upload_parts (upload_id, part_number, hash, size, path) VALUES ('up1', 1, 'h1', 5, 'p1')`,
		`INSERT INTO upload_parts (upload_id, part_number, hash, size, path) VALUES ('up1', 2, 'h2', 5, 'p2')`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}

	if _, err := db.ExecContext(ctx,
		`INSERT INTO upload_parts (upload_id, part_number, hash, size, path) VALUES ('up1', 2, 'h3', 5, 'p3')`); err == nil {
		t.Fatal("duplicate (upload_id, part_number) accepted")
	}

	if _, err := db.ExecContext(ctx, `DELETE FROM uploads WHERE id = 'up1'`); err != nil {
		t.Fatalf("delete upload: %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM upload_parts`).Scan(&n); err != nil {
		t.Fatalf("count parts: %v", err)
	}
	if n != 0 {
		t.Fatalf("%d upload_parts left after deleting upload, want 0", n)
	}
}
