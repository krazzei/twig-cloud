// Package migrations embeds the SQL schema migrations applied by
// internal/database at startup.
//
// Files are named NNN_name.sql and applied in numeric order. The embed lives
// here (not in internal/database) because go:embed cannot reach parent
// directories.
package migrations

import "embed"

// FS holds every *.sql file in this directory.
//
//go:embed *.sql
var FS embed.FS
