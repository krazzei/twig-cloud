package database

import (
	"errors"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// IsUniqueViolation reports whether err is a SQLite UNIQUE (or PRIMARY KEY)
// constraint failure, so callers can map it to a domain error such as
// "email already registered" without matching on error strings.
func IsUniqueViolation(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	return se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE ||
		se.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
}
