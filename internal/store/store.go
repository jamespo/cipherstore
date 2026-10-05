// Package store is the SQLCipher-backed persistence layer.
//
// The passphrase is applied with `PRAGMA key` on a connect hook rather than
// through the DSN, so it never becomes part of a connection string that could
// surface in a driver error message. The pool is pinned to a single connection
// so exactly one keyed handle exists at a time and Close reliably tears it
// down.
package store

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	sqlite3 "github.com/mutecomm/go-sqlcipher/v4"

	"github.com/jamespo/cipherstore/internal/paths"
)

// ErrNotFound is returned when a token ID is not present in the store.
var ErrNotFound = errors.New("token not found")

// ErrBadPassword is returned when the passphrase does not decrypt the database.
var ErrBadPassword = errors.New("incorrect password or corrupt database")

// DBFileMode is the permission set applied to the database file. Only the
// owner may read or write it.
const DBFileMode = 0o600

// noFollow refuses to open a symlink, so a planted link cannot redirect the
// database file we create.
const noFollow = syscall.O_NOFOLLOW

// Store is an open, decrypted handle on the credential database.
type Store struct {
	db   *sql.DB
	path string
}

// Entry is a stored credential. Secret is empty in listings.
type Entry struct {
	TokenID   string
	Secret    string
	Comment   string
	UpdatedAt time.Time
}

const schema = `
CREATE TABLE IF NOT EXISTS secrets (
	token_id   TEXT    PRIMARY KEY NOT NULL,
	secret     TEXT    NOT NULL,
	comment    TEXT    NOT NULL DEFAULT '',
	updated_at INTEGER NOT NULL
) WITHOUT ROWID;
`

// Open decrypts the database at path with password, creating it if absent.
//
// The caller is responsible for the parent directory's permissions; see
// paths.EnsureDataDir.
func Open(path string, password []byte) (*Store, error) {
	if len(password) == 0 {
		return nil, errors.New("password must not be empty")
	}
	// The key is passed to SQLCipher inside a SQL string literal, which is a C
	// string: an embedded NUL would silently truncate the passphrase and key
	// the database with a prefix of what the user typed.
	if bytes.IndexByte(password, 0) >= 0 {
		return nil, errors.New("password must not contain NUL bytes")
	}
	if err := ensureDBFile(path); err != nil {
		return nil, err
	}

	db := sql.OpenDB(&connector{dsn: buildDSN(path, password)})
	// SQLCipher keys are per-connection. Pinning the pool to one connection
	// means the key is applied once, and that no unkeyed connection can be
	// opened behind our back after a lock.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)

	ctx := context.Background()

	// Reading sqlite_master is the standard SQLCipher key check: with the
	// wrong key the page cannot be decrypted and SQLite reports the file as
	// "not a database".
	if _, err := db.ExecContext(ctx, "SELECT count(*) FROM sqlite_master"); err != nil {
		db.Close()
		if isNotADatabase(err) {
			return nil, ErrBadPassword
		}
		return nil, fmt.Errorf("open database: %w", err)
	}

	for _, pragma := range sessionPragmas {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("apply %s: %w", pragma, err)
		}
	}

	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialise schema: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

// Close releases the database handle and the in-memory key material held by
// the SQLCipher connection.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// Get returns the secret for tokenID, or ErrNotFound.
func (s *Store) Get(ctx context.Context, tokenID string) (Entry, error) {
	var (
		e     Entry
		unix_ int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT token_id, secret, comment, updated_at FROM secrets WHERE token_id = ?`,
		tokenID,
	).Scan(&e.TokenID, &e.Secret, &e.Comment, &unix_)
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, ErrNotFound
	}
	if err != nil {
		return Entry{}, fmt.Errorf("get %q: %w", tokenID, err)
	}
	e.UpdatedAt = time.Unix(unix_, 0)
	return e, nil
}

// Put inserts or updates tokenID's secret. When setComment is false and the
// token already exists, its existing comment is preserved. It reports whether
// a new row was created.
func (s *Store) Put(ctx context.Context, tokenID, secret, comment string, setComment bool) (created bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	var existingComment string
	err = tx.QueryRowContext(ctx, `SELECT comment FROM secrets WHERE token_id = ?`, tokenID).Scan(&existingComment)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		created = true
	case err != nil:
		return false, fmt.Errorf("check %q: %w", tokenID, err)
	}

	if !setComment && !created {
		comment = existingComment
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO secrets (token_id, secret, comment, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(token_id) DO UPDATE SET secret = excluded.secret, comment = excluded.comment, updated_at = excluded.updated_at`,
		tokenID, secret, comment, time.Now().Unix(),
	)
	if err != nil {
		return false, fmt.Errorf("store %q: %w", tokenID, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return created, nil
}

// Delete removes tokenID, or returns ErrNotFound if it was not present.
func (s *Store) Delete(ctx context.Context, tokenID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE token_id = ?`, tokenID)
	if err != nil {
		return fmt.Errorf("delete %q: %w", tokenID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete %q: %w", tokenID, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// List returns every entry ordered by token ID, without secrets.
func (s *Store) List(ctx context.Context) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT token_id, comment, updated_at FROM secrets ORDER BY token_id`)
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var (
			e     Entry
			unix_ int64
		)
		if err := rows.Scan(&e.TokenID, &e.Comment, &unix_); err != nil {
			return nil, fmt.Errorf("list: %w", err)
		}
		e.UpdatedAt = time.Unix(unix_, 0)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	return out, nil
}

// connector opens keyed connections to the database.
type connector struct {
	dsn string
}

func (c *connector) Connect(context.Context) (driver.Conn, error) {
	return (&sqlite3.SQLiteDriver{}).Open(c.dsn)
}

func (c *connector) Driver() driver.Driver { return &sqlite3.SQLiteDriver{} }

// buildDSN assembles the connection string, including the SQLCipher key.
//
// The key has to go through the DSN rather than a ConnectHook: the driver
// execs `PRAGMA key` immediately after sqlite3_open_v2, whereas a hook runs at
// the very end of Open, by which point the driver's own user-authentication
// probe has already read the database header unkeyed. Keying that late appears
// to work -- writes succeed -- but the database cannot be reopened.
func buildDSN(path string, password []byte) string {
	// _busy_timeout keeps concurrent client requests from failing outright
	// while the single pooled connection is mid-transaction.
	return path + "?_busy_timeout=5000&_pragma_key=" + url.QueryEscape(escapeKey(password))
}

// escapeKey prepares a passphrase for the driver, which URL-decodes the
// _pragma_key value and interpolates it into `PRAGMA key = "%s"`.
//
// Doubling embedded double quotes is the complete escape for SQLite's
// double-quoted token grammar, so the decoded value cannot terminate the
// literal early or inject further SQL. Open rejects NUL bytes separately,
// since those would truncate the C string instead.
//
// The resulting key is the passphrase itself, so the database stays openable
// with the stock `sqlcipher` CLI via `PRAGMA key = '<passphrase>'`.
func escapeKey(password []byte) string {
	return strings.ReplaceAll(string(password), `"`, `""`)
}

// sessionPragmas are applied after the connection is keyed. They are ordinary
// settings, so unlike the key they are safe to run as normal statements.
var sessionPragmas = []string{
	// Temporary B-trees for ORDER BY and friends would otherwise be written to
	// a plaintext file under /tmp.
	"PRAGMA temp_store = MEMORY",
	"PRAGMA foreign_keys = ON",
}

// ensureDBFile creates the database file with restrictive permissions before
// SQLCipher can create it with the process umask, and validates an existing
// file is a regular file we own.
func ensureDBFile(path string) error {
	fi, err := paths.CheckOwnedNonSymlink(path)
	if err == nil {
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file; refusing to use it", path)
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			// Tighten rather than refuse: a database loosened by a umask or a
			// stray chmod should be repaired, not made unusable.
			if err := os.Chmod(path, DBFileMode); err != nil {
				return fmt.Errorf("chmod %s: %w", path, err)
			}
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// O_EXCL|O_NOFOLLOW: create the file ourselves, never following a symlink
	// an attacker may have planted, so the 0600 mode is applied atomically at
	// creation instead of after SQLCipher has already written a page.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|noFollow, DBFileMode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	return f.Close()
}

// isNotADatabase reports whether err is SQLite's signal that a page could not
// be decrypted, which for an encrypted database means a wrong passphrase.
func isNotADatabase(err error) bool {
	var serr sqlite3.Error
	if errors.As(err, &serr) {
		return serr.Code == sqlite3.ErrNotADB
	}
	return strings.Contains(err.Error(), "file is not a database")
}
