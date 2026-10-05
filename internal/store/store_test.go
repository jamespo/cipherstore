package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testDBPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.sqlite")
}

func openStore(t *testing.T, path, password string) *Store {
	t.Helper()
	s, err := Open(path, []byte(password))
	if err != nil {
		t.Fatalf("Open(%q): %v", password, err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openStore(t, testDBPath(t), "hunter2")

	created, err := s.Put(ctx, "github", "ghp_token", "work", true)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !created {
		t.Error("Put on a new token reported created=false")
	}

	got, err := s.Get(ctx, "github")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Secret != "ghp_token" {
		t.Errorf("secret = %q, want %q", got.Secret, "ghp_token")
	}
	if got.Comment != "work" {
		t.Errorf("comment = %q, want %q", got.Comment, "work")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt is zero")
	}
}

func TestGetMissingReturnsErrNotFound(t *testing.T) {
	s := openStore(t, testDBPath(t), "pw")
	if _, err := s.Get(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get(missing) error = %v, want ErrNotFound", err)
	}
}

func TestDeleteMissingReturnsErrNotFound(t *testing.T) {
	s := openStore(t, testDBPath(t), "pw")
	if err := s.Delete(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete(missing) error = %v, want ErrNotFound", err)
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	s := openStore(t, testDBPath(t), "pw")

	if _, err := s.Put(ctx, "tok", "sec", "", true); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, "tok"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "tok"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Delete error = %v, want ErrNotFound", err)
	}
}

// Put must only replace the comment when one was actually supplied, so that
// `cipherstore add tok newsecret` does not silently wipe an existing comment.
func TestPutPreservesCommentWhenNotSet(t *testing.T) {
	ctx := context.Background()
	s := openStore(t, testDBPath(t), "pw")

	if _, err := s.Put(ctx, "tok", "v1", "original", true); err != nil {
		t.Fatalf("Put: %v", err)
	}

	created, err := s.Put(ctx, "tok", "v2", "", false)
	if err != nil {
		t.Fatalf("Put update: %v", err)
	}
	if created {
		t.Error("Put on an existing token reported created=true")
	}

	got, err := s.Get(ctx, "tok")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Secret != "v2" {
		t.Errorf("secret = %q, want %q", got.Secret, "v2")
	}
	if got.Comment != "original" {
		t.Errorf("comment = %q, want it preserved as %q", got.Comment, "original")
	}
}

func TestPutReplacesCommentWhenSet(t *testing.T) {
	ctx := context.Background()
	s := openStore(t, testDBPath(t), "pw")

	if _, err := s.Put(ctx, "tok", "v1", "original", true); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := s.Put(ctx, "tok", "v2", "replaced", true); err != nil {
		t.Fatalf("Put update: %v", err)
	}

	got, err := s.Get(ctx, "tok")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Comment != "replaced" {
		t.Errorf("comment = %q, want %q", got.Comment, "replaced")
	}
}

func TestListIsOrderedAndOmitsSecrets(t *testing.T) {
	ctx := context.Background()
	s := openStore(t, testDBPath(t), "pw")

	for _, tok := range []string{"zebra", "alpha", "middle"} {
		if _, err := s.Put(ctx, tok, "secret-"+tok, "c-"+tok, true); err != nil {
			t.Fatalf("Put %q: %v", tok, err)
		}
	}

	entries, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"alpha", "middle", "zebra"}
	if len(entries) != len(want) {
		t.Fatalf("List returned %d entries, want %d", len(entries), len(want))
	}
	for i, e := range entries {
		if e.TokenID != want[i] {
			t.Errorf("entry %d = %q, want %q", i, e.TokenID, want[i])
		}
		if e.Secret != "" {
			t.Errorf("entry %d leaked a secret: %q", i, e.Secret)
		}
	}
}

// Reopening is the regression test for the keying bug: applying PRAGMA key too
// late let writes succeed but made the database unopenable afterwards.
func TestReopenWithSamePassword(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)

	s1, err := Open(path, []byte("hunter2"))
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if _, err := s1.Put(ctx, "tok", "sec", "c", true); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := Open(path, []byte("hunter2"))
	if err != nil {
		t.Fatalf("reopen with correct password: %v", err)
	}
	defer s2.Close()

	got, err := s2.Get(ctx, "tok")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got.Secret != "sec" {
		t.Errorf("secret = %q, want %q", got.Secret, "sec")
	}
}

func TestWrongPasswordRejected(t *testing.T) {
	path := testDBPath(t)

	s, err := Open(path, []byte("right"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.Put(context.Background(), "tok", "sec", "", true); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s.Close()

	if _, err := Open(path, []byte("wrong")); !errors.Is(err, ErrBadPassword) {
		t.Errorf("Open with wrong password error = %v, want ErrBadPassword", err)
	}
}

// A failed unlock attempt must not damage the database.
func TestWrongPasswordDoesNotPoisonDatabase(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)

	s, err := Open(path, []byte("right"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.Put(ctx, "tok", "sec", "", true); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s.Close()

	for range 3 {
		if _, err := Open(path, []byte("wrong")); err == nil {
			t.Fatal("Open with wrong password unexpectedly succeeded")
		}
	}

	s2, err := Open(path, []byte("right"))
	if err != nil {
		t.Fatalf("Open with correct password after failed attempts: %v", err)
	}
	defer s2.Close()
	if _, err := s2.Get(ctx, "tok"); err != nil {
		t.Errorf("Get after failed attempts: %v", err)
	}
}

// The passphrase reaches SQLCipher inside a double-quoted SQL token, so values
// containing quotes, percent signs and ampersands must survive both the URL
// encoding and the SQL escaping intact -- and must not be able to inject SQL.
func TestHostilePasswords(t *testing.T) {
	passwords := []string{
		`quo"te`,
		`sin'gle`,
		`""`,
		`a"); DROP TABLE secrets;--`,
		`PRAGMA key = "other"`,
		`per%cent`,
		`%22`,
		`amp&ersand`,
		`eq=uals`,
		`que?stion`,
		`pl+us`,
		`sp ace`,
		`ha#sh`,
		`back\slash`,
		`semi;colon`,
		"uni¢ode→🔑",
		"tab\there",
		"new\nline",
	}

	for _, pw := range passwords {
		t.Run(pw, func(t *testing.T) {
			ctx := context.Background()
			path := testDBPath(t)

			s, err := Open(path, []byte(pw))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if _, err := s.Put(ctx, "tok", "sec", "", true); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			// The same passphrase must reopen it: proof the key was not
			// mangled by escaping.
			s2, err := Open(path, []byte(pw))
			if err != nil {
				t.Fatalf("reopen with same password: %v", err)
			}
			got, err := s2.Get(ctx, "tok")
			if err != nil {
				t.Fatalf("Get after reopen: %v", err)
			}
			if got.Secret != "sec" {
				t.Errorf("secret = %q, want %q", got.Secret, "sec")
			}
			s2.Close()

			// A different passphrase must not: proof the escaping did not
			// collapse distinct passwords onto the same key.
			if _, err := Open(path, []byte(pw+"X")); !errors.Is(err, ErrBadPassword) {
				t.Errorf("Open with %q error = %v, want ErrBadPassword", pw+"X", err)
			}
		})
	}
}

// Token IDs, secrets and comments are bound as query parameters, so arbitrary
// bytes must round-trip without affecting the schema.
func TestHostileValues(t *testing.T) {
	ctx := context.Background()
	s := openStore(t, testDBPath(t), "pw")

	values := []string{
		`sin'gle`,
		`quo"te`,
		`'; DROP TABLE secrets; --`,
		"new\nline",
		"tab\there",
		"uni¢ode→🔑",
		`%s%d%n`,
		`$(whoami)`,
		"",
		strings.Repeat("A", 100_000),
	}

	for i, v := range values {
		tok := "tok" + string(rune('a'+i))
		if _, err := s.Put(ctx, tok, v, v, true); err != nil {
			t.Fatalf("Put %q: %v", tok, err)
		}
		got, err := s.Get(ctx, tok)
		if err != nil {
			t.Fatalf("Get %q: %v", tok, err)
		}
		if got.Secret != v {
			t.Errorf("secret for %q did not round-trip", tok)
		}
		if got.Comment != v {
			t.Errorf("comment for %q did not round-trip", tok)
		}
	}

	// The table must still be intact after all of that.
	entries, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != len(values) {
		t.Errorf("List returned %d entries, want %d", len(entries), len(values))
	}
}

func TestEmptyPasswordRejected(t *testing.T) {
	if _, err := Open(testDBPath(t), nil); err == nil {
		t.Error("Open with empty password succeeded, want error")
	}
}

func TestNULPasswordRejected(t *testing.T) {
	// A NUL would truncate the C string and silently key the database with a
	// prefix of the passphrase.
	if _, err := Open(testDBPath(t), []byte("ab\x00cd")); err == nil {
		t.Error("Open with NUL in password succeeded, want error")
	}
}

func TestDatabaseFileIsNotWorldReadable(t *testing.T) {
	path := testDBPath(t)
	s := openStore(t, path, "pw")
	if _, err := s.Put(context.Background(), "tok", "sec", "", true); err != nil {
		t.Fatalf("Put: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("database mode = %#o, want no group or world bits", perm)
	}
}

// A database loosened by a stray chmod should be repaired on open rather than
// refused, so the store stays usable.
func TestOpenTightensLoosePermissions(t *testing.T) {
	path := testDBPath(t)
	s := openStore(t, path, "pw")
	if _, err := s.Put(context.Background(), "tok", "sec", "", true); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s.Close()

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	s2, err := Open(path, []byte("pw"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s2.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != DBFileMode {
		t.Errorf("database mode = %#o, want %#o", perm, DBFileMode)
	}
}

func TestOpenRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.sqlite")
	link := filepath.Join(dir, "link.sqlite")

	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := Open(link, []byte("pw"))
	if err == nil {
		t.Fatal("Open on a symlink succeeded, want error")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error = %v, want it to mention a symlink", err)
	}
}

// Nothing recognisable from the plaintext may appear in the file on disk.
func TestDatabaseIsEncryptedOnDisk(t *testing.T) {
	path := testDBPath(t)
	s := openStore(t, path, "pw")
	if _, err := s.Put(context.Background(), "mytokenid", "mysupersecret", "mycomment", true); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	for _, plaintext := range []string{"mytokenid", "mysupersecret", "mycomment", "SQLite format 3"} {
		if strings.Contains(string(raw), plaintext) {
			t.Errorf("database file contains plaintext %q", plaintext)
		}
	}
}

func TestEscapeKey(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{`plain`, `plain`},
		{`quo"te`, `quo""te`},
		{`""`, `""""`},
		{`sin'gle`, `sin'gle`},
		{``, ``},
	}
	for _, tt := range tests {
		if got := escapeKey([]byte(tt.in)); got != tt.want {
			t.Errorf("escapeKey(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// The passphrase must be URL-encoded in the DSN, since the driver parses the
// query string before interpolating the key.
func TestBuildDSNEncodesKey(t *testing.T) {
	dsn := buildDSN("/tmp/x.sqlite", []byte(`a&b=c"d`))
	if strings.Contains(dsn, `a&b=c`) {
		t.Errorf("DSN %q contains the raw passphrase; it must be URL-encoded", dsn)
	}
	if !strings.Contains(dsn, "_pragma_key=") {
		t.Errorf("DSN %q is missing _pragma_key", dsn)
	}
}
