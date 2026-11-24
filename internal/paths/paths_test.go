package paths

import (
	"syscall"

	"github.com/jamespo/cipherstore/internal/access"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultHonoursXDGVariables(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/custom/state")
	t.Setenv("XDG_DATA_HOME", "/custom/data")

	l, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}

	tests := []struct{ name, got, want string }{
		{"StateDir", l.StateDir, "/custom/state/cipherstore"},
		{"ControlSocket", l.ControlSocket, "/custom/state/cipherstore/control"},
		{"AuthedSocket", l.AuthedSocket, "/custom/state/cipherstore/authed"},
		{"LockFile", l.LockFile, "/custom/state/cipherstore/daemon.lock"},
		{"DataDir", l.DataDir, "/custom/data/cipherstore"},
		{"DBPath", l.DBPath, "/custom/data/cipherstore/cipherstore.sqlite"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
		}
	}
}

func TestDefaultFallsBackToHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "/home/testuser")

	l, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if want := "/home/testuser/.local/state/cipherstore/control"; l.ControlSocket != want {
		t.Errorf("ControlSocket = %q, want %q", l.ControlSocket, want)
	}
	if want := "/home/testuser/.local/share/cipherstore/cipherstore.sqlite"; l.DBPath != want {
		t.Errorf("DBPath = %q, want %q", l.DBPath, want)
	}
}

// The XDG spec says a relative value is invalid and must be ignored.
func TestDefaultIgnoresRelativeXDGValues(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "relative/path")
	t.Setenv("HOME", "/home/testuser")

	l, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if !strings.HasPrefix(l.StateDir, "/home/testuser/.local/state") {
		t.Errorf("StateDir = %q, want the HOME fallback", l.StateDir)
	}
}

func TestEnsureDirsCreateWith0700(t *testing.T) {
	root := t.TempDir()
	l := Layout{
		StateDir: filepath.Join(root, "state", "cipherstore"),
		DataDir:  filepath.Join(root, "data", "cipherstore"),
	}

	if err := l.EnsureStateDir(); err != nil {
		t.Fatalf("EnsureStateDir: %v", err)
	}
	if err := l.EnsureDataDir(); err != nil {
		t.Fatalf("EnsureDataDir: %v", err)
	}

	for _, dir := range []string{l.StateDir, l.DataDir} {
		fi, err := os.Lstat(dir)
		if err != nil {
			t.Fatalf("Lstat %s: %v", dir, err)
		}
		if perm := fi.Mode().Perm(); perm != 0o700 {
			t.Errorf("%s mode = %#o, want 0700", dir, perm)
		}
	}
}

// An existing directory left too open by an earlier umask must be tightened,
// since every other protection assumes nobody else can write here.
func TestEnsureStateDirTightensLoosePermissions(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	l := Layout{StateDir: dir}
	if err := l.EnsureStateDir(); err != nil {
		t.Fatalf("EnsureStateDir: %v", err)
	}

	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Errorf("mode = %#o, want 0700", perm)
	}
}

func TestCheckSecureDirRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real")
	link := filepath.Join(root, "link")

	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	err := CheckSecureDir(link)
	if err == nil {
		t.Fatal("CheckSecureDir accepted a symlink, want it refused")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error = %v, want it to mention a symlink", err)
	}
}

func TestCheckSecureDirRejectsLoosePermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o750, 0o705, 0o777, 0o770} {
		dir := filepath.Join(t.TempDir(), "d")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		if err := CheckSecureDir(dir); err == nil {
			t.Errorf("CheckSecureDir accepted mode %#o, want it refused", mode)
		}
	}
}

func TestCheckSecureDirRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := CheckSecureDir(path); err == nil {
		t.Error("CheckSecureDir accepted a regular file, want it refused")
	}
}

func TestCheckOwnedNonSymlinkRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real")
	link := filepath.Join(root, "link")

	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	if _, err := CheckOwnedNonSymlink(link); err == nil {
		t.Error("CheckOwnedNonSymlink accepted a symlink, want it refused")
	}
}

// store.ensureDBFile distinguishes "absent" from "unsafe" via os.ErrNotExist,
// so a missing path must report exactly that.
func TestCheckOwnedNonSymlinkReportsNotExist(t *testing.T) {
	_, err := CheckOwnedNonSymlink(filepath.Join(t.TempDir(), "absent"))
	if !os.IsNotExist(err) {
		t.Errorf("error = %v, want it to satisfy os.IsNotExist", err)
	}
}

func TestCheckOwnedNonSymlinkAcceptsOwnedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fi, err := CheckOwnedNonSymlink(path)
	if err != nil {
		t.Fatalf("CheckOwnedNonSymlink: %v", err)
	}
	if !fi.Mode().IsRegular() {
		t.Errorf("mode = %v, want a regular file", fi.Mode())
	}
}

func TestNewUsesExplicitDirectories(t *testing.T) {
	l, err := New("/srv/sockets", "/srv/db")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tests := []struct{ name, got, want string }{
		{"StateDir", l.StateDir, "/srv/sockets"},
		{"ControlSocket", l.ControlSocket, "/srv/sockets/control"},
		{"AuthedSocket", l.AuthedSocket, "/srv/sockets/authed"},
		{"LockFile", l.LockFile, "/srv/sockets/daemon.lock"},
		{"DataDir", l.DataDir, "/srv/db"},
		{"DBPath", l.DBPath, "/srv/db/cipherstore.sqlite"},
		{"DataLockFile", l.DataLockFile, "/srv/db/daemon.lock"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
		}
	}
}

func TestNewMakesRelativePathsAbsolute(t *testing.T) {
	l, err := New("rel/sock", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !filepath.IsAbs(l.StateDir) || !strings.HasSuffix(l.StateDir, "rel/sock") {
		t.Errorf("StateDir = %q, want an absolute path ending in rel/sock", l.StateDir)
	}
}

func dirStat(t *testing.T, dir string) (os.FileMode, uint32) {
	t.Helper()
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	return fi.Mode().Perm(), fi.Sys().(*syscall.Stat_t).Gid
}

func TestEnsureStateDirAppliesAccessMode(t *testing.T) {
	gid := os.Getgid()
	tests := []struct {
		policy access.Policy
		want   os.FileMode
	}{
		{access.Policy{}, 0o700},
		{access.Policy{Mode: access.Group, GID: gid}, 0o750},
		{access.Policy{Mode: access.All}, 0o755},
	}
	for _, tt := range tests {
		t.Run(tt.policy.Mode.String(), func(t *testing.T) {
			root := t.TempDir()
			l := Layout{
				StateDir: filepath.Join(root, "state"),
				DataDir:  filepath.Join(root, "data"),
				Access:   tt.policy,
			}
			if err := l.EnsureStateDir(); err != nil {
				t.Fatalf("EnsureStateDir: %v", err)
			}
			if err := l.EnsureDataDir(); err != nil {
				t.Fatalf("EnsureDataDir: %v", err)
			}
			perm, g := dirStat(t, l.StateDir)
			if perm != tt.want {
				t.Errorf("state dir mode = %#o, want %#o", perm, tt.want)
			}
			if tt.policy.Mode == access.Group && int(g) != gid {
				t.Errorf("state dir gid = %d, want %d", g, gid)
			}
			// The database directory is owner-only in every mode.
			if perm, _ := dirStat(t, l.DataDir); perm != 0o700 {
				t.Errorf("data dir mode = %#o, want 0700", perm)
			}
		})
	}
}

// Switching from a shared mode back to solo must close the directory again.
func TestEnsureStateDirTightensWhenModeNarrows(t *testing.T) {
	l := Layout{StateDir: filepath.Join(t.TempDir(), "state"), Access: access.Policy{Mode: access.All}}
	if err := l.EnsureStateDir(); err != nil {
		t.Fatalf("EnsureStateDir(all): %v", err)
	}
	l.Access = access.Policy{}
	if err := l.EnsureStateDir(); err != nil {
		t.Fatalf("EnsureStateDir(solo): %v", err)
	}
	if perm, _ := dirStat(t, l.StateDir); perm != 0o700 {
		t.Errorf("mode = %#o, want 0700", perm)
	}
}

// A symlink in place of the state directory must be refused without changing
// the permissions of the directory it points to.
func TestEnsureStateDirDoesNotChmodThroughSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "state")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	l := Layout{StateDir: link, Access: access.Policy{Mode: access.All}}
	if err := l.EnsureStateDir(); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("EnsureStateDir = %v, want a symlink refusal", err)
	}
	if perm, _ := dirStat(t, target); perm != 0o700 {
		t.Errorf("symlink target mode changed to %#o", perm)
	}
}

func TestEnsureStateDirCreatesSearchableParentsDespiteUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	root := t.TempDir()
	l := Layout{StateDir: filepath.Join(root, "a", "b", "state"), Access: access.Policy{Mode: access.All}}
	if err := l.EnsureStateDir(); err != nil {
		t.Fatalf("EnsureStateDir: %v", err)
	}
	for _, d := range []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b")} {
		if perm, _ := dirStat(t, d); perm != 0o755 {
			t.Errorf("%s mode = %#o, want 0755", d, perm)
		}
	}
}

func TestCheckDirRejectsWritableByOthers(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := CheckDir(dir, access.Policy{Mode: access.All}); err == nil {
			t.Errorf("CheckDir(all) accepted mode %#o", mode)
		}
	}
}

func TestCheckDirRejectsWrongGroup(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	p := access.Policy{Mode: access.Group, GID: os.Getgid() + 1}
	if err := CheckDir(dir, p); err == nil {
		t.Error("CheckDir accepted a directory belonging to another group")
	}
}

func TestUnreachableAncestors(t *testing.T) {
	root := t.TempDir()
	closed := filepath.Join(root, "closed")
	state := filepath.Join(closed, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}

	if got := UnreachableAncestors(state, access.Policy{}); got != nil {
		t.Errorf("solo mode reported %v, want nil", got)
	}
	got := UnreachableAncestors(state, access.Policy{Mode: access.All})
	if len(got) == 0 || got[0] != closed {
		t.Errorf("UnreachableAncestors = %v, want %s first", got, closed)
	}

	if err := os.Chmod(closed, 0o711); err != nil {
		t.Fatal(err)
	}
	for _, d := range UnreachableAncestors(state, access.Policy{Mode: access.All}) {
		if d == closed || d == root {
			t.Errorf("%s reported unreachable after opening it", d)
		}
	}
}
