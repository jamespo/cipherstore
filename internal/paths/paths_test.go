package paths

import (
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
		{"DataDir", l.DataDir, "/custom/data/sqlcipher"},
		{"DBPath", l.DBPath, "/custom/data/sqlcipher/sqlcipher.sqlite"},
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
	if want := "/home/testuser/.local/share/sqlcipher/sqlcipher.sqlite"; l.DBPath != want {
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
		DataDir:  filepath.Join(root, "data", "sqlcipher"),
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
