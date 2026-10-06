// Package paths resolves the filesystem locations cipherstore uses and
// enforces the ownership/permission invariants those locations must satisfy.
//
// Every directory cipherstore relies on is created with mode 0700 and is
// re-validated on each use: it must be a real directory (not a symlink), owned
// by the current user, and must not be group- or world-accessible. This is the
// foundation the socket and database protections rest on -- if an attacker
// cannot write into the parent directory, they cannot swap a socket or the
// database file for a symlink of their own.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Layout holds the resolved paths for a single cipherstore instance.
type Layout struct {
	// StateDir holds the runtime sockets and the daemon lock file.
	StateDir string
	// ControlSocket accepts lifecycle commands (unlock, lock, stop, status).
	// It exists for as long as the daemon runs.
	ControlSocket string
	// AuthedSocket accepts secret operations (get, add, delete, list).
	// It exists only while the store is unlocked.
	AuthedSocket string
	// LockFile is flock'd by the daemon to enforce a single instance.
	LockFile string
	// DataDir holds the encrypted database.
	DataDir string
	// DBPath is the SQLCipher database file.
	DBPath string
}

// Default resolves the standard XDG locations. It does not touch the
// filesystem; use EnsureStateDir and EnsureDataDir for that.
func Default() (Layout, error) {
	stateHome, err := xdgDir("XDG_STATE_HOME", ".local/state")
	if err != nil {
		return Layout{}, err
	}
	dataHome, err := xdgDir("XDG_DATA_HOME", ".local/share")
	if err != nil {
		return Layout{}, err
	}

	stateDir := filepath.Join(stateHome, "cipherstore")
	dataDir := filepath.Join(dataHome, "cipherstore")

	return Layout{
		StateDir:      stateDir,
		ControlSocket: filepath.Join(stateDir, "control"),
		AuthedSocket:  filepath.Join(stateDir, "authed"),
		LockFile:      filepath.Join(stateDir, "daemon.lock"),
		DataDir:       dataDir,
		DBPath:        filepath.Join(dataDir, "cipherstore.sqlite"),
	}, nil
}

func xdgDir(env, fallback string) (string, error) {
	// An XDG variable must be an absolute path to be honoured; the spec says
	// relative values are invalid and should be ignored.
	if v := os.Getenv(env); filepath.IsAbs(v) {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, fallback), nil
}

// EnsureStateDir creates and validates the runtime state directory.
func (l Layout) EnsureStateDir() error {
	return ensureSecureDir(l.StateDir)
}

// EnsureDataDir creates and validates the database directory.
func (l Layout) EnsureDataDir() error {
	return ensureSecureDir(l.DataDir)
}

// ensureSecureDir creates dir (and its parents) with mode 0700 and then
// verifies the result is a directory we exclusively own.
func ensureSecureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	// MkdirAll leaves pre-existing directories alone, and the mode it applies
	// to new ones is masked by umask, so tighten explicitly.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	return CheckSecureDir(dir)
}

// CheckSecureDir verifies that dir is a real directory, owned by the current
// user, with no group or world permission bits set.
func CheckSecureDir(dir string) error {
	// Lstat, not Stat: a symlink here must be reported as a symlink rather
	// than followed to whatever it points at.
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to use it", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if err := checkOwner(dir, fi); err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s has permissions %#o; must not be accessible to group or others", dir, perm)
	}
	return nil
}

// CheckOwnedNonSymlink verifies that path is not a symlink and is owned by the
// current user. It returns os.ErrNotExist (wrapped) if path does not exist, so
// callers can distinguish "absent" from "unsafe".
func CheckOwnedNonSymlink(path string) (os.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink; refusing to use it", path)
	}
	if err := checkOwner(path, fi); err != nil {
		return nil, err
	}
	return fi, nil
}

func checkOwner(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot determine owner on this platform", path)
	}
	if uid := os.Getuid(); st.Uid != uint32(uid) {
		return fmt.Errorf("%s is owned by uid %d, not %d; refusing to use it", path, st.Uid, uid)
	}
	return nil
}
