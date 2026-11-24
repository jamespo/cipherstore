// Package paths resolves the filesystem locations cipherstore uses and
// enforces the ownership/permission invariants those locations must satisfy.
//
// Every directory cipherstore relies on is re-validated on each use: it must be
// a real directory (not a symlink) owned by the current user, and it must not
// be writable by anyone else. This is the foundation the socket and database
// protections rest on -- if an attacker cannot write into the parent
// directory, they cannot swap a socket or the database file for a symlink of
// their own.
//
// The data directory is always 0700. The state (socket) directory is 0700 in
// solo mode, and in group or all mode it is opened up for reading and
// searching only; see package access.
package paths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/jamespo/cipherstore/internal/access"
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
	// LockFile is flock'd by the daemon so only one daemon serves a socket
	// directory.
	LockFile string
	// DataDir holds the encrypted database.
	DataDir string
	// DBPath is the SQLCipher database file.
	DBPath string
	// DataLockFile is flock'd by the daemon so only one daemon opens a
	// database. With -socketpath and -dbpath set independently, the socket
	// lock alone would not prevent that.
	DataLockFile string

	// Access says who may use the sockets. The zero value is solo mode.
	Access access.Policy
}

// Default resolves the standard XDG locations. It does not touch the
// filesystem; use EnsureStateDir and EnsureDataDir for that.
func Default() (Layout, error) {
	return New("", "")
}

// New resolves a layout with the sockets in socketDir and the database in
// dbDir. An empty value selects the XDG default for that directory. Relative
// paths are made absolute against the current directory.
func New(socketDir, dbDir string) (Layout, error) {
	stateDir, err := resolveDir(socketDir, "XDG_STATE_HOME", ".local/state")
	if err != nil {
		return Layout{}, err
	}
	dataDir, err := resolveDir(dbDir, "XDG_DATA_HOME", ".local/share")
	if err != nil {
		return Layout{}, err
	}

	return Layout{
		StateDir:      stateDir,
		ControlSocket: filepath.Join(stateDir, "control"),
		AuthedSocket:  filepath.Join(stateDir, "authed"),
		LockFile:      filepath.Join(stateDir, "daemon.lock"),
		DataDir:       dataDir,
		DBPath:        filepath.Join(dataDir, "cipherstore.sqlite"),
		DataLockFile:  filepath.Join(dataDir, "daemon.lock"),
	}, nil
}

func resolveDir(explicit, env, fallback string) (string, error) {
	if explicit != "" {
		abs, err := filepath.Abs(explicit)
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", explicit, err)
		}
		return abs, nil
	}
	base, err := xdgDir(env, fallback)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "cipherstore"), nil
}

// DefaultConfigFile is the config file read when -config is not given:
// $XDG_CONFIG_HOME/cipherstore.toml, which is normally
// ~/.config/cipherstore.toml.
func DefaultConfigFile() (string, error) {
	dir, err := xdgDir("XDG_CONFIG_HOME", ".config")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "cipherstore.toml"), nil
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

// EnsureStateDir creates the runtime state directory, applies the layout's
// access policy to it and validates the result.
func (l Layout) EnsureStateDir() error {
	return ensureDir(l.StateDir, l.Access)
}

// EnsureDataDir creates and validates the database directory. It is always
// owner-only, whatever the access mode: only the daemon opens the database.
func (l Layout) EnsureDataDir() error {
	return ensureDir(l.DataDir, access.Policy{})
}

// ensureDir creates dir if needed, sets the ownership and mode p requires, and
// verifies the result.
func ensureDir(dir string, p access.Policy) error {
	// Missing parents are created 0700 in solo mode. In the other modes they
	// are created searchable, otherwise the other users could not reach the
	// sockets at all.
	parentPerm := os.FileMode(0o700)
	if p.Mode != access.Solo {
		parentPerm = 0o755
	}
	if err := mkdirParents(filepath.Dir(dir), parentPerm); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	// Change ownership and mode through a descriptor opened with O_NOFOLLOW,
	// not by path. A path-based chmod follows a symlink planted in place of the
	// directory and would change the permissions of whatever it points to.
	f, err := os.OpenFile(dir, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		// A symlink fails with ELOOP, or ENOTDIR on Linux because of
		// O_DIRECTORY; report it as a symlink either way.
		if fi, lerr := os.Lstat(dir); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; refusing to use it", dir)
		}
		return fmt.Errorf("open %s: %w", dir, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	if err := checkOwner(dir, fi); err != nil {
		return err
	}
	if p.Mode == access.Group {
		// Fails with EPERM unless we are a member of the group.
		if err := f.Chown(-1, p.GID); err != nil {
			return fmt.Errorf("set group of %s to gid %d: %w", dir, p.GID, err)
		}
	}
	// Mkdir's mode is masked by umask, and an existing directory keeps its old
	// mode, so set it explicitly.
	if err := f.Chmod(p.DirPerm()); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	return CheckDir(dir, p)
}

// mkdirParents is os.MkdirAll, except that directories it creates get exactly
// perm. MkdirAll applies the umask, so under a umask of 077 (as in the systemd
// unit) the parents would come out 0700 even when they need to be searchable.
func mkdirParents(dir string, perm os.FileMode) error {
	fi, err := os.Stat(dir)
	if err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
		return nil
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := mkdirParents(parent, perm); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, perm); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, perm); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	return nil
}

// CheckSecureDir verifies that dir is a real directory, owned by the current
// user, with no group or world permission bits set.
func CheckSecureDir(dir string) error {
	return CheckDir(dir, access.Policy{})
}

// CheckDir verifies that dir is a real directory owned by the current user,
// with no permission bits beyond those p allows. In group mode its group must
// also be p's group.
func CheckDir(dir string, p access.Policy) error {
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
	allowed := p.DirPerm()
	if perm := fi.Mode().Perm(); perm&^allowed != 0 {
		return fmt.Errorf("%s has permissions %#o; %s mode allows at most %#o", dir, perm, p.Mode, allowed)
	}
	if p.Mode == access.Group {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: cannot determine group on this platform", dir)
		}
		if int(st.Gid) != p.GID {
			return fmt.Errorf("%s belongs to gid %d, not %d", dir, st.Gid, p.GID)
		}
	}
	return nil
}

// UnreachableAncestors returns the ancestors of dir that a user other than the
// owner could not search under p, because the needed execute bit is missing.
// Such a user cannot reach the sockets however dir itself is set up. In solo
// mode it returns nil.
//
// Only the permission bits are checked. ACLs and the like are not considered,
// so the result is a hint to show the user, not a guarantee.
func UnreachableAncestors(dir string, p access.Policy) []string {
	if p.Mode == access.Solo {
		return nil
	}
	var blocked []string
	for d := filepath.Dir(dir); ; d = filepath.Dir(d) {
		if fi, err := os.Stat(d); err == nil && !searchable(fi, p) {
			blocked = append(blocked, d)
		}
		if parent := filepath.Dir(d); parent == d {
			break
		}
	}
	return blocked
}

func searchable(fi os.FileInfo, p access.Policy) bool {
	perm := fi.Mode().Perm()
	if perm&0o001 != 0 {
		return true
	}
	if p.Mode == access.Group && perm&0o010 != 0 {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Gid) == p.GID {
			return true
		}
	}
	return false
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
