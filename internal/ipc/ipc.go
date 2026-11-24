// Package ipc provides hardened UNIX-domain socket setup for cipherstore.
//
// Two defences are layered here:
//
//  1. Path safety. The socket's parent directory must be a non-symlink
//     directory that nobody but its owner can write to, and the socket itself
//     must be a non-symlink socket with the same owner. An attacker who could
//     plant a symlink where the daemon expects a socket would otherwise
//     receive the passphrase that `cipherstore unlock` sends.
//
//  2. Peer credentials. Both ends ask the kernel who is on the other end
//     (SO_PEERCRED on Linux, LOCAL_PEERCRED on Darwin). This closes the gap
//     left by the inevitable time-of-check/time-of-use window in any
//     path-based check.
//
// How strict each check is depends on the access policy:
//
//   - Solo (the default): the directory and socket must be ours, the
//     directory must be 0700, and the peer must run as our UID on both sides.
//   - Group and All: the daemon accepts peers allowed by the policy (members
//     of the group, or anyone). The client accepts a daemon run by another
//     user, but requires the directory, the socket and the listening process
//     to all belong to that same user, and the directory not to be writable by
//     anyone else.
package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/jamespo/cipherstore/internal/access"
	"github.com/jamespo/cipherstore/internal/paths"
)

// procMu serialises the process-global state Listen and Dial have to touch:
// the umask, and the working directory used for relative binds. Both are
// per-process rather than per-call, so two concurrent operations could
// otherwise restore each other's value.
var procMu sync.Mutex

// maxSocketPath is the usable length of sockaddr_un.sun_path on Linux: 108
// bytes including the terminating NUL. Exceeding it makes bind and connect
// fail with a bare EINVAL.
//
// cipherstore never gets near the limit because it binds and connects by
// relative name from inside the socket's directory (see inSocketDir), so only
// the file name counts, not the full path. The check remains as a guard.
const maxSocketPath = 107

// inSocketDir runs fn with the process working directory set to the directory
// containing path, passing fn the socket's bare file name.
//
// Binding and connecting relatively is what keeps a long $HOME or
// XDG_STATE_HOME from overflowing sun_path: only "control" or "authed" is
// passed to the kernel. The working directory is restored before returning.
//
// Callers must hold procMu.
func inSocketDir(path string, fn func(name string) error) error {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	name = filepath.Clean(name)
	if len(name) > maxSocketPath {
		return fmt.Errorf("socket name %q is %d bytes, over the %d-byte limit for unix sockets",
			name, len(name), maxSocketPath)
	}

	// A failure to read the current directory (it may have been removed) must
	// not stop the daemon from starting; in that case there is nothing
	// meaningful to restore.
	orig, origErr := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		return fmt.Errorf("enter %s: %w", dir, err)
	}
	defer func() {
		if origErr == nil {
			_ = os.Chdir(orig)
		}
	}()

	return fn(name)
}

// Listener wraps a UNIX socket listener and removes the socket file on Close.
type Listener struct {
	inner  net.Listener
	path   string
	policy access.Policy
}

// Listen creates a UNIX socket at path with the ownership and permissions the
// policy requires. Accept then admits only the peers the policy allows.
//
// A stale socket left behind by a crashed daemon is removed, but only after
// confirming it really is a socket we own. Callers must already hold the
// daemon lock, so no live daemon can be using it.
func Listen(path string, policy access.Policy) (*Listener, error) {
	if err := paths.CheckDir(filepath.Dir(path), policy); err != nil {
		return nil, err
	}
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}

	var inner net.Listener
	procMu.Lock()
	err := inSocketDir(path, func(name string) error {
		// net.Listen creates the socket with 0777 masked by umask, which could
		// leave a window where the socket is group/world accessible. Clamp
		// umask across the bind so the socket is never more permissive than
		// intended, then set the exact mode below.
		oldMask := unix.Umask(0o077)
		defer unix.Umask(oldMask)

		var err error
		inner, err = net.Listen("unix", name)
		return err
	})
	procMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}

	// The socket was created 0700 under the clamped umask. Set its group
	// before opening the mode up, so it is never group-accessible while it
	// still has the wrong group.
	if policy.Mode == access.Group {
		if err := os.Lchown(path, -1, policy.GID); err != nil {
			inner.Close()
			os.Remove(path)
			return nil, fmt.Errorf("set group of %s to gid %d: %w", path, policy.GID, err)
		}
	}
	if err := os.Chmod(path, policy.SocketPerm()); err != nil {
		inner.Close()
		os.Remove(path)
		return nil, fmt.Errorf("chmod %s: %w", path, err)
	}

	// Go's unix listener unlinks the socket itself on Close, but only when it
	// created the file; owning removal here keeps cleanup predictable.
	if ul, ok := inner.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	return &Listener{inner: inner, path: path, policy: policy}, nil
}

// Accept returns the next connection whose peer the policy allows.
// Connections from anyone else are closed and skipped rather than returned.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		if err := checkPeerAllowed(conn, l.policy); err != nil {
			conn.Close()
			// Not fatal: a rejected peer must not take the daemon down.
			continue
		}
		return conn, nil
	}
}

// Addr returns the listener's address.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// Close stops listening and unlinks the socket file.
func (l *Listener) Close() error {
	err := l.inner.Close()
	if rmErr := os.Remove(l.path); rmErr != nil && !os.IsNotExist(rmErr) && err == nil {
		err = rmErr
	}
	return err
}

// Path returns the socket path.
func (l *Listener) Path() string { return l.path }

// Dial connects to a cipherstore socket, verifying both the path and the
// listening process's credentials before returning.
//
// In solo mode the daemon must be running as us. In group and all modes it may
// run as another user: the directory's owner, who must also own the socket and
// be the process actually listening on it.
func Dial(path string, policy access.Policy) (net.Conn, error) {
	owner, err := checkClientDir(filepath.Dir(path), policy)
	if err != nil {
		return nil, err
	}

	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink; refusing to connect", path)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("%s is not a socket; refusing to connect", path)
	}
	if err := checkStatUID(path, fi, owner); err != nil {
		return nil, err
	}

	var conn net.Conn
	procMu.Lock()
	err = inSocketDir(path, func(name string) error {
		var err error
		conn, err = net.Dial("unix", name)
		return err
	})
	procMu.Unlock()
	if err != nil {
		return nil, err
	}
	// The path checks above are inherently racy. This is the authoritative
	// check: ask the kernel who is actually on the other end.
	uid, _, err := peerCredentials(conn, false)
	if err == nil && uid != owner {
		err = fmt.Errorf("peer uid %d is not %d, the owner of %s", uid, owner, filepath.Dir(path))
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return conn, nil
}

// checkClientDir validates the socket directory from the client's side and
// returns the UID the daemon must be running as.
func checkClientDir(dir string, policy access.Policy) (uint32, error) {
	if policy.Mode == access.Solo {
		if err := paths.CheckSecureDir(dir); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return 0, err
			}
			return 0, fmt.Errorf("%w (to use a daemon shared by another user, pass -mode group or -mode all)", err)
		}
		return uint32(os.Getuid()), nil
	}

	fi, err := os.Lstat(dir)
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", dir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("%s is a symlink; refusing to use it", dir)
	}
	if !fi.IsDir() {
		return 0, fmt.Errorf("%s is not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("%s: cannot determine owner on this platform", dir)
	}
	// Anyone who can write to the directory can replace the sockets, so only
	// the owner may.
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return 0, fmt.Errorf("%s has permissions %#o; must not be writable by group or others", dir, perm)
	}
	return st.Uid, nil
}

func checkStatUID(path string, fi os.FileInfo, want uint32) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot determine owner on this platform", path)
	}
	if st.Uid != want {
		return fmt.Errorf("%s is owned by uid %d, not %d; refusing to use it", path, st.Uid, want)
	}
	return nil
}

// removeStaleSocket unlinks path if it is a socket we own, and errors out if
// it is anything else.
func removeStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket; refusing to replace it", path)
	}
	if err := checkStatUID(path, fi, uint32(os.Getuid())); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	return nil
}

// checkPeerAllowed requires the connection's peer to be one the policy lets
// in: our own UID in solo mode, our UID or a member of the group in group
// mode, and anyone in all mode.
func checkPeerAllowed(conn net.Conn, policy access.Policy) error {
	if policy.Mode == access.All {
		return nil
	}
	uid, gids, err := peerCredentials(conn, policy.Mode == access.Group)
	if err != nil {
		return err
	}
	if uid == uint32(os.Getuid()) {
		return nil
	}
	if policy.Mode == access.Group {
		for _, g := range gids {
			if g == uint32(policy.GID) {
				return nil
			}
		}
		return fmt.Errorf("peer uid %d is not in group %d", uid, policy.GID)
	}
	return fmt.Errorf("peer uid %d is not %d", uid, os.Getuid())
}

// PeerUID returns the UID of the process on the other end of conn, as the
// kernel reports it. The daemon uses it to keep the lifecycle operations
// (unlock, lock, stop) to its owner when the sockets are shared.
func PeerUID(conn net.Conn) (uint32, error) {
	uid, _, err := peerCredentials(conn, false)
	return uid, err
}

// SocketDirOwner returns the UID owning the directory a socket lives in, which
// a client may use to tell, before asking for anything, whether it is the
// daemon's owner. It is advisory only: the daemon makes the real decision.
func SocketDirOwner(path string) (uint32, error) {
	fi, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("%s: cannot determine owner on this platform", filepath.Dir(path))
	}
	return st.Uid, nil
}

// peerCredentials asks the kernel for the UID of the process on the other end
// of conn and, when withGroups is set, its group IDs. Reading the credentials
// is platform-specific; see peerCred.
func peerCredentials(conn net.Conn, withGroups bool) (uid uint32, gids []uint32, err error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, nil, fmt.Errorf("connection is not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, nil, fmt.Errorf("access socket: %w", err)
	}

	var credErr error
	if err := raw.Control(func(fd uintptr) {
		uid, gids, credErr = peerCred(int(fd), withGroups)
	}); err != nil {
		return 0, nil, fmt.Errorf("access socket: %w", err)
	}
	if credErr != nil {
		return 0, nil, fmt.Errorf("read peer credentials: %w", credErr)
	}
	return uid, gids, nil
}
