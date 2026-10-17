// Package ipc provides hardened UNIX-domain socket setup for cipherstore.
//
// Two defences are layered here:
//
//  1. Path safety. The socket's parent directory must be a non-symlink
//     directory we own with mode 0700, and the socket itself must be a
//     non-symlink socket we own. An attacker who could plant a symlink where
//     the daemon expects a socket would otherwise receive the passphrase that
//     `cipherstore unlock` sends.
//
//  2. Peer credentials. Both ends read SO_PEERCRED and require the other end's
//     UID to match their own. This closes the gap left by the inevitable
//     time-of-check/time-of-use window in any path-based check: even if a peer
//     managed to interpose, it would have to do so as the same UID, which
//     already has full access to the user's files.
package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
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
	inner net.Listener
	path  string
}

// Listen creates a UNIX socket at path with the given permissions.
//
// A stale socket left behind by a crashed daemon is removed, but only after
// confirming it really is a socket we own. Callers must already hold the
// daemon lock, so no live daemon can be using it.
func Listen(path string, mode os.FileMode) (*Listener, error) {
	if err := checkParentDir(path); err != nil {
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

	if err := os.Chmod(path, mode); err != nil {
		inner.Close()
		os.Remove(path)
		return nil, fmt.Errorf("chmod %s: %w", path, err)
	}

	// Go's unix listener unlinks the socket itself on Close, but only when it
	// created the file; owning removal here keeps cleanup predictable.
	if ul, ok := inner.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	return &Listener{inner: inner, path: path}, nil
}

// Accept returns the next connection whose peer runs as the same UID.
// Connections from other users are closed and skipped rather than returned.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		if err := checkPeerUID(conn); err != nil {
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
func Dial(path string) (net.Conn, error) {
	if err := checkParentDir(path); err != nil {
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
	if err := checkStatOwner(path, fi); err != nil {
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
	if err := checkPeerUID(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return conn, nil
}

// checkParentDir validates the directory containing path.
func checkParentDir(path string) error {
	dir := filepath.Dir(path)
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
	if err := checkStatOwner(dir, fi); err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s has permissions %#o; must not be accessible to group or others", dir, perm)
	}
	return nil
}

func checkStatOwner(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot determine owner on this platform", path)
	}
	if uid := os.Getuid(); st.Uid != uint32(uid) {
		return fmt.Errorf("%s is owned by uid %d, not %d; refusing to use it", path, st.Uid, uid)
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
	if err := checkStatOwner(path, fi); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	return nil
}

// checkPeerUID requires the connection's peer to run as the current UID.
// Reading the credential itself is platform-specific; see peerUID.
func checkPeerUID(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("connection is not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return fmt.Errorf("access socket: %w", err)
	}

	var uid uint32
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		uid, credErr = peerUID(int(fd))
	}); err != nil {
		return fmt.Errorf("access socket: %w", err)
	}
	if credErr != nil {
		return fmt.Errorf("read peer credentials: %w", credErr)
	}
	if want := uint32(os.Getuid()); uid != want {
		return fmt.Errorf("peer uid %d is not %d", uid, want)
	}
	return nil
}
