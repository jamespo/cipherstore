package ipc

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// secureDir returns a 0700 directory suitable for sockets.
func secureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	return dir
}

func TestListenAndDial(t *testing.T) {
	path := filepath.Join(secureDir(t), "sock")

	l, err := Listen(path, 0o700)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("hello"))
	}()

	conn, err := Dial(path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("read %q, want %q", buf, "hello")
	}
}

func TestListenSetsRequestedMode(t *testing.T) {
	path := filepath.Join(secureDir(t), "sock")

	l, err := Listen(path, 0o700)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Errorf("mode = %v, want a socket", fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Errorf("perm = %#o, want %#o", perm, 0o700)
	}
}

func TestCloseUnlinksSocket(t *testing.T) {
	path := filepath.Join(secureDir(t), "sock")

	l, err := Listen(path, 0o700)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("socket still present after Close (err = %v)", err)
	}
}

// Binding and connecting happen by relative name from inside the socket's
// directory, so a path far longer than sockaddr_un's 108 bytes must still
// work. Without that, bind fails with a bare EINVAL.
func TestLongPathBeyondSunPathLimit(t *testing.T) {
	root := secureDir(t)

	// Build a path well past the limit.
	deep := root
	for range 4 {
		deep = filepath.Join(deep, strings.Repeat("d", 40))
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(deep, "control")
	if len(path) <= maxSocketPath {
		t.Fatalf("test path is only %d bytes; it must exceed %d to be meaningful", len(path), maxSocketPath)
	}
	t.Logf("socket path is %d bytes (limit %d)", len(path), maxSocketPath)

	l, err := Listen(path, 0o700)
	if err != nil {
		t.Fatalf("Listen on a %d-byte path: %v", len(path), err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	conn, err := Dial(path)
	if err != nil {
		t.Fatalf("Dial on a %d-byte path: %v", len(path), err)
	}
	conn.Close()
}

// Listen and Dial restore the working directory they borrowed.
func TestWorkingDirectoryIsRestored(t *testing.T) {
	before, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}

	path := filepath.Join(secureDir(t), "sock")
	l, err := Listen(path, 0o700)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	if after, _ := os.Getwd(); after != before {
		t.Errorf("after Listen, cwd = %q, want %q", after, before)
	}

	go func() {
		if conn, err := l.Accept(); err == nil {
			conn.Close()
		}
	}()
	conn, err := Dial(path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	if after, _ := os.Getwd(); after != before {
		t.Errorf("after Dial, cwd = %q, want %q", after, before)
	}
}

func TestDialRefusesSymlink(t *testing.T) {
	dir := secureDir(t)
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")

	l, err := Listen(real, 0o700)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err = Dial(link)
	if err == nil {
		t.Fatal("Dial through a symlink succeeded, want it refused")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error = %v, want it to mention a symlink", err)
	}
}

func TestDialRefusesNonSocket(t *testing.T) {
	dir := secureDir(t)
	path := filepath.Join(dir, "regular")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := Dial(path); err == nil {
		t.Error("Dial on a regular file succeeded, want it refused")
	}
}

func TestDialMissingSocketReportsNotExist(t *testing.T) {
	// The CLI distinguishes "daemon not running" from a real fault by testing
	// for os.ErrNotExist, so this error must stay unwrapped in that respect.
	_, err := Dial(filepath.Join(secureDir(t), "absent"))
	if !os.IsNotExist(err) {
		t.Errorf("error = %v, want it to satisfy os.IsNotExist", err)
	}
}

// A socket whose parent directory is group- or world-accessible is not
// trustworthy: another user could swap the socket out.
func TestRefusesLooseParentDirectory(t *testing.T) {
	dir := secureDir(t)
	path := filepath.Join(dir, "sock")

	l, err := Listen(path, 0o700)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	defer os.Chmod(dir, 0o700)

	if _, err := Dial(path); err == nil {
		t.Error("Dial with a world-readable parent directory succeeded, want it refused")
	}
	if _, err := Listen(filepath.Join(dir, "other"), 0o700); err == nil {
		t.Error("Listen with a world-readable parent directory succeeded, want it refused")
	}
}

// A stale socket from a crashed daemon must be replaced...
func TestListenReplacesStaleSocket(t *testing.T) {
	path := filepath.Join(secureDir(t), "sock")

	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("create stale socket: %v", err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()

	l, err := Listen(path, 0o700)
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	l.Close()
}

// ...but anything that is not a socket must not be silently deleted.
func TestListenRefusesToReplaceNonSocket(t *testing.T) {
	dir := secureDir(t)
	path := filepath.Join(dir, "important")
	if err := os.WriteFile(path, []byte("do not delete"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := Listen(path, 0o700); err == nil {
		t.Fatal("Listen over a regular file succeeded, want it refused")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "do not delete" {
		t.Errorf("the file was modified: %q, %v", b, err)
	}
}

func TestAcceptAcceptsSameUIDPeer(t *testing.T) {
	path := filepath.Join(secureDir(t), "sock")
	l, err := Listen(path, 0o700)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			accepted <- err
			return
		}
		conn.Close()
		accepted <- nil
	}()

	conn, err := Dial(path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if err := <-accepted; err != nil {
		t.Errorf("Accept rejected a same-uid peer: %v", err)
	}
}
