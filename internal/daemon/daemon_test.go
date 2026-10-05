package daemon

import (
	"bufio"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jamespo/cipherstore/internal/ipc"
	"github.com/jamespo/cipherstore/internal/paths"
	"github.com/jamespo/cipherstore/internal/protocol"
)

const testPassword = "correct horse battery staple"

// harness is a running daemon plus the paths needed to talk to it.
type harness struct {
	t      *testing.T
	layout paths.Layout
}

// start brings up a daemon on a private state and data directory and tears it
// down when the test ends.
func start(t *testing.T) *harness {
	t.Helper()

	// t.TempDir is created 0700, which satisfies the daemon's checks. Keeping
	// the path short also keeps it well inside the sun_path limit.
	root := t.TempDir()
	layout := paths.Layout{
		StateDir:      filepath.Join(root, "state"),
		ControlSocket: filepath.Join(root, "state", "control"),
		AuthedSocket:  filepath.Join(root, "state", "authed"),
		LockFile:      filepath.Join(root, "state", "daemon.lock"),
		DataDir:       filepath.Join(root, "data"),
		DBPath:        filepath.Join(root, "data", "cipherstore.sqlite"),
	}

	d, err := New(layout, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		if err := d.Run(); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()

	h := &harness{t: t, layout: layout}
	waitFor(t, layout.ControlSocket, true)

	t.Cleanup(func() {
		d.stop()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			t.Error("daemon did not shut down within 10s")
		}
	})
	return h
}

// control sends a request to the control socket.
func (h *harness) control(req *protocol.Request) *protocol.Response {
	h.t.Helper()
	return h.send(h.layout.ControlSocket, req)
}

// authed sends a request to the authed socket.
func (h *harness) authed(req *protocol.Request) *protocol.Response {
	h.t.Helper()
	return h.send(h.layout.AuthedSocket, req)
}

func (h *harness) send(socket string, req *protocol.Request) *protocol.Response {
	h.t.Helper()
	conn, err := ipc.Dial(socket)
	if err != nil {
		h.t.Fatalf("dial %s: %v", socket, err)
	}
	defer conn.Close()

	if err := protocol.WriteMessage(conn, req); err != nil {
		h.t.Fatalf("write %s: %v", req.Op, err)
	}
	var resp protocol.Response
	if err := protocol.ReadMessage(conn, bufio.NewReader(conn), &resp); err != nil {
		h.t.Fatalf("read response to %s: %v", req.Op, err)
	}
	return &resp
}

// unlock unlocks the store and fails the test if it does not succeed.
func (h *harness) unlock() {
	h.t.Helper()
	resp := h.control(&protocol.Request{Op: protocol.OpUnlock, Password: testPassword})
	if resp.Error != "" {
		h.t.Fatalf("unlock: %s", resp.Error)
	}
	waitFor(h.t, h.layout.AuthedSocket, true)
}

// waitFor blocks until path exists (or stops existing), or the test times out.
func waitFor(t *testing.T, path string, wantExists bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := os.Lstat(path)
		if (err == nil) == wantExists {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: exists=%v, want exists=%v after 10s", path, err == nil, wantExists)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The authed socket's presence is the lock state, so clients can see whether
// the store is open without sending anything.
func TestAuthedSocketTracksLockState(t *testing.T) {
	h := start(t)

	if _, err := os.Lstat(h.layout.AuthedSocket); !os.IsNotExist(err) {
		t.Errorf("authed socket exists while locked (err = %v)", err)
	}

	h.unlock()

	fi, err := os.Lstat(h.layout.AuthedSocket)
	if err != nil {
		t.Fatalf("authed socket missing after unlock: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Errorf("authed path is not a socket: mode %v", fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm != SocketMode {
		t.Errorf("authed socket mode = %#o, want %#o", perm, SocketMode)
	}

	if resp := h.control(&protocol.Request{Op: protocol.OpLock}); resp.Error != "" {
		t.Fatalf("lock: %s", resp.Error)
	}
	waitFor(t, h.layout.AuthedSocket, false)
}

func TestSecretOperations(t *testing.T) {
	h := start(t)
	h.unlock()

	resp := h.authed(&protocol.Request{Op: protocol.OpAdd, TokenID: "github", Secret: "ghp_tok", Comment: "work", SetComment: true})
	if resp.Error != "" {
		t.Fatalf("add: %s", resp.Error)
	}
	if !resp.Created {
		t.Error("add of a new token reported created=false")
	}

	resp = h.authed(&protocol.Request{Op: protocol.OpGet, TokenID: "github"})
	if resp.Error != "" {
		t.Fatalf("get: %s", resp.Error)
	}
	if !resp.Found || resp.Secret != "ghp_tok" {
		t.Errorf("get returned found=%v secret=%q, want true/%q", resp.Found, resp.Secret, "ghp_tok")
	}

	resp = h.authed(&protocol.Request{Op: protocol.OpList})
	if resp.Error != "" {
		t.Fatalf("list: %s", resp.Error)
	}
	if len(resp.Entries) != 1 {
		t.Fatalf("list returned %d entries, want 1", len(resp.Entries))
	}
	if resp.Entries[0].Comment != "work" {
		t.Errorf("listed comment = %q, want %q", resp.Entries[0].Comment, "work")
	}

	resp = h.authed(&protocol.Request{Op: protocol.OpDelete, TokenID: "github"})
	if resp.Error != "" || !resp.Found {
		t.Errorf("delete returned error=%q found=%v", resp.Error, resp.Found)
	}

	resp = h.authed(&protocol.Request{Op: protocol.OpGet, TokenID: "github"})
	if resp.Found {
		t.Error("get found the token after it was deleted")
	}
}

// A missing token is reported as found=false, not as an error, so the CLI can
// map it to a distinct exit code.
func TestMissingTokenIsNotAnError(t *testing.T) {
	h := start(t)
	h.unlock()

	for _, op := range []protocol.Op{protocol.OpGet, protocol.OpDelete} {
		resp := h.authed(&protocol.Request{Op: op, TokenID: "nope"})
		if resp.Error != "" {
			t.Errorf("%s on a missing token returned error %q", op, resp.Error)
		}
		if resp.Found {
			t.Errorf("%s on a missing token reported found=true", op)
		}
	}
}

func TestDataSurvivesLockCycle(t *testing.T) {
	h := start(t)
	h.unlock()

	if resp := h.authed(&protocol.Request{Op: protocol.OpAdd, TokenID: "tok", Secret: "sec"}); resp.Error != "" {
		t.Fatalf("add: %s", resp.Error)
	}
	if resp := h.control(&protocol.Request{Op: protocol.OpLock}); resp.Error != "" {
		t.Fatalf("lock: %s", resp.Error)
	}
	waitFor(t, h.layout.AuthedSocket, false)

	h.unlock()
	resp := h.authed(&protocol.Request{Op: protocol.OpGet, TokenID: "tok"})
	if !resp.Found || resp.Secret != "sec" {
		t.Errorf("after relock got found=%v secret=%q, want true/%q", resp.Found, resp.Secret, "sec")
	}
}

func TestWrongPasswordLeavesStoreLocked(t *testing.T) {
	h := start(t)
	h.unlock()
	if resp := h.control(&protocol.Request{Op: protocol.OpLock}); resp.Error != "" {
		t.Fatalf("lock: %s", resp.Error)
	}
	waitFor(t, h.layout.AuthedSocket, false)

	resp := h.control(&protocol.Request{Op: protocol.OpUnlock, Password: "wrong"})
	if resp.Error == "" {
		t.Fatal("unlock with the wrong password succeeded")
	}
	if _, err := os.Lstat(h.layout.AuthedSocket); !os.IsNotExist(err) {
		t.Errorf("authed socket created despite a bad password (err = %v)", err)
	}

	// The correct password must still work afterwards.
	h.unlock()
}

func TestDoubleUnlockAndDoubleLockRejected(t *testing.T) {
	h := start(t)

	if resp := h.control(&protocol.Request{Op: protocol.OpLock}); resp.Error == "" {
		t.Error("lock while already locked succeeded, want an error")
	}

	h.unlock()
	if resp := h.control(&protocol.Request{Op: protocol.OpUnlock, Password: testPassword}); resp.Error == "" {
		t.Error("unlock while already unlocked succeeded, want an error")
	}
}

// `unlock 50ms` must auto-lock when the duration elapses.
func TestUnlockWithDurationAutoLocks(t *testing.T) {
	h := start(t)

	resp := h.control(&protocol.Request{Op: protocol.OpUnlock, Password: testPassword, Duration: "50ms"})
	if resp.Error != "" {
		t.Fatalf("unlock: %s", resp.Error)
	}
	if resp.Status == nil || resp.Status.LockAt.IsZero() {
		t.Error("unlock with a duration did not report a lock time")
	}
	waitFor(t, h.layout.AuthedSocket, false)
}

// `lock 10m` means "lock in 10 minutes", so the store must stay usable.
func TestLockWithDurationDefersTheLock(t *testing.T) {
	h := start(t)
	h.unlock()

	resp := h.control(&protocol.Request{Op: protocol.OpLock, Duration: "10m"})
	if resp.Error != "" {
		t.Fatalf("lock 10m: %s", resp.Error)
	}
	if resp.Status == nil || !resp.Status.Unlocked {
		t.Fatal("lock with a duration locked immediately")
	}
	if resp.Status.LockAt.IsZero() {
		t.Error("lock with a duration did not report a lock time")
	}
	if _, err := os.Lstat(h.layout.AuthedSocket); err != nil {
		t.Errorf("authed socket removed by a deferred lock: %v", err)
	}
}

// A later unlock must replace the pending auto-lock rather than leaving a
// stale timer that locks the store unexpectedly.
func TestUnlockReplacesPendingAutoLock(t *testing.T) {
	h := start(t)

	if resp := h.control(&protocol.Request{Op: protocol.OpUnlock, Password: testPassword, Duration: "40ms"}); resp.Error != "" {
		t.Fatalf("unlock 40ms: %s", resp.Error)
	}
	waitFor(t, h.layout.AuthedSocket, false)

	if resp := h.control(&protocol.Request{Op: protocol.OpUnlock, Password: testPassword}); resp.Error != "" {
		t.Fatalf("unlock: %s", resp.Error)
	}
	waitFor(t, h.layout.AuthedSocket, true)

	// Well past the original 40ms deadline, the store must still be open.
	time.Sleep(150 * time.Millisecond)
	if _, err := os.Lstat(h.layout.AuthedSocket); err != nil {
		t.Errorf("a stale auto-lock timer locked the store: %v", err)
	}
}

func TestInvalidDurationRejected(t *testing.T) {
	h := start(t)

	for _, d := range []string{"12parsecs", "-5m", "0s"} {
		resp := h.control(&protocol.Request{Op: protocol.OpUnlock, Password: testPassword, Duration: d})
		if resp.Error == "" {
			t.Errorf("unlock with duration %q succeeded, want an error", d)
		}
	}
}

func TestStatus(t *testing.T) {
	h := start(t)

	resp := h.control(&protocol.Request{Op: protocol.OpStatus})
	if resp.Status == nil {
		t.Fatal("status returned no status")
	}
	if resp.Status.Unlocked {
		t.Error("status reports unlocked before any unlock")
	}
	if resp.Status.PID != os.Getpid() {
		t.Errorf("status PID = %d, want %d", resp.Status.PID, os.Getpid())
	}
	if resp.Status.DBPath != h.layout.DBPath {
		t.Errorf("status DBPath = %q, want %q", resp.Status.DBPath, h.layout.DBPath)
	}

	h.unlock()
	if resp := h.control(&protocol.Request{Op: protocol.OpStatus}); !resp.Status.Unlocked {
		t.Error("status reports locked after unlock")
	}
}

func TestUnknownOperationRejected(t *testing.T) {
	h := start(t)
	h.unlock()

	if resp := h.control(&protocol.Request{Op: "frobnicate"}); resp.Error == "" {
		t.Error("unknown control op succeeded, want an error")
	}
	if resp := h.authed(&protocol.Request{Op: "frobnicate"}); resp.Error == "" {
		t.Error("unknown authed op succeeded, want an error")
	}
}

func TestEmptyTokenIDRejected(t *testing.T) {
	h := start(t)
	h.unlock()

	for _, op := range []protocol.Op{protocol.OpGet, protocol.OpAdd, protocol.OpDelete} {
		if resp := h.authed(&protocol.Request{Op: op, TokenID: ""}); resp.Error == "" {
			t.Errorf("%s with an empty token id succeeded, want an error", op)
		}
	}
}

// Only one daemon may own the sockets, so a second instance must be refused
// rather than stealing them from the first.
func TestSecondDaemonRefused(t *testing.T) {
	h := start(t)

	_, err := New(h.layout, log.New(io.Discard, "", 0))
	if err == nil {
		t.Fatal("a second daemon started, want it refused")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Errorf("error = %v, want it to mention another daemon running", err)
	}

	// The first daemon must be unharmed.
	if resp := h.control(&protocol.Request{Op: protocol.OpStatus}); resp.Status == nil {
		t.Error("the original daemon stopped responding")
	}
}

// Shutdown must not leave sockets behind for a later run to trip over.
func TestShutdownRemovesSockets(t *testing.T) {
	root := t.TempDir()
	layout := paths.Layout{
		StateDir:      filepath.Join(root, "state"),
		ControlSocket: filepath.Join(root, "state", "control"),
		AuthedSocket:  filepath.Join(root, "state", "authed"),
		LockFile:      filepath.Join(root, "state", "daemon.lock"),
		DataDir:       filepath.Join(root, "data"),
		DBPath:        filepath.Join(root, "data", "cipherstore.sqlite"),
	}

	d, err := New(layout, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		d.Run()
	}()
	waitFor(t, layout.ControlSocket, true)

	conn, err := ipc.Dial(layout.ControlSocket)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := protocol.WriteMessage(conn, &protocol.Request{Op: protocol.OpUnlock, Password: testPassword}); err != nil {
		t.Fatalf("write unlock: %v", err)
	}
	var resp protocol.Response
	if err := protocol.ReadMessage(conn, bufio.NewReader(conn), &resp); err != nil {
		t.Fatalf("read unlock response: %v", err)
	}
	conn.Close()
	if resp.Error != "" {
		t.Fatalf("unlock: %s", resp.Error)
	}
	waitFor(t, layout.AuthedSocket, true)

	d.stop()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not shut down")
	}

	for _, p := range []string{layout.ControlSocket, layout.AuthedSocket, layout.LockFile} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists after shutdown (err = %v)", p, err)
		}
	}
}

// A crashed daemon leaves its socket and lock file behind; the next start must
// clean them up instead of refusing to run.
func TestStartOverStaleSocketAndLock(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	layout := paths.Layout{
		StateDir:      stateDir,
		ControlSocket: filepath.Join(stateDir, "control"),
		AuthedSocket:  filepath.Join(stateDir, "authed"),
		LockFile:      filepath.Join(stateDir, "daemon.lock"),
		DataDir:       filepath.Join(root, "data"),
		DBPath:        filepath.Join(root, "data", "cipherstore.sqlite"),
	}
	if err := layout.EnsureStateDir(); err != nil {
		t.Fatalf("EnsureStateDir: %v", err)
	}

	// Simulate the debris a SIGKILL leaves: a socket file with nothing
	// listening, plus a lock file nobody holds an flock on.
	stale, err := net.Listen("unix", layout.ControlSocket)
	if err != nil {
		t.Fatalf("create stale socket: %v", err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatalf("close stale socket: %v", err)
	}
	if fi, err := os.Lstat(layout.ControlSocket); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected a stale socket at %s (err = %v)", layout.ControlSocket, err)
	}

	if err := os.WriteFile(layout.LockFile, nil, 0o600); err != nil {
		t.Fatalf("write stale lock: %v", err)
	}

	d, err := New(layout, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("New over stale state: %v", err)
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		d.Run()
	}()
	waitFor(t, layout.ControlSocket, true)
	d.stop()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not shut down")
	}
}

func TestParseOptionalDuration(t *testing.T) {
	if d, err := parseOptionalDuration(""); err != nil || d != 0 {
		t.Errorf(`parseOptionalDuration("") = %v, %v; want 0, nil`, d, err)
	}
	if d, err := parseOptionalDuration("10m"); err != nil || d != 10*time.Minute {
		t.Errorf(`parseOptionalDuration("10m") = %v, %v; want 10m, nil`, d, err)
	}
	for _, in := range []string{"nope", "0", "0s", "-1m"} {
		if _, err := parseOptionalDuration(in); err == nil {
			t.Errorf("parseOptionalDuration(%q) succeeded, want an error", in)
		}
	}
}
