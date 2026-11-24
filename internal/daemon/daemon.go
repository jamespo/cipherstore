// Package daemon implements the long-running cipherstore process.
//
// The daemon owns two listeners. The control socket exists for the daemon's
// whole lifetime and accepts lifecycle commands. The authed socket exists only
// while the store is unlocked and accepts secret operations -- its mere
// presence is the lock state, so a client can tell whether the store is open
// without sending anything.
package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jamespo/cipherstore/internal/ipc"
	"github.com/jamespo/cipherstore/internal/paths"
	"github.com/jamespo/cipherstore/internal/protocol"
	"github.com/jamespo/cipherstore/internal/store"
)

// Daemon serves the control and authed sockets.
type Daemon struct {
	layout paths.Layout
	logger *log.Logger
	// ownerUID is the only user allowed to unlock, lock or stop the daemon.
	// It is the UID the daemon runs as; tests replace it to play another user.
	ownerUID uint32

	// lockFile and dataLockFile hold the flocks that allow only one daemon
	// per socket directory and per database.
	lockFile     *os.File
	dataLockFile *os.File

	control *ipc.Listener

	// mu guards every field below. It is held across store open/close and
	// authed-listener setup/teardown so lock state and socket presence can
	// never disagree.
	mu       sync.Mutex
	store    *store.Store
	authed   *ipc.Listener
	lockAt   time.Time
	lockTmr  *time.Timer
	shutdown bool

	// done is closed once the daemon should stop serving.
	done     chan struct{}
	doneOnce sync.Once

	// wg tracks in-flight connection handlers so Run can drain them.
	wg sync.WaitGroup
}

// New prepares a daemon, acquiring the single-instance lock and creating the
// control socket. The caller must call Run, which closes everything down on
// return.
func New(layout paths.Layout, logger *log.Logger) (*Daemon, error) {
	if err := layout.EnsureStateDir(); err != nil {
		return nil, err
	}
	if err := layout.EnsureDataDir(); err != nil {
		return nil, err
	}

	lockFile, err := acquireLock(layout.LockFile, "using "+layout.StateDir)
	if err != nil {
		return nil, err
	}
	dataLockFile, err := acquireLock(layout.DataLockFile, "using "+layout.DataDir)
	if err != nil {
		releaseLock(lockFile, layout.LockFile)
		return nil, err
	}

	d := &Daemon{
		layout:       layout,
		logger:       logger,
		ownerUID:     uint32(os.Getuid()),
		lockFile:     lockFile,
		dataLockFile: dataLockFile,
		done:         make(chan struct{}),
	}

	// Only now that we hold the lock is it safe to clear a stale socket.
	control, err := ipc.Listen(layout.ControlSocket, layout.Access)
	if err != nil {
		d.releaseLocks()
		return nil, err
	}
	d.control = control

	for _, dir := range paths.UnreachableAncestors(layout.StateDir, layout.Access) {
		logger.Printf("warning: %s is not searchable by other users in %s mode, so they cannot reach the sockets",
			dir, layout.Access.Mode)
	}
	return d, nil
}

// Run serves until the daemon is stopped via OpStop or a termination signal.
func (d *Daemon) Run() error {
	hardenProcess(d.logger)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	go func() {
		select {
		case sig := <-signals:
			d.logger.Printf("received %s, shutting down", sig)
			d.stop()
		case <-d.done:
		}
	}()

	d.logger.Printf("listening on %s (locked, access: %s)", d.control.Path(), d.layout.Access)
	d.serve(d.control, d.handleControl)

	<-d.done
	d.closeAll()
	d.wg.Wait()
	d.logger.Print("stopped")
	return nil
}

// serve accepts connections on l until it is closed, dispatching each to
// handler in its own goroutine.
func (d *Daemon) serve(l *ipc.Listener, handler func(net.Conn)) {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				// A closed listener is the normal exit path, both for shutdown
				// and for the authed listener being torn down by a lock.
				if !errors.Is(err, net.ErrClosed) {
					d.logger.Printf("accept on %s: %v", l.Path(), err)
				}
				return
			}
			d.wg.Add(1)
			go func() {
				defer d.wg.Done()
				defer conn.Close()
				handler(conn)
			}()
		}
	}()
}

// handleControl serves one request on the control socket.
func (d *Daemon) handleControl(conn net.Conn) {
	req, err := readRequest(conn)
	if err != nil {
		d.logger.Printf("control: %v", err)
		return
	}

	var resp protocol.Response
	if ownerOnly(req.Op) {
		if err := d.checkOwner(conn); err != nil {
			d.logger.Printf("control: refused %s: %v", req.Op, err)
			resp := errResponse(err)
			if err := protocol.WriteMessage(conn, &resp); err != nil {
				d.logger.Printf("control: %v", err)
			}
			return
		}
	}
	switch req.Op {
	case protocol.OpUnlock:
		resp = d.doUnlock(req)
	case protocol.OpLock:
		resp = d.doLock(req)
	case protocol.OpStatus:
		resp = d.doStatus()
	case protocol.OpStop:
		resp = protocol.Response{}
	default:
		resp = errResponse(fmt.Errorf("unknown control operation %q", req.Op))
	}

	if err := protocol.WriteMessage(conn, &resp); err != nil {
		d.logger.Printf("control: %v", err)
	}
	// Reply before stopping, so the client learns the stop was accepted.
	if req.Op == protocol.OpStop {
		d.logger.Print("stop requested")
		d.stop()
	}
}

// ownerOnly reports whether a control operation is reserved for the user the
// daemon runs as. In group and all modes other users may read and write
// secrets and ask for the status, but only the owner may change whether the
// store is open or stop the daemon.
func ownerOnly(op protocol.Op) bool {
	switch op {
	case protocol.OpUnlock, protocol.OpLock, protocol.OpStop:
		return true
	}
	return false
}

// checkOwner requires the peer on conn to be the daemon's owner. It asks the
// kernel, so it holds whatever the socket permissions are.
func (d *Daemon) checkOwner(conn net.Conn) error {
	uid, err := ipc.PeerUID(conn)
	if err != nil {
		return err
	}
	if uid != d.ownerUID {
		return fmt.Errorf("permission denied: only the daemon's owner (uid %d) may unlock, lock or stop it", d.ownerUID)
	}
	return nil
}

// handleAuthed serves one request on the authed socket.
func (d *Daemon) handleAuthed(conn net.Conn) {
	req, err := readRequest(conn)
	if err != nil {
		d.logger.Printf("authed: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), protocol.Timeout)
	defer cancel()

	var resp protocol.Response
	switch req.Op {
	case protocol.OpGet:
		resp = d.doGet(ctx, req)
	case protocol.OpAdd:
		resp = d.doAdd(ctx, req)
	case protocol.OpDelete:
		resp = d.doDelete(ctx, req)
	case protocol.OpList:
		resp = d.doList(ctx)
	case protocol.OpExport:
		resp = d.doExport(ctx)
	case protocol.OpImport:
		resp = d.doImport(ctx, req)
	default:
		resp = errResponse(fmt.Errorf("unknown operation %q", req.Op))
	}

	if err := protocol.WriteMessage(conn, &resp); err != nil {
		d.logger.Printf("authed: %v", err)
	}
}

func (d *Daemon) doUnlock(req *protocol.Request) protocol.Response {
	password := []byte(req.Password)
	// The plaintext passphrase in req.Password cannot be wiped (Go strings are
	// immutable), but the copy we pass onward can be.
	defer zero(password)

	lockAfter, err := parseOptionalDuration(req.Duration)
	if err != nil {
		return errResponse(err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.shutdown {
		return errResponse(errors.New("daemon is shutting down"))
	}
	if d.store != nil {
		return errResponse(errors.New("store is already unlocked"))
	}

	st, err := store.Open(d.layout.DBPath, password)
	if err != nil {
		return errResponse(err)
	}

	authed, err := ipc.Listen(d.layout.AuthedSocket, d.layout.Access)
	if err != nil {
		st.Close()
		return errResponse(fmt.Errorf("create authed socket: %w", err))
	}

	d.store = st
	d.authed = authed
	d.serve(authed, d.handleAuthed)
	d.scheduleLockLocked(lockAfter)

	if lockAfter > 0 {
		d.logger.Printf("unlocked; auto-lock in %s", lockAfter)
	} else {
		d.logger.Print("unlocked")
	}
	return protocol.Response{Status: d.statusLocked()}
}

func (d *Daemon) doLock(req *protocol.Request) protocol.Response {
	lockAfter, err := parseOptionalDuration(req.Duration)
	if err != nil {
		return errResponse(err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if lockAfter > 0 {
		// `lock 10m` means "lock in 10 minutes", leaving the store usable in
		// the meantime -- not an immediate lock.
		if d.store == nil {
			return errResponse(errors.New("store is already locked"))
		}
		d.scheduleLockLocked(lockAfter)
		d.logger.Printf("lock scheduled in %s", lockAfter)
		return protocol.Response{Status: d.statusLocked()}
	}

	if d.store == nil {
		return errResponse(errors.New("store is already locked"))
	}
	if err := d.lockNowLocked(); err != nil {
		return errResponse(err)
	}
	d.logger.Print("locked")
	return protocol.Response{Status: d.statusLocked()}
}

func (d *Daemon) doStatus() protocol.Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	return protocol.Response{Status: d.statusLocked()}
}

func (d *Daemon) doGet(ctx context.Context, req *protocol.Request) protocol.Response {
	st, err := d.unlockedStore()
	if err != nil {
		return errResponse(err)
	}
	if req.TokenID == "" {
		return errResponse(errors.New("token id must not be empty"))
	}
	e, err := st.Get(ctx, req.TokenID)
	if errors.Is(err, store.ErrNotFound) {
		return protocol.Response{Found: false}
	}
	if err != nil {
		return errResponse(err)
	}
	return protocol.Response{Found: true, Secret: e.Secret}
}

func (d *Daemon) doAdd(ctx context.Context, req *protocol.Request) protocol.Response {
	st, err := d.unlockedStore()
	if err != nil {
		return errResponse(err)
	}
	if req.TokenID == "" {
		return errResponse(errors.New("token id must not be empty"))
	}
	created, err := st.Put(ctx, req.TokenID, req.Secret, req.Comment, req.SetComment, req.NoOverwrite)
	if errors.Is(err, store.ErrExists) {
		return protocol.Response{Exists: true}
	}
	if err != nil {
		return errResponse(err)
	}
	return protocol.Response{Created: created}
}

func (d *Daemon) doDelete(ctx context.Context, req *protocol.Request) protocol.Response {
	st, err := d.unlockedStore()
	if err != nil {
		return errResponse(err)
	}
	if req.TokenID == "" {
		return errResponse(errors.New("token id must not be empty"))
	}
	if err := st.Delete(ctx, req.TokenID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.Response{Found: false}
		}
		return errResponse(err)
	}
	return protocol.Response{Found: true}
}

func (d *Daemon) doList(ctx context.Context) protocol.Response {
	st, err := d.unlockedStore()
	if err != nil {
		return errResponse(err)
	}
	entries, err := st.List(ctx)
	if err != nil {
		return errResponse(err)
	}
	out := make([]protocol.Entry, 0, len(entries))
	for _, e := range entries {
		out = append(out, protocol.Entry{TokenID: e.TokenID, Comment: e.Comment, UpdatedAt: e.UpdatedAt})
	}
	return protocol.Response{Entries: out}
}

func (d *Daemon) doExport(ctx context.Context) protocol.Response {
	st, err := d.unlockedStore()
	if err != nil {
		return errResponse(err)
	}
	entries, err := st.Export(ctx)
	if err != nil {
		return errResponse(err)
	}
	out := make([]protocol.Entry, 0, len(entries))
	for _, e := range entries {
		out = append(out, protocol.Entry{TokenID: e.TokenID, Secret: e.Secret, Comment: e.Comment, UpdatedAt: e.UpdatedAt})
	}
	return protocol.Response{Entries: out}
}

func (d *Daemon) doImport(ctx context.Context, req *protocol.Request) protocol.Response {
	st, err := d.unlockedStore()
	if err != nil {
		return errResponse(err)
	}
	entries := make([]store.Entry, 0, len(req.Entries))
	for _, e := range req.Entries {
		if e.TokenID == "" {
			return errResponse(errors.New("import entry has an empty token id"))
		}
		entries = append(entries, store.Entry{TokenID: e.TokenID, Secret: e.Secret, Comment: e.Comment, UpdatedAt: e.UpdatedAt})
	}
	stats, err := st.Import(ctx, entries, req.ReplaceNewer)
	if err != nil {
		return errResponse(err)
	}
	return protocol.Response{Import: &protocol.ImportStats{
		Imported: stats.Imported,
		Replaced: stats.Replaced,
		Skipped:  stats.Skipped,
	}}
}

// unlockedStore returns the open store, or an error if the daemon locked
// between the client connecting and its request being handled.
func (d *Daemon) unlockedStore() (*store.Store, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.store == nil {
		return nil, errors.New("store is locked")
	}
	return d.store, nil
}

// statusLocked builds a status snapshot. Caller must hold d.mu.
func (d *Daemon) statusLocked() *protocol.Status {
	return &protocol.Status{
		Unlocked: d.store != nil,
		LockAt:   d.lockAt,
		DBPath:   d.layout.DBPath,
		PID:      os.Getpid(),
		Access:   d.layout.Access.String(),
	}
}

// scheduleLockLocked arms (or disarms, when after is 0) the automatic lock.
// Caller must hold d.mu.
func (d *Daemon) scheduleLockLocked(after time.Duration) {
	if d.lockTmr != nil {
		d.lockTmr.Stop()
		d.lockTmr = nil
	}
	d.lockAt = time.Time{}
	if after <= 0 {
		return
	}
	d.lockAt = time.Now().Add(after)
	d.lockTmr = time.AfterFunc(after, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.store == nil {
			return
		}
		if err := d.lockNowLocked(); err != nil {
			d.logger.Printf("auto-lock: %v", err)
			return
		}
		d.logger.Print("auto-locked")
	})
}

// lockNowLocked closes the store and removes the authed socket. Caller must
// hold d.mu.
func (d *Daemon) lockNowLocked() error {
	if d.lockTmr != nil {
		d.lockTmr.Stop()
		d.lockTmr = nil
	}
	d.lockAt = time.Time{}

	var errs []error
	// Close the socket first: once it is gone no new request can arrive, so
	// there is no window where a client is accepted onto a closing store.
	if d.authed != nil {
		if err := d.authed.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close authed socket: %w", err))
		}
		d.authed = nil
	}
	if d.store != nil {
		if err := d.store.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close database: %w", err))
		}
		d.store = nil
	}
	return errors.Join(errs...)
}

// stop signals Run to shut down. It is safe to call more than once.
func (d *Daemon) stop() {
	d.mu.Lock()
	d.shutdown = true
	d.mu.Unlock()
	d.doneOnce.Do(func() { close(d.done) })
}

// closeAll tears down all resources held by the daemon.
func (d *Daemon) closeAll() {
	d.mu.Lock()
	if err := d.lockNowLocked(); err != nil {
		d.logger.Printf("shutdown: %v", err)
	}
	d.mu.Unlock()

	if err := d.control.Close(); err != nil {
		d.logger.Printf("shutdown: close control socket: %v", err)
	}
	d.releaseLocks()
}

func (d *Daemon) releaseLocks() {
	releaseLock(d.dataLockFile, d.layout.DataLockFile)
	releaseLock(d.lockFile, d.layout.LockFile)
}

// readRequest reads and validates a single request from conn.
func readRequest(conn net.Conn) (*protocol.Request, error) {
	var req protocol.Request
	if err := protocol.ReadMessage(conn, bufio.NewReader(conn), &req); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("client closed connection without sending a request")
		}
		return nil, fmt.Errorf("read request: %w", err)
	}
	return &req, nil
}

func errResponse(err error) protocol.Response {
	return protocol.Response{Error: err.Error()}
}

// parseOptionalDuration parses a duration string, treating "" as unset. A
// duration must be positive: a past or zero auto-lock deadline is a typo, not
// an instruction to lock immediately.
func parseOptionalDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	if dur <= 0 {
		return 0, fmt.Errorf("duration %q must be positive", s)
	}
	return dur, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// acquireLock takes an exclusive, non-blocking flock on path to guarantee a
// single daemon per directory. what describes the directory for the error a
// second daemon reports.
func acquireLock(path, what string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("another cipherstore daemon is already running (%s)", what)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return f, nil
}

func releaseLock(f *os.File, path string) {
	if f == nil {
		return
	}
	// Remove before unlocking so a daemon starting concurrently cannot grab
	// the lock on a file we are about to unlink.
	os.Remove(path)
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	f.Close()
}

// hardenProcess applies best-effort runtime protections for the in-memory key
// and decrypted pages. Each is advisory: failures are logged, never fatal,
// because the daemon is still useful without them.
func hardenProcess(logger *log.Logger) {
	// A core dump would contain the passphrase and decrypted secrets.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		logger.Printf("warning: could not disable core dumps: %v", err)
	}
	// Stops another process running as the same user from attaching with
	// ptrace or reading process memory. What this takes is platform-specific;
	// see disableDumpable.
	disableDumpable(logger)
	// Keeping pages resident stops the key or decrypted rows from reaching
	// swap. Commonly fails on RLIMIT_MEMLOCK, hence best-effort.
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		logger.Printf("notice: could not lock memory (secrets may reach swap): %v", err)
	}
}
