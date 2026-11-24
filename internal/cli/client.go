package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"

	"github.com/jamespo/cipherstore/internal/access"
	"github.com/jamespo/cipherstore/internal/ipc"
	"github.com/jamespo/cipherstore/internal/protocol"
)

// errNoDaemon reports that the control socket is absent, which means no daemon
// is running.
var errNoDaemon = errors.New("cipherstore daemon is not running (start it with `cipherstore start`)")

// errLocked reports that the authed socket is absent, which means the store is
// locked.
var errLocked = errors.New("cipherstore is locked (unlock it with `cipherstore unlock`)")

// send performs one request/response exchange against the given socket.
//
// With ownDaemon set, the request is only sent if the daemon runs as us. The
// lifecycle commands use it: only the owner may run them anyway, and it means
// `unlock` never hands the passphrase to a daemon run by another user, even
// in the shared modes where Dial would otherwise accept one.
func send(socket string, policy access.Policy, req *protocol.Request, absent error, ownDaemon bool) (*protocol.Response, error) {
	conn, err := ipc.Dial(socket, policy)
	if err != nil {
		// A missing socket is the daemon's way of signalling state, not a
		// fault: translate it into the caller's domain-specific message.
		if errors.Is(err, os.ErrNotExist) {
			return nil, absent
		}
		return nil, err
	}
	defer conn.Close()

	if ownDaemon {
		uid, err := ipc.PeerUID(conn)
		if err != nil {
			return nil, err
		}
		if uid != uint32(os.Getuid()) {
			return nil, fmt.Errorf("only the daemon's owner (uid %d) can %s it", uid, req.Op)
		}
	}

	if err := protocol.WriteMessage(conn, req); err != nil {
		return nil, err
	}

	var resp protocol.Response
	if err := protocol.ReadMessage(conn, bufio.NewReader(conn), &resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if err := resp.Err(); err != nil {
		return nil, err
	}
	return &resp, nil
}

// sendControl talks to the control socket, which is present whenever the
// daemon runs.
func (e *env) sendControl(req *protocol.Request) (*protocol.Response, error) {
	return send(e.layout.ControlSocket, e.layout.Access, req, errNoDaemon, false)
}

// sendOwnerControl talks to the control socket for an owner-only command
// (unlock, lock, stop), refusing to send anything to another user's daemon.
func (e *env) sendOwnerControl(req *protocol.Request) (*protocol.Response, error) {
	return send(e.layout.ControlSocket, e.layout.Access, req, errNoDaemon, true)
}

// sendAuthed talks to the authed socket, which is present only while unlocked.
func (e *env) sendAuthed(req *protocol.Request) (*protocol.Response, error) {
	resp, err := send(e.layout.AuthedSocket, e.layout.Access, req, errLocked, false)
	if errors.Is(err, errLocked) {
		// Distinguish "locked" from "not running" for a clearer message.
		if _, statErr := os.Lstat(e.layout.ControlSocket); os.IsNotExist(statErr) {
			return nil, errNoDaemon
		}
	}
	return resp, err
}
