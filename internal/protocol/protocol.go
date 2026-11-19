// Package protocol defines the wire format shared by the cipherstore CLI and
// daemon.
//
// Each connection carries exactly one newline-delimited JSON request and one
// newline-delimited JSON response, then closes. Single-shot connections keep
// the daemon's state machine trivial and mean a wedged client cannot hold a
// session open across a lock.
package protocol

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Op identifies a request type.
type Op string

// Operations accepted on the control socket.
const (
	OpUnlock Op = "unlock"
	OpLock   Op = "lock"
	OpStop   Op = "stop"
	OpStatus Op = "status"
)

// Operations accepted on the authed socket.
const (
	OpGet    Op = "get"
	OpAdd    Op = "add"
	OpDelete Op = "delete"
	OpList   Op = "list"
	OpExport Op = "export"
	OpImport Op = "import"
)

// MaxMessageBytes caps a single request or response. Secrets are expected to
// be small; the limit stops a malfunctioning or hostile peer from forcing the
// daemon to buffer without bound.
const MaxMessageBytes = 1 << 20 // 1 MiB

// Timeout bounds every socket read and write. Both sides are local and
// single-shot, so anything slower than this is a fault, not congestion.
const Timeout = 30 * time.Second

// Request is a command sent to the daemon.
type Request struct {
	Op Op `json:"op"`

	// Password carries the passphrase for OpUnlock.
	Password string `json:"password,omitempty"`

	// Duration is an optional time.ParseDuration string. On OpUnlock it
	// schedules an automatic lock that far in the future; on OpLock it defers
	// the lock rather than performing it immediately.
	Duration string `json:"duration,omitempty"`

	TokenID string `json:"token_id,omitempty"`
	Secret  string `json:"secret,omitempty"`
	Comment string `json:"comment,omitempty"`

	// SetComment distinguishes "no comment argument given" from "comment
	// explicitly set to the empty string" on OpAdd. When false, an update
	// leaves any existing comment untouched.
	SetComment bool `json:"set_comment,omitempty"`

	// NoOverwrite, on OpAdd, makes the daemon refuse to replace an existing
	// token: nothing is written and the response has Exists set. When false,
	// OpAdd is an upsert.
	NoOverwrite bool `json:"no_overwrite,omitempty"`

	// Entries carries the entries to write on OpImport.
	Entries []Entry `json:"entries,omitempty"`

	// ReplaceNewer, on OpImport, allows an imported entry to overwrite an
	// existing one when the imported entry's UpdatedAt is strictly newer.
	// When false, an existing entry is never touched by an import.
	ReplaceNewer bool `json:"replace_newer,omitempty"`
}

// Entry is one row of the store, as returned by OpList and OpExport. Secret
// is populated by OpExport but left empty by OpList, and is also what a
// client sends (filled in) on OpImport.
type Entry struct {
	TokenID   string    `json:"token_id"`
	Secret    string    `json:"secret,omitempty"`
	Comment   string    `json:"comment,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ImportStats summarises the result of OpImport.
type ImportStats struct {
	Imported int `json:"imported"`
	Replaced int `json:"replaced"`
	Skipped  int `json:"skipped"`
}

// Status reports daemon state, returned by OpStatus.
type Status struct {
	Unlocked bool `json:"unlocked"`
	// LockAt is the scheduled automatic lock time, zero if none is pending.
	LockAt time.Time `json:"lock_at,omitzero"`
	DBPath string    `json:"db_path"`
	PID    int       `json:"pid"`
}

// Response is the daemon's reply. Error is non-empty exactly when the request
// failed.
type Response struct {
	Error string `json:"error,omitempty"`

	Secret  string       `json:"secret,omitempty"`
	Found   bool         `json:"found,omitempty"`
	Created bool         `json:"created,omitempty"`
	Exists  bool         `json:"exists,omitempty"`
	Entries []Entry      `json:"entries,omitempty"`
	Status  *Status      `json:"status,omitempty"`
	Import  *ImportStats `json:"import,omitempty"`
}

// Err returns the response's error as a Go error, or nil if the request
// succeeded.
func (r *Response) Err() error {
	if r.Error == "" {
		return nil
	}
	return errors.New(r.Error)
}

// WriteMessage encodes v as a single JSON line on conn.
func WriteMessage(conn net.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode message: %w", err)
	}
	if len(b)+1 > MaxMessageBytes {
		return fmt.Errorf("message of %d bytes exceeds limit of %d", len(b), MaxMessageBytes)
	}
	b = append(b, '\n')
	if err := conn.SetWriteDeadline(time.Now().Add(Timeout)); err != nil {
		return err
	}
	if _, err := conn.Write(b); err != nil {
		return fmt.Errorf("write message: %w", err)
	}
	return nil
}

// ReadMessage decodes a single JSON line from r into v.
func ReadMessage(conn net.Conn, r *bufio.Reader, v any) error {
	if err := conn.SetReadDeadline(time.Now().Add(Timeout)); err != nil {
		return err
	}
	line, err := readLine(r)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(line, v); err != nil {
		return fmt.Errorf("decode message: %w", err)
	}
	return nil
}

// readLine reads up to and including the next newline, refusing to buffer more
// than MaxMessageBytes.
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > MaxMessageBytes {
			return nil, fmt.Errorf("message exceeds limit of %d bytes", MaxMessageBytes)
		}
		if err == nil {
			return buf, nil
		}
		// ReadSlice fills its internal buffer and returns ErrBufferFull when
		// the line is longer than the buffer; keep accumulating.
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(buf) > 0 {
			// Tolerate a final message with no trailing newline.
			return buf, nil
		}
		return nil, err
	}
}
