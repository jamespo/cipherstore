package protocol

import (
	"bufio"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// pipe returns a connected pair of unix socket connections.
func pipe(t *testing.T) (client, server net.Conn) {
	t.Helper()
	c, s, err := socketPair()
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

func socketPair() (net.Conn, net.Conn, error) {
	l, err := net.Listen("unix", "")
	if err != nil {
		// Autobind (binding an empty address to get a kernel-assigned name)
		// is Linux-specific; fall back to a real, short-lived socket file.
		l, err = listenTempSocket()
		if err != nil {
			return nil, nil, err
		}
	}
	defer l.Close()

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := l.Accept()
		ch <- result{conn, err}
	}()

	client, err := net.Dial("unix", l.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	r := <-ch
	if r.err != nil {
		client.Close()
		return nil, nil, r.err
	}
	return client, r.conn, nil
}

// listenTempSocket binds a unix socket at a short-lived temporary path,
// removing the file once the listener closes.
func listenTempSocket() (net.Listener, error) {
	f, err := os.CreateTemp("", "cipherstore-test-*.sock")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	f.Close()
	os.Remove(path) // net.Listen creates the socket file itself.

	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	return &unlinkOnCloseListener{Listener: l, path: path}, nil
}

type unlinkOnCloseListener struct {
	net.Listener
	path string
}

func (l *unlinkOnCloseListener) Close() error {
	err := l.Listener.Close()
	os.Remove(l.path)
	return err
}

func TestRoundTripRequest(t *testing.T) {
	client, server := pipe(t)

	want := &Request{
		Op:         OpAdd,
		TokenID:    "github",
		Secret:     "ghp_tok",
		Comment:    "work",
		SetComment: true,
	}
	if err := WriteMessage(client, want); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	var got Request
	if err := ReadMessage(server, bufio.NewReader(server), &got); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if !reflect.DeepEqual(got, *want) {
		t.Errorf("got %+v, want %+v", got, *want)
	}
}

func TestRoundTripImportRequestAndResponse(t *testing.T) {
	client, server := pipe(t)

	now := time.Now().Truncate(time.Second)
	want := &Request{
		Op:           OpImport,
		ReplaceNewer: true,
		Entries: []Entry{
			{TokenID: "a", Secret: "sa", Comment: "ca", UpdatedAt: now},
			{TokenID: "b", Secret: "sb", UpdatedAt: now},
		},
	}
	if err := WriteMessage(client, want); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	var got Request
	if err := ReadMessage(server, bufio.NewReader(server), &got); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if !reflect.DeepEqual(got, *want) {
		t.Errorf("got %+v, want %+v", got, *want)
	}

	client2, server2 := pipe(t)
	wantResp := &Response{Import: &ImportStats{Imported: 1, Replaced: 2, Skipped: 3}}
	if err := WriteMessage(client2, wantResp); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	var gotResp Response
	if err := ReadMessage(server2, bufio.NewReader(server2), &gotResp); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if gotResp.Import == nil || *gotResp.Import != *wantResp.Import {
		t.Errorf("got %+v, want %+v", gotResp.Import, wantResp.Import)
	}
}

func TestRoundTripResponseWithEntries(t *testing.T) {
	client, server := pipe(t)

	now := time.Now().Truncate(time.Second)
	want := &Response{Entries: []Entry{{TokenID: "a", Comment: "c", UpdatedAt: now}}}
	if err := WriteMessage(client, want); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	var got Response
	if err := ReadMessage(server, bufio.NewReader(server), &got); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if len(got.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(got.Entries))
	}
	if got.Entries[0].TokenID != "a" || got.Entries[0].Comment != "c" {
		t.Errorf("entry = %+v, want token a / comment c", got.Entries[0])
	}
	if !got.Entries[0].UpdatedAt.Equal(now) {
		t.Errorf("UpdatedAt = %v, want %v", got.Entries[0].UpdatedAt, now)
	}
}

// Secrets can be large, so a message longer than bufio's internal buffer must
// still be read in full rather than truncated.
func TestLargeMessageRoundTrips(t *testing.T) {
	client, server := pipe(t)

	big := strings.Repeat("A", 500_000)
	go func() {
		WriteMessage(client, &Request{Op: OpAdd, TokenID: "big", Secret: big})
	}()

	var got Request
	if err := ReadMessage(server, bufio.NewReader(server), &got); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if got.Secret != big {
		t.Errorf("secret round-tripped as %d bytes, want %d", len(got.Secret), len(big))
	}
}

func TestWriteRejectsOversizedMessage(t *testing.T) {
	client, _ := pipe(t)

	err := WriteMessage(client, &Request{Op: OpAdd, Secret: strings.Repeat("A", MaxMessageBytes+1)})
	if err == nil {
		t.Fatal("WriteMessage accepted an oversized message, want an error")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("error = %v, want it to mention the limit", err)
	}
}

// A peer that streams without a newline must not be able to make the daemon
// buffer without bound.
func TestReadRejectsOversizedMessage(t *testing.T) {
	client, server := pipe(t)

	go func() {
		chunk := strings.Repeat("A", 64<<10)
		for range (MaxMessageBytes / len(chunk)) + 4 {
			if _, err := client.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}()

	var got Request
	err := ReadMessage(server, bufio.NewReader(server), &got)
	if err == nil {
		t.Fatal("ReadMessage accepted an unbounded stream, want an error")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("error = %v, want it to mention the limit", err)
	}
}

func TestReadRejectsMalformedJSON(t *testing.T) {
	client, server := pipe(t)

	go func() {
		client.Write([]byte("{this is not json}\n"))
	}()

	var got Request
	if err := ReadMessage(server, bufio.NewReader(server), &got); err == nil {
		t.Error("ReadMessage accepted malformed JSON, want an error")
	}
}

// The daemon writes one line per message; a trailing message without its
// newline (a peer that closed early) should still decode.
func TestReadToleratesMissingTrailingNewline(t *testing.T) {
	client, server := pipe(t)

	go func() {
		client.Write([]byte(`{"op":"list"}`))
		client.Close()
	}()

	var got Request
	if err := ReadMessage(server, bufio.NewReader(server), &got); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if got.Op != OpList {
		t.Errorf("op = %q, want %q", got.Op, OpList)
	}
}

func TestResponseErr(t *testing.T) {
	if err := (&Response{}).Err(); err != nil {
		t.Errorf("Err() on a successful response = %v, want nil", err)
	}
	err := (&Response{Error: "boom"}).Err()
	if err == nil || err.Error() != "boom" {
		t.Errorf("Err() = %v, want \"boom\"", err)
	}
}

// A response carrying only a secret must not include stray fields that would
// confuse the client; omitempty keeps the wire format tight.
func TestReadDeadlineApplies(t *testing.T) {
	_, server := pipe(t)

	// Nothing is ever written, so the read must fail on its deadline rather
	// than hanging forever.
	start := time.Now()
	if err := server.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := server.Read(buf); err == nil {
		t.Fatal("read succeeded with nothing written")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("read blocked for %v, want it bounded by the deadline", elapsed)
	}
}
