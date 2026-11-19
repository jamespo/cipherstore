package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// noEchoEnv names the environment variable that, when set to any value,
// suppresses the * feedback at password and secret prompts so nothing at all
// is echoed -- not even the length of what was typed.
const noEchoEnv = "CIPHERSTORE_NOECHO"

// errEntryCancelled is returned when the user aborts a prompt with Ctrl-C or
// Ctrl-D.
var errEntryCancelled = errors.New("password entry cancelled")

// readPassword reads a passphrase from the terminal, echoing a * for each
// character typed (or nothing, if CIPHERSTORE_NOECHO is set).
//
// The prompt is written to and read from /dev/tty rather than stdin/stdout, so
// it still works when either is redirected -- `cipherstore unlock > log` must
// not send the prompt into the file, and must not read the passphrase from it.
// When no terminal is available (a script, a pipe) it falls back to reading a
// single line from stdin, with no echo of any kind.
func (e *env) readPassword(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return e.readPasswordFromStdin()
	}
	defer tty.Close()

	fd := int(tty.Fd())
	if !term.IsTerminal(fd) {
		return e.readPasswordFromStdin()
	}

	fmt.Fprint(tty, prompt)
	var pw []byte
	if _, noEcho := os.LookupEnv(noEchoEnv); noEcho {
		pw, err = term.ReadPassword(fd)
		fmt.Fprintln(tty)
	} else {
		pw, err = readMaskedTTY(tty, fd)
	}
	if err != nil {
		if errors.Is(err, syscall.EINTR) {
			return nil, errEntryCancelled
		}
		if errors.Is(err, errEntryCancelled) {
			return nil, err
		}
		return nil, fmt.Errorf("read password: %w", err)
	}
	if len(pw) == 0 {
		return nil, errors.New("password must not be empty")
	}
	return pw, nil
}

// readMaskedTTY puts the terminal in raw mode for the duration of a masked
// read, restoring it afterwards whatever happens.
func readMaskedTTY(tty *os.File, fd int) ([]byte, error) {
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	defer term.Restore(fd, state)
	return readMasked(tty, tty)
}

// Control bytes readMasked acts on. In raw mode the terminal delivers these
// as ordinary input rather than turning them into signals or line edits.
const (
	keyCtrlC     = 0x03
	keyCtrlD     = 0x04
	keyBackspace = 0x08
	keyLF        = '\n'
	keyCR        = '\r'
	keyCtrlU     = 0x15
	keyCtrlW     = 0x17
	keyEscape    = 0x1b
	keyDelete    = 0x7f
)

// readMasked reads a line from r one byte at a time, writing a * to w for each
// character entered. It implements just enough line editing to be usable:
// Backspace removes the last character, Ctrl-U and Ctrl-W clear the input,
// Enter finishes, and Ctrl-C (or Ctrl-D) cancels. Terminal escape sequences,
// such as those sent by the arrow keys, are discarded.
//
// A multi-byte UTF-8 character produces a single *, and Backspace removes it
// whole. The terminal is expected to be in raw mode, so line endings are
// written as \r\n.
//
// The returned slice is the only copy of the input left in memory: buffers
// outgrown along the way are zeroed, as is everything on error.
func readMasked(r io.Reader, w io.Writer) ([]byte, error) {
	buf := make([]byte, 0, 64)
	var b [1]byte
	inEscape := false // inside an escape sequence, after ESC [ or ESC O
	afterEsc := false // just read ESC

	fail := func(err error) ([]byte, error) {
		zero(buf[:cap(buf)])
		fmt.Fprint(w, "\r\n")
		return nil, err
	}

	for {
		n, err := r.Read(b[:])
		if n == 0 {
			if err == nil {
				continue
			}
			if errors.Is(err, io.EOF) {
				return fail(errEntryCancelled)
			}
			return fail(err)
		}
		c := b[0]

		switch {
		case afterEsc:
			afterEsc = false
			// ESC [ and ESC O introduce multi-byte sequences; anything else
			// was a two-byte Alt-key combination, now fully consumed.
			inEscape = c == '[' || c == 'O'
			continue
		case inEscape:
			// A sequence ends with a final byte in the range @ to ~.
			if c >= 0x40 && c <= 0x7e {
				inEscape = false
			}
			continue
		}

		switch c {
		case keyCR, keyLF:
			fmt.Fprint(w, "\r\n")
			return buf, nil
		case keyCtrlC, keyCtrlD:
			return fail(errEntryCancelled)
		case keyBackspace, keyDelete:
			if len(buf) == 0 {
				continue
			}
			// Drop UTF-8 continuation bytes, then the lead byte.
			i := len(buf) - 1
			for i > 0 && isContinuation(buf[i]) {
				i--
			}
			zero(buf[i:])
			buf = buf[:i]
			fmt.Fprint(w, "\b \b")
		case keyCtrlU, keyCtrlW:
			// The input is invisible, so there are no word boundaries for the
			// user to see; treat Ctrl-W like Ctrl-U and clear everything.
			fmt.Fprint(w, strings.Repeat("\b \b", runeCount(buf)))
			zero(buf)
			buf = buf[:0]
		case keyEscape:
			afterEsc = true
		default:
			if c < 0x20 {
				// Ignore other control characters (Tab, Ctrl-A, ...).
				continue
			}
			if len(buf) == cap(buf) {
				grown := make([]byte, len(buf), 2*cap(buf))
				copy(grown, buf)
				zero(buf)
				buf = grown
			}
			buf = append(buf, c)
			if !isContinuation(c) {
				fmt.Fprint(w, "*")
			}
		}
	}
}

// isContinuation reports whether c is a UTF-8 continuation byte.
func isContinuation(c byte) bool { return c&0xc0 == 0x80 }

// runeCount counts the characters readMasked has echoed a * for.
func runeCount(b []byte) int {
	n := 0
	for _, c := range b {
		if !isContinuation(c) {
			n++
		}
	}
	return n
}

// readPasswordFromStdin reads one line from stdin for non-interactive use.
func (e *env) readPasswordFromStdin() ([]byte, error) {
	r := bufio.NewReader(io.LimitReader(e.stdin, maxStdinPasswordBytes))
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read password from stdin: %w", err)
	}
	pw := []byte(strings.TrimRight(line, "\r\n"))
	if len(pw) == 0 {
		return nil, errors.New("password must not be empty")
	}
	return pw, nil
}

// maxStdinPasswordBytes bounds a passphrase read from a pipe.
const maxStdinPasswordBytes = 4096
