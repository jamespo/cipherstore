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

// readPassword reads a passphrase without echoing it.
//
// The prompt is written to and read from /dev/tty rather than stdin/stdout, so
// it still works when either is redirected -- `cipherstore unlock > log` must
// not send the prompt into the file, and must not read the passphrase from it.
// When no terminal is available (a script, a pipe) it falls back to reading a
// single line from stdin.
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
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(tty)
	if err != nil {
		if errors.Is(err, syscall.EINTR) {
			return nil, errors.New("password entry cancelled")
		}
		return nil, fmt.Errorf("read password: %w", err)
	}
	if len(pw) == 0 {
		return nil, errors.New("password must not be empty")
	}
	return pw, nil
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
