package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jamespo/cipherstore/internal/ipc"
)

// newEnv returns an env whose streams are captured and whose sockets point at
// a directory with no daemon, so client commands fail fast.
func newEnv(t *testing.T, stdin string) (*env, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	// t.TempDir creates its numbered subdirectory with 0777 masked by umask,
	// which the socket path checks reject; tighten it to what cipherstore
	// creates for itself.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	var out, errOut bytes.Buffer
	e := &env{
		stdin:  strings.NewReader(stdin),
		stdout: &out,
		stderr: &errOut,
	}
	e.layout.StateDir = dir
	e.layout.ControlSocket = filepath.Join(dir, "control")
	e.layout.AuthedSocket = filepath.Join(dir, "authed")
	return e, &out, &errOut
}

func TestUsageErrorsExitTwo(t *testing.T) {
	tests := []struct {
		name string
		run  func(e *env) error
	}{
		{"get with no args", func(e *env) error { return e.cmdGet(nil) }},
		{"get with two args", func(e *env) error { return e.cmdGet([]string{"a", "b"}) }},
		{"add with no args", func(e *env) error { return e.cmdAdd(nil) }},
		{"add with four args", func(e *env) error { return e.cmdAdd([]string{"a", "b", "c", "d"}) }},
		{"delete with no args", func(e *env) error { return e.cmdDelete(nil) }},
		{"delete with two args", func(e *env) error { return e.cmdDelete([]string{"a", "b"}) }},
		{"list with args", func(e *env) error { return e.cmdList([]string{"x"}) }},
		{"status with args", func(e *env) error { return e.cmdStatus([]string{"x"}) }},
		{"stop with args", func(e *env) error { return e.cmdStop([]string{"x"}) }},
		{"start with args", func(e *env) error { return e.cmdStart([]string{"x"}) }},
		{"unlock with two durations", func(e *env) error { return e.cmdUnlock([]string{"10m", "20m"}) }},
		{"unlock with a bad duration", func(e *env) error { return e.cmdUnlock([]string{"12parsecs"}) }},
		{"lock with a bad duration", func(e *env) error { return e.cmdLock([]string{"soon"}) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, _, _ := newEnv(t, "")
			err := tt.run(e)
			if err == nil {
				t.Fatal("command succeeded, want a usage error")
			}
			if code := exitCodeFor(err); code != exitUsage {
				t.Errorf("exit code = %d, want %d (error: %v)", code, exitUsage, err)
			}
		})
	}
}

// A bad duration must be caught before the passphrase is prompted for, so the
// user is not asked to type a password that is about to be thrown away.
func TestUnlockRejectsBadDurationBeforePrompting(t *testing.T) {
	const pw = "a password that must not be consumed\n"
	e, _, _ := newEnv(t, pw)
	if err := e.cmdUnlock([]string{"nonsense"}); err == nil {
		t.Fatal("cmdUnlock accepted a bad duration")
	}
	if left := e.stdin.(*strings.Reader).Len(); left != len(pw) {
		t.Errorf("%d bytes consumed from stdin; the duration should be rejected before prompting", len(pw)-left)
	}
}

// Without a daemon the error must say so, rather than surfacing ENOENT.
func TestCommandsReportMissingDaemon(t *testing.T) {
	for _, tt := range []struct {
		name string
		run  func(e *env) error
	}{
		{"status", func(e *env) error { return e.cmdStatus(nil) }},
		{"stop", func(e *env) error { return e.cmdStop(nil) }},
		{"list", func(e *env) error { return e.cmdList(nil) }},
		{"get", func(e *env) error { return e.cmdGet([]string{"tok"}) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e, _, _ := newEnv(t, "")
			err := tt.run(e)
			if err == nil {
				t.Fatal("command succeeded with no daemon running")
			}
			if !errors.Is(err, errNoDaemon) {
				t.Errorf("error = %v, want errNoDaemon", err)
			}
		})
	}
}

// When the daemon is running but locked, the authed socket is absent and the
// message must point the user at `unlock` instead of `start`.
func TestAuthedCommandsReportLockedWhenDaemonPresent(t *testing.T) {
	e, _, _ := newEnv(t, "")

	// Stand in for a running daemon by creating a control socket.
	l, err := ipc.Listen(e.layout.ControlSocket, 0o700)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	err = e.cmdGet([]string{"tok"})
	if err == nil {
		t.Fatal("get succeeded while locked")
	}
	if !errors.Is(err, errLocked) {
		t.Errorf("error = %v, want errLocked", err)
	}
}

func TestExitCodeFor(t *testing.T) {
	tests := []struct {
		err  error
		want int
	}{
		{nil, exitError},
		{errors.New("boom"), exitError},
		{fmt.Errorf("x: %w", errUsage), exitUsage},
		{fmt.Errorf("x: %w", errNotFound), exitNotFound},
	}
	for _, tt := range tests {
		if tt.err == nil {
			continue
		}
		if got := exitCodeFor(tt.err); got != tt.want {
			t.Errorf("exitCodeFor(%v) = %d, want %d", tt.err, got, tt.want)
		}
	}
}

func TestRunUnknownCommandExitsTwo(t *testing.T) {
	if code := Run([]string{"frobnicate"}); code != exitUsage {
		t.Errorf("Run(frobnicate) = %d, want %d", code, exitUsage)
	}
}

func TestRunNoArgsExitsTwo(t *testing.T) {
	if code := Run(nil); code != exitUsage {
		t.Errorf("Run(nil) = %d, want %d", code, exitUsage)
	}
}

func TestRunHelpAndVersionSucceed(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h", "version", "--version", "-v"} {
		if code := Run([]string{arg}); code != exitOK {
			t.Errorf("Run(%q) = %d, want %d", arg, code, exitOK)
		}
	}
}

func TestOptionalDurationArg(t *testing.T) {
	if got, err := optionalDurationArg(nil, "form"); err != nil || got != "" {
		t.Errorf(`optionalDurationArg(nil) = %q, %v; want "", nil`, got, err)
	}
	if got, err := optionalDurationArg([]string{"10m"}, "form"); err != nil || got != "10m" {
		t.Errorf(`optionalDurationArg(["10m"]) = %q, %v; want "10m", nil`, got, err)
	}
	for _, args := range [][]string{{"nope"}, {"10m", "20m"}} {
		if _, err := optionalDurationArg(args, "form"); err == nil {
			t.Errorf("optionalDurationArg(%v) succeeded, want an error", args)
		}
	}
}

// A shell here-string or `echo` adds exactly one trailing newline, which must
// not become part of the secret.
func TestReadAllTrimNewline(t *testing.T) {
	tests := []struct{ in, want string }{
		{"secret\n", "secret"},
		{"secret\r\n", "secret"},
		{"secret", "secret"},
		{"secret\n\n", "secret\n"},
		{"", ""},
		{"with spaces \n", "with spaces "},
		{"multi\nline\n", "multi\nline"},
	}
	for _, tt := range tests {
		got, err := readAllTrimNewline(strings.NewReader(tt.in))
		if err != nil {
			t.Fatalf("readAllTrimNewline(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("readAllTrimNewline(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestReadPasswordFromStdinRejectsEmpty(t *testing.T) {
	for _, in := range []string{"", "\n", "\r\n"} {
		e, _, _ := newEnv(t, in)
		if _, err := e.readPasswordFromStdin(); err == nil {
			t.Errorf("readPasswordFromStdin(%q) succeeded, want an error", in)
		}
	}
}

func TestReadPasswordFromStdinStripsNewline(t *testing.T) {
	e, _, _ := newEnv(t, "my password\n")
	pw, err := e.readPasswordFromStdin()
	if err != nil {
		t.Fatalf("readPasswordFromStdin: %v", err)
	}
	if string(pw) != "my password" {
		t.Errorf("password = %q, want %q", pw, "my password")
	}
}

func TestZero(t *testing.T) {
	b := []byte("secret")
	zero(b)
	for i, c := range b {
		if c != 0 {
			t.Fatalf("byte %d = %d, want 0", i, c)
		}
	}
}

func TestUsageMentionsEveryCommand(t *testing.T) {
	var buf bytes.Buffer
	usage(&buf)
	text := buf.String()
	for _, cmd := range []string{"start", "stop", "unlock", "lock", "status", "get", "add", "delete", "list", "version", "help"} {
		if !strings.Contains(text, cmd) {
			t.Errorf("usage does not mention %q", cmd)
		}
	}
}
