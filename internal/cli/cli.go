// Package cli implements cipherstore's command-line interface.
//
// Every command except `start` is a thin client: it opens one of the daemon's
// sockets, sends a single request and renders the reply. No command touches
// the database directly, so the decrypted store only ever lives in the
// daemon's address space.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/jamespo/cipherstore/internal/daemon"
	"github.com/jamespo/cipherstore/internal/paths"
	"github.com/jamespo/cipherstore/internal/protocol"
)

// Exit codes. These are part of the interface: scripts rely on being able to
// tell "no such token" apart from a real failure.
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitNotFound = 3
)

// env carries the process environment a command needs, so commands stay
// testable and never reach for globals.
type env struct {
	layout paths.Layout
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

// version is overridden at build time with -ldflags "-X ...version=...".
var version = "dev"

// Run dispatches argv (excluding the program name) and returns the process
// exit code.
func Run(args []string) int {
	layout, err := paths.Default()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cipherstore: %v\n", err)
		return exitError
	}
	e := &env{layout: layout, stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr}

	if len(args) == 0 {
		usage(e.stderr)
		return exitUsage
	}

	cmd, rest := args[0], args[1:]
	var cmdErr error
	switch cmd {
	case "start":
		cmdErr = e.cmdStart(rest)
	case "unlock":
		cmdErr = e.cmdUnlock(rest)
	case "lock":
		cmdErr = e.cmdLock(rest)
	case "stop":
		cmdErr = e.cmdStop(rest)
	case "status":
		cmdErr = e.cmdStatus(rest)
	case "get":
		cmdErr = e.cmdGet(rest)
	case "add":
		cmdErr = e.cmdAdd(rest)
	case "delete":
		cmdErr = e.cmdDelete(rest)
	case "list":
		cmdErr = e.cmdList(rest)
	case "export":
		cmdErr = e.cmdExport(rest)
	case "import":
		cmdErr = e.cmdImport(rest)
	case "version", "--version", "-v":
		fmt.Fprintf(e.stdout, "cipherstore %s\n", version)
		return exitOK
	case "help", "--help", "-h":
		usage(e.stdout)
		return exitOK
	default:
		fmt.Fprintf(e.stderr, "cipherstore: unknown command %q\n\n", cmd)
		usage(e.stderr)
		return exitUsage
	}

	if cmdErr != nil {
		fmt.Fprintf(e.stderr, "cipherstore: %v\n", cmdErr)
		return exitCodeFor(cmdErr)
	}
	return exitOK
}

// errNotFound marks a missing token so Run can map it to exitNotFound.
var errNotFound = errors.New("not found")

// errUsage marks an argument error so Run can map it to exitUsage.
var errUsage = errors.New("usage")

func exitCodeFor(err error) int {
	switch {
	case errors.Is(err, errNotFound):
		return exitNotFound
	case errors.Is(err, errUsage):
		return exitUsage
	default:
		return exitError
	}
}

func (e *env) cmdStart(args []string) error {
	fs := newFlagSet("start")
	detach := fs.Bool("detach", false, "fork into the background instead of running in the foreground")
	fs.BoolVar(detach, "d", false, "shorthand for -detach")
	quiet := fs.Bool("quiet", false, "suppress log output")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%w: start takes no arguments", errUsage)
	}

	if *detach {
		return e.detach(*quiet)
	}

	logOut := io.Writer(e.stderr)
	if *quiet {
		logOut = io.Discard
	}
	logger := log.New(logOut, "cipherstore: ", log.LstdFlags)

	// When started by `start -d` this is the pipe the parent is waiting on.
	ready := readyPipe()

	d, err := daemon.New(e.layout, logger)
	if err != nil {
		reportStartup(ready, err)
		return err
	}
	reportStartup(ready, nil)
	return d.Run()
}

// readyFDEnv names the environment variable `start -d` uses to hand the child
// the write end of its startup-status pipe.
const readyFDEnv = "CIPHERSTORE_READY_FD"

// readyOK is the sentinel a successfully started daemon writes to the pipe.
const readyOK = "ok"

// readyPipe returns the startup-status pipe inherited from a `start -d`
// parent, or nil when the daemon was started directly.
func readyPipe() *os.File {
	fd, err := strconv.Atoi(os.Getenv(readyFDEnv))
	if err != nil || fd < 3 {
		return nil
	}
	return os.NewFile(uintptr(fd), "startup-status")
}

// reportStartup tells the `start -d` parent whether startup succeeded, then
// closes the pipe. Closing matters as much as writing: it is what releases the
// parent from its read, and it stops later daemon logging from blocking on a
// pipe nobody is draining.
func reportStartup(pipe *os.File, startErr error) {
	if pipe == nil {
		return
	}
	defer pipe.Close()
	if startErr != nil {
		fmt.Fprint(pipe, startErr.Error())
		return
	}
	fmt.Fprint(pipe, readyOK)
}

// detach re-executes the daemon in a new session so an interactive shell is
// not blocked. Under systemd, run without -detach and use Type=simple.
//
// Because the child's stderr goes to /dev/null, its log output is discarded;
// startup errors are relayed over a dedicated pipe so a failure to start is
// still reported to the caller rather than silently swallowed.
func (e *env) detach(quiet bool) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate own executable: %w", err)
	}
	args := []string{exe, "start"}
	if quiet {
		args = append(args, "-quiet")
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer devNull.Close()

	statusR, statusW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create status pipe: %w", err)
	}
	defer statusR.Close()

	proc, err := os.StartProcess(exe, args, &os.ProcAttr{
		// The status pipe is fd 3 in the child; stdio goes to /dev/null so the
		// daemon holds no reference to the launching terminal.
		Files: []*os.File{devNull, devNull, devNull, statusW},
		Env:   append(os.Environ(), fmt.Sprintf("%s=3", readyFDEnv)),
		// Setsid detaches from the controlling terminal so the daemon is not
		// killed when the launching shell exits.
		Sys: sysDetach(),
	})
	// Drop the parent's copy of the write end, so reading reaches EOF when the
	// child closes its end or dies.
	statusW.Close()
	if err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}
	pid := proc.Pid
	// Release before waiting: the daemon outlives us, and we must not leave it
	// as an un-reaped child of a shell.
	if err := proc.Release(); err != nil {
		return err
	}

	status, err := readStatus(statusR, 10*time.Second)
	switch {
	case err != nil:
		return fmt.Errorf("daemon (pid %d) did not report startup: %w", pid, err)
	case status == readyOK:
		fmt.Fprintf(e.stdout, "cipherstore daemon started (pid %d)\n", pid)
		return nil
	case status == "":
		return fmt.Errorf("daemon (pid %d) exited during startup without reporting an error", pid)
	default:
		return errors.New(status)
	}
}

// readStatus reads the child's startup report until EOF, bounded by timeout so
// a wedged child cannot hang the shell.
func readStatus(r *os.File, timeout time.Duration) (string, error) {
	if err := r.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(r, 64<<10))
	if err != nil && !errors.Is(err, io.EOF) {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return "", fmt.Errorf("timed out after %s", timeout)
		}
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (e *env) cmdUnlock(args []string) error {
	fs := newFlagSet("unlock")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	duration, err := optionalDurationArg(fs.Args(), "unlock [duration]")
	if err != nil {
		return err
	}

	password, err := e.readPassword("Password: ")
	if err != nil {
		return err
	}
	defer zero(password)

	resp, err := e.sendControl(&protocol.Request{
		Op:       protocol.OpUnlock,
		Password: string(password),
		Duration: duration,
	})
	if err != nil {
		return err
	}
	if resp.Status != nil && !resp.Status.LockAt.IsZero() {
		fmt.Fprintf(e.stdout, "unlocked; locks at %s\n", resp.Status.LockAt.Format(time.RFC1123))
	} else {
		fmt.Fprintln(e.stdout, "unlocked")
	}
	return nil
}

func (e *env) cmdLock(args []string) error {
	fs := newFlagSet("lock")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	duration, err := optionalDurationArg(fs.Args(), "lock [duration]")
	if err != nil {
		return err
	}

	resp, err := e.sendControl(&protocol.Request{Op: protocol.OpLock, Duration: duration})
	if err != nil {
		return err
	}
	if resp.Status != nil && !resp.Status.LockAt.IsZero() {
		fmt.Fprintf(e.stdout, "locks at %s\n", resp.Status.LockAt.Format(time.RFC1123))
	} else {
		fmt.Fprintln(e.stdout, "locked")
	}
	return nil
}

func (e *env) cmdStop(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("%w: stop takes no arguments", errUsage)
	}
	if _, err := e.sendControl(&protocol.Request{Op: protocol.OpStop}); err != nil {
		return err
	}
	fmt.Fprintln(e.stdout, "daemon stopping")
	return nil
}

func (e *env) cmdStatus(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("%w: status takes no arguments", errUsage)
	}
	resp, err := e.sendControl(&protocol.Request{Op: protocol.OpStatus})
	if err != nil {
		return err
	}
	st := resp.Status
	if st == nil {
		return errors.New("daemon returned no status")
	}
	state := "locked"
	if st.Unlocked {
		state = "unlocked"
	}
	fmt.Fprintf(e.stdout, "state:    %s\n", state)
	fmt.Fprintf(e.stdout, "pid:      %d\n", st.PID)
	fmt.Fprintf(e.stdout, "database: %s\n", st.DBPath)
	if !st.LockAt.IsZero() {
		fmt.Fprintf(e.stdout, "locks at: %s (in %s)\n",
			st.LockAt.Format(time.RFC1123), time.Until(st.LockAt).Round(time.Second))
	}
	return nil
}

func (e *env) cmdGet(args []string) error {
	fs := newFlagSet("get")
	noNewline := fs.Bool("n", false, "do not print a trailing newline after the secret")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("%w: get <tokenid>", errUsage)
	}
	tokenID := fs.Arg(0)

	resp, err := e.sendAuthed(&protocol.Request{Op: protocol.OpGet, TokenID: tokenID})
	if err != nil {
		return err
	}
	if !resp.Found {
		return fmt.Errorf("%q: %w", tokenID, errNotFound)
	}
	if *noNewline {
		fmt.Fprint(e.stdout, resp.Secret)
	} else {
		fmt.Fprintln(e.stdout, resp.Secret)
	}
	return nil
}

func (e *env) cmdAdd(args []string) error {
	fs := newFlagSet("add")
	fromStdin := fs.Bool("stdin", false, "read the secret from standard input instead of the command line")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	rest := fs.Args()
	if len(rest) == 0 || len(rest) > 3 {
		return fmt.Errorf("%w: add <tokenid> [secret] [comment]", errUsage)
	}

	req := &protocol.Request{Op: protocol.OpAdd, TokenID: rest[0]}

	switch {
	case *fromStdin:
		if len(rest) > 2 {
			return fmt.Errorf("%w: with -stdin, use add -stdin <tokenid> [comment]", errUsage)
		}
		secret, err := readAllTrimNewline(e.stdin)
		if err != nil {
			return fmt.Errorf("read secret from stdin: %w", err)
		}
		req.Secret = secret
		if len(rest) == 2 {
			req.Comment, req.SetComment = rest[1], true
		}

	case len(rest) == 1:
		// No secret on the command line: prompt for it, so it stays out of
		// the shell history and the process table.
		secret, err := e.readPassword("Secret: ")
		if err != nil {
			return err
		}
		defer zero(secret)
		req.Secret = string(secret)

	default:
		req.Secret = rest[1]
		if len(rest) == 3 {
			req.Comment, req.SetComment = rest[2], true
		}
	}

	resp, err := e.sendAuthed(req)
	if err != nil {
		return err
	}
	if resp.Created {
		fmt.Fprintf(e.stdout, "added %s\n", req.TokenID)
	} else {
		fmt.Fprintf(e.stdout, "updated %s\n", req.TokenID)
	}
	return nil
}

func (e *env) cmdDelete(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("%w: delete <tokenid>", errUsage)
	}
	tokenID := args[0]
	resp, err := e.sendAuthed(&protocol.Request{Op: protocol.OpDelete, TokenID: tokenID})
	if err != nil {
		return err
	}
	if !resp.Found {
		return fmt.Errorf("%q: %w", tokenID, errNotFound)
	}
	fmt.Fprintf(e.stdout, "deleted %s\n", tokenID)
	return nil
}

func (e *env) cmdList(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("%w: list takes no arguments", errUsage)
	}
	resp, err := e.sendAuthed(&protocol.Request{Op: protocol.OpList})
	if err != nil {
		return err
	}
	if len(resp.Entries) == 0 {
		fmt.Fprintln(e.stderr, "store is empty")
		return nil
	}

	tw := tabwriter.NewWriter(e.stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "TOKEN ID\tCOMMENT\tLAST UPDATED")
	for _, en := range resp.Entries {
		comment := en.Comment
		if comment == "" {
			comment = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", en.TokenID, comment, en.UpdatedAt.Local().Format(time.RFC3339))
	}
	return tw.Flush()
}

// cmdExport writes every entry, including secrets, to a JSON flat file.
func (e *env) cmdExport(args []string) error {
	fs := newFlagSet("export")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("%w: export <file>", errUsage)
	}
	path := fs.Arg(0)

	resp, err := e.sendAuthed(&protocol.Request{Op: protocol.OpExport})
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(resp.Entries, "", "  ")
	if err != nil {
		return fmt.Errorf("encode export: %w", err)
	}
	data = append(data, '\n')

	if err := writeOwnerOnlyFile(path, data); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "exported %d entries to %s\n", len(resp.Entries), path)
	return nil
}

// cmdImport reads entries from a JSON flat file (as produced by `export`) and
// adds them to the store. An entry colliding with an existing token is left
// untouched unless -replace-newer is given and the imported entry is newer.
func (e *env) cmdImport(args []string) error {
	fs := newFlagSet("import")
	replaceNewer := fs.Bool("replace-newer", false, "replace an existing entry when the imported entry is newer (by updated_at)")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("%w: import [-replace-newer] <file>", errUsage)
	}
	path := fs.Arg(0)

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var entries []protocol.Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	for i, en := range entries {
		if en.TokenID == "" {
			return fmt.Errorf("%s: entry %d has an empty token id", path, i)
		}
	}

	resp, err := e.sendAuthed(&protocol.Request{
		Op:           protocol.OpImport,
		Entries:      entries,
		ReplaceNewer: *replaceNewer,
	})
	if err != nil {
		return err
	}
	st := resp.Import
	if st == nil {
		return errors.New("daemon returned no import result")
	}
	fmt.Fprintf(e.stdout, "imported %d, replaced %d, skipped %d\n", st.Imported, st.Replaced, st.Skipped)
	return nil
}

// writeOwnerOnlyFile writes data to path such that only its owner can read
// it, refusing to follow an existing symlink so a planted link cannot
// redirect the write.
func writeOwnerOnlyFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	// OpenFile's mode is only applied on creation and is masked by umask, and
	// an existing file keeps whatever mode it already had; chmod explicitly so
	// the file is 0600 either way.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Close()
}

// newFlagSet builds a flag set that reports errors through our own messages
// rather than printing its own usage block.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// optionalDurationArg validates a trailing, optional duration argument shared
// by `unlock` and `lock`.
func optionalDurationArg(args []string, form string) (string, error) {
	switch len(args) {
	case 0:
		return "", nil
	case 1:
		// Parse client-side so a typo is rejected before the passphrase is
		// prompted for and sent.
		if _, err := time.ParseDuration(args[0]); err != nil {
			return "", fmt.Errorf("%w: invalid duration %q (try 10m, 2h, 90s)", errUsage, args[0])
		}
		return args[0], nil
	default:
		return "", fmt.Errorf("%w: %s", errUsage, form)
	}
}

// readAllTrimNewline reads r fully and strips a single trailing newline, which
// is what a shell here-string or `echo` adds.
func readAllTrimNewline(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, protocol.MaxMessageBytes))
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"), nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `cipherstore - an encrypted store for logins and other secrets

Usage:
  cipherstore <command> [arguments]

Daemon:
  start [-d] [-quiet]        Run the daemon (foreground by default; -d detaches)
  stop                       Stop the daemon
  unlock [duration]          Prompt for the password and decrypt the store,
                             optionally auto-locking after duration (e.g. 10m)
  lock [duration]            Lock now, or schedule a lock after duration
  status                     Report whether the store is unlocked

Secrets (require an unlocked store):
  get [-n] <tokenid>         Print the secret for tokenid
  add <tokenid> [secret] [comment]
                             Add or update a token; the secret is prompted for
                             when omitted
  add -stdin <tokenid> [comment]
                             Read the secret from standard input
  delete <tokenid>           Remove a token
  list                       List token ids, comments and update times
  export <file>              Write every entry, including secrets, to a JSON
                             file readable only by its owner
  import [-replace-newer] <file>
                             Add entries from a JSON file (as produced by
                             export); an entry colliding with an existing
                             token is left untouched unless -replace-newer is
                             given and the imported entry is newer

Other:
  version                    Print the version
  help                       Print this message

Exit status:
  0  success
  1  error
  2  invalid usage
  3  token not found

Passing a secret as a command-line argument exposes it to other processes via
the process table and to your shell history. Prefer the prompt or -stdin.
`)
}
