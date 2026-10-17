# cipherstore

A single-binary interface to a [SQLCipher](https://www.zetetic.net/sqlcipher/)
database for storing login credentials and other secrets.

cipherstore splits into a long-running daemon that holds the decrypted database
in memory and a thin client that talks to it over UNIX-domain sockets. You
unlock once, then every other command is instant and passwordless until the
store locks again. The daemon is designed to run as a systemd **user** service.

```console
$ cipherstore start -d
cipherstore daemon started (pid 4213)
$ cipherstore unlock 30m
Password:
unlocked; locks at Mon, 05 Oct 2026 19:26:11 BST
$ cipherstore add github ghp_xxxxxxxx "work account"
added github
$ cipherstore get github
ghp_xxxxxxxx
$ cipherstore list
TOKEN ID  COMMENT       LAST UPDATED
github    work account  2026-10-05T18:56:11+01:00
```

Design and implementation notes — architecture, protocol, the SQLCipher keying
details and the full security analysis — live in [TECHNOTES.md](TECHNOTES.md).

## Install

Requires Go 1.24+ and a C compiler. SQLCipher itself is vendored through
[`mutecomm/go-sqlcipher`](https://github.com/mutecomm/go-sqlcipher), built with
its bundled LibTomCrypt backend, so there is no SQLCipher package — nor
OpenSSL — to install.

```sh
go build -o cipherstore .
install -Dm755 cipherstore ~/.local/bin/cipherstore
```

Stamp a version in if you like:

```sh
go build -ldflags "-X github.com/jamespo/cipherstore/internal/cli.version=$(git describe --tags --always)" -o cipherstore .
```

The first build compiles the SQLCipher amalgamation and takes a minute or two;
later builds are cached.

## Commands

### Daemon lifecycle

| Command | Description |
| --- | --- |
| `cipherstore start` | Run the daemon in the foreground. This is the form systemd wants. |
| `cipherstore start -d` | Fork into the background and return once the daemon is listening. |
| `cipherstore start -quiet` | Suppress log output. |
| `cipherstore stop` | Stop the daemon and remove its sockets. |
| `cipherstore unlock [duration]` | Prompt for the password and decrypt the store. With a duration, lock again after it elapses. |
| `cipherstore lock [duration]` | Lock now, or — with a duration — schedule a lock that far ahead. |
| `cipherstore status` | Report lock state, PID, database path and any pending auto-lock. |

Durations are Go duration strings: `90s`, `10m`, `2h`, `1h30m`.

Note the asymmetry, which follows from reading each command as an instruction
about the future:

- `unlock 10m` unlocks **now** and locks in 10 minutes.
- `lock 10m` stays unlocked and locks in 10 minutes. It does *not* lock
  immediately. Use a bare `cipherstore lock` for that.

Re-running either command replaces any pending auto-lock, so you can extend or
shorten a session at will.

### Secrets

These require an unlocked store.

| Command | Description |
| --- | --- |
| `cipherstore get <tokenid>` | Print the secret. |
| `cipherstore get -n <tokenid>` | Print the secret with no trailing newline. |
| `cipherstore add <tokenid> [secret] [comment]` | Add or update a token. Prompts for the secret if omitted. |
| `cipherstore add -stdin <tokenid> [comment]` | Read the secret from standard input. |
| `cipherstore delete <tokenid>` | Remove a token. |
| `cipherstore list` | List token IDs, comments and update times. |

`add` is an upsert. When you supply no comment, an existing comment is left
alone, so `cipherstore add github <rotated-token>` rotates a secret without
losing its label. Pass an explicit `""` to clear a comment.

### Getting secrets in without exposing them

A secret on the command line is visible to every process on the machine via
`/proc/<pid>/cmdline`, and lands in your shell history. cipherstore accepts it
that way because it is convenient, but prefer one of these:

```sh
cipherstore add github                     # prompts, echo off
pwgen -s 32 1 | cipherstore add -stdin github "work account"
cipherstore add -stdin github < token.txt
```

`unlock` reads its password from `/dev/tty` with echo disabled, so a redirected
stdout or stderr does not capture the prompt or divert the password. When no
terminal is available it falls back to reading one line from stdin, which is
what makes non-interactive use possible:

```sh
systemd-ask-password | cipherstore unlock 8h
```

### Exit status

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Error (locked, no daemon, wrong password, I/O failure) |
| 2 | Invalid usage |
| 3 | Token not found |

Exit code 3 is distinct so scripts can tell "no such token" from a real
failure:

```sh
if token=$(cipherstore get ci-deploy-key); then
    deploy --token "$token"
elif [ $? -eq 3 ]; then
    echo "no deploy key configured" >&2
fi
```

## Running under systemd

Install the unit from `contrib/cipherstore.service`:

```sh
install -Dm644 contrib/cipherstore.service ~/.config/systemd/user/cipherstore.service
systemctl --user daemon-reload
systemctl --user enable --now cipherstore
```

Then unlock it once per login:

```sh
cipherstore unlock 8h
```

Logs go to the journal:

```sh
journalctl --user -u cipherstore -f
```

The daemon always starts locked, including after a restart, so a crash or a
reboot never leaves the store readable.

Note that `start -d` sends the daemon's stdio to `/dev/null`, so its log output
is discarded. Startup failures are still reported to the caller over a
dedicated pipe, but for ongoing logs use systemd (or run `start` in the
foreground).

## Files

| Path | Mode | Purpose |
| --- | --- | --- |
| `~/.local/state/cipherstore/` | 0700 | Runtime directory |
| `~/.local/state/cipherstore/control` | 0700 | Control socket; exists while the daemon runs |
| `~/.local/state/cipherstore/authed` | 0700 | Secret-operation socket; **exists only while unlocked** |
| `~/.local/state/cipherstore/daemon.lock` | 0600 | `flock`ed to enforce a single daemon per user |
| `~/.local/share/cipherstore/cipherstore.sqlite` | 0600 | The encrypted database |

`XDG_STATE_HOME` and `XDG_DATA_HOME` are honoured when set to absolute paths.

## Security

cipherstore protects secrets at rest and limits exposure while unlocked. It
does **not** defend against an attacker who already runs code as your user:
such an attacker can simply ask the daemon for the secrets, exactly as you can.
The hardening is aimed at other local users, at the on-disk footprint, and at
mistakes. [TECHNOTES.md](TECHNOTES.md#security) has the full analysis; the
practical points for a user are:

- **Secrets passed as command-line arguments** are world-visible via `/proc`.
  Use the prompt or `-stdin`.
- **`cipherstore get` output** goes to stdout and may land in shell history,
  scrollback or a pipe buffer.
- **The passphrase strength is the security of the database.** SQLCipher uses
  PBKDF2-HMAC-SHA512 with 256,000 iterations over a random per-database salt,
  which is strong, but it cannot rescue a weak passphrase.
- **Secrets may reach swap.** `mlockall` usually fails for an unprivileged
  process; use an encrypted swap device or no swap if this matters to you.
- **No duress or tamper detection.** An attacker with write access to the
  database can destroy or roll it back; they cannot read it.
- **No key rotation command.** Re-keying means `list`ing, `get`ting each secret,
  and rebuilding a fresh database under a new passphrase.

## Testing

```sh
go test ./...
```

The first run compiles the SQLCipher amalgamation and takes a couple of
minutes. See [TECHNOTES.md](TECHNOTES.md#testing) for what the suite covers.

## License

MIT.
