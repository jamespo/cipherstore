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
| `cipherstore add <tokenid> [secret] [comment]` | Add a token. Prompts for the secret if omitted. |
| `cipherstore add -force <tokenid> [secret] [comment]` | Add a token, or update it if it already exists. |
| `cipherstore add -stdin <tokenid> [comment]` | Read the secret from standard input. |
| `cipherstore delete <tokenid>` | Remove a token. |
| `cipherstore list` | List token IDs, comments and update times. |

`add` refuses to overwrite an existing token: it exits with status 1 and
changes nothing unless you pass `-force`. With `-force`, when you supply no
comment an existing comment is left alone, so
`cipherstore add -force github <rotated-token>` rotates a secret without losing
its label. Pass an explicit `""` to clear a comment.

### Getting secrets in without exposing them

A secret on the command line is visible to every process on the machine via
`/proc/<pid>/cmdline`, and lands in your shell history. cipherstore accepts it
that way because it is convenient, but prefer one of these:

```sh
cipherstore add github                     # prompts, shows * per keystroke
pwgen -s 32 1 | cipherstore add -stdin github "work account"
cipherstore add -stdin github < token.txt
```

`unlock` and the `add` prompt read from `/dev/tty`, showing a `*` for each
character typed, so a redirected stdout or stderr does not capture the prompt
or divert the password. Set `CIPHERSTORE_NOECHO` (to any value) to echo
nothing at all, not even the length of what you type. When no
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

## Sharing a daemon with other users

By default only the user who started the daemon can use it. Five global
options, given **before** the command or in the [config file](#config-file),
change that:

| Option | Description |
| --- | --- |
| `-mode solo\|group\|all` | Who may use the daemon's sockets. Default `solo`. |
| `-group name` | The group allowed in `group` mode. Defaults to your primary group. Only valid with `-mode group`. |
| `-fullaccess` | Let other users list, export, import, add and delete secrets. Without it they may only `get` and `status`. Only valid with `-mode group` or `-mode all`. |
| `-socketpath dir` | Directory the sockets (and the daemon's lock file) are created in. Default `~/.local/state/cipherstore`. |
| `-dbpath dir` | Directory the database is created in. Default `~/.local/share/cipherstore`. |

The mode sets the permissions on the socket directory and the sockets:

| Mode | Socket directory | Sockets | Who can connect |
| --- | --- | --- | --- |
| `solo` | 0700 | 0700 | The daemon's user |
| `group` | 0750, group set to `-group` | 0770, same group | The daemon's user and members of the group |
| `all` | 0755 | 0777 | Every local user |

The daemon also checks each connection's kernel credentials against the mode
(the peer's UID, and in `group` mode its group list), so the file permissions
are not the only thing deciding who is let in. The database directory stays
0700 in every mode, because only the daemon opens it.

For example, to share a store with the members of `ops`:

```sh
# as the owning user
cipherstore -mode group -group ops -socketpath /srv/cipherstore start -d
cipherstore -mode group -socketpath /srv/cipherstore unlock 8h

# as any member of ops
cipherstore -mode group -socketpath /srv/cipherstore get db-password
```

The other users must also give `-mode` (`group` or `all`) and the same
`-socketpath`, normally by putting them in their config file. A client in the default `solo` mode only talks to a daemon run by
its own user, and refuses a shared directory. In the shared modes the client
accepts a daemon run by another user, but only if the socket directory, the
socket and the listening process all belong to the same user and nobody else
can write to the directory.

Points to bear in mind:

- **Other users may only `get` and `status` by default.** They can fetch a
  secret whose name they know, but cannot `list`, `export`, `import`, `add` or
  `delete`. Start the daemon with `-fullaccess` to allow those too. There are
  no per-user permissions inside the store: every user the mode lets in gets
  the same rights.
- **Only the owner can unlock, lock or stop the daemon**, with or without
  `-fullaccess`. The daemon enforces this, and the restriction above, with the
  kernel's peer credentials. The client also refuses lifecycle commands up
  front, so a non-owner's `unlock` never prompts for (or sends) a password.
- **The other users need to reach the directory.** Every directory above
  `-socketpath` must be searchable by them. Home directories usually are not,
  so pick a path outside `$HOME`, such as `/srv/cipherstore`. The daemon creates
  any missing parent directories as 0755 in the shared modes, and logs a
  warning at startup for any parent that other users cannot search.
- **One daemon per socket directory and per database.** The daemon locks both
  directories, so a second daemon cannot serve the same sockets or open the
  same database, even with a different `-socketpath`.
- **Group membership is read when a client connects.** Someone removed from the
  group keeps access through any process that was started before the change.

### Config file

The global options can also be set in a TOML file, by default
`~/.config/cipherstore.toml` (`$XDG_CONFIG_HOME/cipherstore.toml`). Choose
another with `-config file`, or read none with `-config ""`. Options given on
the command line override the file, and a missing default file is ignored.

```toml
# Every key is optional.
mode = "group"                  # solo, group or all
socketpath = "/srv/cipherstore" # where the sockets are
group = "ops"                   # used by start, in group mode
fullaccess = false              # used by start, in group or all mode
dbpath = "~/.local/share/cipherstore"   # used by start
```

`mode` and `socketpath` matter to every command, because the client needs
them to find and trust the daemon. `group`, `fullaccess` and `dbpath` are only
used by `start`. A `group` is ignored when the effective mode is not `group`,
and `fullaccess` when it is `solo`, so `-mode solo` on the command line
overrides a shared-mode config. `-fullaccess=false` overrides
`fullaccess = true`.

Paths must be absolute or start with `~/`. Because the file decides which
daemon the client trusts, cipherstore refuses one that is not owned by you (or
root) or that is writable by group or others, and it rejects unknown keys
rather than silently ignoring a typo. A symlinked config file is fine, and its
target is what gets checked.

`start -d` passes `-config` on to the daemon, and a systemd unit reads the
default file like any other command.

## Python client

`contrib/python/cipherstore.py` is a single-file, standard-library-only Python
client. It talks to the daemon's sockets directly, with the same symlink,
ownership and peer-UID checks as the Go client:

```python
import cipherstore
token = cipherstore.get("github-token")
```

For details, see [contrib/python/README.md](contrib/python/README.md).

## Files

| Path | Mode | Purpose |
| --- | --- | --- |
| `~/.local/state/cipherstore/` | 0700 | Runtime directory (`-socketpath`) |
| `~/.local/state/cipherstore/control` | 0700 | Control socket; exists while the daemon runs |
| `~/.local/state/cipherstore/authed` | 0700 | Secret-operation socket; **exists only while unlocked** |
| `~/.local/state/cipherstore/daemon.lock` | 0600 | `flock`ed so only one daemon serves this directory |
| `~/.local/share/cipherstore/` | 0700 | Database directory (`-dbpath`) |
| `~/.local/share/cipherstore/cipherstore.sqlite` | 0600 | The encrypted database |
| `~/.local/share/cipherstore/daemon.lock` | 0600 | `flock`ed so only one daemon opens this database |
| `~/.config/cipherstore.toml` | not group/other-writable | Optional [config file](#config-file) (`-config`) |

The modes shown are for the default `solo` mode. See
[Sharing a daemon with other users](#sharing-a-daemon-with-other-users) for
the others.

`XDG_STATE_HOME`, `XDG_DATA_HOME` and `XDG_CONFIG_HOME` are honoured when set
to absolute paths.

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
- **`-mode group` and `-mode all` share every secret.** Every user who can
  connect can `get` any secret whose name they know or can guess. With
  `-fullaccess` they can also list, export, add and delete them. Only the
  owner can unlock, lock or stop the daemon.

## Testing

```sh
go test ./...
```

The first run compiles the SQLCipher amalgamation and takes a couple of
minutes. See [TECHNOTES.md](TECHNOTES.md#testing) for what the suite covers.

## License

MIT.
