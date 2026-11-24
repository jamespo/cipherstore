# cipherstore — technical notes

Design and implementation notes for cipherstore. See [README.md](README.md) for
installation and usage.

## Implementation

### Layout

```
main.go                    Entry point; delegates to internal/cli
internal/cli/              Command dispatch, password prompting, output formatting
internal/daemon/           The daemon: listeners, lock state, auto-lock timers
internal/store/            SQLCipher persistence
internal/ipc/              Hardened UNIX socket setup
internal/protocol/         Request/response types and framing
internal/paths/            XDG path resolution and permission invariants
internal/access/           The -mode/-group access policy
internal/cli/config.go     The -config TOML file
```

### The two sockets

The daemon listens on two sockets, and which ones exist *is* the lock state:

- **`control`** exists for the daemon's whole lifetime and accepts `unlock`,
  `lock`, `stop` and `status`.
- **`authed`** is created on unlock and removed on lock, and accepts `get`,
  `add`, `delete` and `list`.

So a client can tell whether the store is open without sending anything, and a
locked daemon has no socket that can serve secrets at all — the failure mode is
a missing file rather than a permission check that might be wrong.

On lock, the socket is removed *before* the database is closed, so there is no
window in which a client is accepted onto a store that is going away.

### Protocol

Newline-delimited JSON, one request and one response per connection, then
close. Single-shot connections keep the daemon's state machine trivial and mean
a wedged client cannot hold a session open across a lock. Messages are capped at
1 MiB and every read and write has a 30-second deadline.

### Database

Four fields, as specified:

```sql
CREATE TABLE secrets (
    token_id   TEXT    PRIMARY KEY NOT NULL,
    secret     TEXT    NOT NULL,
    comment    TEXT    NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL      -- unix seconds
) WITHOUT ROWID;
```

The database is created if absent. The connection pool is pinned to a single
connection, because a SQLCipher key is per-connection: one connection means the
key is applied exactly once, and that no unkeyed connection can be opened behind
the daemon's back after a lock.

The key is passed via the driver's `_pragma_key` DSN parameter rather than a
`ConnectHook`. This matters: the driver execs `PRAGMA key` immediately after
`sqlite3_open_v2`, whereas a hook runs at the very *end* of `Open`, by which
point the driver's own user-authentication probe has already read the database
header unkeyed. Keying that late appears to work — writes succeed — but the
database cannot be reopened afterwards. There is a regression test for this
(`TestReopenWithSamePassword`).

Because the driver interpolates the key into `PRAGMA key = "%s"`, the passphrase
is URL-encoded for the DSN and embedded double quotes are doubled for the SQL
token. The resulting key is the passphrase itself, so the database stays
openable with the stock `sqlcipher` CLI — useful for disaster recovery:

```console
$ sqlcipher ~/.local/share/cipherstore/cipherstore.sqlite
sqlite> PRAGMA key = 'your passphrase';
sqlite> SELECT token_id, comment FROM secrets;
```

`PRAGMA temp_store = MEMORY` is set so that temporary B-trees for `ORDER BY`
and friends are never written to a plaintext file under `/tmp`.

### Long socket paths

`sockaddr_un.sun_path` holds only 108 bytes, and `bind()` fails with a bare
`EINVAL` past that — a real risk with a long `$HOME` or `XDG_STATE_HOME`.
cipherstore avoids it by `chdir`ing into the socket's directory and binding or
connecting by relative name, so only `control` or `authed` is passed to the
kernel and the full path length stops mattering. The working directory is
restored immediately afterwards, and the swap is serialised against the umask
change described below.

### Database file mode

The specification for this project asked for mode 0700 on the database file.
cipherstore uses **0600** instead: the execute bit is meaningless on a database,
and the two modes grant the same access to the same single user. If a 0700
database shows up (from an older build or a manual `chmod`), it is tightened on
open rather than rejected.

## Security

### Threat model

cipherstore protects secrets at rest, and limits exposure while unlocked. It
does **not** defend against an attacker who already runs code as your user:
such an attacker can simply ask the daemon for the secrets, exactly as you can.
The protections below are aimed at other local users, at the on-disk footprint,
and at mistakes.

### Path and socket hardening

**Directory invariants.** Every directory cipherstore uses is re-validated on
each use: it must be a real directory (not a symlink), owned by the current UID,
and have no permission bits beyond those the access mode allows (0700 in solo
mode; see [Access modes](#access-modes)). No mode ever allows anyone but the
owner to write. An existing directory loosened by a stray umask is tightened.
The ownership and mode are changed through a descriptor opened with
`O_NOFOLLOW|O_DIRECTORY`, so a symlink planted in place of the directory is
refused instead of having its target's permissions changed. This is the
foundation everything else rests on — an attacker who cannot write into the
parent directory cannot swap a socket or the database for something of their
own.

**Symlink attacks.** Socket paths are `Lstat`ed, not `Stat`ed: a symlink where a
socket is expected is refused rather than followed. This matters most for
`unlock`, which would otherwise send the passphrase to whatever the link points
at. The database is opened with `O_NOFOLLOW` on creation and refused if it is a
symlink or not a regular file.

**Stale socket replacement.** A socket left behind by a crashed daemon is
removed on startup, but only after confirming it really is a socket owned by the
current user — anything else is refused rather than silently deleted, so a
misconfigured path cannot destroy an unrelated file.

**Peer credentials.** Path checks are inherently racy (time-of-check to
time-of-use), so they are backed by the authoritative check: both ends read the
peer's credentials from the kernel (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on
Darwin). In solo mode both ends require the other end's UID to match their own.
The daemon closes and skips connections from other users; the client refuses to
send anything to a socket served by another user. An attacker would have to
interpose *as the same UID*, which already has full access. The shared modes
relax this as described below.

**Socket creation race.** `net.Listen` creates the socket with `0777` masked by
umask, which could briefly leave it group- or world-accessible. cipherstore
clamps the umask to `0077` across the bind and then sets the mode explicitly, so
the socket is never more permissive than intended, even momentarily. umask and
the working directory are both process-global, so both swaps are serialised
under one mutex.

**Single instance.** The daemon holds an exclusive `flock` on a `daemon.lock`
in both the socket directory and the database directory, so a second daemon is
refused rather than stealing the first one's sockets or opening the same
database, even when `-socketpath` and `-dbpath` are combined differently. The
lock files are unlinked before being unlocked, so a daemon starting
concurrently cannot acquire a lock on a file that is about to vanish.

### Access modes

`-mode` selects one of three policies (package `internal/access`):

| Mode | Socket dir | Sockets | Daemon accepts a peer whose… |
| --- | --- | --- | --- |
| `solo` | 0700 | 0700 | UID is the daemon's |
| `group` | 0750, gid G | 0770, gid G | UID is the daemon's, or group list contains G |
| `all` | 0755 | 0777 | (anyone) |

The file permissions are the primary gate: connecting to a unix socket needs
search permission on its directory and write permission on the socket. The
daemon then repeats the decision with the kernel's peer credentials. In group
mode it reads the peer's full group list with `SO_PEERGROUPS` (Linux 4.13+) or
from the `xucred` (Darwin, up to 16 groups), plus the primary GID. These are the
credentials the client had when it connected.

The socket's group is set with `lchown` while it is still 0700 from the clamped
umask, and only then is the mode opened up, so it is never group-accessible
with the wrong group.

The database directory is always 0700: only the daemon opens it.

**Owner-only operations.** `unlock`, `lock` and `stop` are refused unless the
peer UID (from `SO_PEERCRED`/`LOCAL_PEERCRED`, as for the access check) is the
daemon's own. `status` and every authed-socket operation stay open to whoever
the mode lets in. The check is in `Daemon.handleControl` and runs before the
request is acted on. A refused `unlock` never reaches `store.Open`.

The client also enforces this, for two reasons. First, `unlock` checks the
socket directory's owner before prompting, so a non-owner is not asked for a
password that is going to be refused. Second, for all three commands the
client checks the peer UID on the connection before writing the request, and
refuses unless it is its own UID. So `unlock` never sends a passphrase to
another user's daemon, even in the shared modes where `ipc.Dial` would accept
one. That closes the passphrase-collecting attack described below for
`unlock`: an attacker who owns a socket directory can still serve fake
secrets, but cannot harvest a password.

**Client side.** In solo mode the client keeps the strict checks: directory and
socket owned by us, directory 0700, peer UID ours. A solo client given a shared
directory refuses it and suggests `-mode`. In group and all modes the client
accepts a daemon run by another user, and pins its trust to the directory's
owner:

- the directory must not be a symlink and must not be writable by group or
  others, so only its owner can put a socket there;
- the socket must be owned by that same user;
- the peer UID reported by the kernel must be that same user.

So in a shared mode the client trusts "whoever owns the socket directory". It
is up to the user to point `-socketpath` at a directory they trust. A directory
in a location where an attacker could have created it first (such as `/tmp`)
is a bad choice, because the attacker would own it and could run a daemon that
serves fake secrets or collects what clients `add`. (It cannot collect
passphrases, because `unlock` only talks to the user's own daemon.) The owning
user's daemon would refuse to start there, since it requires the directory to
be its own.

**Reachability.** Other users need search permission on every ancestor of the
socket directory. Missing parents are created 0755 in the shared modes
(explicitly chmodded, so a `UMask=0077` in the unit does not undo it), and at
startup the daemon logs a warning for each ancestor that the allowed users
cannot search. This only looks at mode bits, not ACLs, so it is a hint rather
than a guarantee.

### Config file

`-config` (default `$XDG_CONFIG_HOME/cipherstore.toml`) supplies defaults for
`mode`, `group`, `socketpath` and `dbpath`. Flags given on the command line win,
which `parseGlobal` tracks with `flag.Visit`. The file is parsed with
BurntSushi/toml, and `MetaData.Undecoded` turns an unknown key into an error.

The file is security-relevant, because `mode` and `socketpath` decide which
daemon a client trusts. So it is opened, then checked through the open
descriptor: it must be a regular file owned by the user or root, with no group
or other write bit. A symlink is followed on purpose (dotfile managers use
them), and what is checked is the file actually read, not the link. A missing
default file is not an error, but a missing `-config` file is. Paths must be
absolute or start with `~/`, because a relative path would change meaning with
the working directory. `-config ""` disables the file.

A `group` from the file is dropped when the effective mode is not `group`,
whereas `-group` given on the command line in another mode is a usage error.
Without that, a group-mode config could not be overridden with `-mode solo`.

### Protecting the in-memory key

While unlocked, the daemon holds the database key and decrypted pages in
memory. On startup it applies, best-effort (each failure is logged, never
fatal):

- `RLIMIT_CORE = 0` — a core dump would contain the passphrase and secrets.
- `PR_SET_DUMPABLE = 0` — stops another process running as the same user from
  attaching with `ptrace` or reading `/proc/<pid>/mem`.
- `mlockall(MCL_CURRENT|MCL_FUTURE)` — would keep pages out of swap, but in
  practice **usually fails**, and when it does cipherstore logs a notice,
  carries on, and secrets may reach swap.

  Be aware that `LimitMEMLOCK=infinity` in a *user* unit does not fix this:
  raising a hard limit needs `CAP_SYS_RESOURCE`, which an unprivileged user
  manager lacks, so the value is clamped to `DefaultLimitMEMLOCK` — commonly
  8 MiB, far less than a Go process's address space. The shipped unit sets it
  anyway, for the case where the system default has been raised. If you want
  this protection for real, raise the limit system-wide (a drop-in under
  `/etc/systemd/user.conf.d/`) or — simpler and more effective — use an
  encrypted swap device or no swap.

Passphrase byte slices are zeroed after use. Note the honest limit: Go strings
are immutable and cannot be wiped, so the passphrase that arrives in a JSON
request, and the DSN built from it, persist until garbage collected.

### Input handling

Token IDs, secrets and comments are bound as query parameters, never
interpolated, so arbitrary bytes round-trip without touching the schema. The
passphrase is the one value that *cannot* be parameterised — SQLite has no
parameter binding for `PRAGMA` — so it is escaped as described above and tested
against a corpus of hostile inputs (`TestHostilePasswords`), checking both that
each passphrase reopens its own database and that a near-miss variant does not.
Passphrases containing NUL are rejected, since a NUL would truncate the C string
and silently key the database with a prefix of what was typed.

### What is not protected

- **Secrets passed as command-line arguments** are world-visible via
  `/proc`. Use the prompt or `-stdin`.
- **`cipherstore get` output** goes to stdout and may land in shell history,
  scrollback or a pipe buffer.
- **The passphrase strength is the security of the database.** SQLCipher uses
  PBKDF2-HMAC-SHA512 with 256,000 iterations over a random per-database salt,
  which is strong, but it cannot rescue a weak passphrase.
- **No duress or tamper detection.** An attacker with write access to the
  database can destroy or roll it back; they cannot read it.
- **No key rotation command.** Re-keying means `list`ing, `get`ting each secret,
  and rebuilding a fresh database under a new passphrase.
- **No per-user access control over secrets in the shared modes.** In `group`
  and `all` mode every user who can connect can read, add and delete every
  secret. Only unlock, lock and stop are reserved to the owner. Group membership is checked against the credentials the
  client had when it connected, so removing a user from the group does not
  affect processes they started earlier.

## Testing

```sh
go test ./...
```

The suite covers the store (round-trips, reopening, wrong passwords, hostile
passphrases and values, file permissions, on-disk encryption), the daemon
end-to-end over real sockets (lock-state transitions, auto-lock timers, stale
socket and lock recovery, single-instance enforcement), the socket layer
(symlink and permission refusals, peer credentials, paths past the 108-byte
limit), the protocol framing (oversized and malformed messages), path resolution
and the CLI's argument handling.

The first run compiles the SQLCipher amalgamation and takes a couple of minutes.
