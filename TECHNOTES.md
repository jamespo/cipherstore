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

**Directory invariants.** Every directory cipherstore uses is created 0700 and
re-validated on each use: it must be a real directory (not a symlink), owned by
the current UID, with no group or world permission bits. An existing directory
loosened by a stray umask is tightened. This is the foundation everything else
rests on — an attacker who cannot write into the parent directory cannot swap a
socket or the database for something of their own.

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
time-of-use), so they are backed by the authoritative check: both ends read
`SO_PEERCRED` and require the other end's UID to match their own. The daemon
closes and skips connections from other users; the client refuses to send
anything to a socket served by another user. An attacker would have to interpose
*as the same UID*, which already has full access.

**Socket creation race.** `net.Listen` creates the socket with `0777` masked by
umask, which could briefly leave it group- or world-accessible. cipherstore
clamps the umask to `0077` across the bind and then sets the mode explicitly, so
the socket is never more permissive than intended, even momentarily. umask and
the working directory are both process-global, so both swaps are serialised
under one mutex.

**Single instance.** The daemon holds an exclusive `flock` on
`daemon.lock`, so a second daemon is refused rather than stealing the first
one's sockets. The lock file is unlinked before being unlocked, so a daemon
starting concurrently cannot acquire a lock on a file that is about to vanish.

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
