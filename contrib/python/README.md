# cipherstore Python client

`cipherstore.py` is a single-file client for the cipherstore daemon. It needs
only the standard library and Python 3.8 or later, on Linux or macOS. It talks
to the daemon's UNIX sockets directly, so it doesn't run the `cipherstore`
binary or pass secrets through a subprocess pipe.

Copy it into your project, or put its directory on `PYTHONPATH`.

## Library

```python
import cipherstore

token = cipherstore.get("github-token")          # raises NotFoundError if absent
token = cipherstore.get("github-token", None)    # or returns the default

created = cipherstore.add("github-token", "ghp_...", comment="CI token")
cipherstore.delete("github-token")

for e in cipherstore.list_entries():             # Entry(token_id, comment, updated_at)
    print(e.token_id, e.comment, e.updated_at)

if cipherstore.is_unlocked():
    ...
```

`add(token_id, secret)` with no `comment` leaves any existing comment as it
is. Pass `comment=""` to clear it. This matches the Go CLI.

To use a state directory other than `$XDG_STATE_HOME/cipherstore` (by default
`~/.local/state/cipherstore`), create a client for it:

```python
client = cipherstore.Client("/path/to/state/cipherstore")
client.get("foo")
```

### Exceptions

All exceptions derive from `cipherstore.CipherstoreError`.

| Exception | Meaning |
| --- | --- |
| `NotRunningError` | The control socket is absent, so no daemon is running |
| `LockedError` | The daemon is running but the store is locked |
| `NotFoundError` | No such token id. It is also a `KeyError` |
| `CipherstoreError` | A daemon-reported error, a failed security check, or an I/O error |

## Command line

```sh
python3 cipherstore.py get github-token
python3 cipherstore.py list
python3 cipherstore.py status
```

Exit codes match the Go CLI: 0 means success, 1 an error, 2 invalid usage and
3 that the token was not found.

## Security

The client makes the same checks as the Go client before it sends anything:

- The state directory must be a real directory, not a symlink. It must be
  owned by the current user and must have no group or world permission bits.
- The socket must be a real socket, not a symlink, owned by the current user.
- After connecting, the client reads the listener's UID from the kernel
  (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS). It refuses the
  connection unless that UID is its own. This check is the authoritative one,
  because the path checks above can race.

If the socket path is longer than `sun_path` allows, the client connects
through `/proc/self/fd/N/<socket>` on an `O_NOFOLLOW` directory handle on
Linux. It does not change the process's working directory.

## Tests

```sh
python3 -m unittest discover -s contrib/python
```

The tests use a fake daemon, so they don't need the Go binary.
