# cipherstore Python client

`cipherstore.py` is a single-file client for the cipherstore daemon. It needs
only the standard library and Python 3.8 or later, on Linux or macOS. It talks
to the daemon's UNIX sockets directly, so it doesn't run the `cipherstore`
binary or pass secrets through a subprocess pipe.

Copy it into your project, or put its directory on `PYTHONPATH`.

## Library

Everything is in the `CipherStore` class:

```python
from cipherstore import CipherStore

c = CipherStore()

token = c.get("github-token")          # raises CipherStore.NotFoundError if absent
token = c.get("github-token", None)    # or returns the default

created = c.add("github-token", "ghp_...", comment="CI token")
c.delete("github-token")

for e in c.list_entries():             # CipherStore.Entry(token_id, comment, updated_at)
    print(e.token_id, e.comment, e.updated_at)

if c.is_unlocked():
    ...
```

`add(token_id, secret)` with no `comment` leaves any existing comment as it
is. Pass `comment=""` to clear it. This matches the Go CLI.

To use a state directory other than `$XDG_STATE_HOME/cipherstore` (by default
`~/.local/state/cipherstore`), pass it to the constructor:

```python
c = CipherStore("/path/to/state/cipherstore")
```

To use a daemon that another user runs with `-mode group` or `-mode all`, pass
`shared=True` along with its `-socketpath`:

```python
c = CipherStore("/srv/cipherstore", shared=True)
```

The command-line form takes the same global options as the Go client, before
the command: `python3 cipherstore.py -mode group -socketpath /srv/cipherstore get TOKENID`.

To use the Go CLI's config file (`~/.config/cipherstore.toml`, see the main
README) instead, call `CipherStore.from_config()`, or `from_config(path)` for a
different file. Only `mode` and `socketpath` are used. The file is checked the
same way as in Go: it must be owned by you or root, must not be writable by
group or others, and must not contain unknown keys. The command-line
`cipherstore.py` reads it by default, takes `-config FILE` (or `-config ""` for
none), and its `-mode`/`-socketpath` override the file. Reading a config file
needs Python 3.11+ (`tomllib`). On older versions the client works as before
but fails if a config file is present.

### Exceptions

All exceptions derive from `CipherstoreError`. Each one is also an attribute
of the class (for example `CipherStore.LockedError`), so you only need to
import `CipherStore`.

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

With `shared=True` "the current user" becomes "the owner of the state
directory" in each check above. The directory may then be group- or
world-readable, but it must still not be writable by anyone except its owner.

If the socket path is longer than `sun_path` allows, the client connects
through `/proc/self/fd/N/<socket>` on an `O_NOFOLLOW` directory handle on
Linux. It does not change the process's working directory.

## Tests

```sh
python3 -m unittest discover -s contrib/python
```

The tests use a fake daemon, so they don't need the Go binary.
