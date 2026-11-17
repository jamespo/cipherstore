"""Native Python client for the cipherstore daemon.

Talks directly to the daemon's UNIX sockets, so retrieving a secret does not
fork the ``cipherstore`` binary and the secret never appears in a process
argument list or a pipe owned by another process.

Standard library only; Python 3.8+ on Linux or macOS.

Everything lives in the ``CipherStore`` class; the exception classes are also
reachable as its attributes, so one import is enough::

    from cipherstore import CipherStore

    c = CipherStore()
    token = c.get("github-token")          # raises CipherStore.NotFoundError
    token = c.get("github-token", None)    # returns None if absent

    c.add("github-token", "ghp_...", comment="CI token")
    c.delete("github-token")
    for e in c.list_entries():
        print(e.token_id, e.comment, e.updated_at)

Usage from the shell (same exit codes as the Go CLI)::

    python3 cipherstore.py get github-token

Wire protocol: each connection carries one newline-terminated JSON request
and one newline-terminated JSON response, then closes. See
internal/protocol/protocol.go.

Security: this mirrors the checks the Go client makes before trusting a
socket. The state directory must be a real directory owned by us with no
group/world bits; the socket must be a real socket (not a symlink) owned by
us; and after connecting, the kernel-reported UID of the listening process
must equal ours. The last check is the authoritative one -- the path checks
are inherently racy, but a peer that passes the credential check is already
running as the same user.
"""

import json
import os
import re
import socket
import stat
import struct
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, NamedTuple, Optional

__all__ = [
    "CipherStore",
    "CipherstoreError",
    "NotRunningError",
    "LockedError",
    "NotFoundError",
]


class CipherstoreError(Exception):
    """Base class for all errors raised by this module."""


class NotRunningError(CipherstoreError):
    """The daemon is not running (the control socket is absent)."""

    def __init__(self) -> None:
        super().__init__(
            "cipherstore daemon is not running (start it with `cipherstore start`)"
        )


class LockedError(CipherstoreError):
    """The store is locked (the authed socket is absent)."""

    def __init__(self) -> None:
        super().__init__("cipherstore is locked (unlock it with `cipherstore unlock`)")


class NotFoundError(CipherstoreError, KeyError):
    """The requested token id does not exist."""

    def __init__(self, token_id: str) -> None:
        super().__init__("token %r not found" % token_id)
        self.token_id = token_id

    def __str__(self) -> str:  # KeyError would otherwise repr() the message
        return str(self.args[0])


class CipherStore:
    """A cipherstore client bound to a particular state directory.

    ``state_dir`` defaults to ``$XDG_STATE_HOME/cipherstore`` (falling back to
    ``~/.local/state/cipherstore``), matching the daemon.
    """

    # Exceptions, exposed here so callers need only import CipherStore.
    Error = CipherstoreError
    CipherstoreError = CipherstoreError
    NotRunningError = NotRunningError
    LockedError = LockedError
    NotFoundError = NotFoundError

    class Entry(NamedTuple):
        token_id: str
        comment: str
        updated_at: Optional[datetime]

    class Status(NamedTuple):
        unlocked: bool
        lock_at: Optional[datetime]
        db_path: str
        pid: int

    # Must match internal/protocol/protocol.go.
    MAX_MESSAGE_BYTES = 1 << 20
    TIMEOUT = 30.0

    # sockaddr_un.sun_path is 108 bytes on Linux (104 on macOS) including the NUL.
    _MAX_SUN_PATH = 103 if sys.platform == "darwin" else 107

    _MISSING = object()
    _FRACTION_RE = re.compile(r"(\.\d{6})\d+")

    def __init__(self, state_dir: Optional[str] = None) -> None:
        self.state_dir = state_dir or self.default_state_dir()
        self.control_socket = os.path.join(self.state_dir, "control")
        self.authed_socket = os.path.join(self.state_dir, "authed")

    # -- operations --------------------------------------------------------

    def get(self, token_id: str, default: Any = _MISSING) -> Any:
        """Return the secret for ``token_id``.

        Raises NotFoundError if it does not exist, unless ``default`` is
        given, in which case that is returned instead.
        """
        self._require_token(token_id)
        resp = self._send_authed({"op": "get", "token_id": token_id})
        if not resp.get("found"):
            if default is not self._MISSING:
                return default
            raise NotFoundError(token_id)
        return resp.get("secret", "")

    def add(self, token_id: str, secret: str, comment: Optional[str] = None) -> bool:
        """Add or update a secret. Returns True if it was newly created.

        When ``comment`` is None an existing comment is left untouched; pass
        ``""`` to clear it.
        """
        self._require_token(token_id)
        req = {"op": "add", "token_id": token_id, "secret": secret}
        if comment is not None:
            req["comment"] = comment
            req["set_comment"] = True
        return bool(self._send_authed(req).get("created"))

    def delete(self, token_id: str) -> None:
        """Delete a secret. Raises NotFoundError if it does not exist."""
        self._require_token(token_id)
        if not self._send_authed({"op": "delete", "token_id": token_id}).get("found"):
            raise NotFoundError(token_id)

    def list_entries(self) -> List["CipherStore.Entry"]:
        """Return all token ids with comments and last-updated times."""
        resp = self._send_authed({"op": "list"})
        return [
            self.Entry(
                token_id=e.get("token_id", ""),
                comment=e.get("comment", ""),
                updated_at=self._parse_time(e.get("updated_at")),
            )
            for e in resp.get("entries") or []
        ]

    def status(self) -> "CipherStore.Status":
        """Return daemon status from the control socket."""
        s = self._send_control({"op": "status"}).get("status") or {}
        return self.Status(
            unlocked=bool(s.get("unlocked")),
            lock_at=self._parse_time(s.get("lock_at")),
            db_path=s.get("db_path", ""),
            pid=int(s.get("pid", 0)),
        )

    def is_unlocked(self) -> bool:
        """True if the daemon is running and unlocked. Never raises for
        "not running" or "locked"."""
        try:
            return self.status().unlocked
        except (NotRunningError, LockedError):
            return False

    # -- transport ---------------------------------------------------------

    def _send(self, path: str, req: Dict[str, Any], absent: CipherstoreError) -> Dict[str, Any]:
        data = json.dumps(req, separators=(",", ":")).encode() + b"\n"
        if len(data) > self.MAX_MESSAGE_BYTES:
            raise CipherstoreError(
                "message of %d bytes exceeds limit of %d"
                % (len(data), self.MAX_MESSAGE_BYTES)
            )
        sock = self._dial(path, absent)
        try:
            sock.sendall(data)
            line = self._recv_line(sock)
        except socket.timeout as e:
            raise CipherstoreError("timed out talking to cipherstore daemon") from e
        finally:
            sock.close()
        try:
            resp = json.loads(line)
        except ValueError as e:
            raise CipherstoreError("decode response: %s" % e) from e
        if not isinstance(resp, dict):
            raise CipherstoreError("decode response: not a JSON object")
        if resp.get("error"):
            raise CipherstoreError(resp["error"])
        return resp

    def _send_control(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self._send(self.control_socket, req, NotRunningError())

    def _send_authed(self, req: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return self._send(self.authed_socket, req, LockedError())
        except LockedError:
            # Distinguish "locked" from "not running" for a clearer message.
            if not os.path.lexists(self.control_socket):
                raise NotRunningError() from None
            raise

    def _dial(self, path: str, absent: CipherstoreError) -> socket.socket:
        """Connect to a cipherstore socket after validating it, as ipc.Dial does."""
        self._check_dir(os.path.dirname(path))

        try:
            st = os.lstat(path)
        except FileNotFoundError:
            # A missing socket signals daemon state, not a fault.
            raise absent from None
        except OSError as e:
            raise CipherstoreError("stat %s: %s" % (path, e.strerror)) from e
        if stat.S_ISLNK(st.st_mode):
            raise CipherstoreError("%s is a symlink; refusing to connect" % path)
        if not stat.S_ISSOCK(st.st_mode):
            raise CipherstoreError("%s is not a socket; refusing to connect" % path)
        self._check_owner(path, st)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.TIMEOUT)
            self._connect(sock, path)
            # Authoritative check: ask the kernel who is on the other end.
            uid = self._peer_uid(sock)
            if uid != os.getuid():
                raise CipherstoreError(
                    "%s: peer uid %d is not %d" % (path, uid, os.getuid())
                )
        except FileNotFoundError:
            sock.close()
            raise absent from None
        except ConnectionRefusedError:
            # Socket file left behind but nobody listening: treat as absent.
            sock.close()
            raise absent from None
        except BaseException:
            sock.close()
            raise
        return sock

    @classmethod
    def _connect(cls, sock: socket.socket, path: str) -> None:
        encoded = os.fsencode(path)
        if len(encoded) <= cls._MAX_SUN_PATH:
            sock.connect(path)
            return
        # A long $HOME/XDG_STATE_HOME can overflow sun_path. On Linux, reach the
        # socket through a directory fd instead of changing the process cwd
        # (which a library must not do). O_NOFOLLOW refuses a symlinked directory.
        if not sys.platform.startswith("linux"):
            raise CipherstoreError(
                "socket path %s is %d bytes, over the %d-byte unix socket limit"
                % (path, len(encoded), cls._MAX_SUN_PATH)
            )
        dirname, name = os.path.split(path)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_PATH", 0)
        dfd = os.open(dirname, flags)
        try:
            sock.connect("/proc/self/fd/%d/%s" % (dfd, name))
        finally:
            os.close(dfd)

    @classmethod
    def _recv_line(cls, sock: socket.socket) -> bytes:
        buf = bytearray()
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                if buf:
                    return bytes(buf)  # tolerate a final message with no newline
                raise CipherstoreError("read response: connection closed by daemon")
            buf += chunk
            nl = buf.find(b"\n")
            if nl >= 0:
                return bytes(buf[: nl + 1])
            if len(buf) > cls.MAX_MESSAGE_BYTES:
                raise CipherstoreError(
                    "message exceeds limit of %d bytes" % cls.MAX_MESSAGE_BYTES
                )

    @staticmethod
    def _peer_uid(sock: socket.socket) -> int:
        if sys.platform.startswith("linux"):
            so_peercred = getattr(socket, "SO_PEERCRED", 17)
            raw = sock.getsockopt(socket.SOL_SOCKET, so_peercred, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", raw)
            return uid
        if sys.platform == "darwin":
            # LOCAL_PEERCRED (0x001) at SOL_LOCAL (0) returns struct xucred:
            #   u_int cr_version; uid_t cr_uid; short cr_ngroups; gid_t cr_groups[16]
            sol_local = getattr(socket, "SOL_LOCAL", 0)
            local_peercred = getattr(socket, "LOCAL_PEERCRED", 0x001)
            raw = sock.getsockopt(sol_local, local_peercred, 4 + 4 + 2 + 2 + 16 * 4)
            _version, uid = struct.unpack_from("=II", raw)
            return uid
        raise CipherstoreError("peer credential check not supported on %s" % sys.platform)

    # -- validation helpers ------------------------------------------------

    @staticmethod
    def _check_owner(path: str, st: os.stat_result) -> None:
        uid = os.getuid()
        if st.st_uid != uid:
            raise CipherstoreError(
                "%s is owned by uid %d, not %d; refusing to use it"
                % (path, st.st_uid, uid)
            )

    @classmethod
    def _check_dir(cls, path: str) -> None:
        try:
            st = os.lstat(path)
        except OSError as e:
            raise CipherstoreError("stat %s: %s" % (path, e.strerror)) from e
        if stat.S_ISLNK(st.st_mode):
            raise CipherstoreError("%s is a symlink; refusing to use it" % path)
        if not stat.S_ISDIR(st.st_mode):
            raise CipherstoreError("%s is not a directory" % path)
        cls._check_owner(path, st)
        perm = stat.S_IMODE(st.st_mode)
        if perm & 0o077:
            raise CipherstoreError(
                "%s has permissions %#o; must not be accessible to group or others"
                % (path, perm)
            )

    @staticmethod
    def _require_token(token_id: str) -> None:
        if not isinstance(token_id, str) or not token_id:
            raise ValueError("token id must be a non-empty string")

    @classmethod
    def _parse_time(cls, s: Optional[str]) -> Optional[datetime]:
        """Parse a Go RFC 3339 timestamp; returns None for Go's zero time."""
        if not s or s.startswith("0001-01-01"):
            return None
        # Go emits up to 9 fractional digits and a literal "Z"; older Pythons'
        # fromisoformat accepts neither.
        s = cls._FRACTION_RE.sub(r"\1", s)
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            return None

    @staticmethod
    def default_state_dir() -> str:
        # Relative XDG values are invalid per the spec and ignored, as in Go.
        v = os.environ.get("XDG_STATE_HOME", "")
        base = v if os.path.isabs(v) else os.path.join(os.path.expanduser("~"), ".local/state")
        return os.path.join(base, "cipherstore")

    # -- minimal CLI -------------------------------------------------------

    _USAGE = """usage: cipherstore.py get TOKENID
       cipherstore.py list
       cipherstore.py status"""

    @classmethod
    def main(cls, argv: Optional[List[str]] = None) -> int:
        args = sys.argv[1:] if argv is None else argv
        try:
            c = cls()
            if len(args) == 2 and args[0] == "get":
                sys.stdout.write(c.get(args[1]) + "\n")
            elif args == ["list"]:
                for e in c.list_entries():
                    ts = (
                        e.updated_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
                        if e.updated_at
                        else ""
                    )
                    print("%s\t%s\t%s" % (e.token_id, ts, e.comment))
            elif args == ["status"]:
                print("unlocked" if c.status().unlocked else "locked")
            else:
                print(cls._USAGE, file=sys.stderr)
                return 2
        except NotFoundError as e:
            print("cipherstore: %s" % e, file=sys.stderr)
            return 3
        except (CipherstoreError, ValueError, OSError) as e:
            print("cipherstore: %s" % e, file=sys.stderr)
            return 1
        return 0


if __name__ == "__main__":
    sys.exit(CipherStore.main())
