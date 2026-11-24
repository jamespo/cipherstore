"""Tests for cipherstore.py against a fake daemon. Run with:

    python3 -m unittest discover -s contrib/python
"""

import contextlib
import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
import unittest.mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cipherstore  # noqa: E402


class FakeDaemon:
    """Serves single-shot JSON exchanges on a unix socket, like the daemon."""

    def __init__(self, path, handler):
        self.path = path
        self.handler = handler
        self.requests = []
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        self.sock.listen(8)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                if not buf:
                    continue  # client hung up without sending (e.g. rejected peer)
                req = json.loads(buf)
                self.requests.append(req)
                conn.sendall(json.dumps(self.handler(req)).encode() + b"\n")

    def close(self):
        self.sock.close()
        os.unlink(self.path)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.tmp.name, "cipherstore")
        os.mkdir(self.state, 0o700)
        self.client = cipherstore.CipherStore(self.state)
        self.daemons = []
        # Never read the config of the user running the tests.
        env = unittest.mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name})
        env.start()
        self.addCleanup(env.stop)

    def tearDown(self):
        for d in self.daemons:
            d.close()
        self.tmp.cleanup()

    def serve(self, name, handler):
        d = FakeDaemon(os.path.join(self.state, name), handler)
        self.daemons.append(d)
        return d


class TestOperations(Base):
    def setUp(self):
        super().setUp()
        self.store = {"foo": "bar"}

        def handle(req):
            op, tid = req["op"], req.get("token_id")
            if op == "get":
                if tid in self.store:
                    return {"found": True, "secret": self.store[tid]}
                return {}
            if op == "add":
                created = tid not in self.store
                self.store[tid] = req.get("secret", "")
                return {"created": created}
            if op == "delete":
                return {"found": self.store.pop(tid, None) is not None}
            if op == "list":
                return {"entries": [
                    {"token_id": k, "comment": "c",
                     "updated_at": "2026-11-17T13:54:19.123456789Z"}
                    for k in self.store
                ]}
            return {"error": "unknown op"}

        self.authed = self.serve("authed", handle)
        self.serve("control", lambda r: {"status": {
            "unlocked": True, "db_path": "/x", "pid": 42,
            "lock_at": "0001-01-01T00:00:00Z"}})

    def test_get(self):
        self.assertEqual(self.client.get("foo"), "bar")

    def test_get_missing(self):
        with self.assertRaises(cipherstore.NotFoundError):
            self.client.get("nope")
        with self.assertRaises(cipherstore.CipherStore.NotFoundError):
            self.client.get("nope")
        with self.assertRaises(KeyError):
            self.client.get("nope")
        self.assertIsNone(self.client.get("nope", None))

    def test_add_comment_semantics(self):
        self.assertTrue(self.client.add("new", "s"))
        self.assertNotIn("set_comment", self.authed.requests[-1])
        self.assertFalse(self.client.add("new", "s2", comment=""))
        self.assertTrue(self.authed.requests[-1]["set_comment"])
        self.assertEqual(self.store["new"], "s2")

    def test_delete(self):
        self.client.delete("foo")
        with self.assertRaises(cipherstore.NotFoundError):
            self.client.delete("foo")

    def test_list_parses_nanosecond_time(self):
        (e,) = self.client.list_entries()
        self.assertEqual(e.token_id, "foo")
        self.assertEqual(e.updated_at.microsecond, 123456)
        self.assertIsNotNone(e.updated_at.tzinfo)

    def test_status(self):
        s = self.client.status()
        self.assertTrue(s.unlocked)
        self.assertIsNone(s.lock_at)
        self.assertEqual(s.pid, 42)
        self.assertTrue(self.client.is_unlocked())

    def test_empty_token_rejected(self):
        with self.assertRaises(ValueError):
            self.client.get("")


class TestStateSignals(Base):
    def test_not_running(self):
        with self.assertRaises(cipherstore.NotRunningError):
            self.client.get("foo")
        self.assertFalse(self.client.is_unlocked())

    def test_locked(self):
        self.serve("control", lambda r: {})
        with self.assertRaises(cipherstore.LockedError):
            self.client.get("foo")

    def test_daemon_error(self):
        self.serve("authed", lambda r: {"error": "boom"})
        with self.assertRaisesRegex(cipherstore.CipherstoreError, "boom"):
            self.client.get("foo")


class TestSecurityChecks(Base):
    def test_symlinked_socket_rejected(self):
        real = os.path.join(self.tmp.name, "elsewhere")
        self.daemons.append(FakeDaemon(real, lambda r: {"found": True, "secret": "x"}))
        os.symlink(real, os.path.join(self.state, "authed"))
        with self.assertRaisesRegex(cipherstore.CipherstoreError, "symlink"):
            self.client.get("foo")

    def test_symlinked_state_dir_rejected(self):
        link = os.path.join(self.tmp.name, "link")
        os.symlink(self.state, link)
        self.serve("authed", lambda r: {"found": True, "secret": "x"})
        with self.assertRaisesRegex(cipherstore.CipherstoreError, "symlink"):
            cipherstore.CipherStore(link).get("foo")

    def test_permissive_state_dir_rejected(self):
        os.chmod(self.state, 0o755)
        with self.assertRaisesRegex(cipherstore.CipherstoreError, "permissions"):
            self.client.get("foo")

    def test_non_socket_rejected(self):
        open(os.path.join(self.state, "authed"), "w").close()
        with self.assertRaisesRegex(cipherstore.CipherstoreError, "not a socket"):
            self.client.get("foo")

    def test_peer_uid_mismatch_rejected(self):
        self.serve("authed", lambda r: {"found": True, "secret": "x"})
        orig = cipherstore.CipherStore.__dict__["_peer_uid"]
        cipherstore.CipherStore._peer_uid = staticmethod(lambda s: os.getuid() + 1)
        try:
            with self.assertRaisesRegex(cipherstore.CipherstoreError, "peer uid"):
                self.client.get("foo")
        finally:
            cipherstore.CipherStore._peer_uid = orig


class TestSharedMode(Base):
    def setUp(self):
        super().setUp()
        os.chmod(self.state, 0o755)
        self.shared = cipherstore.CipherStore(self.state, shared=True)

    def test_shared_dir_accepted(self):
        self.serve("authed", lambda r: {"found": True, "secret": "x"})
        self.assertEqual(self.shared.get("foo"), "x")

    def test_solo_client_refuses_shared_dir_with_hint(self):
        self.serve("authed", lambda r: {"found": True, "secret": "x"})
        with self.assertRaisesRegex(cipherstore.CipherstoreError, "shared=True"):
            self.client.get("foo")

    def test_writable_dir_rejected(self):
        self.serve("authed", lambda r: {"found": True, "secret": "x"})
        for mode in (0o775, 0o757):
            os.chmod(self.state, mode)
            with self.assertRaisesRegex(cipherstore.CipherstoreError, "writable"):
                self.shared.get("foo")

    def test_peer_must_be_dir_owner(self):
        self.serve("authed", lambda r: {"found": True, "secret": "x"})
        orig = cipherstore.CipherStore.__dict__["_peer_uid"]
        cipherstore.CipherStore._peer_uid = staticmethod(lambda s: os.getuid() + 1)
        try:
            with self.assertRaisesRegex(cipherstore.CipherstoreError, "peer uid"):
                self.shared.get("foo")
        finally:
            cipherstore.CipherStore._peer_uid = orig

    def test_main_global_options(self):
        self.serve("control", lambda r: {"status": {"unlocked": True, "access": "all"}})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cipherstore.CipherStore.main(["-mode", "all", "-socketpath", self.state, "status"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), "unlocked\n")
        self.assertEqual(cipherstore.CipherStore.main(["-mode", "bogus", "status"]), 2)


@unittest.skipIf(sys.version_info < (3, 11), "tomllib needs Python 3.11")
class TestConfig(Base):
    def write(self, body, mode=0o600):
        path = os.path.join(self.state, "cs.toml")
        with open(path, "w") as f:
            f.write(body)
        os.chmod(path, mode)
        return path

    def test_from_config(self):
        os.chmod(self.state, 0o755)
        self.serve("authed", lambda r: {"found": True, "secret": "x"})
        path = self.write('mode = "all"\nsocketpath = "%s"\ndbpath = "/ignored"\n' % self.state)
        c = cipherstore.CipherStore.from_config(path)
        self.assertTrue(c.shared)
        self.assertEqual(c.state_dir, self.state)
        self.assertEqual(c.get("foo"), "x")

    def test_missing_default_is_fine_but_explicit_is_not(self):
        with unittest.mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.state}):
            self.assertEqual(cipherstore.CipherStore.load_config(), {})
        with self.assertRaisesRegex(cipherstore.CipherstoreError, "does not exist"):
            cipherstore.CipherStore.load_config(os.path.join(self.state, "nope.toml"))

    def test_rejects(self):
        for body, mode, msg in (
            ('sockpath = "/x"', 0o600, "unknown key"),
            ('socketpath = "rel"', 0o600, "absolute"),
            ('mode = "bogus"', 0o600, "invalid mode"),
            ("mode = 3", 0o600, "string"),
            ('mode = "all"', 0o620, "writable"),
        ):
            with self.assertRaisesRegex(cipherstore.CipherstoreError, msg):
                cipherstore.CipherStore.load_config(self.write(body, mode))

    def test_main_options_override_config(self):
        self.serve("control", lambda r: {"status": {"unlocked": False}})
        path = self.write('mode = "all"\nsocketpath = "/nonexistent-cipherstore"\n')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cipherstore.CipherStore.main(
                ["-config", path, "-mode", "solo", "-socketpath", self.state, "status"]
            )
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), "locked\n")


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux-only fallback")
class TestLongPath(unittest.TestCase):
    def test_long_state_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = os.path.join(tmp, "d" * 120, "cipherstore")
            os.makedirs(state, 0o700)
            os.chmod(state, 0o700)
            # Bind relatively: the full path is too long for sun_path.
            cwd = os.getcwd()
            os.chdir(state)
            try:
                d = FakeDaemon("authed", lambda r: {"found": True, "secret": "long"})
            finally:
                os.chdir(cwd)
            d.path = os.path.join(state, "authed")
            try:
                self.assertEqual(cipherstore.CipherStore(state).get("foo"), "long")
            finally:
                d.close()


if __name__ == "__main__":
    unittest.main()
