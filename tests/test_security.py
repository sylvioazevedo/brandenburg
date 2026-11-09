import asyncio
from dataclasses import replace
import json
import logging
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import asyncssh
import bcrypt

import app
from ssh_security import (
    AttemptLimiter, ConfigurationError, PasswordVerifier, Settings, _windows_acl,
    check_private_file, load_settings, normalize_ip, provision, write_private_document,
)


# Deliberately non-production fixture; no default accounts exist in the application.
PASSWORD = "fixture-only passphrase 4862"
HASH = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(10))


def secure(path: Path) -> None:
    if os.name == "nt":
        _windows_acl(path, restrict=True)
    else:
        path.chmod(0o600)


def command(code: str) -> str:
    args = [sys.executable, "-c", code]
    return subprocess.list2cmdline(args) if os.name == "nt" else shlex.join(args)


class ConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.key = cls.root / "host-key"
        asyncssh.generate_private_key("ssh-ed25519").write_private_key(cls.key)
        secure(cls.key)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def setUp(self) -> None:
        self.path = self.root / "brandenburg.private.json"
        self.document = {
            "administrators": {"admin": HASH.decode()},
            "host_key": str(self.key), "log_file": str(self.root / "server.security.log"),
        }
        write_private_document(self.path, self.document)

    def test_valid_configuration_and_defaults(self) -> None:
        settings = load_settings(self.path)
        self.assertEqual(settings.administrators, {"admin": HASH})
        self.assertEqual((settings.login_timeout, settings.attempts_per_connection), (30, 3))
        self.assertEqual((settings.failures_per_ip, settings.failure_window, settings.block_seconds), (5, 900, 900))
        check_private_file(self.path)

    def test_invalid_configuration_values_fail_closed(self) -> None:
        for key, value in (
            ("administrators", {}), ("administrators", {"guest": ""}),
            ("administrators", {"admin": "bad-hash"}), ("port", True),
            ("port", 65536), ("password_workers", 0), ("host", ""),
            ("unknown", 1), ("attempts_per_connection", 101),
        ):
            with self.subTest(key=key, value=value):
                write_private_document(self.path, dict(self.document, **{key: value}))
                with self.assertRaises(ConfigurationError):
                    load_settings(self.path)

    def test_duplicate_keys_rejected(self) -> None:
        self.path.write_text('{"administrators": {}, "administrators": {}}', encoding="utf-8")
        with self.assertRaisesRegex(ConfigurationError, "Duplicate"):
            load_settings(self.path)

    def test_missing_and_malformed_configuration(self) -> None:
        with self.assertRaises(ConfigurationError):
            load_settings(self.root / "absent")
        self.path.write_text("invalid", encoding="utf-8")
        with self.assertRaises(ConfigurationError):
            load_settings(self.path)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_unsafe_permissions_rejected(self) -> None:
        self.path.chmod(0o644)
        with self.assertRaises(ConfigurationError):
            load_settings(self.path)
        self.path.chmod(0o600)

    @unittest.skipUnless(os.name == "nt", "Windows ACLs")
    def test_unsafe_acl_rejected(self) -> None:
        result = subprocess.run(
            ["icacls.exe", str(self.path), "/grant", "*S-1-1-0:(R)"],
            capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0)
        try:
            with self.assertRaises(ConfigurationError):
                load_settings(self.path)
        finally:
            secure(self.path)

    def test_provision_rejects_bad_passwords(self) -> None:
        for value in ("", "short", " " * 16, "x" * 73, "\u00e9" * 40):
            with self.subTest(length=len(value)), patch("ssh_security.getpass.getpass", return_value=value):
                with self.assertRaises(ConfigurationError):
                    provision(self.path, "new-admin", None, None)

    def test_provision_updates_named_admin_atomically(self) -> None:
        with patch("ssh_security.getpass.getpass", side_effect=[PASSWORD, PASSWORD]):
            provision(self.path, "new-admin", None, None)
        settings = load_settings(self.path)
        self.assertTrue(bcrypt.checkpw(PASSWORD.encode(), settings.administrators["new-admin"]))
        self.assertIn("admin", settings.administrators)
        self.assertFalse(list(self.root.glob(".brandenburg-*")))
        self.assertNotIn(PASSWORD, self.path.read_text())

    def test_empty_template_requires_provisioning_before_startup(self) -> None:
        write_private_document(self.path, dict(self.document, administrators={}))
        with self.assertRaises(ConfigurationError):
            load_settings(self.path)
        with patch("ssh_security.getpass.getpass", side_effect=[PASSWORD, PASSWORD]):
            provision(self.path, "admin", None, None)
        self.assertTrue(bcrypt.checkpw(PASSWORD.encode(), load_settings(self.path).administrators["admin"]))

    def test_provision_confirmation_must_match(self) -> None:
        before = self.path.read_bytes()
        with patch("ssh_security.getpass.getpass", side_effect=[PASSWORD, PASSWORD + "different"]):
            with self.assertRaises(ConfigurationError):
                provision(self.path, "new-admin", None, None)
        self.assertEqual(before, self.path.read_bytes())

    def test_check_does_not_bind(self) -> None:
        with patch("app.start_server") as server, patch(
            "sys.argv", ["app.py", "--config", str(self.path), "check"],
        ):
            self.assertEqual(app.main(), 0)
        server.assert_not_called()

    def test_no_arguments_uses_default_config_and_serves(self) -> None:
        settings = load_settings(self.path)
        with (
            patch("sys.argv", ["app.py"]),
            patch("app.load_settings", return_value=settings) as load,
            patch("asyncssh.read_private_key"),
            patch("app.configure_logging") as configure,
            patch("app.serve") as serve,
            patch("app.asyncio.run", side_effect=lambda coro: coro.close()) as run,
        ):
            self.assertEqual(app.main(), 0)
        self.assertEqual(load.call_args.args[0], Path("brandenburg.private.json").absolute())
        configure.assert_called_once_with(settings)
        serve.assert_called_once_with(settings)
        run.assert_called_once()

    def test_config_argument_can_be_used_without_explicit_serve(self) -> None:
        settings = load_settings(self.path)
        with (
            patch("sys.argv", ["app.py", "--config", str(self.path)]),
            patch("app.load_settings", return_value=settings),
            patch("asyncssh.read_private_key"),
            patch("app.configure_logging"),
            patch("app.serve"),
            patch("app.asyncio.run", side_effect=lambda coro: coro.close()),
        ):
            self.assertEqual(app.main(), 0)

    def test_logging_is_private_rotated_and_escaped(self) -> None:
        settings = replace(load_settings(self.path), log_bytes=200, log_backups=2)
        app.configure_logging(settings)
        try:
            for _ in range(10):
                app.event("authentication_result", username="bad\nforged-event", success=False)
            for handler in app.LOG.handlers:
                handler.flush()
            files = list(self.root.glob("server.security.log*"))
            self.assertLessEqual(len(files), 3)
            self.assertGreater(len(files), 1)
            for path in files:
                check_private_file(path)
                for line in path.read_text().splitlines():
                    payload = json.loads(line.split("Z ", 1)[1])
                    self.assertEqual(payload["username"], "bad\nforged-event")
                    self.assertNotIn(HASH.decode(), line)
        finally:
            for handler in list(app.LOG.handlers):
                handler.close()
                app.LOG.removeHandler(handler)
            for path in self.root.glob("server.security.log*"):
                path.unlink()


class LimiterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 0.0
        self.settings = Settings({"admin": HASH}, Path("unused"), Path("unused"))
        self.limiter = AttemptLimiter(self.settings, lambda: self.now)

    def test_exact_five_failures_and_fifteen_minute_block(self) -> None:
        ip = "192.0.2.1"
        for attempt in range(5):
            self.assertTrue(self.limiter.begin(ip), attempt)
            self.limiter.finish(ip, False)
        self.assertFalse(self.limiter.begin(ip))
        self.now = 899.999
        self.assertFalse(self.limiter.begin(ip))
        self.now = 900
        self.assertTrue(self.limiter.begin(ip))
        self.limiter.finish(ip, True)

    def test_window_expiration_and_success_do_not_reset_other_failures(self) -> None:
        self.limiter.begin("192.0.2.1")
        self.limiter.finish("192.0.2.1", False)
        self.limiter.begin("192.0.2.1")
        self.limiter.finish("192.0.2.1", True)
        self.assertEqual(len(self.limiter.entries["192.0.2.1"].failures), 1)
        self.now = 900
        self.assertTrue(self.limiter.allowed("192.0.2.1"))
        self.assertNotIn("192.0.2.1", self.limiter.entries)

    def test_concurrent_attempts_reserve_budget(self) -> None:
        for _ in range(5):
            self.assertTrue(self.limiter.begin("192.0.2.1"))
        self.assertFalse(self.limiter.begin("192.0.2.1"))
        for _ in range(5):
            self.limiter.finish("192.0.2.1", False)
        self.assertFalse(self.limiter.allowed("192.0.2.1"))

    def test_state_capacity_fails_closed_then_expires(self) -> None:
        limiter = AttemptLimiter(replace(self.settings, max_ip_entries=2), lambda: self.now)
        for ip in ("192.0.2.1", "192.0.2.2"):
            self.assertTrue(limiter.begin(ip))
            limiter.finish(ip, False)
        self.assertFalse(limiter.begin("192.0.2.3"))
        self.assertEqual(len(limiter.entries), 2)
        self.now = 900
        self.assertTrue(limiter.begin("192.0.2.3"))
        limiter.finish("192.0.2.3", True)

    def test_address_normalization(self) -> None:
        self.assertEqual(normalize_ip("::ffff:192.0.2.1"), "192.0.2.1")
        self.assertEqual(normalize_ip("2001:0db8::1"), "2001:db8::1")


class VerifierTests(unittest.IsolatedAsyncioTestCase):
    async def test_password_checks_and_length_guards(self) -> None:
        verifier = PasswordVerifier(Settings({"admin": HASH}, Path("unused"), Path("unused")))
        try:
            self.assertTrue(await verifier.verify(PASSWORD, HASH))
            for password, hashed in ((PASSWORD, None), ("wrong", HASH), ("", HASH), ("x" * 73, HASH)):
                self.assertFalse(await verifier.verify(password, hashed))
        finally:
            verifier.close()

    async def test_worker_bound_survives_cancellation_and_does_not_block_loop(self) -> None:
        verifier = PasswordVerifier(replace(
            Settings({"admin": HASH}, Path("unused"), Path("unused")), password_workers=1,
        ))
        entered = threading.Event()
        release = threading.Event()

        def slow_check(password: bytes, hashed: bytes) -> bool:
            entered.set()
            release.wait(5)
            return True

        try:
            with patch("ssh_security.bcrypt.checkpw", side_effect=slow_check):
                task = asyncio.create_task(verifier.verify(PASSWORD, HASH))
                for _ in range(100):
                    if entered.is_set():
                        break
                    await asyncio.sleep(0.01)
                self.assertTrue(entered.is_set())
                self.assertIsNone(await verifier.verify(PASSWORD, HASH))
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assertEqual(verifier.active, 1)
                self.assertIsNone(await verifier.verify(PASSWORD, HASH))
                release.set()
                for _ in range(100):
                    if not verifier.active:
                        break
                    await asyncio.sleep(0.01)
                self.assertEqual(verifier.active, 0)
        finally:
            release.set()
            verifier.close()


class ServerTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.key = Path(cls.temp.name) / "host-key"
        asyncssh.generate_private_key("ssh-ed25519").write_private_key(cls.key)
        cls.public_key = asyncssh.read_private_key(cls.key).convert_to_public()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    async def asyncSetUp(self) -> None:
        asyncio.get_running_loop().slow_callback_duration = 2
        self.settings = Settings({"admin": HASH}, self.key, Path("unused"))
        self.runtime = app.Runtime(self.settings)
        self.server = await app.start_server(self.runtime, host="127.0.0.1", port=0)
        self.port = self.server.get_port()

    async def asyncTearDown(self) -> None:
        self.server.close()
        await self.server.wait_closed()
        await self.runtime.close()

    async def connect(self, username: str = "admin", password: str = PASSWORD) -> asyncssh.SSHClientConnection:
        return await asyncssh.connect(
            "127.0.0.1", self.port, username=username, password=password,
            known_hosts=([self.public_key], [], []), client_keys=[],
            preferred_auth=["password"], login_timeout=5,
        )

    async def test_guest_unknown_empty_and_wrong_password_rejected(self) -> None:
        for username, password in (("guest", ""), ("unknown", PASSWORD), ("admin", ""), ("admin", "wrong")):
            with self.subTest(username=username, password_length=len(password)):
                with self.assertRaises(asyncssh.PermissionDenied):
                    await self.connect(username, password)

    async def test_authenticated_commands_stderr_unicode_and_exit_status(self) -> None:
        async with await self.connect() as conn:
            result = await asyncio.wait_for(conn.run(command(
                "import sys; sys.stdout.buffer.write('hello \\u00e9\\n'.encode('utf-8')); "
                "sys.stderr.write('separate-error\\n'); sys.exit(7)"
            )), 15)
            self.assertEqual(result.stdout, "hello \u00e9\n")
            self.assertEqual(result.stderr.replace("\r\n", "\n"), "separate-error\n")
            self.assertEqual(result.exit_status, 7)
        self.assertEqual(self.runtime.pending, 0)

    async def test_interactive_shell_accepts_pty_request_and_input(self) -> None:
        async with await self.connect() as conn:
            async with conn.create_process(term_type="xterm") as process:
                process.stdin.write("echo shell-ready\nexit\n")
                result = await asyncio.wait_for(process.wait(), 15)
                self.assertIn("shell-ready", result.stdout)
                self.assertEqual(result.exit_status, 0)

    async def test_terminal_keystrokes_echo_and_enter_executes_command(self) -> None:
        marker = Path(self.temp.name) / "terminal-command-marker"
        marker.unlink(missing_ok=True)
        async with await self.connect() as conn:
            async with conn.create_process(term_type="xterm") as process:
                # Real terminals send individual characters and CR for Enter.
                for character in "echo terminal-marker":
                    process.stdin.write(character)
                    await process.stdin.drain()
                echoed = await asyncio.wait_for(process.stdout.readuntil("echo terminal-marker"), 3)
                self.assertIn("echo terminal-marker", echoed)
                process.stdin.write("\x7fX\r")
                output = await asyncio.wait_for(process.stdout.readuntil("terminal-markeX"), 3)
                self.assertIn("terminal-markeX", output)
                process.stdin.write(command(
                    f"from pathlib import Path; Path({str(marker)!r}).write_text('executed')"
                ) + "\r")
                process.stdin.write("exit\r")
                result = await asyncio.wait_for(process.wait(), 10)
                self.assertEqual(result.exit_status, 0)
                self.assertEqual(marker.read_text(), "executed")
        marker.unlink()

    async def test_nonterminal_commands_preserve_binary_streams(self) -> None:
        payload = bytes(range(256))
        async with await self.connect() as conn:
            result = await asyncio.wait_for(conn.run(command(
                "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"
            ), input=payload, encoding=None), 10)
            self.assertEqual(result.stdout, payload)
            self.assertEqual(result.exit_status, 0)

    async def test_full_duplex_command_input(self) -> None:
        async with await self.connect() as conn:
            result = await asyncio.wait_for(conn.run(command(
                "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"
            ), input="unicode input \u00e9\n"), 15)
            self.assertEqual(result.stdout, "unicode input \u00e9\n")

    async def test_remote_termination_stops_the_session(self) -> None:
        async with await self.connect() as conn:
            process = await conn.create_process(command("import time; print('ready',flush=True); time.sleep(60)"))
            self.assertEqual((await asyncio.wait_for(process.stdout.readline(), 10)).strip(), "ready")
            process.terminate()
            result = await asyncio.wait_for(process.wait(), 10)
            self.assertNotEqual(result.exit_status, 0)

    async def test_direct_and_remote_forwarding_for_admin(self) -> None:
        async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                data = await reader.read(1024)
                writer.write(data)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        async with await asyncio.start_server(echo, "127.0.0.1", 0) as target:
            target_port = target.sockets[0].getsockname()[1]
            async with await self.connect() as conn:
                reader, writer = await conn.open_connection("127.0.0.1", target_port)
                writer.write(b"direct")
                self.assertEqual(await asyncio.wait_for(reader.read(6), 5), b"direct")
                writer.close()
                await writer.wait_closed()
                socks = await conn.forward_socks("127.0.0.1", 0)
                try:
                    sr, sw = await asyncio.open_connection("127.0.0.1", socks.get_port())
                    sw.write(b"\x05\x01\x00")
                    await sw.drain()
                    self.assertEqual(await asyncio.wait_for(sr.readexactly(2), 5), b"\x05\x00")
                    sw.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target_port.to_bytes(2, "big"))
                    await sw.drain()
                    self.assertEqual((await asyncio.wait_for(sr.readexactly(10), 5))[:2], b"\x05\x00")
                    sw.write(b"dynamic")
                    await sw.drain()
                    self.assertEqual(await asyncio.wait_for(sr.readexactly(7), 5), b"dynamic")
                    sw.close()
                    await sw.wait_closed()
                finally:
                    socks.close()
                    await socks.wait_closed()
                listener = await conn.forward_remote_port("127.0.0.1", 0, "127.0.0.1", target_port)
                try:
                    reader2, writer2 = await asyncio.open_connection("127.0.0.1", listener.get_port())
                    writer2.write(b"remote")
                    await writer2.drain()
                    self.assertEqual(await asyncio.wait_for(reader2.read(6), 5), b"remote")
                    writer2.close()
                    await writer2.wait_closed()
                finally:
                    listener.close()
                    await listener.wait_closed()

    async def test_unauthenticated_forwarding_callbacks_deny(self) -> None:
        owner = app.BrandenburgSSHServer(self.runtime)
        self.assertTrue(owner.begin_auth("guest"))
        self.assertFalse(owner.connection_requested("127.0.0.1", 22, "127.0.0.1", 1000))
        self.assertFalse(owner.server_requested("0.0.0.0", 0))
        process = Mock()
        process.get_extra_info.return_value = None
        await app.handle_client(process)
        process.exit.assert_called_once_with(1)

    async def test_authentication_deadline_closes_idle_transport(self) -> None:
        self.runtime.settings = replace(self.settings, login_timeout=1)
        extra = await app.start_server(self.runtime, host="127.0.0.1", port=0)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", extra.get_port())
            banner = await asyncio.wait_for(reader.readline(), 2)
            self.assertTrue(banner.startswith(b"SSH-"))
            await asyncio.wait_for(reader.read(), 4)
            writer.close()
            await writer.wait_closed()
        finally:
            extra.close()
            await extra.wait_closed()

    async def test_pending_connection_capacity_and_release(self) -> None:
        self.runtime.settings = replace(self.settings, max_pending_connections=1)
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        await reader.readline()
        try:
            other_reader, other_writer = await asyncio.open_connection("127.0.0.1", self.port)
            self.assertEqual(await asyncio.wait_for(other_reader.read(), 3), b"")
            other_writer.close()
            await other_writer.wait_closed()
            self.assertEqual(self.runtime.pending, 1)
        finally:
            writer.close()
            await writer.wait_closed()
        for _ in range(100):
            if self.runtime.pending == 0:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(self.runtime.pending, 0)

    async def test_three_failed_attempts_close_connection(self) -> None:
        owner = app.BrandenburgSSHServer(self.runtime)
        conn = Mock(spec=asyncssh.SSHServerConnection)
        conn.get_extra_info.return_value = ("192.0.2.1", 1234)
        owner.connection_made(conn)
        owner.begin_auth("admin")
        for _ in range(3):
            self.assertFalse(await owner.validate_password("admin", "wrong"))
        conn.close.assert_called_once()
        self.assertEqual(owner.attempts, 3)
        owner.connection_lost(None)
        self.runtime.connections.discard(conn)

    async def test_source_ip_block_rejects_even_a_correct_password(self) -> None:
        for _ in range(5):
            with self.assertRaises((asyncssh.PermissionDenied, asyncssh.DisconnectError)):
                await self.connect(password="wrong")
        self.assertGreater(self.runtime.limiter.entries["127.0.0.1"].blocked_until, 0)
        with self.assertRaises((asyncssh.DisconnectError, ConnectionResetError)):
            await self.connect()

    async def test_disconnect_kills_shell_descendants(self) -> None:
        marker = Path(self.temp.name) / "orphan-marker"
        marker.unlink(missing_ok=True)
        code = (
            "import subprocess,sys,time; "
            f"subprocess.Popen([sys.executable,'-c',"
            f"{('import time,pathlib; time.sleep(2); pathlib.Path(' + repr(str(marker)) + ').write_text(\"orphan\")')!r}]); "
            "print('spawned',flush=True); time.sleep(60)"
        )
        conn = await self.connect()
        process = await conn.create_process(command(code))
        try:
            self.assertEqual((await asyncio.wait_for(process.stdout.readline(), 10)).strip(), "spawned")
        finally:
            conn.abort()
            await conn.wait_closed()
        await asyncio.sleep(3)
        self.assertFalse(marker.exists(), "A disconnected session left an executing descendant")
