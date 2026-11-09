import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest

import asyncssh

from ssh_security import write_private_document
from test_security import HASH, PASSWORD, secure


EXECUTABLE = os.environ.get("BRANDENBURG_TEST_EXECUTABLE")


@unittest.skipUnless(EXECUTABLE, "Set BRANDENBURG_TEST_EXECUTABLE to a candidate package")
class PackageTests(unittest.IsolatedAsyncioTestCase):
    async def test_external_configuration_login_shell_and_forwarding(self) -> None:
        assert EXECUTABLE is not None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host_key = asyncssh.generate_private_key("ssh-ed25519")
            key = root / "host-key"
            host_key.write_private_key(key)
            secure(key)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            config = root / "brandenburg.private.json"
            write_private_document(config, {
                "administrators": {"admin": HASH.decode()}, "host_key": str(key),
                "log_file": str(root / "package.security.log"), "host": "127.0.0.1", "port": port,
            })
            checked = await asyncio.to_thread(
                subprocess.run, [EXECUTABLE, "--config", str(config), "check"],
                cwd=root, capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertFalse((root / "package.security.log").exists())
            running = subprocess.Popen(
                [EXECUTABLE, "--config", str(config), "serve"],
                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                connection = None
                for _ in range(100):
                    self.assertIsNone(running.poll(), "Candidate exited before becoming ready")
                    try:
                        connection = await asyncssh.connect(
                            "127.0.0.1", port, username="admin", password=PASSWORD,
                            known_hosts=([host_key.convert_to_public()], [], []),
                            client_keys=[], preferred_auth=["password"], login_timeout=5,
                        )
                        break
                    except ConnectionRefusedError:
                        await asyncio.sleep(0.1)
                self.assertIsNotNone(connection, "Candidate never became responsive")
                assert connection is not None
                async with connection:
                    result = await asyncio.wait_for(connection.run("echo packaged-ok"), 10)
                    self.assertEqual(result.exit_status, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), "packaged-ok")
                    async with connection.create_process(term_type="xterm") as terminal:
                        terminal.stdin.write("echo packaged-terminal")
                        await asyncio.wait_for(terminal.stdout.readuntil("echo packaged-terminal"), 5)
                        terminal.stdin.write("\rexit\r")
                        terminal_result = await asyncio.wait_for(terminal.wait(), 10)
                        self.assertIn("packaged-terminal", terminal_result.stdout)
                        self.assertEqual(terminal_result.exit_status, 0)
                    listener = await connection.forward_remote_port("127.0.0.1", 0, "127.0.0.1", 1)
                    listener.close()
                    await listener.wait_closed()
                with self.assertRaises(asyncssh.PermissionDenied):
                    await asyncssh.connect(
                        "127.0.0.1", port, username="guest", password="",
                        known_hosts=([host_key.convert_to_public()], [], []),
                        client_keys=[], preferred_auth=["password"], login_timeout=5,
                    )
            finally:
                running.terminate()
                try:
                    stdout, stderr = await asyncio.to_thread(running.communicate, timeout=15)
                except subprocess.TimeoutExpired:
                    running.kill()
                    stdout, stderr = await asyncio.to_thread(running.communicate, timeout=15)
                self.assertNotIn(PASSWORD.encode(), stdout + stderr)
            for line in (root / "package.security.log").read_text().splitlines():
                payload = json.loads(line.split("Z ", 1)[1])
                self.assertIn("event", payload)
                self.assertNotIn(PASSWORD, line)
