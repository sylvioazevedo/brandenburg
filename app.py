"""Password-authenticated SSH administration for trusted named administrators."""

import argparse
import asyncio
import codecs
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from typing import IO, AnyStr, Mapping, cast

import asyncssh

from ssh_security import (
    AttemptLimiter, ConfigurationError, PasswordVerifier, Settings,
    _windows_acl, check_private_file, load_settings, normalize_ip, provision,
)


LOG = logging.getLogger("brandenburg")


def event(name: str, **fields: object) -> None:
    LOG.info(json.dumps({"event": name, **fields}, ensure_ascii=True))


class StrictRotatingHandler(RotatingFileHandler):
    def _open(self) -> IO[str]:
        path = Path(self.baseFilename)
        if path.exists():
            check_private_file(path)
        fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            if os.name == "nt":
                _windows_acl(path, restrict=True)
            return os.fdopen(fd, "a", encoding="utf-8")
        except (OSError, ConfigurationError):
            os.close(fd)
            raise

    def handleError(self, record: logging.LogRecord) -> None:
        # Logging failures must be visible even when logging.raiseExceptions is false.
        print("SECURITY ERROR: unable to write the security log", file=sys.stderr)


def configure_logging(settings: Settings) -> None:
    path = settings.log_file
    if path.exists():
        check_private_file(path)
    else:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        if os.name == "nt":
            _windows_acl(path, restrict=True)
    check_private_file(path)
    handler = StrictRotatingHandler(
        path, maxBytes=settings.log_bytes, backupCount=settings.log_backups, encoding="utf-8",
    )
    formatter = logging.Formatter("%(asctime)sZ %(message)s")
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    LOG.setLevel(logging.INFO)
    LOG.addHandler(handler)


class Runtime:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.limiter = AttemptLimiter(settings)
        self.verifier = PasswordVerifier(settings)
        self.pending = 0
        self.connections: set[asyncssh.SSHServerConnection] = set()

    async def close(self) -> None:
        connections = list(self.connections)
        for connection in connections:
            connection.close()
        await asyncio.gather(*(connection.wait_closed() for connection in connections))
        self.verifier.close()


class BrandenburgSSHServer(asyncssh.SSHServer):
    def __init__(self, runtime: Runtime):
        self.runtime = runtime
        self.connection: asyncssh.SSHServerConnection | None = None
        self.ip = ""
        self.username = ""
        self.authenticated = False
        self.counted_pending = False
        self.attempts = 0

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.connection = conn
        self.ip = normalize_ip(conn.get_extra_info("peername")[0])
        self.runtime.connections.add(conn)
        event("connection_received", ip=self.ip)
        reason = None
        if self.runtime.pending >= self.runtime.settings.max_pending_connections:
            reason = "preauthentication_capacity"
        elif not self.runtime.limiter.allowed(self.ip):
            reason = "ip_limit_or_state_capacity"
        if reason is not None:
            event("connection_rejected", ip=self.ip, reason=reason)
            conn.abort()
            return
        self.runtime.pending += 1
        self.counted_pending = True

    def _release_pending(self) -> None:
        if self.counted_pending:
            self.runtime.pending -= 1
            self.counted_pending = False

    def connection_lost(self, exc: Exception | None) -> None:
        self._release_pending()
        if self.connection is not None:
            self.runtime.connections.discard(self.connection)
        event("connection_closed", ip=self.ip, username=self.username,
              authenticated=self.authenticated, error_type=type(exc).__name__ if exc else None)

    def begin_auth(self, username: str) -> bool:
        self.username = username[:128]
        return True

    def password_auth_supported(self) -> bool:
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        settings = self.runtime.settings
        if (not self.counted_pending or self.attempts >= settings.attempts_per_connection
                or not self.runtime.limiter.begin(self.ip)):
            event("authentication_rejected", ip=self.ip, username=self.username, reason="limit")
            if self.connection:
                self.connection.close()
            return False
        self.attempts += 1
        success = False
        try:
            result = await self.runtime.verifier.verify(password, settings.administrators.get(username))
            success = result is True
            event("authentication_result", ip=self.ip, username=self.username,
                  success=success, reason="password" if result is not None else "password_capacity")
        finally:
            # A cancelled/expired verification is conservatively counted as a failure.
            self.runtime.limiter.finish(self.ip, success)
        if not success and self.runtime.limiter.entries[self.ip].blocked_until:
            event("authentication_ip_blocked", ip=self.ip, seconds=settings.block_seconds)
        if not success and self.connection and (
            self.attempts >= settings.attempts_per_connection
            or not self.runtime.limiter.allowed(self.ip)
        ):
            self.connection.close()
        return success

    def auth_completed(self) -> None:
        self.authenticated = self.username in self.runtime.settings.administrators
        self._release_pending()
        event("authentication_completed", ip=self.ip, username=self.username,
              authorized=self.authenticated)
        if not self.authenticated and self.connection:
            self.connection.close()

    def connection_requested(self, dest_host: str, dest_port: int,
                             orig_host: str, orig_port: int) -> bool:
        event("forwarding_request", ip=self.ip, username=self.username,
              direction="direct", host=dest_host[:256], port=dest_port,
              allowed=self.authenticated)
        return self.authenticated

    def server_requested(self, listen_host: str, listen_port: int) -> bool:
        event("forwarding_request", ip=self.ip, username=self.username,
              direction="remote", host=listen_host[:256], port=listen_port,
              allowed=self.authenticated)
        return self.authenticated

    def session_requested(self) -> "TerminalProcess | bool":
        if not self.authenticated:
            return False
        return TerminalProcess(handle_client, None, 3, False)


class TerminalProcess(asyncssh.SSHServerProcess[AnyStr]):
    """Choose terminal text encoding before stream and line-editor initialization."""

    def connection_made(self, channel: asyncssh.SSHServerChannel[AnyStr]) -> None:
        self.pending_channel = channel
        self.streams_started = False

    def pty_requested(self, term_type: str, term_size: tuple[int, int, int, int],
                      term_modes: Mapping[int, int]) -> bool:
        self.pending_channel.set_encoding("utf-8")
        return True

    def session_started(self) -> None:
        super().connection_made(self.pending_channel)
        self.streams_started = True
        super().session_started()

    def connection_lost(self, exc: Exception | None) -> None:
        if self.streams_started:
            super().connection_lost(exc)

    def eof_received(self) -> bool:
        return super().eof_received() if self.streams_started else False

    def data_received(self, data: AnyStr, datatype: int | None) -> None:
        if not self.streams_started:
            event("session_rejected", reason="data_before_shell_or_command")
            self.pending_channel.close()
            return
        super().data_received(data, datatype)


async def stop_child(child: asyncio.subprocess.Process) -> None:
    if os.name == "nt":
        if child.returncode is None:
            killer = await asyncio.create_subprocess_exec(
                "taskkill.exe", "/PID", str(child.pid), "/T", "/F",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            status = await killer.wait()
            if status and child.returncode is None:
                event("process_cleanup_failed", pid=child.pid, status=status)
                child.kill()
    else:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    await child.wait()


async def handle_client(process: asyncssh.SSHServerProcess[AnyStr]) -> None:
    connection = process.get_extra_info("connection")
    owner = connection.get_owner() if connection else None
    if not isinstance(owner, BrandenburgSSHServer) or not owner.authenticated:
        event("session_rejected", reason="not_authorized")
        process.exit(1)
        return
    event("session_started", ip=owner.ip, username=owner.username)
    command = process.command
    terminal = bool(process.get_terminal_type())

    def write_error(message: str) -> None:
        process.stderr.write(cast(AnyStr, message if terminal else message.encode("utf-8")))
    if os.name == "nt":
        args = [os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"), "/d"]
        args += ["/q"]
        if terminal and not command:
            args += ["/k", "chcp 65001 >nul"]
        # Assign to a kill-on-close job before any shell code can spawn descendants.
        options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000004}
    else:
        args = ["/bin/sh", "-c", command] if command else ["/bin/sh", "-i"]
        options = {"start_new_session": True}
    child: asyncio.subprocess.Process | None = None
    tasks: list[asyncio.Task] = []
    job = None
    termination_signal: str | None = None
    try:
        if os.name == "nt":
            from windows_job import WindowsJob
            job = WindowsJob()
        if os.name == "nt" and command:
            # subprocess shell mode applies cmd.exe's outer-quote convention.
            child = await asyncio.create_subprocess_shell(
                command, executable=args[0], stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, **options,
            )
        else:
            child = await asyncio.create_subprocess_exec(
                *args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, **options,
            )
        if job is not None:
            job.assign_and_resume(child.pid)
        assert child.stdin is not None and child.stdout is not None and child.stderr is not None

        async def feed_input() -> None:
            nonlocal termination_signal
            assert child is not None and child.stdin is not None
            try:
                while True:
                    try:
                        data = await process.stdin.read(65536)
                    except asyncssh.SignalReceived as received:
                        try:
                            if os.name == "nt":
                                if received.signal in ("TERM", "KILL") and job is not None:
                                    termination_signal = received.signal
                                    job.close()
                                elif received.signal == "INT":
                                    child.send_signal(signal.CTRL_BREAK_EVENT)
                                else:
                                    write_error("Unsupported shell signal on Windows.\r\n")
                            else:
                                supported = {
                                    "INT": signal.SIGINT, "TERM": signal.SIGTERM,
                                    "HUP": signal.SIGHUP, "KILL": signal.SIGKILL,
                                }
                                if received.signal in supported:
                                    os.killpg(child.pid, supported[received.signal])
                                else:
                                    write_error("Unsupported shell signal.\n")
                            event("session_signal", ip=owner.ip, username=owner.username,
                                  signal=received.signal)
                        except OSError as exc:
                            event("session_signal_failed", ip=owner.ip, username=owner.username,
                                  error_type=type(exc).__name__)
                            write_error("Unable to deliver shell signal.\n")
                        continue
                    except (asyncssh.TerminalSizeChanged, asyncssh.BreakReceived) as received:
                        event("terminal_control_unsupported", ip=owner.ip, username=owner.username,
                              control=type(received).__name__)
                        continue
                    if not data:
                        break
                    child.stdin.write(data.encode("utf-8") if isinstance(data, str) else data)
                    await child.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                event("session_input_closed", ip=owner.ip, username=owner.username)
            finally:
                child.stdin.close()

        async def copy_output(source: asyncio.StreamReader, target: asyncssh.SSHWriter[AnyStr]) -> None:
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace") if terminal else None
            while data := await source.read(65536):
                target.write(cast(AnyStr, decoder.decode(data) if decoder else data))
                await target.drain()
            if decoder:
                target.write(cast(AnyStr, decoder.decode(b"", final=True)))

        input_task = asyncio.create_task(feed_input())
        stdout_task = asyncio.create_task(copy_output(child.stdout, process.stdout))
        stderr_task = asyncio.create_task(copy_output(child.stderr, process.stderr))
        wait_task = asyncio.create_task(child.wait())
        closed_task = asyncio.create_task(process.wait_closed())
        tasks = [input_task, stdout_task, stderr_task, wait_task, closed_task]
        done, _ = await asyncio.wait(
            [wait_task, closed_task, stdout_task, stderr_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        # Output EOF may precede process exit; it is not itself a disconnect.
        while wait_task not in done and closed_task not in done:
            for task in done:
                task.result()
            watched = [task for task in (wait_task, closed_task, stdout_task, stderr_task) if not task.done()]
            done, _ = await asyncio.wait(watched, return_when=asyncio.FIRST_COMPLETED)
        if closed_task in done and not wait_task.done():
            event("session_disconnected", ip=owner.ip, username=owner.username)
        else:
            await asyncio.gather(stdout_task, stderr_task)
            status = await wait_task
            if termination_signal is not None:
                process.exit_with_signal(termination_signal)
            elif status < 0:
                process.exit_with_signal(signal.Signals(-status).name.removeprefix("SIG"))
            else:
                process.exit(status)
    except (OSError, asyncssh.Error) as exc:
        event("session_error", ip=owner.ip, username=owner.username, error_type=type(exc).__name__)
        process.exit(1)
    finally:
        for task in tasks:
            task.cancel()
        if job is not None:
            job.close()
        if child is not None:
            await stop_child(child)
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                event("session_task_error", ip=owner.ip, username=owner.username,
                      error_type=type(result).__name__)
        event("session_ended", ip=owner.ip, username=owner.username)


async def start_server(runtime: Runtime, *, host: str | None = None, port: int | None = None) -> asyncssh.SSHAcceptor:
    settings = runtime.settings
    return await asyncssh.create_server(
        lambda: BrandenburgSSHServer(runtime),
        host if host is not None else settings.host,
        port if port is not None else settings.port,
        server_host_keys=[str(settings.host_key)],
        encoding=None,
        line_editor=True,
        line_echo=True,
        login_timeout=settings.login_timeout,
        password_auth=True, public_key_auth=False, kbdint_auth=False,
        host_based_auth=False, gss_auth=False, gss_kex=False,
        agent_forwarding=False, x11_forwarding=False,
        allow_pty=True,
    )


async def serve(settings: Settings) -> None:
    runtime = Runtime(settings)
    try:
        async with await start_server(runtime):
            event("server_started", host=settings.host, port=settings.port,
                  forwarding="unrestricted_authenticated_administrators")
            print(f"SSH listening on {settings.host}:{settings.port}; passwords enabled; admin forwarding unrestricted.")
            await asyncio.Future()
    finally:
        await runtime.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=Path("brandenburg.private.json"),
        help="External private JSON configuration (default: brandenburg.private.json)",
    )
    subparsers = parser.add_subparsers(dest="action")
    subparsers.add_parser("check", help="Validate configuration and host key without binding")
    subparsers.add_parser("serve")
    add = subparsers.add_parser("provision", help="Add/update an administrator using a hidden prompt")
    add.add_argument("username")
    add.add_argument("--host-key", type=Path)
    add.add_argument("--log-file", type=Path)
    args = parser.parse_args()
    action = args.action or "serve"
    try:
        if action == "provision":
            provision(args.config.absolute(), args.username, args.host_key, args.log_file)
            print("Administrator configuration saved. No running service was changed.")
        else:
            settings = load_settings(args.config.absolute())
            asyncssh.read_private_key(settings.host_key)
            if action == "check":
                print("Configuration and host key are valid. No listener was started.")
            else:
                configure_logging(settings)
                asyncio.run(serve(settings))
        return 0
    except (ConfigurationError, OSError, asyncssh.Error, ValueError) as exc:
        event("startup_failed", error_type=type(exc).__name__)
        print(f"Startup/configuration error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        event("server_stopped", reason="operator_interrupt")
        return 0
    finally:
        for handler in list(LOG.handlers):
            handler.close()
            LOG.removeHandler(handler)


if __name__ == "__main__":
    sys.exit(main())
