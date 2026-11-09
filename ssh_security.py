"""Configuration, provisioning, and bounded password authentication."""

import asyncio
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import getpass
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from typing import Callable

import bcrypt


class ConfigurationError(ValueError):
    pass


def _windows_acl(path: Path, *, restrict: bool = False) -> None:
    env = dict(os.environ, BRANDENBURG_ACL_PATH=str(path.resolve()))
    script = """
$ErrorActionPreference = 'Stop'
$path = $env:BRANDENBURG_ACL_PATH
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$trusted = @($user.Value, 'S-1-5-18', 'S-1-5-32-544')
"""
    if restrict:
        script += """
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetOwner($user)
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in $trusted) {
    $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identity, 'FullControl', 'Allow')
    $acl.AddAccessRule($rule)
}
[System.IO.File]::SetAccessControl($path, $acl)
"""
    script += """
$acl = [System.IO.File]::GetAccessControl($path)
if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
    throw 'Untrusted file owner'
}
foreach ($rule in $acl.Access) {
    $sid = $rule.IdentityReference.Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    if ($rule.AccessControlType -eq 'Allow' -and $sid -notin $trusted) {
        throw 'File grants access to an untrusted identity'
    }
}
"""
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            env=env, capture_output=True, text=True, check=False, timeout=15,
        )
    except subprocess.TimeoutExpired as exc:
        raise ConfigurationError(f"Timed out checking private file ACL: {path}") from exc
    if result.returncode:
        raise ConfigurationError(
            f"Unsafe file ACL or ACL check failed: {path}. "
            "Grant access only to the service identity, SYSTEM, and Administrators."
        )


def check_private_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ConfigurationError(f"Expected a regular, non-symlink private file: {path}")
    if os.name == "nt":
        _windows_acl(path)
    else:
        info = path.stat()
        if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO) or info.st_uid != os.getuid():
            raise ConfigurationError(f"Private file must be owned by this user with mode 600: {path}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError(f"Duplicate configuration key: {key!r}")
        result[key] = value
    return result


@dataclass(frozen=True)
class Settings:
    administrators: dict[str, bytes]
    host_key: Path
    log_file: Path
    host: str = "0.0.0.0"
    port: int = 22
    login_timeout: int = 30
    attempts_per_connection: int = 3
    failures_per_ip: int = 5
    failure_window: int = 900
    block_seconds: int = 900
    max_pending_connections: int = 64
    max_ip_entries: int = 4096
    password_workers: int = 4
    log_bytes: int = 5_000_000
    log_backups: int = 5


def read_document(path: Path) -> dict[str, object]:
    check_private_file(path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Invalid JSON configuration: {path}") from exc
    if not isinstance(document, dict):
        raise ConfigurationError("Configuration must be a JSON object")
    return document


def load_settings(path: Path, *, allow_empty_administrators: bool = False) -> Settings:
    document = read_document(path)
    allowed = set(Settings.__dataclass_fields__)
    if document.keys() - allowed:
        raise ConfigurationError("Unknown configuration option")
    admins = document.get("administrators")
    if not isinstance(admins, dict) or (not admins and not allow_empty_administrators):
        raise ConfigurationError("At least one named administrator is required")
    hashes: dict[str, bytes] = {}
    for username, value in admins.items():
        if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", username):
            raise ConfigurationError("Administrator names must use 1-64 ASCII letters, digits, dot, dash or underscore")
        if not isinstance(value, str) or not re.fullmatch(r"\$2[aby]\$(1[0-4])\$[./A-Za-z0-9]{53}", value):
            raise ConfigurationError(f"Invalid bcrypt hash or cost (expected 10-14) for {username!r}")
        encoded = value.encode("ascii")
        try:
            bcrypt.checkpw(b"configuration-validation", encoded)
        except ValueError as exc:
            raise ConfigurationError(f"Invalid bcrypt hash for {username!r}") from exc
        hashes[username] = encoded
    paths: dict[str, Path] = {}
    for key in ("host_key", "log_file"):
        value = document.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ConfigurationError(f"{key} must be an explicit nonempty path")
        paths[key] = (path.parent / value).absolute()
    check_private_file(paths["host_key"])
    host = document.get("host", "0.0.0.0")
    if not isinstance(host, str) or not host.strip():
        raise ConfigurationError("host must be a nonempty address")
    numbers: dict[str, int] = {}
    for name in allowed - {"administrators", "host_key", "log_file", "host"}:
        value = document.get(name, getattr(Settings, name))
        if type(value) is not int or not 1 <= value <= 10_000_000:
            raise ConfigurationError(f"{name} must be a positive bounded integer")
        numbers[name] = value
    if numbers["port"] > 65535 or numbers["password_workers"] > 32:
        raise ConfigurationError("port must be <=65535; password_workers must be <=32")
    if numbers["max_pending_connections"] > 4096 or numbers["max_ip_entries"] > 100_000:
        raise ConfigurationError("Connection/state limits are too large")
    if numbers["login_timeout"] > 300 or numbers["log_backups"] > 100:
        raise ConfigurationError("login_timeout must be <=300; log_backups must be <=100")
    if numbers["attempts_per_connection"] > 100 or numbers["failures_per_ip"] > 100:
        raise ConfigurationError("Authentication failure thresholds must be <=100")
    return Settings(
        administrators=hashes, host_key=paths["host_key"], log_file=paths["log_file"],
        host=host, port=numbers["port"], login_timeout=numbers["login_timeout"],
        attempts_per_connection=numbers["attempts_per_connection"],
        failures_per_ip=numbers["failures_per_ip"], failure_window=numbers["failure_window"],
        block_seconds=numbers["block_seconds"], max_pending_connections=numbers["max_pending_connections"],
        max_ip_entries=numbers["max_ip_entries"], password_workers=numbers["password_workers"],
        log_bytes=numbers["log_bytes"], log_backups=numbers["log_backups"],
    )


def write_private_document(path: Path, document: dict[str, object]) -> None:
    """Replace configuration atomically, securing the temporary file before writing."""
    if path.exists():
        check_private_file(path)
    fd, temporary = tempfile.mkstemp(prefix=".brandenburg-", dir=path.parent)
    temp = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            if os.name == "nt":
                _windows_acl(temp, restrict=True)
            else:
                os.fchmod(output.fileno(), 0o600)
            json.dump(document, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def provision(path: Path, username: str, host_key: Path | None, log_file: Path | None) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", username):
        raise ConfigurationError("Invalid administrator username")
    if path.exists():
        load_settings(path, allow_empty_administrators=True)
        document = read_document(path)
    else:
        if host_key is None or log_file is None:
            raise ConfigurationError("New configuration requires --host-key and --log-file")
        check_private_file(host_key)
        document = {
            "host_key": str(host_key.absolute()), "log_file": str(log_file.absolute()),
            "administrators": {},
        }
    password = getpass.getpass("New administrator password (16+ characters): ")
    if len(password) < 16 or len(password.encode("utf-8")) > 72 or not password.strip():
        raise ConfigurationError("Use a nonblank password of at least 16 characters and at most 72 UTF-8 bytes")
    if password != getpass.getpass("Confirm password: "):
        raise ConfigurationError("Passwords do not match")
    admins = document["administrators"]
    if not isinstance(admins, dict):
        raise ConfigurationError("administrators must be an object")
    admins[username] = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12)).decode("ascii")
    write_private_document(path, document)


def normalize_ip(address: str) -> str:
    value = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped:
        return str(value.ipv4_mapped)
    return str(value)


@dataclass
class IPState:
    failures: deque[float] = field(default_factory=deque)
    pending: int = 0
    blocked_until: float = 0


class AttemptLimiter:
    def __init__(self, settings: Settings, clock: Callable[[], float] = time.monotonic):
        self.settings = settings
        self.clock = clock
        self.entries: dict[str, IPState] = {}

    def _prune(self) -> None:
        now = self.clock()
        for ip, state in list(self.entries.items()):
            while state.failures and state.failures[0] <= now - self.settings.failure_window:
                state.failures.popleft()
            if state.blocked_until and state.blocked_until <= now:
                state.blocked_until = 0
                state.failures.clear()
            if not state.pending and not state.failures and not state.blocked_until:
                del self.entries[ip]

    def allowed(self, ip: str) -> bool:
        self._prune()
        state = self.entries.get(ip)
        return (
            (state is None and len(self.entries) < self.settings.max_ip_entries)
            or (state is not None and not state.blocked_until
                and len(state.failures) + state.pending < self.settings.failures_per_ip)
        )

    def begin(self, ip: str) -> bool:
        if not self.allowed(ip):
            return False
        self.entries.setdefault(ip, IPState()).pending += 1
        return True

    def finish(self, ip: str, success: bool) -> None:
        state = self.entries[ip]
        state.pending -= 1
        if not success:
            state.failures.append(self.clock())
            if len(state.failures) >= self.settings.failures_per_ip:
                state.blocked_until = self.clock() + self.settings.block_seconds


class PasswordVerifier:
    def __init__(self, settings: Settings):
        self.limit = settings.password_workers
        self.active = 0
        self.executor = ThreadPoolExecutor(max_workers=self.limit, thread_name_prefix="ssh-password")
        self.dummy = bcrypt.hashpw(os.urandom(32), bcrypt.gensalt(12))

    async def verify(self, password: str, hashed: bytes | None) -> bool | None:
        if self.active >= self.limit:
            return None
        raw = password.encode("utf-8")
        valid_length = 0 < len(raw) <= 72
        self.active += 1
        future = asyncio.get_running_loop().run_in_executor(
            self.executor, bcrypt.checkpw, raw if valid_length else b"invalid-length", hashed or self.dummy,
        )
        future.add_done_callback(self._finished)
        result = await asyncio.shield(future)
        return bool(result and hashed is not None and valid_length)

    def _finished(self, future: asyncio.Future[bool]) -> None:
        self.active -= 1
        # Retrieve failures even if the SSH authentication task was cancelled.
        if not future.cancelled():
            error = future.exception()
            if error is not None:
                logging.getLogger("brandenburg").error(json.dumps({
                    "event": "password_worker_error", "error_type": type(error).__name__,
                }))

    def close(self) -> None:
        self.executor.shutdown(wait=True, cancel_futures=True)
