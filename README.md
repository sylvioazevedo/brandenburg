# Brandenburg SSH administration

Python/AsyncSSH SSH administration for trusted named administrators on Windows
and Linux. The public application can remain public; this server controls SSH,
not HTTP or host firewall rules.

Run the server on the machine you want to access, then connect from an SSH client.
Run the setup commands below from the project directory on that server.

## Security policy

- Every connection requires an explicitly configured administrator and password.
  There are no built-in accounts, default passwords, or anonymous guest access.
- Password hashes live in an external private JSON file, not the executable.
  Provisioning requires at least 16 characters, no blank-only passwords, and at
  most 72 UTF-8 bytes. Choose a long, unique, randomly generated password or
  passphrase; length alone does not guarantee strength.
- Administrators have shell/remote-command access and **unrestricted direct,
  dynamic (SOCKS), and remote TCP forwarding**, as requested. This includes
  destinations inside the server's network and remote listeners on public
  interfaces. A compromised administrator password can therefore expose other
  services. Use a VPN/IP allowlist and key authentication instead if feasible.
- All administrators run as the **same OS identity as the Python service**.
  Usernames are not separate OS accounts or sandboxes. Select service privileges
  deliberately; the application does not elevate itself.
- Agent forwarding, X11, SFTP/SCP subsystems, and alternative authentication
  methods are not enabled. The shell uses pipes, not a native terminal/ConPTY:
  basic interactive commands are supported, but full-screen terminal programs,
  terminal resizing, and native terminal job control are not guaranteed.
  Terminal sessions use UTF-8 with server-side line editing and echo, including
  Enter and Backspace handling. Interactive Windows shells select code page
  65001. Non-terminal commands retain byte-preserving input/output; terminal
  programs should emit UTF-8 (invalid output sequences display as replacement
  characters).
- AsyncSSH must be at least 2.24.0. The lockfile includes a patched release for
  [GHSA-rw4j-r22c-9gc3](https://github.com/advisories/GHSA-rw4j-r22c-9gc3),
  an SSH channel packet issue capable of freezing the event loop in older releases.

## Install and configure

Use Python 3.12+ and the existing lockfile:

```powershell
uv sync --locked
```

In the following commands, `python` means the project's environment interpreter
(`uv run --locked python` also works). Store configuration, keys, and logs in a
directory writable only by the service identity and trusted OS administrators.
Do not place them in a public web directory or a shared writable directory.

**Keep the current SSH session/service running during setup.** Do not generate a
new host key over the existing one: preserving the host identity avoids an
unexpected client trust change.

First secure the existing host private key. On Linux, run as its intended owner:

```sh
chmod 600 ssh-host-key
```

On Windows, run PowerShell as the identity that will run the service, selecting
the intended existing key path. This replaces its ACL, so verify recovery access
and the service identity first:

```powershell
$key = (Resolve-Path .\ssh-host-key).Path
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetOwner($user)
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($user.Value, 'S-1-5-18', 'S-1-5-32-544')) {
    $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identity, 'FullControl', 'Allow')
    $acl.AddAccessRule($rule)
}
[System.IO.File]::SetAccessControl($key, $acl)
```

Create a **new**, named administrator through a hidden password prompt:

```powershell
python app.py --config brandenburg.private.json provision admin --host-key ssh-host-key --log-file brandenburg.security.log
```

The command creates a private configuration atomically. It neither starts nor
reconfigures a running server. On POSIX, the owner must match the service user,
with no group/other access; on Windows, allowed identities are the service user,
SYSTEM, and local Administrators. Windows permission checks use the built-in
Windows PowerShell/.NET security APIs. A failed check is a startup error.

If a private configuration template already exists with an empty `administrators`
object, run `python app.py --config brandenburg.private.json provision admin`
to add the first administrator. An empty template cannot start the server; no
default password is supplied.

If configuring a different service identity, provision under that identity or
have an OS administrator deliberately transfer ownership/ACLs. Do not solve
permission errors by granting Everyone access.

Repeat `provision admin` to change that administrator's password; omit
`--host-key` and `--log-file` when updating an existing configuration.
Only hashes are stored. No password is accepted through command-line arguments.
Removing a username from the configuration disables it on the next server start;
editing configuration does not revoke already authenticated sessions.

The [example](brandenburg.example.json) documents all options but deliberately
has no valid administrators. Do not serve it directly. Relative paths resolve
against the configuration file's directory, independent of the working directory.

The private configuration defaults to `brandenburg.private.json` in the current
working directory, and starting the server is the default action. After
provisioning, from the project directory you can start it with:

```powershell
uv run --locked python app.py
```

This is equivalent to explicitly selecting `serve`:

```powershell
uv run --locked python app.py --config brandenburg.private.json serve
```

Use the explicit `--config` option when the private configuration is in a
different location. The path is resolved from the current working directory.

Check configuration and host-key parsing without starting a listener:

```powershell
uv run --locked python app.py --config brandenburg.private.json check
```

Before a staged test, edit your private configuration's `host` to a deliberately
chosen interface and `port` to an unused candidate port, for example 2222.
For testing on the same host, use `127.0.0.1`; remote testing requires a reachable
interface and an explicitly approved firewall rule.

On Windows, open the generated configuration with:

```powershell
notepad .\brandenburg.private.json
```

Add these top-level fields, keeping the existing administrator hashes and paths.
Separate JSON fields with commas:

```json
"host": "127.0.0.1",
"port": 2222
```

Validate the edited configuration and start the candidate server:

```powershell
uv run --locked python app.py --config brandenburg.private.json check
uv run --locked python app.py --config brandenburg.private.json serve
```

Keep the server terminal open. From a second terminal on the same machine:

```powershell
ssh -p 2222 admin@127.0.0.1
```

Use the username and password you provisioned; `admin` is only an example name,
not a built-in account. Enter `exit` to disconnect.

For a remote client, replace `127.0.0.1` with the server's reachable hostname or
IP address. The server must also listen on a reachable interface, and the firewall
must permit that connection. A listener bound to `127.0.0.1` cannot accept remote
connections. Follow the safe rollout section before changing existing access.

`test.py` is now only a compatibility launcher with the same required CLI and
authentication policy; it is no longer an alternate insecure server.

## Login limits and logs

Defaults, configurable using the example's field names:

| Control | Default |
|---|---|
| Authentication deadline, starting at connection establishment | 30 seconds |
| Failed password attempts per connection | 3 |
| Failed attempts per source IP within a rolling window | 5 in 900 seconds |
| Block after reaching that threshold | 900 seconds |
| Concurrent unauthenticated connections | 64 |
| IP limiter entries | 4096 |
| Concurrent bcrypt checks, off the event loop | 4 |
| Security log rotation | 5,000,000 bytes, 5 backups |

Connections are rejected when capacity is exhausted; active limiter entries are
not evicted to admit attackers. In-flight password attempts reserve IP budget.
Cancelled authentication counts conservatively as failure. Successful login does
not erase other recent failures. IPv4-mapped IPv6 addresses share IPv4 budgets.
Authenticated shells have no new forced lifetime limit.

Limits are process-local and reset on restart. Multiple workers/instances do not
share budgets. Shared NATs can block legitimate users together; adjust policy
deliberately. A public port still receives probes and SSH handshakes; these
controls are not a network firewall or protection from volumetric denial of service.

Logs are timestamped UTC JSON events with source IP, safely escaped username,
and authentication/authorization decisions. Passwords, hashes, host-key material,
command contents, and shell I/O are not recorded. `authentication_result` is a
password-check result; `authentication_completed` records completion of login.
`forwarding_request` with `allowed: true` means authorization of a request, **not
proof that a destination connection or listener succeeded**.

Keep logs private and preserve them when investigating. Startup errors are
reported on stderr; log write failures also emit an explicit stderr error.
Run with a service manager that captures stderr. Rotated logs retain private
permissions, and replacement log files are secured before writing.

## Safe rollout: do not lock yourself out

1. Preserve existing logs. Determine whether suspicious connections authenticated
   or actually forwarded traffic; probing/request messages alone do not prove a
   breach. Verify the deployed source/version and service account.
2. Keep the existing session and service alive. Provision a fresh strong
   administrator password and run `check`. Preserve the existing host identity.
3. Run this candidate separately on an unused port, with a separate log file.
   If a temporary firewall rule is necessary, limit it to your source IP and
   obtain approval. Do not change public web ports or silently expose a new port.
4. Open a second client connection. Verify host identity, login, required
   commands, forwarding, and reconnect. Do not close the original session.
5. Arrange a viable recovery route before a disruptive cutover. A second SSH
   session helps but is not a substitute for console recovery if the host becomes
   inaccessible. If SSH is the only access and recovery is unavailable, defer
   disruptive changes.
6. Only after verification and operator approval, update service startup to the
   new CLI/configuration and switch the intended listener. Keep known-good startup
   files/configuration for rollback; do not rely on restoring anonymous guest
   access. Check fresh connections after switching.
7. Retire the insecure service, temporary listener, and temporary firewall rule
   only after successful validation. Change other credentials/host keys if
   evidence warrants it, using a separate recovery and client trust-update plan.

No commands in the implementation automatically change firewall rules, restart
the live service, replace existing keys, or change live passwords. **Source
changes alone do not secure a previously deployed Python process or executable.**

## Tests and packaging

```powershell
python -m unittest discover -s tests -v
python -m compileall -q app.py ssh_security.py windows_job.py test.py tests
```

Tests use generated temporary host keys and ephemeral loopback ports, not the
live service or production passwords. CI runs the same suite on Windows/Linux
with Python 3.12 and smoke-tests a freshly built executable.

Build a separate candidate directory, not the existing deployment:
`app.spec` is the PyInstaller build recipe, not a program to run directly.

```powershell
uv run --locked python -m PyInstaller --noconfirm --distpath candidate-dist --workpath candidate-build app.spec
```

Keep private configuration and keys external; they are not bundled. The packaged
`app` executable uses the same optional `--config ... [check|serve|provision]`
interface; omitting the action starts `serve`.
PyInstaller builds for the OS on which it runs; build Linux and Windows
separately. Do not copy the candidate over a running service.

On Windows, validate and run the candidate executable instead of the Python
launcher (do not run both on the same port):

```powershell
.\candidate-dist\app\app.exe --config .\brandenburg.private.json check
.\candidate-dist\app\app.exe --config .\brandenburg.private.json serve
```

With the default config in the current directory, simply running
`.\candidate-dist\app\app.exe` also starts the server.

For a reproducible Windows build and staged deployment named `sshd.exe`, run:

```powershell
.\build-deploy.ps1
```

The script runs the source tests, builds with PyInstaller, renames the executable,
and runs package smoke tests for login, shell/terminal input, and forwarding.
It publishes to a new timestamped directory under `deploy\releases`; it never
overwrites an existing release or copies private configuration/host keys. To
choose a release directory, pass a new path under `deploy\releases`:

```powershell
.\build-deploy.ps1 -Destination .\deploy\releases\sshd-test
```

Run the staged executable with an explicit path to the external private
configuration:

```powershell
.\deploy\releases\sshd-YYYYMMDD-HHMMSS\sshd.exe --config C:\secure\brandenburg.private.json
```

No action is needed to start serving. The script does not install or restart a
Windows service, open firewall ports, or replace the live executable. Keep the
current server and SSH session running until the candidate is validated and you
have a recovery path.

To run the optional executable smoke test in PowerShell:

```powershell
$env:BRANDENBURG_TEST_EXECUTABLE = (Resolve-Path .\candidate-dist\app\app.exe).Path
python -m unittest discover -s tests -p test_package.py -v
Remove-Item Env:\BRANDENBURG_TEST_EXECUTABLE
```

Linux users set `BRANDENBURG_TEST_EXECUTABLE` to the built `app` binary instead.