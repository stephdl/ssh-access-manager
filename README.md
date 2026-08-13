# ssh-access-manager

SSH access auditing and management, in a single Alpine Linux container.

**Stack**: Python 3.12 · Flask · PostgreSQL 18 · Nginx · Vue.js 3 · vue-i18n · Supervisord · Alpine 3.24.1

> 🇫🇷 Une version française de ce document est disponible dans [README.fr.md](README.fr.md).

---

## Installation and first start

### Requirements

- Podman or Docker
- A reachable SMTP smarthost (for email alerts)

### 1. Clone and configure

```bash
git clone https://github.com/stephdl/ssh-access-manager.git
cd ssh-access-manager
cp .env.example .env
# Edit .env with your own values
```

### 2. Build the image

```bash
podman build -t sam-server .
```

### 3. First start

```bash
podman run -d \
  --name sam-server \
  --env-file .env \
  -v ssh_data:/data \
  -p 8080:8080 \
  sam-server
```

On first start, the container:
1. Initialises PostgreSQL and applies the SQL schema
2. Creates `/data/keys/per-server/`, which will hold the ED25519 key pairs generated **per server** (one per host added)
3. Inserts the initial administrator (from `ADMIN_USERNAME` and `ADMIN_EMAIL`)

> **Per-server collector keys.** SAM no longer generates a global SSH key. When a server is added (UI or CLI), a `<uuid>.key{,.pub}` pair is generated in `/data/keys/per-server/`. A compromised key is therefore confined to a single host. A server's public key is available from **ServerDetail** or through `GET /api/servers/<hostname>/collector-key`.

The interface is served on `http://localhost:8080`. Authentication uses a Flask session: sign in with the credentials set through `ADMIN_USERNAME` / `ADMIN_PASSWORD` at startup.

---

## User interface

The Vue.js 3 interface is available in **5 languages**: French, English, Spanish, Italian, German.

The language is detected from the browser, falling back to English. A selector in the navigation bar switches it manually, and the choice is remembered.

---

## Roles and permissions

Three administrator roles are available:

| Role | Rights |
|---|---|
| `sysadmin` | Full access: administrators, servers, SSH keys, access and system configuration |
| `operator` | SSH actions: validate, revoke and deploy keys, lock/unlock Unix accounts, run scans |
| `viewer` | Read-only: every view is visible, no action is possible |

The role is enforced **in the backend** (Flask returns 403 for unauthorised requests) **and in the frontend** (buttons and forms are hidden according to the role).

A `sysadmin` cannot change their own role. An email address is mandatory at creation.

### Permissions by category

| Category | sysadmin | operator | viewer |
|-----------|----------|----------|--------|
| Read (GET — every resource) | ✓ | ✓ | ✓ |
| SSH actions (validate/revoke keys, scans, deployment, lock/unlock) | ✓ | ✓ | ✗ |
| System administration (servers, admins, configuration) | ✓ | ✗ | ✗ |
| Changing one's own password | ✓ | ✓ | ✓ |

To create an administrator with a specific role (default: `operator`):

```bash
$EXEC admin add --username alice --email alice@example.com --password SECRET --role operator
$EXEC admin update alice --role viewer
```

---

## Security — brute-force protection

The system protects against repeated login attempts. After several failures from the same IP address, that address is temporarily banned.

### How it works

- **Attempt limit**: after N consecutive failed logins, the IP is blocked for M seconds
- **HTTP response**: `429 Too Many Requests` for the duration of the ban
- **Configuration**: both parameters are changed at runtime through **Settings → Security** (`sysadmin` role required)
  - `login_max_attempts` (default: 10) — failures before a ban
  - `login_ban_seconds` (default: 300) — ban duration in seconds
- **No restart**: changes take effect immediately

### stdout logs — fail2ban / CrowdSec integration

Every failed login and every ban is written to stdout (visible through `podman logs`) in this format:

```
[LOGIN_FAILED] ip=1.2.3.4 username=admin
[LOGIN_BANNED] ip=1.2.3.4 username=admin ban_seconds=300
```

These structured logs make it straightforward to plug in an intrusion detection system such as **fail2ban** or **CrowdSec** and apply the ban at the host firewall level.

---

## Session handling

Session lifetime is controlled by a checkbox on the login page:

| Mode | Lifetime |
|------|---------|
| Unchecked | 30 minutes |
| "Keep me logged on this device" | 8 hours |

Once expired, protected routes return HTTP 401 and the UI redirects to `/login`.
The durations are constants in `web.py` — no restart is needed to change them in development.

---

## Workflow — adding a remote server

SAM generates **a distinct ed25519 SSH key pair per server** (stored in `/data/keys/per-server/<uuid>.key{,.pub}`, chmod 600, owned by `nobody`, with no SSH comment). A compromised key exposes one host, never the whole estate. The server ↔ key mapping is implicit in the file name (random UUID v4) — **no fingerprint is stored in the database**, so stealing the database alone reveals nothing cryptographically useful.

Five ways to add a server, from the simplest to the most scriptable:

### A. UI, one server, with a password (simplest)

Dashboard → **+ Add server** → fill in:

| Field | Required | Description |
|---|---|---|
| Hostname | ✓ | RFC 1123 name (`server-01`, `web.prod.example.com`) |
| IP address | ✓ | IPv4 or IPv6 — must be unique within SAM |
| SSH user | ✓ | An account with sudo (`root`, or any `sudo ALL` account) |
| SSH password | ✓ | Used **once** for provisioning — never stored |
| SSH port | — | Default: 22 |
| Environment | — | `production` / `staging` / `lab` — changeable later |
| OS | — | OS family (`rhel`, `debian`…) — changeable later |

On submit, SAM: (1) generates the per-server key pair, (2) opens an SSH session with the password, (3) pushes `provision-host.sh`, which creates the `audit-collector` user, deploys the public key and configures sudoers, the SAM groups and the sshd drop-in, (4) INSERTs into the database with `is_provisioned=TRUE`, (5) **runs an automatic scan** in the background (fire-and-forget) to collect the existing `authorized_keys` right away. If SSH fails, **nothing is written**.

### B. CLI, one server, with a password

```bash
podman exec sam-server python3 /app/app/manage.py servers add \
    --hostname server-prod-01 --ip 192.168.1.10 \
    --ssh-user root --ssh-password 'SECRET' \
    [--env production] [--os rhel] [--port 22]
```

If `--ssh-password` is omitted, it is prompted for interactively (`hide_input=True`). The initial scan is **synchronous** from the CLI (the process would otherwise die before the thread finishes) — the command returns after the scan, typically 3–5 s.

### C. CLI, one server, without a password (your own root SSH key)

A three-step workflow, useful when SAM must never see your credentials:

```bash
HOSTNAME=server-prod-01
IP=192.168.1.10

# 1. register — generates the per-server key pair, INSERTs with is_provisioned=FALSE
podman exec sam-server python3 /app/app/manage.py servers register \
    --hostname "$HOSTNAME" --ip "$IP"

# 2. push the per-server public key using YOUR root SSH key
PUB=$(podman exec sam-server python3 /app/app/manage.py servers show "$HOSTNAME" --pubkey)
ssh root@"$IP" "sudo bash -s '$PUB' 'audit-collector'" \
    < <(podman exec sam-server cat /app/provision-host.sh)

# 3. activate — checks connectivity with the per-server key, sets is_provisioned=TRUE,
#    and triggers a synchronous initial scan
podman exec sam-server python3 /app/app/manage.py servers activate "$HOSTNAME"
```

### D. CLI, several servers in bulk, with a password

When every server shares the **same** root password (fresh cloud-init / Ansible images):

```bash
PASS='SECRET'
for ip in 192.168.1.{10..15}; do
  podman exec sam-server python3 /app/app/manage.py servers add \
      --hostname "srv-${ip##*.}" --ip "$ip" \
      --ssh-user root --ssh-password "$PASS"
done
```

For per-host passwords, script a loop reading an `ip:password` file or a vault (vault, pass, sops…) — the password is only ever a CLI argument, never persisted.

### E. CLI, several servers in bulk, without a password (cloud-init / pre-deployed key)

```bash
for ip in 192.168.1.{10..15}; do
  hostname=srv-${ip##*.}
  # register
  podman exec sam-server python3 /app/app/manage.py servers register \
      --hostname "$hostname" --ip "$ip"
  # push using your root key
  PUB=$(podman exec sam-server python3 /app/app/manage.py servers show "$hostname" --pubkey)
  ssh root@"$ip" "sudo bash -s '$PUB' 'audit-collector'" \
      < <(podman exec sam-server cat /app/provision-host.sh)
  # activate (initial scan included)
  podman exec sam-server python3 /app/app/manage.py servers activate "$hostname"
done
```

Parallelisable with GNU `parallel`, Ansible (`ansible -m shell`), or any configuration management tool.

### F. Declarative through `servers.yml` (legacy — manual)

```yaml
# /data/config/servers.yml
servers:
  - hostname: server-prod-01
    ip: 192.168.1.10
    environment: production   # optional
    os_family: rhel           # optional
```

This method creates the database entry without automatic SSH provisioning — the equivalent of a manual `register`. You then deploy the public key and activate as in workflow **C** above.

---

### Provisioning script — interface

`provision-host.sh` takes two positional arguments:

```bash
sudo bash provision-host.sh <pubkey> <collector_user>
```

The script is **idempotent**: it can be replayed safely (SAM rebuild, key rotation, sudoers rule updates). The **Re-provision** button on a server's detail view (`sysadmin` role) invokes it from SAM after asking for a new SSH password; the manual snippet is also shown in the collapsible **"Provision with your own SSH credentials"** block on every ServerDetail.

> **Note**: SSH connections always use the declared IP address, never DNS resolution, to avoid network ambiguity and CrowdSec/fail2ban bans.

---

### Manual per-server key rotation

From **ServerDetail** (`sysadmin` role), the **Rotate collector key** button (teal) performs an **atomic rotation with rollback**:

1. Generates a new key pair `<uuid>.key.new` locally
2. Connects with the old key and appends the new public key to `~audit-collector/.ssh/authorized_keys`
3. Reconnects with the **new** key to verify it works
4. Connects once more to remove the old public key from the remote host
5. Moves the new key onto the canonical path atomically (`os.replace`), leaving no backup to clean up

Up to step 4, any failure leaves the old key as the only active one and writes a `COLLECTOR_KEY_ROTATION_FAILED` audit entry (with the error message, without hostname or IP, to keep the exposed information minimal). Past step 4 the host only accepts the new key, so a failure there keeps the new key pair in place and reports where to find it rather than deleting it. Success writes `COLLECTOR_KEY_ROTATED` with the new fingerprint.

---

### Renaming a server

From **ServerDetail** (`sysadmin` role) → **Edit** → the Hostname field is editable. The form:

- Validates the new name (RFC 1123)
- Refuses a name already used by another server

After saving, the UI redirects to `/servers/<new-hostname>` (the component remounts cleanly). A `SERVER_RENAMED` audit entry records `{old_hostname, new_hostname}` with the administrator and the timestamp.

**About audit history after a rename.** Three sources coexist, each answering a different question:

1. The **SERVER** column in the Audit view always shows the **current** hostname (SQL JOIN on the `target_server` UUID). An audit entry pointing at an obsolete name would be broken.
2. The **`details` JSONB** field of each entry keeps the hostname **frozen at the time of the event** (e.g. `SCAN_COMPLETED → {hostname: "srv-12-119"}`). The code never rewrites audit rows.
3. The **`SERVER_RENAMED`** entries let you reconstruct the whole rename timeline.

Cross-referencing an entry's `details` with the chronology of `SERVER_RENAMED` tells you exactly which name the server went by at any point in time.

---

## Workflow — server lifecycle

From a server's detail view (**Dashboard > click the hostname**):

| Action | Effect |
|---|---|
| **Scan** | Runs a scan immediately, without waiting for the cron cycle. |
| **Edit** | Changes hostname, IP, environment, OS, SSH port or `max_sessions` (`sysadmin` role). A rename emits a `SERVER_RENAMED` audit entry and redirects the UI. |
| **Disable** | The server is no longer scanned automatically. Red indicator on the Dashboard, red banner in ServerDetail. |
| **Re-provision** | Replays `provision-host.sh` remotely with a new password (`sysadmin` role, active server) — useful after a SAM rebuild or a change to the sudoers contract. |
| **Rotate collector key** | Generates a new per-server key pair, deploys it and removes the old one — atomic with rollback (`sysadmin` role, server active and provisioned). |
| **Delete** | Permanently removes the server, all its keys, authorizations and sessions, and its per-server key pair (irreversible). |

---

## Workflow — first scan

```bash
# Scan every active server
podman exec sam-server python3 /app/app/manage.py servers scan

# Or from the web interface: Dashboard > "Scan now"
# Or from a server's detail view: "Scan" button
```

On the first scan:
- The `sam-collect` and `sam-revoke` scripts are deployed to each host (over SFTP, SHA256 hash verified)
- Every key present in `authorized_keys` is imported with the `PENDING_REVIEW` status
- A CRITICAL email alert is sent for each unknown key found

If a server's scan fails (SSH unreachable, sudo missing, timeout…), the server moves to **Scan Failed**:
- 🟠 indicator in the dashboard (orange badge)
- Orange banner at the top of the server detail view
- The **Validate** and **Revoke** buttons are disabled until the next successful scan
- A CRITICAL email alert is sent

---

## Updating SAM

When you update SAM (image rebuild, version bump), there are three cases depending on what the update contains.

### 1. Transparent update (most common)

Most releases only touch the Python application layer or the Vue frontend. Nothing changes on the managed hosts and there is nothing to do — restart the SAM container with the new image.

### 2. Updating the SAM_* scripts (sam-collect, sam-revoke, sam-self-update, etc.)

If the new version changes a `SAM_*` script deployed on the hosts (the `bytes` constants in `app/ssh.py`), `ensure_scripts()` notices at the next scan by comparing SHA256 hashes and redeploys the script over SFTP + `sudo install -m 750`. Visible in the Audit view as `SCRIPT_DEPLOYED`. **No administrator action required.**

### 3. Updating the sudoers or sshd contract laid down by provision-host.sh

If the new version extends `provision-host.sh` (a new sudoers rule, a new Unix group, a hardened sshd drop-in…), servers already provisioned do **not** update themselves. They are flagged with the **"Reprovisioning required"** badge on the Dashboard and show a `PROVISION_UPDATE_FAILED` entry in the audit log.

**Why**: `audit-collector` is not allowed to rewrite its own sudoers file, by design — otherwise compromising the key would grant unlimited root. A root intervention on each affected server is needed **once**; after that `sam-self-update` takes over automatically at every scan.

Two ways to re-provision:

**Option A — from the web interface (practical for ~5 servers)**

Dashboard → click the hostname → **Re-provision** (`sysadmin` role required). The form asks for the root SSH password, which is used once to replay `provision-host.sh` and is never stored.

**Option B — scripted with your own credentials (for 50+ servers)**

If you already have an administrator SSH key deployed on your servers, you can replay `provision-host.sh` without going through the UI and without typing any password:

```bash
for ip in 192.168.1.10 192.168.1.11 192.168.1.12; do
  hostname=$(podman exec sam-server psql -At -d ssh_manager \
      -c "SELECT hostname FROM servers WHERE ip_address='$ip';")
  PUB=$(podman exec sam-server python3 /app/app/manage.py servers show $hostname --pubkey)
  ssh root@"$ip" "sudo bash -s '$PUB'" \
    < <(podman exec sam-server cat /app/provision-host.sh)
done
```

This SSHes with **your** key or ssh-agent, runs `provision-host.sh` as root on the target, and introduces no secret on the SAM side. You can parallelise it with GNU `parallel`, Ansible (`ansible -m shell -a "..."`), or whatever configuration management tool you already use.

At the first scan after re-provisioning, `sam-self-update` succeeds, the badge disappears and the audit log records `PROVISION_UPDATED`. **No further manual action will be needed** for later SAM updates, as long as they do not change the `audit-collector` sudoers contract again.

---

## Auditing the server's sshd configuration

A server's detail view shows an **SSH config audit** panel that reads the host's effective `sshd` configuration (through `sudo sshd -T`, read-only — SAM changes nothing) and compares it against a declarative hardening policy. The panel is available to every role (sysadmin, operator, viewer).

> **Important — what the audit covers**: `sshd -T` returns the **global** daemon configuration, outside `Match` blocks. This audit therefore describes how sshd behaves for users who are **not** members of the `sam-users` group: `root`, system accounts, and accounts created manually outside SAM. SAM users are already covered by the `Match Group sam-users` block laid down by `provision-host.sh` (publickey only, no password, no keyboard-interactive — see *SSH authentication — publickey only for `sam-users`*). In short: a red light here does not endanger SAM accounts, but it does tell you that, for instance, `root` or a legacy account can still log in with a password.

### Global banner

Three possible states, computed each time the panel is opened:

| Banner | Colour | Meaning |
|---|---|---|
| ✓ **Compliant** | green | every audited directive is compliant |
| ⚠ **Hardening needed** | orange | at least one warning or missing directive, no critical non-compliance |
| ✗ **Lax configuration** | red | at least one critical directive is non-compliant |

### Audited directives

| Severity | Directives | Expected value |
|---|---|---|
| **Critical** | PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, HostbasedAuthentication | `no` |
| **Critical** | IgnoreRhosts | `yes` |
| **Warning** | KbdInteractiveAuthentication, ChallengeResponseAuthentication, X11Forwarding | `no` |
| **Warning** | AllowTcpForwarding | `no` or `local` |
| **Warning** | MaxAuthTries | ≤ 3 |
| **Warning** | LoginGraceTime | ≤ 60 |
| **Warning** | UsePAM | `yes` |
| **Info** | ClientAliveInterval | > 0 |
| **Info** | LogLevel | `INFO` or `VERBOSE` |

Hovering the **Expected** cell shows a tooltip describing the directive.

### Filtering

The **Non-compliant only** checkbox is ticked by default: on a compliant server the table is empty (nothing to do), and on a lax one only the problematic rows show. Untick it to see every audited directive.

### A note on the policy

The thresholds above are the OpenSSH hardening values generally expected. SAM makes no claim of formal compliance with a specific standard (CIS, STIG and ANSSI BP-099 have equivalent recommendations for most of these directives, but this is a declarative policy, editable in `app/actions.py` through the `SSHD_HARDENING_POLICY` constant).

---

## Troubleshooting — SSH connection problems

When provisioning or scanning a remote server fails, the errors are in **two places**.

### 1. SAM container logs

```bash
podman logs sam-server
# or live
podman logs -f sam-server
```

Paramiko connection errors (`AuthenticationException`, `NoValidConnectionsError`, `SSHException`) are logged there with the IP address and port of the server concerned.

### 2. SSH logs on the remote host

The SSH connection is logged on the server side. Depending on the OS:

```bash
# systemd (RHEL, Debian, Ubuntu…)
journalctl -u sshd -f

# File (Alpine, some custom setups)
tail -f /var/log/auth.log
# or
tail -f /var/log/secure
```

These logs tell you whether the connection was refused (wrong key, missing user, `MaxAuthTries` reached, and so on).

### 3. sudo requirement on the remote host

**`sudo` is mandatory** for the `audit-collector` user on every managed server. Every SAM script (`sam-collect`, `sam-revoke`, `sam-add`, `sam-lock-user`, `sam-unlock-user`, `sam-sessions`) runs through `sudo` over SSH.

`provision-host.sh` configures the sudoers rules automatically during provisioning. If sudo is unavailable or the rules are missing, every remote operation fails with `Permission denied`.

To check the sudoers configuration on the remote host:

```bash
# On the remote server
sudo -l -U audit-collector
```

The output must list the SAM commands (`/usr/local/bin/sam-*`) without a password prompt (`NOPASSWD`).

`provision-host.sh` also installs the sudoers rules for the SAM groups (`sam-operator`, `sam-pkg`, `sam-root`) — see [SAM sudo groups](#workflow--sam-sudo-groups). All of those rules are validated with `visudo -c` before installation and require `PASSWD:` (never NOPASSWD for SAM users). The `Match Group sam-users` sshd block is laid down as well, to forbid password authentication for users created through `sam-add`.

### 4. Known limitations — sshd AllowGroups/AllowUsers

If the remote host sets `AllowGroups` or `AllowUsers` in `/etc/ssh/sshd_config` (or in `/etc/ssh/sshd_config.d/*.conf`), SAM provisioning fails **when `audit-collector` is not allowed**.

#### Technical background

These OpenSSH directives are **global only** and **cannot be overridden in Match blocks**. SAM therefore cannot work around them with a dedicated sshd configuration. `provision-host.sh` detects the limitation automatically (#438) and refuses to complete provisioning.

#### Symptoms

In the remote host's sshd logs (`journalctl -u sshd` or `/var/log/auth.log`):

```
User audit-collector from <SAM-IP> not allowed because none of user's groups are listed in AllowGroups
input_userauth_request: invalid user audit-collector [preauth]
```

On the SAM side: initial provisioning may succeed (the user is created), but **every scan fails immediately at SSH authentication**. The server is marked `UNREACHABLE` after three consecutive failures.

#### Fix

**Before provisioning** (or when re-provisioning), an administrator must allow `audit-collector` manually:

**Option 1 — AllowGroups**: add `audit-collector` to one of the allowed groups

```bash
# On the remote host, as root
usermod -aG <allowed-group> audit-collector
```

**Option 2 — AllowUsers**: add `audit-collector` to the list in `/etc/ssh/sshd_config`

```bash
# Edit /etc/ssh/sshd_config
AllowUsers existing-user1 existing-user2 audit-collector

# Reload sshd
systemctl reload sshd
```

Once changed, run SAM provisioning again (the script will see the constraint is satisfied and carry on).

#### Automatic detection

Since #438, `provision-host.sh`:
1. Parses `/etc/ssh/sshd_config` and every `sshd_config.d/*.conf` (degrading gracefully when absent)
2. Extracts the `AllowGroups` and `AllowUsers` directives (case-insensitive, multiple directives supported)
3. Checks that `audit-collector` satisfies the constraints (group OR user — OpenSSH ANDs the two together)
4. **Exits 1** with a clear message when the constraint is not met (the message travels through SSH stderr → API → UI modal)

---

## Workflow — handling PENDING_REVIEW keys

After the first scan, every key found is awaiting validation.

A key also moves back to `PENDING_REVIEW` when it had been revoked or had expired and
physically reappears on a server (`ssh-copy-id` after a revocation, for instance). That
case is detected automatically at the next scan and raises a CRITICAL alert.

### From the web interface

1. Go to **Anomalies**
2. For each key: click **Validate** (legitimate key) or **Revoke** (key to remove)

The **Compliant** column shows each key's compliance:
- ✅: `ssh-ed25519` or `ssh-rsa ≥ 4096 bits`
- ⚠️: non-compliant — hover to see why (e.g. *"RSA 2048 bits — 4096 minimum required"*)

### From the CLI

```bash
# List pending keys
podman exec sam-server python3 /app/app/manage.py keys list --status PENDING_REVIEW

# Validate a key
podman exec sam-server python3 /app/app/manage.py keys validate SHA256:...

# Revoke a key
podman exec sam-server python3 /app/app/manage.py keys revoke SHA256:... --reason "Orphan key"
```

---

## Workflow — managing SSH keys

From a server's detail view, the actions available on each ACTIVE key:

| Action | Effect |
|---|---|
| **Revoke** | Immediate revocation with a mandatory reason — removes the key from the remote `authorized_keys` |
| **Assign** | Associates the key with an administrator (shown in the Owner column) |
| **Expiry** | Sets a date and time, or a duration in hours — automatic revocation when it is reached |
| **Unlimited** | Removes a key's expiry (only shown when `expires_at` is set) |

---

## Workflow — locking and unlocking a Unix account

After a key is revoked, the Unix account still exists on the server. To block **every** SSH login, including with another valid key:

**From the web interface**: Access → **Lock / unlock a Unix account**.

| Action | Remote command | Effect |
|---|---|---|
| **Lock** | `usermod -L -s /sbin/nologin <user>` | Locks the password and denies the shell — SSH login impossible even with a valid key |
| **Unlock** | `usermod -U -s /bin/bash <user>` | Restores the account — SSH login possible again with a valid key |

**From the CLI**:
```bash
$EXEC access lock-user --user alice --server server-prod-01
$EXEC access unlock-user --user alice --server server-prod-01
```

---

## Workflow — deploying an SSH key

To grant a user access to a server from the interface:

**From the web interface**: Access → **Deploy an SSH key**.

The form asks for:
- **Unix user** — the account to create on the target server (created when missing). The `root` account is forbidden (#386), and so is the `audit-collector` collector account, whose sudo rules would turn a key deployed there into root on that host.
- **Public key** — the `ssh-ed25519` or `ssh-rsa` key content (authorized_keys format)
- **Target server** — dropdown of active servers
- **SAM group** — *optional*: `sam-operator`, `sam-pkg` or `sam-root` (`sysadmin` only). See [SAM sudo groups](#workflow--sam-sudo-groups).
- **Duration** — hours / exact date / unlimited
- **Justification** — mandatory

> **Requirements on the remote host**: `bash` and `sudo` must be installed. SAM users are created with `useradd -m -s /bin/bash`, and the first-login hook relies on bash being the login shell. Distributions without `bash` by default (a minimal Alpine, for instance) must install the `bash` package before SAM provisions them.

On submit, `sam-add` runs on the remote server over SSH:
1. Creates the Unix user when missing (with `usermod -aG sam-users` — which forbids SSH password authentication)
2. When the account is created: generates a temporary password, sets it with `chpasswd`, writes `~/README_first_login.txt`, and installs a hook that invokes `passwd` at the first interactive login
3. Adds the key to `~/.ssh/authorized_keys`
4. When a SAM group is selected: `sam-grant-group` adds the user to it. Only `sam-operator`, `sam-pkg` and `sam-root` are accepted — any other group is refused.
5. Records the key in the database with the `ACTIVE` status, the chosen expiry and the `sam_group` if any

### A SAM user's first login

At the first SSH login (by key), the user sees the contents of `~/README_first_login.txt` (the temporary password), then `passwd` is invoked automatically to force them to choose their own. That password is required for `sudo` — the SAM sudoers rules all require `PASSWD:`.

The file carrying the hook varies by distribution. `sam-add` reproduces exactly the order bash itself uses to pick its init file for a login shell: it writes to `~/.bash_profile` when it exists (the RHEL / Rocky / Alma / CentOS families, where `/etc/skel/` provides it), otherwise `~/.bash_login` (very rare), otherwise `~/.profile` (Debian / Ubuntu / openSUSE / Arch — created when missing). This detection makes the hook load on every mainstream Linux without depending on the distribution. It relies on the user's shell staying `bash`; switching it later to `zsh` or `fish` would stop the hook from running.

### SSH authentication — publickey only for `sam-users`

A member of the `sam-users` group can **never** log in over SSH with anything other than the public key registered in SAM — not with a password, not with an empty password, not through an interactive mechanism (PAM keyboard-interactive). `provision-host.sh` enforces this on every managed server, and it holds even when password authentication is enabled globally on the host.

The user's Unix password, set at first login, exists **only for `sudo`** — never for the SSH login itself.

`provision-host.sh` validates the sshd configuration before applying it: if validation fails, the previous configuration is restored and sshd is not reloaded — an invalid configuration can never reach production by accident.

---

## Workflow — SAM sudo groups

`provision-host.sh` creates three predefined Unix groups on every managed server: `sam-operator`, `sam-pkg`, `sam-root`. Each has its own set of sudoers rules (validated with `visudo -c` before installation, requiring `PASSWD:` — never `NOPASSWD:`, with an explicit `secure_path` including `/usr/local/bin` so NS8 binaries such as `runagent` / `api-cli` resolve).

### `sam-operator` — operations and diagnostics

Aimed at operators who need to supervise and restart services without installing packages or reaching sensitive data. Rules installed in `/etc/sudoers.d/sam-operator`:

| Category | Allowed commands (as `root`, `PASSWD:`) |
|---|---|
| systemd services | `systemctl restart`, `systemctl reload`, `systemctl status`, `systemctl start` |
| Logs | `journalctl -u`, `journalctl -f`, `journalctl -n`, `journalctl --since`, `journalctl -b`, `journalctl -e` |
| Network / processes | `ss -tlnp`, `lsof`, `lsof -i` |
| Kernel diagnostics | `dmesg` |
| Disk | `du -sh /var/* /opt/* /home/*` |
| NS8 tools (when present) | `runagent` |

`api-cli` is **deliberately absent** from `sam-operator`: this NS8 management tool goes beyond the operations scope and is reserved for `sam-pkg` (#394).

### `sam-pkg` — operations plus package management

Aimed at users who also need to install or update packages. Inherits **every `sam-operator` command** and adds package management for the distribution detected by `provision-host.sh`. Rules in `/etc/sudoers.d/sam-pkg`:

| Category | Allowed commands (in addition to sam-operator) |
|---|---|
| Debian / Ubuntu | `apt install`, `apt upgrade` |
| RHEL / Rocky / Alma | `dnf install`, `dnf upgrade` (or `yum install`, `yum update`) |
| SUSE | `zypper install`, `zypper update` |
| Alpine | `apk add`, `apk upgrade` |
| Arch | `pacman -S`, `pacman -Syu`, `pacman -Sy` |
| NS8 modules (when present) | `add-module`, `remove-module` |
| NS8 tools (when present) | `api-cli` |

### `sam-root` — root equivalent

Aimed at administrators who need full root access. Rules in `/etc/sudoers.d/sam-root`:

```
%sam-root ALL=(ALL) ALL
```

The personal password is still required (`PASSWD:` is implicit — there is no `NOPASSWD`). Granting the `sam-root` group is reserved for the `sysadmin` role on the SAM API side, on every path including key deployment (see the RBAC matrix in `app/CLAUDE.md`).

### Checking the configuration on a server

```bash
# On the managed server
sudo -l -U alice                   # lists the commands allowed for alice
getent group sam-operator sam-pkg sam-root sam-users
cat /etc/sudoers.d/sam-operator
visudo -c                          # validates every /etc/sudoers.d/ file
```

**Group assignment**:
- At key creation: the SAM group field of the "Deploy an SSH key" form
- After creation: the **Promote / Change / Revoke group** actions from the Access view (allowed roles: `operator` for sam-operator/sam-pkg, `sysadmin` only for sam-root)

**Lifecycle**:
- Promotion: `POST /api/access/grant-group`
- Change: `PUT /api/access/change-group` (revokes the old one, assigns the new one)
- Revocation: `POST /api/access/revoke-group` (the Unix user stays active, only the SAM group is removed)

Recorded in the database in `key_authorizations.sam_group` (audit v4) and in `audit_log` (`GROUP_GRANTED`, `GROUP_REVOKED`, `GROUP_CHANGED`).

---

## Workflow — out-of-band revocation

When a scan finds that an `ACTIVE` key has disappeared from `authorized_keys` without any action in the system:

1. The key moves to `REVOKED` with `revoked_automatically = true` and `revoked_by = NULL`
2. An `ANOMALY_DETECTED` entry is written to the audit log
3. A **CRITICAL email** is sent immediately
4. The key shows up in **Anomalies > Out-of-band revocations**

Recommended action: investigate where the removal came from (direct root access? a compromise?).

---

## SSH session limit alert

Each server has a configurable **`max_sessions`** threshold (default: **2**). At the end of every scan, the number of active SSH sessions is compared against it.

### Behaviour

- When the number of active sessions **exceeds** `max_sessions`, a **WARNING** email alert goes to every administrator with `receive_alerts=true`.
- A **24 h anti-spam** rule applies: if a `SESSION_LIMIT_EXCEEDED` alert was already sent for that server in the last 24 hours, the email is suppressed. This avoids spamming at every cron cycle (every 4 hours).
- The alert is recorded in `audit_log` with the `SESSION_LIMIT_EXCEEDED` action and the details `{ hostname, session_count, max_sessions }`.

### Email contents

```
[WARNING] [ssh-access-manager] Session limit exceeded on <hostname>

Server: <hostname>
Active sessions: <N>
Configured limit: <max_sessions>

Please review active connections on this server.
```

### Setting the threshold per server

**From the web interface**: server detail view → **Edit** → **Max sessions** field (minimum 1).

**From the REST API**:

```bash
curl -s -X PUT https://<host>/api/servers/<hostname> \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"ip": "192.168.1.10", "environment": "production", "max_sessions": 5}'
```

The value is returned by both `GET /api/servers` and `GET /api/servers/<hostname>`.

---

## Environment variables

| Variable | Description | Default |
|---|---|---|
| `POSTGRES_DB` | Database name | `ssh_manager` |
| `POSTGRES_USER` | PostgreSQL user | `ssh_manager` |
| `POSTGRES_PASSWORD` | PostgreSQL password | — |
| `NGINX_PORT` | Nginx listening port | `8080` |
| `NGINX_TLS_CERT_PATH` | TLS certificate path (enables HTTPS when set together with `NGINX_TLS_KEY_PATH`) | — |
| `NGINX_TLS_KEY_PATH` | TLS private key path (enables HTTPS when set together with `NGINX_TLS_CERT_PATH`) | — |
| `FLASK_SECRET_KEY` | Flask secret key for sessions — **mandatory**, the container refuses to start without it | — |
| `SMTP_HOST` | SMTP server | — |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_USERNAME` | SMTP user — when empty, msmtp uses `auth off` (relay without authentication) | — |
| `SMTP_PASSWORD` | SMTP password | — |
| `SMTP_FROM` | Sender address | — |
| `SMTP_ENCRYPTION` | TLS mode: `none` / `starttls` / `tls` | `starttls` |
| `SMTP_TLSVERIFY` | TLS certificate verification: `1` (on) / `` (off) | `1` |
| `SMTP_ENABLED` | Enables or disables email sending: `1` / `` (off) | `1` |
| `SCAN_INTERVAL_HOURS` | Cron interval for collect and expire, 1 to 24 hours. Unset or out of range keeps the 5-minute default | — |
| `SSH_USER` | Collector SSH user | `audit-collector` |
| `ADMIN_USERNAME` | Initial administrator username | `admin` |
| `ADMIN_EMAIL` | Initial administrator email | — |
| `ADMIN_PASSWORD` | Initial administrator password | — |

> **Alert recipients**: alerts go to administrators with `receive_alerts=true` (set per administrator in the Admins UI). `SMTP_TO` is no longer used.
>
> **Expiry warning thresholds**: `expire_warn_days` (default 7) and `expire_warn_days_2` (default 2) are configurable without a restart from **Settings → Expiry warnings**.
>
> **Time zone**: dates are stored in UTC in PostgreSQL. The web interface displays them in the browser's time zone.
>
> **HTTPS (optional)**: when both `NGINX_TLS_CERT_PATH` and `NGINX_TLS_KEY_PATH` are set, Nginx uses `nginx.conf.https.template` (TLSv1.2/1.3, ECDHE ciphers, HSTS) and enables an `HTTP -> HTTPS` redirect (`301`), including when an HTTP request lands on the TLS port by mistake. These paths are **paths inside the container**: your certificates must therefore be present, or mounted, at that location in the container. When the files do not exist yet, a self-signed certificate is generated automatically at startup. Without these variables, Nginx uses `nginx.conf.http.template` (plain HTTP, no SSL directive).
>
> **docker-compose example (mounted certificates)**:
> ```yaml
> services:
>   sam-server:
>     volumes:
>       - ssh_data:/data
>       - ./certs:/data/certs:ro
>     environment:
>       - NGINX_TLS_CERT_PATH=/data/certs/server.crt
>       - NGINX_TLS_KEY_PATH=/data/certs/server.key
> ```
> Here `server.crt` and `server.key` live on the host in `./certs` and are exposed read-only inside the container.

> **Secrets to set before a production deployment** — never leave the example values in place:
> ```bash
> # Generate FLASK_SECRET_KEY
> python3 -c "import secrets; print(secrets.token_hex(32))"
> ```
> Copy the generated value into `.env`:
> ```
> FLASK_SECRET_KEY=<generated value>
> POSTGRES_PASSWORD=<strong password>
> ADMIN_PASSWORD=<strong password>
> ```

---

## CLI commands — quick reference

```bash
EXEC="podman exec sam-server python3 /app/app/manage.py"

# Servers
$EXEC servers list
$EXEC servers add --hostname HOST --ip IP --ssh-user USER --ssh-password PASS [--env production] [--os rhel] [--port 22]
$EXEC servers scan
$EXEC servers scan --server HOST
$EXEC servers disable HOST
$EXEC servers enable HOST
$EXEC servers show HOST

# Keys
$EXEC keys list --status PENDING_REVIEW
$EXEC keys show SHA256:...
$EXEC keys search QUERY
$EXEC keys validate SHA256:...
$EXEC keys revoke SHA256:... --reason "Reason"
$EXEC keys assign SHA256:... --owner "Alice Martin"
$EXEC keys set-expiry SHA256:... --hours 24
$EXEC keys set-expiry SHA256:... --date "2026-12-31 23:59"
$EXEC keys remove-expiry SHA256:...

# Temporary access
$EXEC access list
$EXEC access grant --key SHA256:... --server HOST --hours 8 --reason "Reason" [--user alice]
$EXEC access approve <id>
$EXEC access reject <id>
$EXEC access revoke <id>
$EXEC access lock-user --user USER --server HOST
$EXEC access unlock-user --user USER --server HOST

# Administrators
$EXEC admin list
$EXEC admin add --username USER --email EMAIL --password PASSWORD [--role ROLE]
# ROLE: sysadmin | operator (default) | viewer
$EXEC admin update <username> [--email EMAIL] [--role ROLE]
$EXEC admin disable USERNAME
$EXEC admin enable USERNAME
$EXEC admin delete USERNAME
$EXEC admin reset-password USERNAME --password NEW_PASSWORD

# Audit
$EXEC audit list --action ANOMALY_DETECTED --since 2025-01-01
$EXEC audit list --server HOST

# System
$EXEC system status
$EXEC system report
```

`access grant` infers the Unix account from the authorizations already recorded for that key on that server. When the key is authorized for several accounts, pass `--user` to say which one.

---

## Recovering an administrator password

When an administrator loses their password, a sysadmin with access to the container can reset it from the CLI without signing in first:

```bash
# Docker
docker exec -it ssh-access-manager python3 /app/app/manage.py admin reset-password <username> --password <new_password>

# Podman
podman exec -it sam-server python3 /app/app/manage.py admin reset-password <username> --password <new_password>
```

Constraints:
- The password must satisfy the security policy (8+ characters, uppercase, lowercase, digit, special character)
- It works even when the account is disabled
- The operation is recorded in the audit log (`PASSWORD_RESET`, `performed_by=NULL`)

---

## Internationalisation

The interface supports 5 languages through `vue-i18n`. The translation files live in `ui/src/locales/`:

| File | Language |
|---|---|
| `en.json` | English (default fallback) |
| `fr.json` | French |
| `es.json` | Spanish |
| `it.json` | Italian |
| `de.json` | German |

To add a language:
1. Copy `ui/src/locales/en.json` → `ui/src/locales/xx.json` and translate it
2. Add the import to `ui/src/i18n.js`
3. Add `<option value="xx">XX</option>` to `ui/src/App.vue`

---

## Tests

```bash
# Python backend tests
cd app && python3 -m pytest tests/ --cov=actions --cov-fail-under=80

# Vitest frontend tests
cd ui && npx vitest run
```

---

## CI/CD & DevOps

### GitHub Actions workflows

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | Every PR | Python tests (pytest ≥ 80%), Vue.js tests (vitest), Prettier, Commitlint |
| `pr-title.yml` | PR opened / edited | Title validation (Conventional Commits) |
| `build-pr.yml` | Every PR | Build + push the `pr-{N}` image + Trivy CVE scan (CRITICAL/HIGH) |
| `build-main.yml` | Merge to `main` | Build + push the `:main` image to GHCR |
| `publish-release.yml` | Git tag push | Build + push the `:vX.Y.Z` image (+ `:latest` when stable) |
| `cleanup-pr.yml` | PR closed | Delete the `pr-{N}` image from GHCR |
| `codeql.yml` | PR + push to main + weekly | Python security static analysis (SAST) |

### Docker tag strategy (GHCR)

| Event | Published tag |
|---|---|
| PR opened | `pr-{N}` |
| Merge to `main` | `main` |
| Git tag `1.2.0-dev.1` (with `-`) | `1.2.0-dev.1` only |
| Git tag `1.2.0` (without `-`) | `1.2.0` **and** `latest` |

### Commit convention (Conventional Commits)

Every commit must follow the `type: short description` format.

Valid types: `feat` `fix` `docs` `style` `refactor` `test` `ci` `chore`

```
feat: DeployKeyForm in the Access view
fix: key expiry computation
ci: add the Prettier check
docs: update the access workflow in the README
```

Two CI checks enforce the convention:
- **Commit messages** (`ci.yml`) — checks every commit of the PR with `wagoid/commitlint-github-action`
- **PR title** (`pr-title.yml`) — checks the PR title with a `grep -P` shell script

### `main` branch protection

- Direct pushes are forbidden — every change goes through a PR
- The 5 CI checks must pass before merging: Python tests, Vue.js tests, Prettier, Commit messages, Validate PR title
- Force pushes are blocked
- The rule applies to repository administrators too

### Security — Trivy + CodeQL

**Trivy** scans every PR Docker image for CRITICAL and HIGH CVEs (Alpine packages, pip, npm). Results are uploaded to GitHub's **Security > Code scanning** tab.

**CodeQL** analyses the Python code with the `security-extended` queries on every PR, on every merge to `main`, and every Monday morning. Alerts show up under **Security > Code scanning**.

### Automatic updates — Renovate

Renovate is configured through `renovate.json` at the project root. It opens PRs every Monday before 9 a.m. for:

- **npm** (`ui/package.json`) — grouped updates; patches automerge when CI is green
- **pip** (`requirements-test.txt`) — grouped PR, manual merge
- **Docker** (the Dockerfile `FROM` lines) — grouped PR, manual merge

### Vue.js code formatting

Prettier is configured in `.prettierrc` at the project root:

```json
{ "semi": false, "singleQuote": true, "trailingComma": "es5", "printWidth": 100 }
```

```bash
# Check (CI)
cd ui && npm run format:check

# Format locally before committing
cd ui && npm run format:write
```
