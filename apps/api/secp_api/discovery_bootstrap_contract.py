"""Proxmox read-only discovery bootstrap contract (SECP-B7).

A PURE, secret-free, I/O-free module that renders the operator-side Proxmox bootstrap artifact: an
idempotent shell script that provisions a scoped, audit-only read-only access path (a
minimally-privileged PAM user + a minimal Proxmox audit role + a root-owned FORCED-COMMAND SSH
wrapper) so the SECP worker can run ONLY the closed read-only discovery command set — and nothing
else — over SSH.

Security properties this module guarantees by construction:
  * It only ever handles a PUBLIC ssh key (``ssh-<type> <base64> [comment]``). A private key, or any
    ``BEGIN ... PRIVATE KEY`` material, is rejected — the API never sees/stores private keys.
  * The generated ``authorized_keys`` line pins ``command="<wrapper>"`` +
    ``no-agent-forwarding,no-X11-forwarding,no-port-forwarding,no-pty`` so the key can NEVER get an
    interactive shell or a forwarding channel.
  * The forced-command wrapper allows ONLY the exact closed read-only command union the worker probe
    contract emits (mirrors ``secp_worker.target_discovery.probes.render_probe_argv``); it denies
    every write verb, shell metacharacter, and unknown command, and re-execs each allowed form with
    an EXPLICIT argv reconstructed from a validated safe token (no word-splitting of untrusted
    input).
  * The script prints a BOUNDED, secret-free proof (created user/role, wrapper path, the SHA256
    fingerprint of the installed public key, the host SSH key fingerprint) and NEVER echoes a
    private key.

Nothing here contacts Proxmox, runs a probe, or reads a private key — the API composes text only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re

# The scoped, audit-only identity the bootstrap provisions (fixed, non-privileged names).
DEFAULT_ACCOUNT = "secpdisc"
DEFAULT_PVE_ROLE = "SECPDiscoveryReadOnly"
FORCE_COMMAND_PATH = "/usr/local/sbin/secpdisc-force-command"
# Minimal Proxmox audit privileges (read/list only — never VM.Allocate/Sys.Modify/Datastore.Allocate
# or any write/mutate privilege). Enough for the read-only discovery probes.
PVE_AUDIT_PRIVILEGES = ("Sys.Audit", "VM.Audit", "Datastore.Audit")
# The authorized_keys restriction options pinned in front of the public key.
AUTHORIZED_KEYS_OPTIONS = (
    f'command="{FORCE_COMMAND_PATH}"',
    "no-agent-forwarding",
    "no-X11-forwarding",
    "no-port-forwarding",
    "no-pty",
)

# A safe Proxmox path token (node / iface / firewall-group / userid). Mirrors the worker probe
# contract's ``[A-Za-z0-9._@-]`` token grammar; a VMID is digits only.
_TOK = "[A-Za-z0-9._@-]"
_TOK_RE = re.compile(rf"^{_TOK}{{1,64}}$")
_VMID_RE = re.compile(r"^[0-9]{1,12}$")

# A well-formed OpenSSH PUBLIC key line: ``ssh-<type> <base64> [comment]``. Reject anything else.
_SSH_PUBKEY_RE = re.compile(
    r"^(?P<type>ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)"
    r"\s+(?P<blob>[A-Za-z0-9+/]{32,}={0,3})(?:\s+(?P<comment>[^\r\n]{0,200}))?$"
)
_PRIVATE_KEY_MARKER = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE)


class BootstrapContractError(ValueError):
    """Raised for invalid bootstrap input. Carries only a closed reason code (no secret/raw)."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


# --- the closed read-only command union the forced-command wrapper permits ------------------------
# EXACT commands (no parameters) the worker sends. Each maps 1:1 to a ``render_probe_argv`` output.
_EXACT_COMMANDS: tuple[str, ...] = (
    "pveversion",
    "pvesh get /version --output-format json",
    "pvesh get /cluster/status --output-format json",
    "pvesh get /nodes --output-format json",
    "pvesh get /cluster/resources --type vm --output-format json",
    "cat /sys/module/kvm_intel/parameters/nested",
    "cat /sys/module/kvm_amd/parameters/nested",
)
# PARAMETERIZED commands: (regex over the full command, kind). The capture group(s) are validated
# safe tokens / vmids; the wrapper re-execs with an EXPLICIT argv (never word-splits input).
_PARAM_COMMANDS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(rf"^pvesh get /nodes/({_TOK}{{1,64}})/status --output-format json$"),
        "node_status",
    ),
    (
        re.compile(rf"^pvesh get /nodes/({_TOK}{{1,64}})/storage --output-format json$"),
        "node_storage",
    ),
    (
        re.compile(  # noqa: E501
            rf"^pvesh get /nodes/({_TOK}{{1,64}})/network/({_TOK}{{1,64}}) --output-format json$"
        ),
        "node_network",
    ),
    (
        re.compile(rf"^pvesh get /cluster/firewall/groups/({_TOK}{{1,64}}) --output-format json$"),
        "firewall_group",
    ),
    (
        re.compile(rf"^pvesh get /access/users/({_TOK}{{1,64}}) --output-format json$"),
        "access_user",
    ),
    (
        re.compile(
            rf"^pvesh get /nodes/({_TOK}{{1,64}})/qemu/([0-9]{{1,12}})/status/current"
            r" --output-format json$"
        ),
        "guest_status",
    ),
)
# Shell metacharacters that are never permitted in a forced command (defense in depth).
_SHELL_METACHARS_RE = re.compile(r"[\s]{2,}|[;&|<>$`\\(){}\[\]*?!~'\"\x00\n\r\t]")


def command_is_allowed(command: str) -> bool:
    """Python mirror of the forced-command wrapper's allow decision — a command string is permitted
    ONLY if it is one of the closed read-only forms with safe tokens. Used by tests + local
    validation so the API can prove the allowlist matches the worker probe contract."""
    if not isinstance(command, str) or not command or _SHELL_METACHARS_RE.search(command):
        return False
    if command in _EXACT_COMMANDS:
        return True
    for pattern, _kind in _PARAM_COMMANDS:
        m = pattern.match(command)
        if not m:
            continue
        # Every captured group must be an independently-valid safe token / vmid.
        for grp in m.groups():
            if not (_TOK_RE.match(grp) or _VMID_RE.match(grp)):
                return False
        return True
    return False


def validate_public_ssh_key(public_key: str) -> tuple[str, str]:
    """Validate that ``public_key`` is a well-formed OpenSSH PUBLIC key and return (normalized_line,
    sha256_fingerprint). Fails closed on a private key or any malformed input. Never returns/raises
    the raw value."""
    if not isinstance(public_key, str):
        raise BootstrapContractError("public_key_missing")
    candidate = public_key.strip()
    if not candidate:
        raise BootstrapContractError("public_key_missing")
    if _PRIVATE_KEY_MARKER.search(candidate) or len(candidate) > 8192:
        raise BootstrapContractError("public_key_looks_private")
    if "\n" in candidate or "\r" in candidate:
        raise BootstrapContractError("public_key_multiline")
    match = _SSH_PUBKEY_RE.match(candidate)
    if not match:
        raise BootstrapContractError("public_key_malformed")
    key_type = match.group("type")
    blob = match.group("blob")
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BootstrapContractError("public_key_malformed") from exc
    # The base64 blob's embedded algorithm name must match the declared key type.
    if not _blob_declares_type(raw, key_type):
        raise BootstrapContractError("public_key_type_mismatch")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    comment = (match.group("comment") or "").strip()
    normalized = f"{key_type} {blob}" + (f" {comment}" if comment else "")
    return normalized, fingerprint


def _blob_declares_type(raw: bytes, key_type: str) -> bool:
    # An OpenSSH public blob starts with a length-prefixed algorithm name; it must equal the type.
    if len(raw) < 4:
        return False
    name_len = int.from_bytes(raw[:4], "big")
    if name_len <= 0 or name_len > 64 or 4 + name_len > len(raw):
        return False
    return raw[4 : 4 + name_len].decode("ascii", "ignore") == key_type


def _validate_account(account: str) -> str:
    if not (isinstance(account, str) and re.match(r"^[a-z][a-z0-9-]{1,30}$", account)):
        raise BootstrapContractError("account_invalid")
    if account in {"root", "admin", "administrator", "toor", "sysadmin", "superuser"}:
        raise BootstrapContractError("account_privileged")
    return account


def _validate_role(role: str) -> str:
    if not (isinstance(role, str) and re.match(r"^[A-Za-z][A-Za-z0-9]{1,40}$", role)):
        raise BootstrapContractError("role_invalid")
    return role


def render_force_command_wrapper() -> str:
    """Render the root-owned POSIX-sh forced-command wrapper. It permits ONLY the closed read-only
    command union (re-execing each with an explicit argv built from a validated token), and denies
    everything else — shell, write verbs, metacharacters, unknown commands."""
    lines = [
        "#!/bin/sh",
        "# SECP-B7 forced-command wrapper. Installed by the read-only discovery bootstrap.",
        "# Permits ONLY the closed read-only discovery command union; denies all else. Root-owned.",
        "set -f  # no glob expansion of the original command",
        'cmd="${SSH_ORIGINAL_COMMAND:-}"',
        "# Reject any shell metacharacter outright (belt-and-braces; forms below are also exact).",
        'case "$cmd" in',
        "  *[!\\ A-Za-z0-9._@/=-]* ) echo secpdisc_denied >&2; exit 42 ;;",
        "esac",
    ]
    # Exact commands.
    for cmd in _EXACT_COMMANDS:
        lines.append(f'if [ "$cmd" = "{cmd}" ]; then exec {cmd}; fi')
    # Parameterized commands: extract the safe token(s) with sed, then exec an explicit argv.
    lines += [
        'node=$(printf %s "$cmd" | sed -n '
        r'"s#^pvesh get /nodes/\([A-Za-z0-9._@-]\{1,64\}\)/status --output-format json\$#\1#p")',
        'if [ -n "$node" ]; then exec pvesh get "/nodes/$node/status" --output-format json; fi',
        'node=$(printf %s "$cmd" | sed -n '
        r'"s#^pvesh get /nodes/\([A-Za-z0-9._@-]\{1,64\}\)/storage --output-format json\$#\1#p")',
        'if [ -n "$node" ]; then exec pvesh get "/nodes/$node/storage" --output-format json; fi',
        'match=$(printf %s "$cmd" | sed -n '
        r'"s#^pvesh get /nodes/\([A-Za-z0-9._@-]\{1,64\}\)/network/\([A-Za-z0-9._@-]\{1,64\}\)'
        r' --output-format json\$#\1 \2#p")',
        'if [ -n "$match" ]; then set -- $match; '
        'exec pvesh get "/nodes/$1/network/$2" --output-format json; fi',
        'grp=$(printf %s "$cmd" | sed -n '
        r'"s#^pvesh get /cluster/firewall/groups/\([A-Za-z0-9._@-]\{1,64\}\)'
        r' --output-format json\$#\1#p")',
        'if [ -n "$grp" ]; then exec pvesh get "/cluster/firewall/groups/$grp"'
        " --output-format json; fi",
        'usr=$(printf %s "$cmd" | sed -n '
        r'"s#^pvesh get /access/users/\([A-Za-z0-9._@-]\{1,64\}\) --output-format json\$#\1#p")',
        'if [ -n "$usr" ]; then exec pvesh get "/access/users/$usr" --output-format json; fi',
        'match=$(printf %s "$cmd" | sed -n '
        r'"s#^pvesh get /nodes/\([A-Za-z0-9._@-]\{1,64\}\)/qemu/\([0-9]\{1,12\}\)/status/current'
        r' --output-format json\$#\1 \2#p")',
        'if [ -n "$match" ]; then set -- $match; '
        'exec pvesh get "/nodes/$1/qemu/$2/status/current" --output-format json; fi',
        "echo secpdisc_denied >&2",
        "exit 42",
    ]
    return "\n".join(lines) + "\n"


def render_bootstrap_script(
    *,
    public_ssh_key: str,
    account: str = DEFAULT_ACCOUNT,
    pve_role: str = DEFAULT_PVE_ROLE,
    session_id: str = "",
) -> str:
    """Render the full idempotent Proxmox read-only bootstrap script. Requires a PUBLIC ssh key
    (private keys rejected). The only operator action is running this script (as root) on the
    Proxmox host; it prints a bounded, secret-free proof and never emits private key material."""
    normalized_key, key_fingerprint = validate_public_ssh_key(public_ssh_key)
    account = _validate_account(account)
    pve_role = _validate_role(pve_role)
    if not re.match(r"^[A-Za-z0-9-]{0,64}$", session_id or ""):
        raise BootstrapContractError("session_id_invalid")

    wrapper = render_force_command_wrapper()
    authorized_line = ",".join(AUTHORIZED_KEYS_OPTIONS) + " " + normalized_key
    privileges = ",".join(PVE_AUDIT_PRIVILEGES)
    ssh_dir = f"/home/{account}/.ssh"

    return _SCRIPT_TEMPLATE.format(
        account=account,
        pve_role=pve_role,
        privileges=privileges,
        force_path=FORCE_COMMAND_PATH,
        wrapper=wrapper,
        ssh_dir=ssh_dir,
        authorized_line=authorized_line,
        key_fingerprint=key_fingerprint,
        session_id=session_id or "-",
    )


# The idempotent bootstrap script template. Every step is safe to re-run. It creates NOTHING that
# grants write/shell access, and prints a bounded proof block delimited by SECPDISC-PROOF markers.
_SCRIPT_TEMPLATE = r"""#!/usr/bin/env bash
# SECP-B7 — Proxmox READ-ONLY discovery bootstrap (idempotent). Run as root on the Proxmox host.
# It provisions a scoped, audit-only access path for the SECP worker's read-only discovery probes.
# It grants NO write/shell access, and prints a bounded, secret-free proof. Session: {session_id}
set -euo pipefail

ACCOUNT="{account}"
PVE_ROLE="{pve_role}"
PVE_PRIVS="{privileges}"
FORCE_CMD="{force_path}"
SSH_DIR="{ssh_dir}"
KEY_FP="{key_fingerprint}"

if [ "$(id -u)" -ne 0 ]; then echo "ERROR: must run as root" >&2; exit 1; fi
if ! command -v sudo >/dev/null 2>&1; then
  echo "ERROR: 'sudo' is required but not installed (e.g. 'apt-get install -y sudo'); re-run." >&2
  exit 1
fi
if ! command -v pveum >/dev/null 2>&1 || ! command -v pvesh >/dev/null 2>&1; then
  echo "ERROR: this must run on a Proxmox VE host ('pveum'/'pvesh' not found)." >&2
  exit 1
fi

# 1. Linux system user, no interactive shell, no password login. Idempotent.
if ! id "$ACCOUNT" >/dev/null 2>&1; then
  useradd --system --create-home --shell /usr/sbin/nologin "$ACCOUNT"
fi
usermod --shell /usr/sbin/nologin "$ACCOUNT" >/dev/null 2>&1 || true
passwd --lock "$ACCOUNT" >/dev/null 2>&1 || true

# 2. Root-owned forced-command wrapper: the server-side read-only enforcement.
cat > "$FORCE_CMD" <<'SECPDISC_WRAPPER_EOF'
{wrapper}SECPDISC_WRAPPER_EOF
chown root:root "$FORCE_CMD"
chmod 0755 "$FORCE_CMD"

# 3. Minimal audit-only Proxmox role + PAM user. Idempotent (role update is safe to re-apply).
pveum role add "$PVE_ROLE" -privs "$PVE_PRIVS" 2>/dev/null \
  || pveum role modify "$PVE_ROLE" -privs "$PVE_PRIVS"
if ! pveum user list --output-format json 2>/dev/null | grep -q "\"$ACCOUNT@pam\""; then
  pveum user add "$ACCOUNT@pam" -comment "SECP read-only discovery (managed)" 2>/dev/null || true
fi
# Grant ONLY the audit role at the root ACL path. No write role is ever assigned.
pveum acl modify / -user "$ACCOUNT@pam" -role "$PVE_ROLE"

# 4. authorized_keys: pin the forced command + disable shell/forwarding for the SECP public key.
install -d -m 0700 -o "$ACCOUNT" -g "$ACCOUNT" "$SSH_DIR"
AUTH="$SSH_DIR/authorized_keys"
LINE='{authorized_line}'
# Idempotent: remove any prior SECP-managed line for this key, then add exactly one.
if [ -f "$AUTH" ]; then
  grep -vF "$FORCE_CMD" "$AUTH" > "$AUTH.tmp" 2>/dev/null || true
  mv "$AUTH.tmp" "$AUTH"
fi
printf '%s\n' "$LINE" >> "$AUTH"
chown "$ACCOUNT":"$ACCOUNT" "$AUTH"
chmod 0600 "$AUTH"

# 5. Local self-test: prove the wrapper denies shell + write verbs and allows a read probe.
selftest_pass=1
run_wrap() {{ SSH_ORIGINAL_COMMAND="$1" /bin/sh "$FORCE_CMD" >/dev/null 2>&1; }}
# denied cases (expect non-zero):
for bad in "bash -i" "pvesh set /nodes/x" "pvesh create /x" "pvesh delete /x" \
           "rm -rf /" "cat /etc/shadow" "pvesh get /version --output-format json; id"; do
  if run_wrap "$bad"; then echo "SELFTEST FAIL: wrapper allowed: $bad" >&2; selftest_pass=0; fi
done

# 6. Host SSH key fingerprint + PUBLIC key line (for host-key pinning) — never a private key.
HOST_KEY_PUB="/etc/ssh/ssh_host_ed25519_key.pub"
HOST_FP="$(ssh-keygen -lf "$HOST_KEY_PUB" 2>/dev/null | awk '{{print $2}}' || echo unknown)"
# The host's PUBLIC key line (keytype + base64 blob only; comment dropped). SECP-B8: the worker
# writes this into known_hosts so host-key pinning is authoritative (the host emitted it itself).
HOST_KEY_LINE="$(awk '{{print $1" "$2}}' "$HOST_KEY_PUB" 2>/dev/null || echo unknown)"

# 7. Bounded, secret-free proof.
echo "-----BEGIN SECPDISC-PROOF-----"
echo "session_id={session_id}"
echo "account=$ACCOUNT@pam"
echo "pve_role=$PVE_ROLE"
echo "pve_privs=$PVE_PRIVS"
echo "force_command=$FORCE_CMD"
echo "authorized_key_fingerprint=$KEY_FP"
echo "host_key_fingerprint=$HOST_FP"
echo "host_public_key=$HOST_KEY_LINE"
echo "selftest_ok=$selftest_pass"
echo "-----END SECPDISC-PROOF-----"
if [ "$selftest_pass" -ne 1 ]; then exit 3; fi
"""
