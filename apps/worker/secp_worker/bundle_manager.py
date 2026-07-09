"""Worker-owned live discovery bundle manager (SECP-B8).

Worker-side ONLY. Completes the first-time product flow so the worker — not the operator — owns and
generates the SSH/admission key material and assembles the mounted discovery bundle from the
control plane's SECRET-FREE descriptor.

It:
  * generates + owns TWO keypairs (private halves NEVER leave the worker filesystem):
      - an SSH Ed25519 keypair — the private half becomes the bundle ``id_key``; the PUBLIC half is
        what the operator's Proxmox bootstrap script authorizes;
      - an Ed25519 ADMISSION keypair — the private hex signs the control-plane admission nonce; the
        PUBLIC anchor hex is registered as the worker identity;
  * given a secret-free bundle descriptor (target host/port/account, host PUBLIC key + fingerprint,
    and the binding IDs + endpoint digest), writes the four-file mounted bundle
    (``manifest.json`` / ``id_key`` / ``known_hosts`` / ``binding.json``) ATOMICALLY into the
    worker-owned bundle directory with ``0700``/``0600`` permissions.

It fails closed on any invalid descriptor (root/reserved account, malformed/ mismatched host-key
fingerprint, missing field). It NEVER uploads or transmits a private key, contacts no Proxmox host,
and runs no probe — it composes local files only. The public material it RETURNS (SSH public key,
admission anchor hex + fingerprint) is the only thing the control plane ever receives.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass

_IS_POSIX = os.name == "posix"

# Fixed worker-local filenames (inside the worker-owned key directory + the bundle directory).
_ADMISSION_PRIVATE = "admission_key"  # Ed25519 admission private key (hex)
_ADMISSION_ANCHOR = "admission_anchor"  # Ed25519 admission public anchor (hex)
_SSH_PRIVATE = "ssh_id_ed25519"  # OpenSSH Ed25519 private key (worker-owned)
_SSH_PUBLIC = "ssh_id_ed25519.pub"  # OpenSSH public key line

_MANIFEST_NAME = "manifest.json"
_KEY_NAME = "id_key"
_KNOWN_HOSTS_NAME = "known_hosts"
_BINDING_NAME = "binding.json"

# Mirror the mounted-bundle validator's grammar so a bundle we write always validates.
_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")
_SAFE_ACCOUNT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_ENDPOINT_BINDING_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RESERVED_ACCOUNTS = frozenset({"root", "admin", "administrator", "toor", "sysadmin", "superuser"})
_SSH_KEYTYPES = frozenset(
    {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
)
_MANIFEST_FIELDS = ("ssh_host", "ssh_port", "account", "host_key_fingerprint")
_BINDING_FIELDS = (
    "organization_id",
    "execution_target_id",
    "onboarding_id",
    "enrollment_id",
    "authorization_id",
    "authorization_version",
    "endpoint_binding_hash",
)


class BundleManagerError(Exception):
    """Fail-closed bundle error carrying ONLY a closed reason code (no secret/raw value)."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class WorkerPublicMaterial:
    """The ONLY worker material the control plane ever receives — all PUBLIC.

    ``ssh_public_key`` authorizes the worker on Proxmox (via the bootstrap script); ``admission_
    anchor_hex`` / ``admission_anchor_fingerprint`` register + pin the worker identity. No private
    key is present."""

    ssh_public_key: str
    admission_anchor_hex: str
    admission_anchor_fingerprint: str


def _write_private_file(path: str, data: bytes) -> None:
    """Write ``data`` to a fresh 0600 file the worker owns (atomic replace)."""
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".secp-tmp-")
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    if _IS_POSIX:
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read().strip()


def ensure_worker_keys(key_dir: str) -> WorkerPublicMaterial:
    """Generate + persist the worker's SSH + admission keypairs under ``key_dir`` if missing, and
    return the PUBLIC material. Idempotent: existing keys are reused (never regenerated), so the
    worker identity + authorized Proxmox key stay stable across restarts. The directory is created
    0700 (worker-owned); private keys are 0600. NO private key is ever returned."""
    from secp_api.worker_admission_contract import (
        compute_verification_anchor_fingerprint,
        generate_ed25519_keypair,
    )

    if not (isinstance(key_dir, str) and key_dir.strip()):
        raise BundleManagerError("key_dir_unset")
    os.makedirs(key_dir, exist_ok=True)
    if _IS_POSIX:
        os.chmod(key_dir, 0o700)

    admission_priv_path = os.path.join(key_dir, _ADMISSION_PRIVATE)
    admission_anchor_path = os.path.join(key_dir, _ADMISSION_ANCHOR)
    ssh_priv_path = os.path.join(key_dir, _SSH_PRIVATE)
    ssh_pub_path = os.path.join(key_dir, _SSH_PUBLIC)

    # 1. Admission keypair (Ed25519 hex) — reuse if present so the registered anchor stays stable.
    if not (os.path.exists(admission_priv_path) and os.path.exists(admission_anchor_path)):
        priv_hex, anchor_hex = generate_ed25519_keypair()
        _write_private_file(admission_priv_path, priv_hex.encode())
        _write_private_file(admission_anchor_path, anchor_hex.encode())
    anchor_hex = _read_text(admission_anchor_path)

    # 2. SSH keypair (OpenSSH Ed25519) — reuse if present.
    if not (os.path.exists(ssh_priv_path) and os.path.exists(ssh_pub_path)):
        priv_pem, pub_line = _generate_ssh_keypair()
        _write_private_file(ssh_priv_path, priv_pem)
        _write_private_file(ssh_pub_path, pub_line.encode())
    ssh_public = _read_text(ssh_pub_path)

    return WorkerPublicMaterial(
        ssh_public_key=ssh_public,
        admission_anchor_hex=anchor_hex,
        admission_anchor_fingerprint=compute_verification_anchor_fingerprint(anchor_hex),
    )


def _generate_ssh_keypair() -> tuple[bytes, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    public_line = (
        key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    return private_pem, public_line + " secp-worker"


def worker_ssh_private_key_path(key_dir: str) -> str:
    return os.path.join(key_dir, _SSH_PRIVATE)


# --- bundle assembly ---------------------------------------------------------


def _require(descriptor: dict, key: str) -> object:
    if key not in descriptor or descriptor[key] in (None, ""):
        raise BundleManagerError(f"descriptor_missing_{key}")
    return descriptor[key]


def _known_hosts_line(ssh_host: str, ssh_port: int, host_public_key: str) -> str:
    parts = host_public_key.strip().split()
    if len(parts) < 2 or parts[0] not in _SSH_KEYTYPES:
        raise BundleManagerError("host_public_key_malformed")
    keytype, blob = parts[0], parts[1]
    if not re.match(r"^[A-Za-z0-9+/]{32,}={0,3}$", blob):
        raise BundleManagerError("host_public_key_malformed")
    name = ssh_host.lower() if ssh_port == 22 else f"[{ssh_host.lower()}]:{ssh_port}"
    return f"{name} {keytype} {blob}\n"


def _host_key_fingerprint(host_public_key: str) -> str:
    import base64
    import binascii
    import hashlib

    parts = host_public_key.strip().split()
    if len(parts) < 2:
        raise BundleManagerError("host_public_key_malformed")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise BundleManagerError("host_public_key_malformed") from exc
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def write_bundle(descriptor: dict, *, bundle_dir: str, ssh_private_key_path: str) -> None:
    """Write the four-file mounted discovery bundle ATOMICALLY into ``bundle_dir`` from the
    secret-free ``descriptor``. Fails closed on any invalid/inconsistent field, a reserved account,
    or a host-key fingerprint that does not match the host PUBLIC key. Sets 0700 on the dir + 0600
    on every file. The bundle is assembled in a temp dir and swapped in, so a partial bundle is
    never observable."""
    ssh_host = str(_require(descriptor, "ssh_host"))
    account = str(_require(descriptor, "account"))
    fingerprint = str(_require(descriptor, "host_key_fingerprint"))
    host_public_key = str(_require(descriptor, "host_public_key"))
    endpoint_binding_hash = str(_require(descriptor, "endpoint_binding_hash"))
    try:
        ssh_port = int(str(_require(descriptor, "ssh_port")))
    except (TypeError, ValueError) as exc:
        raise BundleManagerError("ssh_port_invalid") from exc

    if not _SAFE_HOST.match(ssh_host):
        raise BundleManagerError("ssh_host_invalid")
    if not _SAFE_ACCOUNT.match(account):
        raise BundleManagerError("account_invalid")
    if account.lower() in _RESERVED_ACCOUNTS:
        raise BundleManagerError("account_privileged")
    if not (1 <= ssh_port <= 65535):
        raise BundleManagerError("ssh_port_invalid")
    if not _FINGERPRINT.match(fingerprint):
        raise BundleManagerError("host_key_fingerprint_invalid")
    if not _ENDPOINT_BINDING_RE.match(endpoint_binding_hash):
        raise BundleManagerError("endpoint_binding_hash_invalid")
    # Defense in depth: the pinned fingerprint MUST match the host public key put in known_hosts.
    if _host_key_fingerprint(host_public_key) != fingerprint:
        raise BundleManagerError("host_key_fingerprint_mismatch")
    if not os.path.exists(ssh_private_key_path):
        raise BundleManagerError("ssh_private_key_missing")

    manifest = {
        "ssh_host": ssh_host,
        "ssh_port": ssh_port,
        "account": account,
        "host_key_fingerprint": fingerprint,
    }
    binding = {field: descriptor[field] for field in _BINDING_FIELDS if field in descriptor}
    missing = [f for f in _BINDING_FIELDS if f not in binding]
    if missing:
        raise BundleManagerError(f"descriptor_missing_{missing[0]}")
    binding["authorization_version"] = int(binding["authorization_version"])
    binding = {k: (str(v) if k != "authorization_version" else v) for k, v in binding.items()}
    known_hosts = _known_hosts_line(ssh_host, ssh_port, host_public_key)
    with open(ssh_private_key_path, "rb") as fh:
        id_key_bytes = fh.read()

    parent = os.path.dirname(os.path.abspath(bundle_dir)) or "."
    os.makedirs(parent, exist_ok=True)
    staging = tempfile.mkdtemp(dir=parent, prefix=".secp-bundle-")
    try:
        if _IS_POSIX:
            os.chmod(staging, 0o700)
        _atomic_write(os.path.join(staging, _MANIFEST_NAME), json.dumps(manifest).encode(), 0o600)
        _atomic_write(os.path.join(staging, _BINDING_NAME), json.dumps(binding).encode(), 0o600)
        _atomic_write(os.path.join(staging, _KNOWN_HOSTS_NAME), known_hosts.encode(), 0o600)
        _atomic_write(os.path.join(staging, _KEY_NAME), id_key_bytes, 0o600)
        # Swap the fully-assembled bundle into place (replace any prior bundle dir).
        _replace_dir(staging, bundle_dir)
        staging = ""  # consumed
    finally:
        if staging and os.path.isdir(staging):
            _rmtree(staging)


def _atomic_write(path: str, data: bytes, mode: int) -> None:
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".secp-f-")
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    if _IS_POSIX:
        os.chmod(tmp, mode)
    os.replace(tmp, path)


def _replace_dir(src: str, dst: str) -> None:
    if os.path.exists(dst):
        # Move the old bundle aside then remove it, so the swap is close to atomic.
        old = dst + ".old"
        if os.path.exists(old):
            _rmtree(old)
        os.replace(dst, old)
        try:
            os.replace(src, dst)
        finally:
            _rmtree(old)
    else:
        os.makedirs(os.path.dirname(os.path.abspath(dst)) or ".", exist_ok=True)
        os.replace(src, dst)


def _rmtree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def bundle_is_present(bundle_dir: str) -> bool:
    """True only if the bundle dir exists and all four bundle files are present (a coarse readiness
    signal; the mounted-bundle source runs the authoritative strict validation before any ssh)."""
    if not os.path.isdir(bundle_dir):
        return False
    return all(
        os.path.isfile(os.path.join(bundle_dir, name))
        for name in (_MANIFEST_NAME, _KEY_NAME, _KNOWN_HOSTS_NAME, _BINDING_NAME)
    )
