"""Fixed production composition for the management-plane real adapters (SECP-PR5G).

This is the ONLY place the five real leaves (``RealManagementHostObserver``,
``RealControllerBootstrapAdapter``, ``RealWorkerBootstrapAdapter``, ``RealRollbackAdapter``,
``LocalManagementEvidenceAuthenticator``) are constructed, wired into a production ``EngineDeps``.

The composition is CLOSED: it consumes only fixed, code-owned, root-controlled deployment-local
through hardened readers and independently reviewed identities.  There is no adapter-selection CLI
flag, no environment variable selecting an implementation, no caller-supplied import, no mutable
global registration, and no arbitrary path/command/Compose-project/service/container name.  The
default ``EngineDeps()`` and the default CLI dependency construction stay sealed; a real adapter is
reachable ONLY through :func:`production_engine_deps`, called by the future supported production CLI
entrypoint.

Importing this module performs NO I/O, process execution, filesystem mutation, Docker, or network
contact — every read happens inside :func:`production_engine_deps`.  Any missing, partial, unsafe,
stale, mismatched, or malformed production input keeps production sealed (``ManagementError``);
the CLI then refuses rather than falling back to an unverified adapter.  No private key, release
key, endpoint, credential, IP address, or environment-specific value is committed here.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from secp_commissioning.descriptor import scan_forbidden
from secp_operator_deployment.host_process import RealCommandRunner
from secp_operator_deployment.pinned_exec import ExecutablePin

from secp_management import ManagementError
from secp_management.engine import EngineDeps
from secp_management.layout import ManagementLocations
from secp_management.real_adapters import (
    LocalManagementEvidenceAuthenticator,
    PinnedExecutables,
    RealAdapterContext,
    RealControllerBootstrapAdapter,
    RealManagementHostObserver,
    RealManagementRollbackAdapter,
    RealWorkerBootstrapAdapter,
)
from secp_management.signing import ReleaseTrustRoot, TrustAnchor

_SHA256 = "sha256:"
_MAX_JSON = 64 * 1024
_KEY_MODE = 0o600  # the evidence-signing private key must be exactly root-owned 0600


def _production_paths(locations: ManagementLocations) -> dict[str, str]:
    base = locations.bootstrap_state
    return {
        "executables": f"{base}/production-executables.json",
        "expected": f"{base}/production-expected-identities.json",
        "trust_anchor": f"{base}/release-trust-anchor.json",
        "evidence_key": f"{base}/evidence-signing.key",
        "evidence_pub": f"{base}/evidence-signing.pub.json",
    }


def _read_json(fs: Any, path: str) -> dict[str, Any]:
    try:
        raw = fs.safe_read(path, max_bytes=_MAX_JSON, expected_uid=0)
    except Exception:  # noqa: BLE001 - a missing/unsafe/hardlinked/symlinked/mis-owned input seals
        raise ManagementError("production_input_unavailable") from None
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        raise ManagementError("production_input_malformed") from None
    if not isinstance(value, dict):
        raise ManagementError("production_input_malformed")
    scan_forbidden(value)  # non-secret production inputs carry no credential-shaped field/value
    return value


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(_SHA256)
        and len(value) == 71
        and all(c in "0123456789abcdef" for c in value[len(_SHA256) :])
    )


def _pin(value: object) -> ExecutablePin:
    if not isinstance(value, dict) or set(value) != {"path", "digest"}:
        raise ManagementError("production_executable_invalid")
    path, digest = value["path"], value["digest"]
    if not (isinstance(path, str) and path.startswith("/") and ".." not in path.split("/")):
        raise ManagementError("production_executable_invalid")
    if not _is_digest(digest):
        raise ManagementError("production_executable_invalid")
    return ExecutablePin(path=path, digest=digest)


def _load_executables(fs: Any, path: str) -> PinnedExecutables:
    doc = _read_json(fs, path)
    if set(doc) != {"container_runtime", "compose_runtime", "service_manager"}:
        raise ManagementError("production_executable_invalid")
    return PinnedExecutables(
        container_runtime=_pin(doc["container_runtime"]),
        compose_runtime=_pin(doc["compose_runtime"]),
        service_manager=_pin(doc["service_manager"]),
    )


def _load_trust_anchor(fs: Any, path: str) -> ReleaseTrustRoot:
    doc = _read_json(fs, path)
    if set(doc) != {"key_id", "public_key_hex"}:
        raise ManagementError("production_trust_anchor_invalid")
    key_id, pub = doc["key_id"], doc["public_key_hex"]
    if not _is_digest(key_id) or not (isinstance(pub, str) and len(bytes.fromhex(pub)) == 32):
        raise ManagementError("production_trust_anchor_invalid")
    if _SHA256 + hashlib.sha256(bytes.fromhex(pub)).hexdigest() != key_id:
        raise ManagementError(
            "production_trust_anchor_invalid"
        )  # anchor id must derive from its key
    return ReleaseTrustRoot(
        anchors=(TrustAnchor(key_id=key_id, public_key_hex=pub),), test_only=False
    )


def _load_evidence_authenticator(
    fs: Any, key_path: str, pub_path: str
) -> LocalManagementEvidenceAuthenticator:
    # the private key must be a root-owned, single-link, regular file with EXACTLY mode 0600.
    stat = fs.lstat(key_path)
    if stat is None or stat.is_dir or stat.is_symlink or stat.uid != 0 or stat.nlink != 1:
        raise ManagementError("production_evidence_key_unsafe")
    if (stat.mode & 0o777) != _KEY_MODE:
        raise ManagementError("production_evidence_key_unsafe")
    try:
        raw = fs.safe_read(key_path, max_bytes=1024, expected_uid=0)
    except Exception:  # noqa: BLE001
        raise ManagementError("production_evidence_key_unsafe") from None
    if len(raw) != 32:
        raise ManagementError("production_evidence_key_unsafe")
    private_hex = raw.hex()

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    public_hex = (
        Ed25519PrivateKey.from_private_bytes(raw)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    # the reviewed, independently pinned public identity must match the derived key id
    doc = _read_json(fs, pub_path)
    if set(doc) != {"key_id", "public_key_hex"}:
        raise ManagementError("production_evidence_identity_invalid")
    derived_id = _SHA256 + hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()
    if doc["public_key_hex"] != public_hex or doc["key_id"] != derived_id:
        raise ManagementError("production_evidence_key_pair_mismatch")
    return LocalManagementEvidenceAuthenticator(private_hex, public_hex)


def production_engine_deps(*, fs: Any = None, runner: Any = None) -> EngineDeps:
    """Build the production ``EngineDeps`` from the fixed root-controlled inputs, or raise
    ``ManagementError`` (keeping production sealed) on any missing/unsafe/mismatched/bad input.

    ``fs``/``runner`` default to the real hardened filesystem + pinned runner; they are dependency
    seams for the hermetic tests, NOT adapter selection (no adapter is ever chosen by a
    caller argument, environment variable, import, or global)."""
    from secp_commissioning.runtime import RealFilesystem

    locations = ManagementLocations()
    filesystem = fs if fs is not None else RealFilesystem()
    command_runner = runner if runner is not None else RealCommandRunner()
    paths = _production_paths(locations)

    executables = _load_executables(filesystem, paths["executables"])
    _read_json(
        filesystem, paths["expected"]
    )  # reviewed expected topology identities must be present
    trust_root = _load_trust_anchor(filesystem, paths["trust_anchor"])
    authenticator = _load_evidence_authenticator(
        filesystem, paths["evidence_key"], paths["evidence_pub"]
    )

    ctx = RealAdapterContext(
        locations=locations,
        fs=filesystem,
        runner=command_runner,
        executables=executables,
    )
    return EngineDeps(
        locations=locations,
        trust_root=trust_root,
        observer=RealManagementHostObserver(ctx),
        controller_adapter=RealControllerBootstrapAdapter(ctx),
        worker_adapter=RealWorkerBootstrapAdapter(ctx),
        rollback_adapter=RealManagementRollbackAdapter(filesystem, locations),
        evidence_authenticator=authenticator,
        evidence_trust_root=trust_root,
        fs=filesystem,
    )


__all__ = ["production_engine_deps"]
