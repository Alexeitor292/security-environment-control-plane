"""Fixed production composition for the management-plane real adapters (SECP-PR5G).

This is the ONLY place the five real leaves (``RealManagementHostObserver``,
``RealControllerBootstrapAdapter``, ``RealWorkerBootstrapAdapter``, ``RealRollbackAdapter``,
``LocalManagementEvidenceAuthenticator``) are constructed, wired into a production ``EngineDeps``.

The composition is CLOSED: it consumes only fixed, code-owned, root-controlled deployment-local
through hardened readers and independently reviewed identities.  There is no adapter-selection CLI
flag, no environment variable selecting an implementation, no caller-supplied import, no mutable
global registration, and no arbitrary path/command/Compose-project/service/container name.  A bare
``EngineDeps()`` (e.g. the default when ``cli.run`` is called with ``deps=None``, or a test double)
stays sealed; a real adapter is reachable ONLY through :func:`production_engine_deps`.

This is the **STEADY-STATE** composer: it reads the fixed production inputs that a completed
installation has ALREADY prepared. It is now wired into the supported CLI via
``cli._production_engine_deps`` for the engine command groups (``bootstrap/adopt/status/evidence/
rollback``), which falls back to the sealed default on any missing/unsafe input. It is deliberately
NOT the clean-host installer: a fresh host has none of these inputs, so calling it there yields the
sealed fallback. Preparing those inputs on a clean host (from the signed release bundle + host facts
+ code-owned identities) is the DISTINCT root-only installation composition (SECP-PR5H-B2, Phase
2b); steady-state commands use this composer only AFTER that installation has committed and been
independently revalidated.

Importing this module performs NO I/O, process execution, filesystem mutation, Docker, or network
contact — every read happens inside :func:`production_engine_deps`.  Any missing, partial, unsafe,
stale, mismatched, or malformed production input keeps production sealed (``ManagementError``);
the CLI then refuses rather than falling back to an unverified adapter.  No private key, release
key, endpoint, credential, IP address, or environment-specific value is committed here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
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
    try:
        scan_forbidden(value)  # non-secret production inputs carry no credential-shaped field/value
    except Exception:  # noqa: BLE001 - a forbidden/credential-shaped field seals production
        raise ManagementError("production_input_forbidden") from None
    return value


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(_SHA256)
        and len(value) == 71
        and all(c in "0123456789abcdef" for c in value[len(_SHA256) :])
    )


def _is_hex32(value: object) -> bool:
    """A 32-byte lowercase-hex string (a raw ed25519 public key), validated WITHOUT bytes.fromhex so
    a malformed value seals production instead of raising an uncaught ValueError."""
    return (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
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
    if not _is_digest(key_id) or not _is_hex32(pub):
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


def _compose_engine_deps(*, fs: Any, runner: Any, finalization: bool) -> EngineDeps:
    """Shared production composition. ``finalization=False`` is the STEADY-STATE composer (the
    finalization seam stays SEALED); ``finalization=True`` is the DISTINCT root-only install
    composition that injects the real finalization adapter. Both read the identical fixed
    root-controlled inputs through the same hardened readers."""
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

    # The evidence attestation is signed by the LOCAL evidence authenticator (its own key K_e), NOT
    # by the release-signing key (K_r, whose private half is never on the host).  The commit gate
    # verifies that attestation against evidence_trust_root, so the evidence root must pin the
    # authenticator's OWN public identity — pinning the release anchor here would fail every commit
    # closed (evidence_attestation_untrusted -> recovery_required).  They are distinct roots.
    evidence_trust_root = ReleaseTrustRoot(
        anchors=(
            TrustAnchor(
                key_id=authenticator.key_id(), public_key_hex=authenticator.public_key_hex()
            ),
        ),
        test_only=False,
    )
    ctx = RealAdapterContext(
        locations=locations,
        fs=filesystem,
        runner=command_runner,
        executables=executables,
    )
    extra: dict[str, Any] = {}
    if finalization:
        # Inject the plan-bound single-use FACTORY (never a mutable singleton adapter) so the write
        # transaction builds one fresh adapter per install from its authenticated plan. The sealed
        # finalization_adapter default is left in place (unused when a factory is present).
        extra["finalization_factory"] = build_real_finalization_factory(ctx)
        # R1: the read-only PRE-MUTATION finalization inventory, whose dedicated-role/identity facts
        # come from the fixed read-only API one-shot through the reviewed root->API boundary.
        from secp_management.controller_finalization_inventory import (
            build_oneshot_finalization_db_probe,
            observe_finalization_inventory,
        )

        _probe = build_oneshot_finalization_db_probe(ctx)
        extra["finalization_inventory"] = lambda: observe_finalization_inventory(
            ctx, role_probe=_probe
        )
        # R3: the read-only LIVE finalization state observer used by exact replay + managed-upgrade
        # eligibility (mutation-free).
        from secp_management.controller_finalization_state import (
            ControllerStateContext,
            build_controller_finalization_state_observer,
        )
        from secp_management.enrollment_signer_runtime_observer import (
            build_api_signer_runtime_observer,
        )

        extra["finalization_state_observer"] = build_controller_finalization_state_observer(
            ControllerStateContext(
                host=ctx,
                # unbound: proves nothing by itself (fail-closed) and is never used in production --
                # the expectation-bound seam below always takes precedence.
                runtime_observer=build_api_signer_runtime_observer(ctx),
                runtime_observer_for=_runtime_observation_for(ctx),
                generation_probe=lambda: _probe().activation_generation,
            )
        )
    return EngineDeps(
        locations=locations,
        trust_root=trust_root,
        observer=RealManagementHostObserver(ctx),
        controller_adapter=RealControllerBootstrapAdapter(ctx),
        worker_adapter=RealWorkerBootstrapAdapter(ctx),
        rollback_adapter=RealManagementRollbackAdapter(filesystem, locations),
        evidence_authenticator=authenticator,
        evidence_trust_root=evidence_trust_root,
        fs=filesystem,
        **extra,
    )


def production_engine_deps(*, fs: Any = None, runner: Any = None) -> EngineDeps:
    """Build the STEADY-STATE production ``EngineDeps`` from the fixed root-controlled inputs, or
    raise ``ManagementError`` (keeping production sealed) on any missing/unsafe/mismatched/bad
    input.
    The finalization seam stays SEALED here — finalization is an install-time mutation, never a
    steady-state read.

    ``fs``/``runner`` default to the real hardened filesystem + pinned runner; they are dependency
    seams for the hermetic tests, NOT adapter selection (no adapter is ever chosen by a
    caller argument, environment variable, import, or global)."""
    return _compose_engine_deps(fs=fs, runner=runner, finalization=False)


def build_real_controller_finalization_adapter(ctx: RealAdapterContext) -> Any:
    """Compose the REAL controller-enrollment finalization adapter (unbound) from a production host
    context. Retained as the reviewed leaf constructor; the driven install uses the plan-bound
    FACTORY below. The reviewed non-root controller-API peer identity is the fixed code constant
    (never selected); no secret is carried."""
    from secp_management.controller_finalization import (
        FinalizationContext,
        RealControllerEnrollmentFinalizationAdapter,
    )
    from secp_management.topology import API_RUNTIME_GID, API_RUNTIME_UID

    return RealControllerEnrollmentFinalizationAdapter(
        FinalizationContext(host=ctx, api_uid=API_RUNTIME_UID, api_gid=API_RUNTIME_GID)
    )


def build_real_finalization_factory(ctx: RealAdapterContext) -> Any:
    """The plan-bound, single-use finalization FACTORY the root-only install composition injects.
    Each call builds ONE fresh adapter bound to exactly the supplied, already-authenticated
    ``ControllerEnrollmentFinalizationPlan`` (its generation + transaction id freeze at
    construction)
    with the REAL boundary-safe runtime observer wired in — so ``enable_api_signer`` proves the live
    API is sealed with the candidate marker rather than fail-closing on the default observer. The
    factory captures only the fixed production context + observer; it accepts NO caller/env/import
    adapter selection and carries no secret."""
    from secp_management.controller_finalization import (
        FinalizationContext,
        RealControllerEnrollmentFinalizationAdapter,
    )
    from secp_management.topology import API_RUNTIME_GID, API_RUNTIME_UID

    def _factory(plan: Any) -> Any:
        # R4: the runtime observer is PLAN-BOUND. It is never constructed unbound, and the complete
        # ApiSignerRuntimeExpectations is deferred until observe(marker) runs AFTER activation --
        # only genuinely post-activation facts (the active identity row, its activation token, the
        # activation-receipt-bound key identity) come from the marker; every independently available
        # fact comes from the authenticated plan, the signed release and fixed code-owned contracts.
        return RealControllerEnrollmentFinalizationAdapter(
            FinalizationContext(
                host=ctx,
                api_uid=API_RUNTIME_UID,
                api_gid=API_RUNTIME_GID,
                runtime_observer=PlanBoundApiSignerRuntimeObserver(ctx=ctx, plan=plan),
            ),
            plan=plan,
        )

    return _factory


def _runtime_observation_for(ctx: RealAdapterContext) -> Any:
    """The REPLAY / UPGRADE-ELIGIBILITY runtime seam (R4). It derives the complete
    ApiSignerRuntimeExpectations from the ALREADY-AUTHENTICATED installed state the caller proved
    (the verified release's signed controller/api image, its release digest + installation id, and
    the current durable generation), taking from the marker only the activation-receipt-bound token
    that genuinely arises after activation."""

    def _observe(expected: Any, marker: Any) -> Any:
        from secp_management.enrollment_signer_runtime_observer import (
            ApiSignerRuntimeExpectations,
            build_api_signer_runtime_observer,
        )

        loc = ctx.locations
        runtime_expected = ApiSignerRuntimeExpectations(
            api_image_digest=expected.api_image_digest,
            release_digest=expected.release_digest,
            installation_id=expected.installation_id,
            finalization_generation=expected.generation,
            controller_stack_generation=expected.generation,
            active_identity_row_id=expected.active_identity_row_id,
            active_identity_activation_token=marker.activation_token,
            marker=marker,
            broker_unit_path=loc.broker_unit_path(),
            broker_socket_path=loc.broker_socket_path(),
        )
        return build_api_signer_runtime_observer(ctx, expected=runtime_expected)(marker)

    return _observe


@dataclass(frozen=True)
class PlanBoundApiSignerRuntimeObserver:
    """The production runtime-observer seam, BOUND to one authenticated finalization plan.

    The finalization adapter calls it as ``runtime_observer(marker)`` after it has written the
    candidate marker and restarted the API. Only then are all the facts available, so the complete
    independently-derived expectation is assembled here and handed to the authoritative observer.
    Constructing it requires no contact and performs no observation."""

    ctx: RealAdapterContext
    plan: Any

    def __call__(self, marker: Any) -> Any:
        from secp_management.enrollment_signer_runtime_observer import (
            ApiSignerRuntimeExpectations,
            build_api_signer_runtime_observer,
        )

        loc = self.ctx.locations
        expected = ApiSignerRuntimeExpectations(
            # --- independently authenticated STATIC facts (plan + signed release) ---
            api_image_digest=self.plan.expected_api_image_digest,
            release_digest=self.plan.release_digest,
            installation_id=self.plan.controller_installation_id,
            finalization_generation=self.plan.generation,
            controller_stack_generation=self.plan.controller_stack_generation,
            # --- fixed code-owned contracts ---
            broker_unit_path=loc.broker_unit_path(),
            broker_socket_path=loc.broker_socket_path(),
            # --- genuinely POST-ACTIVATION facts (activation-receipt bound, via the candidate) ---
            active_identity_row_id=marker.active_identity_row_id,
            active_identity_activation_token=marker.activation_token,
            marker=marker,
        )
        return build_api_signer_runtime_observer(self.ctx, expected=expected)(marker)


def controller_install_engine_deps(*, fs: Any = None, runner: Any = None) -> EngineDeps:
    """The DISTINCT root-only clean-host install composition (SECP-PR5H-B2, 2b-3b-iii): the ONLY
    composer that injects the REAL controller-enrollment finalization adapter. It is gated
    POSIX-root
    up front and is reachable ONLY from a future root-only install verb — NEVER from ``cli.main``'s
    steady-state ``deps = _production_engine_deps()`` line, which keeps finalization sealed, and
    never
    from a CLI flag / environment variable / import / mutable global. A bare ``EngineDeps()`` stays
    sealed. (Driving this seam through the bootstrap write transaction is the separate 2b-3c commit;
    here the real adapter is composed-but-not-yet-orchestrated, changing zero steady-state
    behavior.)"""
    from secp_management.controller_install import assert_posix_root

    assert_posix_root()
    return _compose_engine_deps(fs=fs, runner=runner, finalization=True)


__all__ = [
    "build_real_controller_finalization_adapter",
    "build_real_finalization_factory",
    "controller_install_engine_deps",
    "production_engine_deps",
]
