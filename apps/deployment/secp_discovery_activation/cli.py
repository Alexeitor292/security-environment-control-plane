"""Production-wired administrator CLI for SECP-PR5F discovery activation.

The command surface is the exact eight-operation engine surface.  There is no path argument,
generic command, certificate-generation switch, SSH operation, workflow operation, or provider
mutation operation.  Production inputs are read only from :mod:`layout`'s fixed root-controlled
paths.  ``plan`` and ``render`` resolve and validate those local inputs but construct no host
adapter; module import and parser construction perform no I/O.

``install`` and ``rollback`` default to refusal and require both ``--write`` and ``--confirm``.
The deployed controller and worker are separate hosts, so the CLI selects one fixed local role and
uses an authenticated, receipt-bound controller-offer/worker-result handoff rather than pretending
one process has authority over both machines.  The local evidence key is created only by an explicit
reviewed write, and every missing fixed input or role-local dependency is a bounded refusal rather
than an implicit fallback.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime

from secp_discovery_activation import PACKAGE_VERSION, DiscoveryActivationError
from secp_discovery_activation.engine import (
    EngineDependencies,
    OperationResult,
    WriteGate,
    evidence_operation,
    inspect_operation,
    install_operation,
    plan_operation,
    render_operation,
    rollback_operation,
    status_operation,
    verify_operation,
)
from secp_discovery_activation.evidence import SHIPPED_EVIDENCE_TRUST_ROOT
from secp_discovery_activation.evidence_key import (
    EvidenceKeyPreparation,
    LocalEvidenceAuthenticator,
    local_evidence_trust_root,
    prepare_local_evidence_key,
)
from secp_discovery_activation.layout import PRODUCTION_LAYOUT
from secp_discovery_activation.local_adapter import LocalActivationAdapter, LocalHostRole
from secp_discovery_activation.profile import (
    MAX_PROFILE_BYTES,
    DeploymentProfile,
    parse_profile_bytes,
)
from secp_discovery_activation.render import render_worker_compose_override
from secp_discovery_activation.runtime_overlay import (
    MAX_RUNTIME_OVERLAY_BYTES,
    ValidatedRuntimeOverlay,
    import_runtime_overlay,
)
from secp_discovery_activation.split_engine import (
    ControllerDependencies,
    WorkerDependencies,
    controller_evidence_operation,
    controller_inspect_operation,
    controller_install_operation,
    controller_rollback_operation,
    controller_status_operation,
    controller_verify_operation,
    validate_worker_ca_certificate,
    worker_evidence_operation,
    worker_inspect_operation,
    worker_install_operation,
    worker_rollback_operation,
    worker_status_operation,
    worker_verify_operation,
)
from secp_discovery_activation.state import RealWorkerStateFilesystem
from secp_discovery_activation.tls import ValidatedTLSMaterial, import_tls_material

EXIT_OK = 0
EXIT_REFUSED = 10
EXIT_RECOVERY_REQUIRED = 20

_OPERATIONS = (
    "inspect",
    "plan",
    "render",
    "install",
    "verify",
    "status",
    "rollback",
    "evidence",
)
_MUTATIONS = frozenset({"install", "rollback"})
_CONTROLLER_IMPORT_TLS_OPERATIONS = frozenset({"plan", "render", "install"})
_CONTROLLER_INSTALLED_TLS_OPERATIONS = frozenset({"verify", "status"})
_WORKER_IMPORT_CA_OPERATIONS = frozenset({"plan", "render", "install"})
_WORKER_INSTALLED_CA_OPERATIONS = frozenset({"verify", "status", "evidence"})
_INSTALLATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_MAX_CERTIFICATE_BYTES = 32 * 1024
_MAX_PRIVATE_KEY_BYTES = 64 * 1024
_MAX_ROLE_BYTES = 16


class ActivationCLIError(DiscoveryActivationError):
    """A bounded CLI production-context refusal."""


@dataclass(frozen=True)
class CliDependencies:
    """Already-resolved test seam; production command lines cannot select or inject it."""

    profile: DeploymentProfile | None = None
    tls_material: ValidatedTLSMaterial | None = None
    engine_dependencies: EngineDependencies | None = None


@dataclass(frozen=True)
class SplitCliDependencies:
    """Role-bound production dependencies resolved from fixed local files only."""

    host_role: LocalHostRole
    profile: DeploymentProfile
    controller_dependencies: ControllerDependencies | None = None
    worker_dependencies: WorkerDependencies | None = None
    tls_material: ValidatedTLSMaterial | None = None
    ca_certificate_pem: bytes | None = None
    runtime_overlay: ValidatedRuntimeOverlay | None = None
    evidence_key_preparation: EvidenceKeyPreparation | None = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secp-discovery-activation",
        description=(
            "Production B8 read-only discovery activation. Fixed local inputs only; install and "
            "rollback require --write --confirm. No shell/exec/SSH/OpenTofu/operator operation."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"secp_discovery_activation {PACKAGE_VERSION}"
    )
    subcommands = parser.add_subparsers(dest="operation", required=True)
    for operation in _OPERATIONS:
        command = subcommands.add_parser(operation)
        command.add_argument(
            "--json", action="store_true", help="emit deterministic machine-readable JSON"
        )
        if operation in _MUTATIONS:
            command.add_argument("--write", action="store_true", help="authorize local writes")
            command.add_argument(
                "--confirm", action="store_true", help="confirm the reviewed write"
            )
        if operation == "install":
            command.add_argument(
                "--installation-identity",
                required=True,
                help="bounded non-secret identity recorded in signed evidence",
            )
    return parser


def _gate(args: argparse.Namespace) -> WriteGate:
    return WriteGate(
        write=bool(getattr(args, "write", False)),
        confirm=bool(getattr(args, "confirm", False)),
    )


def _operation_result(
    operation: str,
    outcome: str,
    *,
    reason: str | None = None,
    recovery: bool = False,
    details: dict[str, object] | None = None,
) -> OperationResult:
    return OperationResult(operation, outcome, reason, recovery, details or {})


def _refusal(operation: str, reason: str, *, recovery: bool = False) -> OperationResult:
    return _operation_result(
        operation,
        "recovery-required" if recovery else "refused",
        reason="recovery_required" if recovery else reason,
        recovery=recovery,
    )


def _exit_code(result: OperationResult) -> int:
    if result.recovery_required or result.outcome == "recovery-required":
        return EXIT_RECOVERY_REQUIRED
    if result.outcome == "refused":
        return EXIT_REFUSED
    return EXIT_OK


def _validate_injected(deps: object) -> CliDependencies:
    if type(deps) is not CliDependencies:
        raise ActivationCLIError("cli_dependencies_type_invalid")
    return deps


def _require_profile(deps: CliDependencies) -> DeploymentProfile:
    if type(deps.profile) is not DeploymentProfile:
        raise ActivationCLIError("production_profile_unavailable")
    return deps.profile


def _require_tls(deps: CliDependencies) -> ValidatedTLSMaterial:
    if type(deps.tls_material) is not ValidatedTLSMaterial:
        raise ActivationCLIError("production_tls_material_unavailable")
    return deps.tls_material


def _require_engine_dependencies(deps: CliDependencies) -> EngineDependencies:
    if type(deps.engine_dependencies) is not EngineDependencies:
        raise ActivationCLIError("production_engine_dependencies_unavailable")
    return deps.engine_dependencies


def _dispatch(args: argparse.Namespace, deps: CliDependencies) -> OperationResult:
    operation = args.operation
    if operation == "plan":
        return plan_operation(_require_profile(deps), _require_tls(deps))
    if operation == "render":
        return render_operation(_require_profile(deps), _require_tls(deps))
    if operation == "inspect":
        return inspect_operation(_require_profile(deps), _require_engine_dependencies(deps))
    if operation == "install":
        return install_operation(
            _require_profile(deps),
            _require_tls(deps),
            _gate(args),
            _require_engine_dependencies(deps),
            installation_identity=args.installation_identity,
        )
    if operation == "verify":
        return verify_operation(_require_profile(deps), _require_engine_dependencies(deps))
    if operation == "status":
        return status_operation(_require_profile(deps), _require_engine_dependencies(deps))
    if operation == "rollback":
        return rollback_operation(
            _require_profile(deps), _gate(args), _require_engine_dependencies(deps)
        )
    if operation == "evidence":
        return evidence_operation(_require_engine_dependencies(deps))
    raise ActivationCLIError("operation_invalid")


def _role_result(
    requested_operation: str, role: LocalHostRole, result: OperationResult
) -> OperationResult:
    details = {"host_role": role.value, "role_operation": result.operation, **result.details}
    return OperationResult(
        requested_operation,
        result.outcome,
        result.reason_code,
        result.recovery_required,
        details,
    )


def _worker_pure_operation(
    operation: str,
    profile: DeploymentProfile,
    ca_certificate_pem: bytes,
    runtime_overlay: ValidatedRuntimeOverlay,
) -> OperationResult:
    if type(runtime_overlay) is not ValidatedRuntimeOverlay:
        raise ActivationCLIError("production_worker_runtime_overlay_unavailable")
    ca = validate_worker_ca_certificate(ca_certificate_pem, now=datetime.now(UTC))
    artifact = render_worker_compose_override(profile)
    common: dict[str, object] = {
        "host_role": LocalHostRole.worker.value,
        "artifact": {
            "name": artifact.name,
            "path": artifact.path,
            "sha256": artifact.sha256,
            "size_bytes": len(artifact.content),
            "uid": artifact.uid,
            "gid": artifact.gid,
            "mode": artifact.mode,
        },
        "admission_ca_fingerprint": ca.ca_certificate_fingerprint,
        "worker_runtime_overlay": {
            "sha256": runtime_overlay.sha256,
            "contract_version": runtime_overlay.contract_version,
            "packages": list(runtime_overlay.packages),
            "file_count": len(runtime_overlay.files),
        },
        "host_mutations_during_" + operation: False,
        "external_contacts_during_" + operation: False,
    }
    if operation == "plan":
        common["operations"] = [
            "validate-fixed-worker-state",
            "authenticate-fixed-controller-offer",
            "persist-content-bound-worker-rollback-journal",
            "install-worker-ca-and-compose-override",
            "verify-host-side-pinned-tls",
            "recreate-ordinary-worker-only",
            "verify-in-container-pinned-tls-and-public-node",
            "emit-authenticated-worker-result",
        ]
        return OperationResult("plan", "planned", None, False, common)
    return OperationResult("render", "rendered", None, False, common)


def _dispatch_split(args: argparse.Namespace, deps: SplitCliDependencies) -> OperationResult:
    operation = args.operation
    role = deps.host_role
    profile = deps.profile
    if operation == "install" and not profile.activation_enabled:
        preparation = deps.evidence_key_preparation
        if type(preparation) is not EvidenceKeyPreparation:
            raise ActivationCLIError("evidence_key_preparation_unavailable")
        return OperationResult(
            "install",
            "prepared",
            "activation_disabled_key_preparation_only",
            False,
            {
                "host_role": role.value,
                "evidence_key_id": preparation.key_id,
                "classification": preparation.classification,
                "activation_effects_started": False,
                "container_recreated": False,
                "forbidden_infrastructure_contacts_performed": False,
            },
        )
    if operation in {"plan", "render"}:
        if role is LocalHostRole.controller:
            if type(deps.tls_material) is not ValidatedTLSMaterial:
                raise ActivationCLIError("production_tls_material_unavailable")
            result = (
                plan_operation(profile, deps.tls_material)
                if operation == "plan"
                else render_operation(profile, deps.tls_material)
            )
            return _role_result(operation, role, result)
        if type(deps.ca_certificate_pem) is not bytes:
            raise ActivationCLIError("production_tls_ca_unavailable")
        if type(deps.runtime_overlay) is not ValidatedRuntimeOverlay:
            raise ActivationCLIError("production_worker_runtime_overlay_unavailable")
        return _worker_pure_operation(
            operation, profile, deps.ca_certificate_pem, deps.runtime_overlay
        )

    if role is LocalHostRole.controller:
        controller_deps = deps.controller_dependencies
        if type(controller_deps) is not ControllerDependencies:
            raise ActivationCLIError("production_controller_dependencies_unavailable")
        if operation == "inspect":
            result = controller_inspect_operation(profile, controller_deps)
        elif operation == "install":
            if type(deps.tls_material) is not ValidatedTLSMaterial:
                raise ActivationCLIError("production_tls_material_unavailable")
            result = controller_install_operation(
                profile,
                deps.tls_material,
                _gate(args),
                controller_deps,
                installation_identity=args.installation_identity,
            )
        elif operation == "verify":
            if type(deps.tls_material) is not ValidatedTLSMaterial:
                raise ActivationCLIError("production_tls_material_unavailable")
            result = controller_verify_operation(profile, deps.tls_material, controller_deps)
        elif operation == "status":
            if profile.activation_enabled and type(deps.tls_material) is not ValidatedTLSMaterial:
                raise ActivationCLIError("production_tls_material_unavailable")
            result = controller_status_operation(profile, deps.tls_material, controller_deps)
        elif operation == "rollback":
            result = controller_rollback_operation(profile, _gate(args), controller_deps)
        elif operation == "evidence":
            result = controller_evidence_operation(profile, controller_deps)
        else:
            raise ActivationCLIError("operation_invalid")
        return _role_result(operation, role, result)

    worker_deps = deps.worker_dependencies
    if type(worker_deps) is not WorkerDependencies:
        raise ActivationCLIError("production_worker_dependencies_unavailable")
    if operation == "inspect":
        result = worker_inspect_operation(profile, worker_deps)
    elif operation == "install":
        if type(deps.ca_certificate_pem) is not bytes:
            raise ActivationCLIError("production_tls_ca_unavailable")
        result = worker_install_operation(
            profile,
            deps.ca_certificate_pem,
            _gate(args),
            worker_deps,
            installation_identity=args.installation_identity,
        )
    elif operation == "verify":
        if type(deps.ca_certificate_pem) is not bytes:
            raise ActivationCLIError("production_tls_ca_unavailable")
        result = worker_verify_operation(profile, deps.ca_certificate_pem, worker_deps)
    elif operation == "status":
        if profile.activation_enabled and type(deps.ca_certificate_pem) is not bytes:
            raise ActivationCLIError("production_tls_ca_unavailable")
        result = worker_status_operation(profile, deps.ca_certificate_pem, worker_deps)
    elif operation == "rollback":
        result = worker_rollback_operation(profile, _gate(args), worker_deps)
    elif operation == "evidence":
        if type(deps.ca_certificate_pem) is not bytes:
            raise ActivationCLIError("production_tls_ca_unavailable")
        result = worker_evidence_operation(profile, deps.ca_certificate_pem, worker_deps)
    else:
        raise ActivationCLIError("operation_invalid")
    return _role_result(operation, role, result)


def _dependency_failure(operation: str, exc: Exception) -> OperationResult:
    if isinstance(exc, DiscoveryActivationError):
        return _refusal(operation, exc.reason_code)
    return _refusal(operation, "production_dependency_unavailable")


def run(argv: list[str], deps: CliDependencies | None = None) -> tuple[int, dict[str, object]]:
    """Parse and execute one operation, returning its stable exit code and canonical report."""

    args = build_parser().parse_args(argv)
    operation = args.operation
    gate = _gate(args)

    # Do not resolve a production filesystem/adapter for an unauthorized mutation.  This preserves
    # dry-run refusal even on a host where production dependencies are absent.
    if operation in _MUTATIONS:
        refusal = gate.refusal_reason()
        if refusal is not None:
            result = _refusal(operation, refusal)
            return _exit_code(result), result.canonical()

    try:
        if deps is None:
            result = _dispatch_split(args, _resolve_production(operation, args))
        else:
            result = _dispatch(args, _validate_injected(deps))
    except Exception as exc:
        # argparse's SystemExit and process interrupts are not swallowed. Everything in production
        # resolution collapses to bounded reason codes; raw path/certificate/key/command exceptions
        # never reach output.
        result = _dependency_failure(operation, exc)
    return _exit_code(result), result.canonical()


def _real_filesystem():  # noqa: ANN202
    try:
        from secp_commissioning.runtime import RealFilesystem

        return RealFilesystem()
    except Exception:
        raise ActivationCLIError("production_filesystem_unavailable") from None


def _read_fixed(
    fs,
    *,
    path: str,
    max_bytes: int,
    mode: int,
    gid: int,
    reason: str,
) -> bytes:  # noqa: ANN001
    """Read one exact root-owned, single-link regular file with exact metadata."""

    try:
        st = fs.lstat(path)
        if (
            st is None
            or not st.is_regular
            or st.is_dir
            or st.is_symlink
            or st.is_special
            or st.nlink != 1
            or st.uid != 0
            or st.gid != gid
            or st.mode != mode
            or not (1 <= st.size <= max_bytes)
        ):
            raise ValueError
        raw = fs.safe_read(path, max_bytes=max_bytes, expected_uid=0)
        if len(raw) != st.size:
            raise ValueError
        return raw
    except Exception:
        raise ActivationCLIError(reason) from None


def _load_fixed_profile(fs) -> DeploymentProfile:  # noqa: ANN001
    raw = _read_fixed(
        fs,
        path=PRODUCTION_LAYOUT.profile_path,
        max_bytes=MAX_PROFILE_BYTES,
        mode=0o640,
        gid=0,
        reason="production_profile_unavailable",
    )
    return parse_profile_bytes(raw)


def _load_fixed_host_role(fs) -> LocalHostRole:  # noqa: ANN001
    raw = _read_fixed(
        fs,
        path=PRODUCTION_LAYOUT.host_role_path,
        max_bytes=_MAX_ROLE_BYTES,
        mode=0o644,
        gid=0,
        reason="production_host_role_unavailable",
    )
    if raw == b"controller\n":
        return LocalHostRole.controller
    if raw == b"worker\n":
        return LocalHostRole.worker
    raise ActivationCLIError("production_host_role_invalid")


def _load_fixed_tls(fs, profile: DeploymentProfile) -> ValidatedTLSMaterial:  # noqa: ANN001
    ca = _read_fixed(
        fs,
        path=PRODUCTION_LAYOUT.ca_certificate_path,
        max_bytes=_MAX_CERTIFICATE_BYTES,
        mode=0o644,
        gid=0,
        reason="production_tls_ca_unavailable",
    )
    certificate = _read_fixed(
        fs,
        path=PRODUCTION_LAYOUT.server_certificate_path,
        max_bytes=_MAX_CERTIFICATE_BYTES,
        mode=0o644,
        gid=0,
        reason="production_tls_certificate_unavailable",
    )
    server_key = _read_fixed(
        fs,
        path=PRODUCTION_LAYOUT.server_private_key_path,
        max_bytes=_MAX_PRIVATE_KEY_BYTES,
        mode=0o640,
        gid=profile.admission_proxy_runtime_gid,
        reason="production_tls_private_key_unavailable",
    )
    return import_tls_material(
        ca_certificate_pem=ca,
        server_certificate_pem=certificate,
        server_private_key_pem=server_key,
        expected_dns_identity=profile.admission_certificate_dns_name,
    )


def _load_import_tls(fs, profile: DeploymentProfile) -> ValidatedTLSMaterial:  # noqa: ANN001
    ca = _read_fixed(
        fs,
        path=PRODUCTION_LAYOUT.tls_import_ca_certificate_path,
        max_bytes=_MAX_CERTIFICATE_BYTES,
        mode=0o644,
        gid=0,
        reason="production_tls_import_ca_unavailable",
    )
    certificate = _read_fixed(
        fs,
        path=PRODUCTION_LAYOUT.tls_import_server_certificate_path,
        max_bytes=_MAX_CERTIFICATE_BYTES,
        mode=0o644,
        gid=0,
        reason="production_tls_import_certificate_unavailable",
    )
    server_key = _read_fixed(
        fs,
        path=PRODUCTION_LAYOUT.tls_import_server_private_key_path,
        max_bytes=_MAX_PRIVATE_KEY_BYTES,
        mode=0o600,
        gid=0,
        reason="production_tls_import_private_key_unavailable",
    )
    return import_tls_material(
        ca_certificate_pem=ca,
        server_certificate_pem=certificate,
        server_private_key_pem=server_key,
        expected_dns_identity=profile.admission_certificate_dns_name,
    )


def _load_ca_bytes(fs, *, imported: bool) -> bytes:  # noqa: ANN001
    return _read_fixed(
        fs,
        path=(
            PRODUCTION_LAYOUT.tls_import_ca_certificate_path
            if imported
            else PRODUCTION_LAYOUT.ca_certificate_path
        ),
        max_bytes=_MAX_CERTIFICATE_BYTES,
        mode=0o644,
        gid=0,
        reason=(
            "production_tls_import_ca_unavailable" if imported else "production_tls_ca_unavailable"
        ),
    )


def _load_import_runtime_overlay(
    fs,
    profile: DeploymentProfile,  # noqa: ANN001
) -> ValidatedRuntimeOverlay:
    expected = profile.worker_runtime_overlay_digest
    if expected is None:
        raise ActivationCLIError("production_worker_runtime_overlay_unavailable")
    raw = _read_fixed(
        fs,
        path=PRODUCTION_LAYOUT.worker_runtime_overlay_import_path,
        max_bytes=MAX_RUNTIME_OVERLAY_BYTES,
        mode=0o644,
        gid=0,
        reason="production_worker_runtime_overlay_unavailable",
    )
    return import_runtime_overlay(raw, expected)


def _resolve_production(operation: str, args: argparse.Namespace) -> SplitCliDependencies:
    """Resolve only dependencies used by this operation, from fixed production sources."""

    fs = _real_filesystem()
    host_role = _load_fixed_host_role(fs)
    profile = _load_fixed_profile(fs)
    tls_material: ValidatedTLSMaterial | None = None
    ca_certificate_pem: bytes | None = None
    runtime_overlay: ValidatedRuntimeOverlay | None = None

    if operation == "install" and not profile.activation_enabled:
        identity = args.installation_identity
        if not isinstance(identity, str) or not _INSTALLATION_ID.fullmatch(identity):
            raise ActivationCLIError("installation_identity_invalid")
        preparation = prepare_local_evidence_key(fs, write=True, confirm=True)
        return SplitCliDependencies(
            host_role=host_role,
            profile=profile,
            evidence_key_preparation=preparation,
        )

    if host_role is LocalHostRole.controller:
        if operation in _CONTROLLER_IMPORT_TLS_OPERATIONS:
            tls_material = _load_import_tls(fs, profile)
        elif operation in _CONTROLLER_INSTALLED_TLS_OPERATIONS and not (
            operation == "status" and not profile.activation_enabled
        ):
            tls_material = _load_fixed_tls(fs, profile)
    elif operation in _WORKER_IMPORT_CA_OPERATIONS:
        ca_certificate_pem = _load_ca_bytes(fs, imported=True)
        if profile.activation_enabled:
            runtime_overlay = _load_import_runtime_overlay(fs, profile)
    elif operation in _WORKER_INSTALLED_CA_OPERATIONS and not (
        operation == "status" and not profile.activation_enabled
    ):
        ca_certificate_pem = _load_ca_bytes(fs, imported=False)

    if operation == "install":
        identity = args.installation_identity
        if not isinstance(identity, str) or not _INSTALLATION_ID.fullmatch(identity):
            raise ActivationCLIError("installation_identity_invalid")

    if operation in {"plan", "render"}:
        return SplitCliDependencies(
            host_role=host_role,
            profile=profile,
            tls_material=tls_material,
            ca_certificate_pem=ca_certificate_pem,
            runtime_overlay=runtime_overlay,
        )

    authenticator = LocalEvidenceAuthenticator(fs)
    runtime_binder = (
        authenticator.bind_runtime_configuration
        if profile.activation_enabled and operation in {"install", "verify", "status", "rollback"}
        else None
    )
    if host_role is LocalHostRole.controller:
        adapter = LocalActivationAdapter(
            host_role=host_role,
            runtime_configuration_binder=runtime_binder,
        )
        trust_root = (
            SHIPPED_EVIDENCE_TRUST_ROOT
            if operation == "inspect" or (operation == "status" and not profile.activation_enabled)
            else local_evidence_trust_root(fs)
        )
        controller = ControllerDependencies(
            adapter=adapter,
            handoff_signer=authenticator,
            evidence_authenticator=authenticator,
            evidence_trust_root=trust_root,
        )
        return SplitCliDependencies(
            host_role=host_role,
            profile=profile,
            controller_dependencies=controller,
            tls_material=tls_material,
        )
    state = RealWorkerStateFilesystem()
    adapter = LocalActivationAdapter(
        host_role=host_role,
        state_backend=state,
        runtime_configuration_binder=runtime_binder,
    )
    worker = WorkerDependencies(adapter=adapter, state=state, handoff_signer=authenticator)
    return SplitCliDependencies(
        host_role=host_role,
        profile=profile,
        worker_dependencies=worker,
        ca_certificate_pem=ca_certificate_pem,
    )


def _render_human(exit_code: int, payload: dict[str, object]) -> str:
    return (
        f"[{payload.get('operation', '?')}] exit={exit_code} "
        f"outcome={payload.get('outcome', '?')} "
        f"reason_code={payload.get('reason_code')} "
        f"recovery_required={payload.get('recovery_required')}\n"
    )


def main(argv: list[str] | None = None, deps: CliDependencies | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    exit_code, payload = run(args_list, deps=deps)
    if "--json" in args_list:
        sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    else:
        sys.stdout.write(_render_human(exit_code, payload))
    return exit_code


__all__ = [
    "ActivationCLIError",
    "CliDependencies",
    "EXIT_OK",
    "EXIT_REFUSED",
    "EXIT_RECOVERY_REQUIRED",
    "build_parser",
    "run",
    "main",
]
