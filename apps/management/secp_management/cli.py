"""``secpctl`` — the customer-facing management-plane installer CLI (SECP-PR5E).

Command surface (there is deliberately NO ``activate``/``apply``/``destroy``/``proxmox``/``ssh``/
``exec``/``shell``)::

    secpctl release verify --bundle DIR
    secpctl host inspect
    secpctl bootstrap controller|worker --bundle DIR   [--write --confirm]
    secpctl adopt     controller|worker --bundle DIR    [--write --confirm]
    secpctl status    controller|worker
    secpctl evidence  controller|worker
    secpctl rollback  controller|worker                 [--write --confirm]
    secpctl auth      login|refresh|logout              [--write --confirm]
    secpctl auth      status
    secpctl worker    install --role ordinary|infrastructure_operator ... [--write --confirm]

``worker install`` is the supported single operation for a Proxmox-adjacent worker host. It takes
the invitation by PATH (never the enrollment material itself), installs the service for ONE of the
two logical roles bound to that role's OWN task queue, and drives the authenticated enrollment —
rolling the service back if it activates but enrollment does not reach healthy.

Every mutation defaults to DRY-RUN; a real write requires BOTH ``--write`` and ``--confirm``.
``--json``
prints deterministic JSON. Human-readable and JSON output execute the SAME engine — the CLI only
chooses formatting. There is NO arbitrary Python dependency injection through CLI arguments; the
only
path argument is the read-only offline release-bundle source.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

from secp_management import ManagementError
from secp_management.auth_cli import (
    AuthCliDeps,
    auth_login,
    auth_logout,
    auth_refresh,
    auth_status,
)
from secp_management.engine import (
    EngineDeps,
    adopt,
    bootstrap,
    controller_install,
    host_inspect,
    read_evidence,
    release_verify,
    status,
)
from secp_management.engine import rollback as engine_rollback
from secp_management.enrollment_cli import (
    EnrollmentCliDeps,
    enrollment_revoke,
    enrollment_status,
    invite_create,
    worker_enroll,
    worker_ownership_reset,
    worker_retry,
    worker_status,
)
from secp_management.transaction import EXIT_REFUSED, WriteGate
from secp_management.worker_installer import WORKER_PLANES
from secp_management.worker_roles import WorkerRole

_ROLES = ("controller", "worker")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secpctl",
        description=(
            "SECP management-plane installer (SECP-PR5E). Local-first, human-supervised. No "
            "activate/apply/destroy/proxmox/ssh/exec/shell command; mutations default to dry-run "
            "and require --write --confirm."
        ),
    )
    parser.add_argument("--json", action="store_true", help="deterministic machine-readable output")
    groups = parser.add_subparsers(dest="group", required=True)

    rel = groups.add_parser("release", help="release bundle operations").add_subparsers(
        dest="action", required=True
    )
    rv = rel.add_parser("verify", help="verify a signed offline release bundle (read-only)")
    rv.add_argument("--bundle", required=True, help="path to the offline release bundle directory")

    host = groups.add_parser("host", help="host operations").add_subparsers(
        dest="action", required=True
    )
    host.add_parser("inspect", help="read-only local host inspection")

    for verb, helptext, wc, bundle in (
        ("bootstrap", "local bootstrap of a role", True, True),
        ("adopt", "safe adoption of an existing installation", True, True),
        ("status", "revalidating status of a role", False, False),
        ("evidence", "read + revalidate stored evidence", False, False),
        ("rollback", "remove only objects created by the bootstrap transaction", True, False),
    ):
        sub = groups.add_parser(verb, help=helptext)
        sub.add_argument("role", choices=_ROLES)
        if bundle:
            sub.add_argument("--bundle", required=True, help="offline release bundle directory")
        if wc:
            sub.add_argument(
                "--write", action="store_true", help="perform writes (default: dry-run)"
            )
            sub.add_argument("--confirm", action="store_true", help="confirm a real write")

    _add_controller_parser(groups)
    _add_enrollment_parser(groups)
    _add_worker_parser(groups)
    _add_auth_parser(groups)
    return parser


def _add_auth_parser(groups) -> None:
    """``secpctl auth login|status|refresh|logout`` — operator authentication by OAuth 2.0 Device
    Authorization Grant (RFC 8628), per ADR-028 §3. There is NO ``--issuer``/``--client-id``/
    ``--endpoint``/``--token``/``--password`` argument: the reviewed authority is discovered from
    the bootstrap-recorded controller, and no password is ever collected. There is likewise no
    ``--account``/``--controller`` argument — the credential account is DERIVED from the recorded
    controller locator, so a command can never be pointed at another controller's credential.
    ``login``, ``refresh`` and ``logout`` mutate credential state and keep the standard dry-run
    default; ``status`` is read-only."""
    auth = groups.add_parser("auth", help="operator authentication operations")
    actions = auth.add_subparsers(dest="action", required=True)
    _add_write_confirm(
        actions.add_parser("login", help="authenticate this operator via device authorization")
    )
    actions.add_parser("status", help="read-only local credential status")
    _add_write_confirm(
        actions.add_parser("refresh", help="renew this controller's stored operator credential")
    )
    _add_write_confirm(
        actions.add_parser("logout", help="delete only the credential material secpctl owns")
    )


def _add_controller_parser(groups) -> None:
    """``secpctl controller install`` — the supported root-only controller-enrollment installation
    (SECP-PR5H-B2 2b-3c). It takes ONLY the two reviewed operator facts (``--public-origin``,
    ``--tls-mode``) plus the hardened ``--bundle``; there is NO ``--url``/``--ca``/``--key``/
    ``--credential``/``--dsn``/``--path``/``--command``. ``--write --confirm`` are mandatory for a
    real install; the default is a dry-run plan. Its deps resolve through the root-gated install
    composition; every steady-state command keeps finalization sealed."""
    controller = groups.add_parser("controller", help="controller installation operations")
    actions = controller.add_subparsers(dest="action", required=True)
    install = actions.add_parser(
        "install", help="install controller enrollment finalization (POSIX root only)"
    )
    install.add_argument("--bundle", required=True, help="offline release bundle directory")
    install.add_argument(
        "--public-origin", required=True, help="controller canonical public HTTPS origin"
    )
    install.add_argument("--tls-mode", required=True, help="policy-permitted controller TLS mode")
    _add_write_confirm(install)


def _add_write_confirm(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--write", action="store_true", help="perform writes (default: dry-run)")
    parser.add_argument("--confirm", action="store_true", help="confirm a real write")


def _add_enrollment_parser(groups) -> None:
    """``secpctl enrollment invite create|status|revoke`` — the supported controller enrollment
    commands, operated ONLY over the controller HTTPS API. No ``--url``/``--ca``/``--token`` and no
    internal CAS coordinate (state_digest/sequence/predecessor_digest) is ever accepted."""
    enr = groups.add_parser("enrollment", help="worker-enrollment controller operations")
    actions = enr.add_subparsers(dest="action", required=True)

    invite = actions.add_parser("invite", help="invitation operations").add_subparsers(
        dest="invite_action", required=True
    )
    create = invite.add_parser("create", help="create a single-use worker-enrollment invitation")
    create.add_argument("--site", required=True, help="opaque deployment-site label")
    create.add_argument(
        "--ttl-seconds", type=int, default=3600, help="invitation lifetime in seconds"
    )
    _add_write_confirm(create)

    st = actions.add_parser("status", help="read the bounded public enrollment status")
    st.add_argument("--enrollment-id", required=True, help="the enrollment id from the invitation")

    revoke = actions.add_parser("revoke", help="revoke an enrollment")
    revoke.add_argument("--enrollment-id", required=True, help="the enrollment id to revoke")
    revoke.add_argument(
        "--expected-revision", type=int, required=True, help="the last observed public revision"
    )
    _add_write_confirm(revoke)


def _add_worker_parser(groups) -> None:
    """``secpctl worker enroll|enrollment status|retry`` — the worker side of the exchange, driven
    from the non-secret invitation FILE and authenticated by worker proof-of-possession + the signed
    controller offer (NEVER the operator OIDC token)."""
    worker = groups.add_parser("worker", help="worker-side enrollment operations")
    actions = worker.add_subparsers(dest="action", required=True)

    enroll = actions.add_parser("enroll", help="drive this worker's enrollment to healthy")
    enroll.add_argument(
        "--invitation", required=True, help="path to the non-secret invitation file"
    )
    enroll.add_argument(
        "--controller-trust-anchor",
        help="the EXPECTED controller signing key (raw Ed25519 public key hex), obtained "
        "out of band. An UNOWNED worker requires it: the invitation supplies the origin, "
        "the key id AND the CA together, so a substituted invitation is internally "
        "consistent and only a fact that did NOT travel with it can detect one. An "
        "already-owned worker checks its pinned owner instead and ignores this.",
    )
    _add_write_confirm(enroll)

    # ``install`` is the SUPPORTED single operation for a Proxmox-adjacent worker host: it installs
    # the service for ONE of the two logical roles and drives the authenticated enrollment, failing
    # closed (and rolling the service back) if the service activates but enrollment does not. The
    # enrollment material is referenced by PATH only — it is never a command-line argument, so it
    # never reaches shell history or the process table.
    inst = actions.add_parser("install", help="install + enroll this worker for one role")
    inst.add_argument("--invitation", required=True, help="path to the non-secret invitation file")
    inst.add_argument(
        "--role", required=True, choices=[r.value for r in WorkerRole], help="the worker role"
    )
    inst.add_argument("--plane", required=True, choices=list(WORKER_PLANES))
    inst.add_argument("--installation-id", required=True)
    inst.add_argument("--controller-origin", required=True)
    inst.add_argument(
        "--controller-trust-anchor",
        required=True,
        help="the EXPECTED controller trust anchor (raw Ed25519 public key hex), obtained "
        "out of band; an invitation that does not match it is refused",
    )
    inst.add_argument("--release-digest", required=True)
    inst.add_argument("--service-name", required=True)
    inst.add_argument("--ordinary-queue", required=True, help="the ordinary worker task queue")
    inst.add_argument(
        "--operator-queue", required=True, help="the controlled-live operator task queue"
    )
    inst.add_argument(
        "--target-association",
        default=None,
        help="Proxmox target association; REQUIRED for the operator role, refused for the ordinary",
    )
    _add_write_confirm(inst)

    enrollment = actions.add_parser(
        "enrollment", help="worker enrollment status/retry"
    ).add_subparsers(dest="worker_action", required=True)
    ownership = actions.add_parser(
        "ownership", help="worker controller-ownership operations (LOCAL only)"
    ).add_subparsers(dest="worker_action", required=True)
    wreset = ownership.add_parser(
        "reset",
        help="release this worker from its controller so another may claim it (LOCAL, destructive)",
    )
    _add_write_confirm(wreset)

    wst = enrollment.add_parser("status", help="read-only local reconciliation")
    wst.add_argument("--invitation", required=True, help="path to the non-secret invitation file")
    wretry = enrollment.add_parser("retry", help="resume-safe re-drive")
    wretry.add_argument(
        "--invitation", required=True, help="path to the non-secret invitation file"
    )
    wretry.add_argument(
        "--controller-trust-anchor",
        help="the EXPECTED controller signing key (raw Ed25519 public key hex), obtained "
        "out of band. An UNOWNED worker requires it: the invitation supplies the origin, "
        "the key id AND the CA together, so a substituted invitation is internally "
        "consistent and only a fact that did NOT travel with it can detect one. An "
        "already-owned worker checks its pinned owner instead and ignores this.",
    )
    _add_write_confirm(wretry)


def _gate(args: argparse.Namespace) -> WriteGate:
    return WriteGate(
        write=bool(getattr(args, "write", False)), confirm=bool(getattr(args, "confirm", False))
    )


_ENROLLMENT_GROUPS = ("enrollment", "worker")


def _is_enrollment_group(argv: list[str]) -> bool:
    for token in argv:
        if token.startswith("-"):
            continue
        return token in _ENROLLMENT_GROUPS
    return False


def _is_auth_group(argv: list[str]) -> bool:
    for token in argv:
        if token.startswith("-"):
            continue
        return token == "auth"
    return False


def run(
    argv: list[str],
    deps: EngineDeps | None = None,
    *,
    enrollment_deps: EnrollmentCliDeps | None = None,
    auth_deps: AuthCliDeps | None = None,
) -> tuple[int, dict]:
    """Parse ``argv`` and execute the engine. Returns ``(exit_code, report_dict)``.

    ``deps=None`` builds a SEALED :class:`EngineDeps` (every adapter fails closed) — it is NOT the
    production path. The supported production composition lives in :func:`main`, which passes an
    explicitly-composed ``deps`` (steady-state :func:`_production_engine_deps`, or — Phase 2b — the
    clean-host root installation composition), falling back to this sealed default on any error.
    Tests inject their own ``deps`` directly. The enrollment/worker commands take a separate
    :class:`EnrollmentCliDeps` (SEALED default; tests inject fakes; ``main`` composes the real), and
    the auth commands a separate :class:`AuthCliDeps` whose credential store is likewise SEALED."""
    args = build_parser().parse_args(argv)
    resolved = deps if deps is not None else EngineDeps()
    enr = enrollment_deps if enrollment_deps is not None else EnrollmentCliDeps()
    auth = auth_deps if auth_deps is not None else AuthCliDeps()
    try:
        return _dispatch(args, resolved, enr, auth)
    except ManagementError as exc:  # any uncaught engine refusal → bounded reason, exit 2
        return EXIT_REFUSED, {"command": args.group, "reason_code": exc.reason_code}


def _dispatch(
    args: argparse.Namespace, deps: EngineDeps, enr: EnrollmentCliDeps, auth: AuthCliDeps
) -> tuple[int, dict]:
    group = args.group
    if group == "release":
        return release_verify(args.bundle, deps)
    if group == "host":
        return host_inspect(deps)
    if group == "bootstrap":
        return bootstrap(args.role, args.bundle, _gate(args), deps)
    if group == "adopt":
        return adopt(args.role, args.bundle, _gate(args), deps)
    if group == "status":
        return status(args.role, deps)
    if group == "evidence":
        return read_evidence(args.role, deps)
    if group == "rollback":
        return engine_rollback(args.role, _gate(args), deps)
    if group == "controller":
        if args.action == "install":
            return controller_install(
                args.public_origin, args.tls_mode, args.bundle, _gate(args), deps
            )
        return EXIT_REFUSED, {"command": "controller", "reason_code": "unknown_command"}
    if group == "enrollment":
        return _dispatch_enrollment(args, enr)
    if group == "worker":
        return _dispatch_worker(args, enr)
    if group == "auth":
        return _dispatch_auth(args, auth)
    return EXIT_REFUSED, {"command": group, "reason_code": "unknown_command"}


def _dispatch_auth(args: argparse.Namespace, auth: AuthCliDeps) -> tuple[int, dict]:
    if args.action == "login":
        return auth_login(auth, gate=_gate(args))
    if args.action == "status":
        return auth_status(auth)
    if args.action == "refresh":
        return auth_refresh(auth, gate=_gate(args))
    if args.action == "logout":
        return auth_logout(auth, gate=_gate(args))
    return EXIT_REFUSED, {"command": "auth", "reason_code": "unknown_command"}


def _dispatch_worker(args: argparse.Namespace, enr: EnrollmentCliDeps) -> tuple[int, dict]:
    if args.action == "install":
        return _dispatch_worker_install(args, enr)
    if args.action == "enroll":
        return worker_enroll(
            enr,
            invitation_file=args.invitation,
            gate=_gate(args),
            controller_trust_anchor_hex=args.controller_trust_anchor,
        )
    if args.action == "ownership" and args.worker_action == "reset":
        return worker_ownership_reset(enr, gate=_gate(args))
    if args.action == "enrollment" and args.worker_action == "status":
        return worker_status(enr, invitation_file=args.invitation)
    if args.action == "enrollment" and args.worker_action == "retry":
        return worker_retry(
            enr,
            invitation_file=args.invitation,
            gate=_gate(args),
            controller_trust_anchor_hex=args.controller_trust_anchor,
        )
    return EXIT_REFUSED, {"command": "worker", "reason_code": "unknown_command"}


def _dispatch_worker_install(args: argparse.Namespace, enr: EnrollmentCliDeps) -> tuple[int, dict]:
    """Build the installation request from parsed arguments and run the installer.

    The request is built here and validated inside the installer — never partially validated in the
    parser, so one module owns every refusal.

    The host seams are composed from the REVIEWED POSIX adapters
    (:mod:`~secp_management.worker_service_adapters`), so ``--write --confirm`` performs a real
    installation on a supported host. On an unsupported host it refuses
    ``installer_host_platform_unsupported`` — named directly — rather than reporting an install that
    did not happen. A dry run never reaches this composition at all: ``worker_install`` returns the
    plan before touching ``deps``, so ``secpctl worker install`` still plans on any platform.
    """
    from secp_management.worker_installer import (
        InstallationRequest,
        _exit_for,
        build_installer_deps,
        build_supported_installer_deps,
        worker_install,
    )

    request = InstallationRequest(
        controller_origin=args.controller_origin,
        installation_id=args.installation_id,
        release_digest=args.release_digest,
        role=args.role,
        worker_plane=args.plane,
        controller_trust_anchor_hex=args.controller_trust_anchor,
        invitation_file=args.invitation,
        service_name=args.service_name,
        target_association=args.target_association,
    )
    gate = _gate(args)
    # A DRY RUN must plan on ANY platform, so it is given the sealed deps — ``worker_install``
    # returns the plan before it touches them. Composing the real host adapters here instead would
    # make ``secpctl worker install`` (no ``--write``) raise on an unsupported host, turning a pure,
    # host-free planning command into a platform-dependent one.
    try:
        deps = (
            build_supported_installer_deps(enr.worker_enroller)
            if getattr(gate, "is_write", False)
            else build_installer_deps(enr.worker_enroller)
        )
    except ManagementError as exc:
        # a composition refusal (unsupported platform, missing root-controlled production inputs)
        # is mapped through the installer's OWN exit table, so an operator scripting secpctl sees
        # one consistent set of categories whether the refusal came from composition or from a step
        return _exit_for(exc.reason_code), {
            "command": "worker install",
            "reason_code": exc.reason_code,
        }
    return worker_install(
        request,
        deps,
        ordinary_task_queue=args.ordinary_queue,
        operator_task_queue=args.operator_queue,
        gate=gate,
    )


def _dispatch_enrollment(args: argparse.Namespace, enr: EnrollmentCliDeps) -> tuple[int, dict]:
    if args.action == "invite" and args.invite_action == "create":
        return invite_create(
            enr, deployment_site_label=args.site, ttl_seconds=args.ttl_seconds, gate=_gate(args)
        )
    if args.action == "status":
        return enrollment_status(enr, enrollment_id=args.enrollment_id)
    if args.action == "revoke":
        return enrollment_revoke(
            enr,
            enrollment_id=args.enrollment_id,
            expected_revision=args.expected_revision,
            gate=_gate(args),
        )
    return EXIT_REFUSED, {"command": "enrollment", "reason_code": "unknown_command"}


def _production_enrollment_deps() -> EnrollmentCliDeps:
    """Compose the real controller client from the bootstrap-recorded locator + the protected
    operator token (POSIX/production). Any construction failure falls back to the SEALED default, so
    an unconfigured or non-POSIX host fails closed with a bounded code rather than crashing."""
    try:
        import os

        from secp_commissioning.runtime import RealFilesystem

        from secp_management.controller_api_locator import FileControllerApiLocatorProvider
        from secp_management.enrollment_cli import LocatorControllerCaBundleProvider
        from secp_management.enrollment_controller_client import HttpsEnrollmentControllerClient
        from secp_management.operator_auth import (
            OPERATOR_TOKEN_FILE_ENV,
            ProtectedTokenFileProvider,
        )
        from secp_management.operator_credential_store import (
            ControllerScopedCredentialProvider,
            build_operator_credential_store,
        )

        fs = RealFilesystem()
        # ONE locator instance, shared by the client, the credential provider AND the controller-CA
        # provider, so the credential read is scoped to exactly the controller the request is sent
        # to, and the CA chain put into the invitation is the one this client pinned its TLS to.
        # A SECOND FileControllerApiLocatorProvider(fs) here would type-check, satisfy "a real
        # provider is composed", and still be the defect: two instances can resolve two different
        # locators, handing the worker a chain the operator's own client never trusted.
        locator_provider = FileControllerApiLocatorProvider(fs)
        # The OS credential store is the PRIMARY provider: what `secpctl auth login` writes is what
        # authenticated commands read. Before this wiring existed the two never met — login stored a
        # credential nothing consumed, leaving the plaintext token FILE as the only working path.
        #
        # The token file remains reachable ONLY when the operator explicitly sets the env var. That
        # is an opt-in recovery seam, never an automatic fallback: when it is unset the credential
        # store is used, and a store that cannot reach a keystore REFUSES rather than degrading to a
        # file (`operator_auth` and `operator_credential_store` both state this rule).
        token_path = os.environ.get(OPERATOR_TOKEN_FILE_ENV, "")
        token_provider = (
            ProtectedTokenFileProvider(token_path)
            if token_path
            else ControllerScopedCredentialProvider(
                build_operator_credential_store(), locator_provider
            )
        )
        client = HttpsEnrollmentControllerClient(
            locator_provider=locator_provider,
            token_provider=token_provider,
        )
        from secp_management.worker_enroller import build_worker_enroller

        return EnrollmentCliDeps(
            controller_client=client,
            worker_enroller=build_worker_enroller(),
            # Sourced from the operator's OWN bootstrap-recorded locator, never from the controller
            # API's response — a controller serving its own CA is circular. Without this the field
            # falls to SealedControllerCaBundleProvider and every `enrollment invite create` refuses
            # secpctl_controller_ca_unavailable, i.e. the CA distribution feature ships inert.
            ca_bundle=LocatorControllerCaBundleProvider(fs, locator_provider),
        )
    # Same rule as `_production_auth_deps`: an environmental failure seals, a coding defect -- or a
    # test tripwire installed on a seam inside this region -- is loud.
    except (NameError, AttributeError, ImportError, AssertionError):
        raise
    except Exception:  # noqa: BLE001 - fail closed to the sealed default; commands refuse, bounded
        return EnrollmentCliDeps()


def _production_auth_deps() -> AuthCliDeps:
    """Compose the operator-auth deps: the real bootstrap-recorded controller locator plus the
    credential store from :func:`build_operator_credential_store`.

    That builder resolves the platform's OS keystore (Windows Credential Manager, macOS Keychain,
    or the freedesktop Secret Service) or, when none is reachable, the SEALED store; ``auth login``
    then refuses before starting a grant and never falls back to plaintext. The protected token-file
    selection is likewise composed independently.

    The root-owned locator has a narrower platform surface than those credential providers. If its
    hardened filesystem cannot be constructed (notably on Windows), ONLY the locator is sealed:
    locator-dependent commands still refuse, while pre-bootstrap ``auth status`` can truthfully
    report the selected credential backend and token provider. A live Windows Credential Manager
    report is therefore backend assurance, not a production Windows controller-trust claim. The MVP
    production posture is trusted POSIX/controller-local; Windows requires a separately reviewed
    locator + CA provisioning workflow. No identity, endpoint or trust input is read from a flag or
    an env var."""
    import os

    from secp_commissioning.runtime import FilesystemError, RealFilesystem

    from secp_management.controller_api_locator import (
        ControllerApiLocatorError,
        ControllerApiLocatorProvider,
        FileControllerApiLocatorProvider,
        SealedControllerApiLocatorProvider,
    )
    from secp_management.operator_auth import (
        OPERATOR_TOKEN_FILE_ENV,
        OperatorAccessTokenProvider,
        ProtectedTokenFileProvider,
        SealedOperatorAccessTokenProvider,
    )
    from secp_management.operator_credential_store import build_operator_credential_store

    credential_store = build_operator_credential_store()

    # Snapshot one selection for both the report probe and the provider status will actually read.
    # Constructing a protected provider validates only the path; no file/token I/O occurs until
    # `auth status` resolves the selected active principal.
    token_path = os.environ.get(OPERATOR_TOKEN_FILE_ENV, "")
    token_file_provider: OperatorAccessTokenProvider = SealedOperatorAccessTokenProvider()
    token_file_state: bool | None = False
    if token_path:
        try:
            token_file_provider = ProtectedTokenFileProvider(token_path)
        except ManagementError:
            token_file_state = None
        else:
            token_file_state = True

    locator_provider: ControllerApiLocatorProvider = SealedControllerApiLocatorProvider()
    # A coding defect must be LOUD, never a silent locator degradation. Only the bounded
    # filesystem/locator refusals at this construction boundary become a sealed locator.
    try:
        locator_provider = FileControllerApiLocatorProvider(RealFilesystem())
    except (FilesystemError, ControllerApiLocatorError):
        # These are the two bounded environmental contracts at this construction boundary. Anything
        # else is a programming/packaging defect and must remain loud.
        pass

    return AuthCliDeps(
        credential_store=credential_store,
        locator_provider=locator_provider,
        # The env read lives HERE, beside the composition it governs — `auth_cli` must never touch
        # the environment. `auth status` reports the result so an operator can see that a token file
        # is overriding the keystore they just logged in to.
        token_file_active=lambda: token_file_state,
        token_file_provider=token_file_provider,
    )


def _controller_install_engine_deps() -> EngineDeps | None:
    """Compose the ROOT-ONLY controller-install deps (the ONLY composition that reaches the real
    finalization factory). It is gated POSIX-root up front (``assert_posix_root`` inside
    ``controller_install_engine_deps``) and falls back to the SEALED default on any error, so a
    non-root/non-POSIX/unprovisioned host fails closed with a bounded reason. No adapter/factory is
    ever selected by a flag, environment variable, or import."""
    try:
        from secp_management.production import controller_install_engine_deps

        return controller_install_engine_deps()
    except Exception:  # noqa: BLE001 - fail closed to the sealed default; the command refuses
        return None


def _is_controller_install_group(argv: list[str]) -> bool:
    positionals = [a for a in argv if not a.startswith("-")]
    return len(positionals) >= 2 and positionals[0] == "controller" and positionals[1] == "install"


def _production_engine_deps() -> EngineDeps | None:
    """Compose the production management-engine deps from the fixed root-controlled bootstrap inputs
    (SECP-PR5H-B2). This is the supported production CLI entrypoint's composition: it wires the real
    hardened adapters so ``secpctl bootstrap/adopt/status/evidence/rollback`` act on a real host.

    Any missing / unsafe / mismatched / non-production input (e.g. an unprovisioned or non-POSIX
    host) falls back to the SEALED default (``None`` → ``run`` builds a sealed ``EngineDeps()``), so
    the command fails closed with a bounded reason code rather than crashing or acting on an
    unverified adapter. No adapter is ever selected by a CLI flag, environment variable, or import —
    ``production_engine_deps`` reads only the fixed code-owned inputs."""
    try:
        from secp_management.production import production_engine_deps

        return production_engine_deps()
    except Exception:  # noqa: BLE001 - fail closed to the sealed default; the command refuses, bounded
        return None


#: A bounded reason token: lowercase, underscore-separated, length-capped. Anything failing this is
#: replaced wholesale rather than trimmed — a partial match is how a path fragment gets through.
_REASON_TOKEN = re.compile(r"[a-z][a-z0-9_]{3,63}")

#: The token emitted when an unexpected failure escapes the command surface.
INTERNAL_ERROR_REASON = "secpctl_internal_error"


def _bounded_failure_reason(exc: BaseException) -> str:
    """A bounded reason token for an unexpected failure — NEVER the exception's message.

    The message is precisely where the dangerous content lives: an ``ImportError`` carries a module
    path, an ``OSError`` an absolute filesystem path, and either can name a deployment's layout on
    an operator's terminal. Only a ``ManagementError``'s own ``reason_code`` is eligible, and only
    if it matches the bounded grammar; everything else collapses to a single fixed token.
    """
    reason = getattr(exc, "reason_code", None)
    if isinstance(reason, str) and _REASON_TOKEN.fullmatch(reason):
        return reason
    return INTERNAL_ERROR_REASON


def main(argv: list[str] | None = None) -> int:
    """The process entrypoint. Every failure leaves as a bounded report and an exit code.

    ``SystemExit`` and ``KeyboardInterrupt`` deliberately propagate — argparse's ``--help``/usage
    exits and an operator's Ctrl-C are not failures to be rendered.
    """
    args_list = list(sys.argv[1:] if argv is None else argv)
    try:
        return _dispatch_main(args_list)
    except Exception as exc:  # noqa: BLE001 - bounded token, never a traceback, never the message
        # `_production_*_deps` now let programming and packaging errors propagate rather than
        # silently sealing (which is right — a silent seal is invisible). But loud must not mean a
        # raw traceback on a customer-facing installer: an operator on a partial install used to
        # get a bounded code and now must still get one. This is the boundary that guarantees it.
        payload = {"command": "secpctl", "reason_code": _bounded_failure_reason(exc)}
        _emit(args_list, EXIT_REFUSED, payload)
        return EXIT_REFUSED


def _emit(args_list: list[str], exit_code: int, payload: dict) -> None:
    if "--json" in args_list:
        sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    else:
        sys.stdout.write(_render_human(exit_code, payload))


def _dispatch_main(args_list: list[str]) -> int:
    # the enrollment/worker groups get the production controller-client composition; every OTHER
    # (engine) group gets the production management-engine deps. BOTH fall back to their SEALED
    # default on any error, so an unprovisioned/non-POSIX host still fails closed with a bounded
    # reason (unchanged) while a properly provisioned production host drives the real adapters.
    is_enrollment = _is_enrollment_group(args_list)
    is_auth = _is_auth_group(args_list)
    enr = _production_enrollment_deps() if is_enrollment else None
    # the auth group composes ONLY the locator + credential store; it never builds an engine, so a
    # login can never reach a filesystem/service mutation adapter.
    auth = _production_auth_deps() if is_auth else None
    if is_enrollment or is_auth:
        deps = None
    elif _is_controller_install_group(args_list):
        # the ONLY path that reaches the real finalization factory (root-gated); steady-state groups
        # stay on the finalization-SEALED steady-state composition.
        deps = _controller_install_engine_deps()
    else:
        deps = _production_engine_deps()
    exit_code, payload = run(args_list, deps=deps, enrollment_deps=enr, auth_deps=auth)
    if "--json" in args_list:
        sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    else:
        sys.stdout.write(_render_human(exit_code, payload))
    return exit_code


#: Fields shown FIRST, in this order, because they are the ones an operator scans for.
_HUMAN_LEADING_KEYS = ("role", "mode", "status", "ok", "trusted", "reason_code")

#: Report fields that carry a WARNING an operator must not miss, and the text for each. A report
#: field alone is not a warning: it prints among a dozen others and reads as noise.
_HUMAN_WARNINGS: dict[str, dict[object, str]] = {
    "token_file_override_active": {
        True: (
            "NOTE: SECP_OPERATOR_TOKEN_FILE is set, so authenticated commands use that FILE\n"
            "  and not the OS keystore. A successful 'auth login' will not change which token\n"
            "  they send."
        )
    },
    "active_token_provider": {
        "unknown": (
            "NOTE: which token provider authenticated commands will use could not be\n"
            "  determined (deps did not compose, or the probe failed). This is NOT a statement\n"
            "  that the OS keystore is live."
        )
    },
    "token_still_live": {
        True: (
            "WARNING: logout is INCOMPLETE; at least one known credential may still be live at\n"
            "  the identity provider. 'removed' describes only owned OS-keystore cleanup; a\n"
            "  configured token file is never deleted or rewritten."
        )
    },
}


def _human_scalar(value: str | int | float | bool | None) -> str:
    """Render one scalar without allowing its bytes to control the terminal.

    Removing JSON's surrounding quotes preserves the established ``key=value`` layout while
    retaining JSON's deterministic escaping of quotes, backslashes, C0/C1 controls, and every
    non-ASCII code point (including bidi controls).  Consequently an untrusted scalar remains on
    one physical report line and cannot manufacture a second ``[command] exit=...`` record.
    """
    if isinstance(value, str):
        encoded = json.dumps(value, ensure_ascii=True)
        return encoded[1:-1]
    return str(value)


def _render_human(exit_code: int, payload: dict) -> str:
    """Render a report for a terminal.

    Every scalar field is printed. This deliberately does NOT use a fixed allowlist: one used to
    live here, and it silently swallowed ``token_still_live`` — so ``auth logout`` printed
    ``exit=0 mode=written`` while the token was still valid at the issuer, and ``auth status``
    reported no credential state at all. A renderer that drops fields it was not told about turns
    every new report field into an invisible one, which is exactly the failure a bounded,
    secret-free report format exists to make impossible. Reports are bounded and carry no secrets by
    construction, so printing all of them is both safe and the honest default.

    **That property is now load-bearing for every command group, not just ``auth``**, because fields
    that previously appeared only under ``--json`` now print by default. It is enforced two ways in
    ``test_auth_cli``: live invocations are rendered and scanned for secret-shaped VALUES, and every
    report-producing module is scanned for secret-shaped FIELD NAMES. The second is the one that
    holds the line — it is host-independent and fails in the file another stream would have to edit.

    **A deliberate asymmetry, decided rather than inherited.** The auth surface reduces the
    credential ACCOUNT to a non-reversing fingerprint, while enrollment reports print
    ``controller_origin`` in the clear. That is not an oversight and the two are not the same kind
    of fact. The credential account is metadata ABOUT A HELD SECRET — it says which controller this
    operator has a working credential for, which is exactly what an attacker reading a pasted ticket
    would want. ``controller_origin`` is a deployment address the operator supplied themselves and
    can read out of their own configuration; it identifies a service, not a secret anyone holds.
    Fingerprinting the first and not the second is therefore consistent, and the guard above is what
    keeps the line where it was drawn. Neither is a secret, and nothing here prints one.

    Scalar strings are JSON-escaped without their surrounding quotes. This keeps the familiar
    ``key=value`` form for ordinary ASCII while ensuring provider-, controller-, or operator-derived
    text cannot emit terminal controls or forge an additional physical report line. Warning text is
    code-owned and deliberately remains multiline.
    """
    command_value = payload.get("command", "?")
    command = (
        _human_scalar(command_value)
        if command_value is None or isinstance(command_value, (str, int, float, bool))
        else "?"
    )
    parts = [f"[{command}] exit={exit_code}"]
    shown = {"command"}
    for key in _HUMAN_LEADING_KEYS:
        if key in payload:
            value = payload[key]
            if value is None or isinstance(value, (str, int, float, bool)):
                parts.append(f"{_human_scalar(key)}={_human_scalar(value)}")
            shown.add(key)
    for key in sorted(payload):
        if key in shown:
            continue
        value = payload[key]
        # Only scalars render as `key=value`; a nested structure belongs in `--json`.
        if value is None or isinstance(value, (str, int, float, bool)):
            parts.append(f"{_human_scalar(key)}={_human_scalar(value)}")

    line = " ".join(str(p) for p in parts)
    warnings = [
        text
        for key, by_value in _HUMAN_WARNINGS.items()
        for trigger, text in by_value.items()
        if key in payload and payload[key] == trigger and type(payload[key]) is type(trigger)
    ]
    for text in warnings:
        line += f"\n  {text}"
    return line + "\n"
