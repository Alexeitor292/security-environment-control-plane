"""The supported worker installer for a Proxmox-adjacent Linux host (P1).

Turns the pieces already delivered on ``main`` — the sealed enrollment transport, the enrollment
driver, the protected key seam, the durable restart-state store and the host-local health probes —
into ONE supported operation an operator can run on a fresh VM or LXC in the management
environment, for either of the two logical worker roles in
:mod:`~secp_management.worker_roles`.

WHAT THIS MODULE ADDS, AND WHAT IT DELIBERATELY DOES NOT
--------------------------------------------------------
It adds the ORDER and the REFUSALS. It does not re-implement enrollment: the exchange is driven
through the existing :class:`~secp_management.enrollment_cli.WorkerEnroller` seam, which is already
worker-initiated, CA-pinned to the invitation, and authenticated by proof-of-possession. Nothing
here opens a socket, signs anything, or handles key material.

DIRECTION OF CONNECTION
-----------------------
The WORKER dials the controller. Every step below is either host-local or an outbound call made by
the enrollment transport; nothing in this installer listens, and no step requires an inbound
connection into the Proxmox management network. That is a property of the composition, not a
configuration option — there is no bind address to set.

ENROLLMENT MATERIAL
-------------------
:class:`InstallationRequest` carries the PATH to the invitation file and never its contents. The
material is short-lived, single-purpose, and is consumed only through the existing sealed transport.
It is therefore never a CLI argument, never in an environment variable, never in the plan, never in
the evidence record, and never in a report or a refusal — and :func:`validate_installation_request`
runs the shared forbidden-secret scanner over the request so a field that smuggles material in is
refused before anything runs.

THE ORDERING CONSTRAINT WORTH STATING
-------------------------------------
The service must be ACTIVE before enrollment can complete, because the health evidence the worker
signs is observed from a running service. That ordering creates the window this installer exists to
close: a host whose service is up and enabled but whose authenticated enrollment never succeeded is
a worker that will start polling at every boot while the controller has no verified identity for it.
:func:`install` therefore treats "service activated, enrollment did not reach healthy" as a FAILED
installation and rolls the service back — it is never reported as a partial success to be finished
later.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import NoReturn, Protocol

from secp_management import ManagementError
from secp_management.worker_roles import (
    WorkerRole,
    capabilities_for,
    parse_worker_role,
    require_role_capability_separation,
    resolve_role_queue,
)

# --- bounded grammars (identities and labels only; the request carries no secret-shaped field) ---
_INSTALLATION_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
_SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
_TARGET_ASSOCIATION = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_TRUST_ANCHOR_HEX = re.compile(r"^[0-9a-f]{64}$")  # raw Ed25519 public key, 32 bytes
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ABS_POSIX = re.compile(r"^/[^\x00\\]{1,255}$")

#: The closed set of worker planes. ``management`` is the Proxmox-adjacent management environment;
#: ``workload`` is a plane with no management-network reach. The set is closed so an unrecognised
#: plane refuses rather than being recorded verbatim into evidence.
WORKER_PLANES = ("management", "workload")

#: The state a completed enrollment drive must reach. Anything else is a failed installation.
_STATE_HEALTHY = "healthy"


class WorkerInstallerError(ManagementError):
    """A bounded installer refusal. Carries ONLY a reason code — never a path, origin, invitation
    field, queue name, credential, or raw upstream error."""


def _reject(reason_code: str) -> NoReturn:
    raise WorkerInstallerError(reason_code)


# --- the request -----------------------------------------------------------------------------


@dataclass(frozen=True)
class InstallationRequest:
    """Everything the operator supplies to install ONE worker. Secret-free by construction.

    ``invitation_file`` is a PATH. The enrollment material behind it is read only by the enrollment
    path, through the existing sealed transport — see the module docstring.
    """

    controller_origin: str
    installation_id: str
    release_digest: str
    role: WorkerRole
    worker_plane: str
    controller_trust_anchor_hex: str
    invitation_file: str
    service_name: str
    target_association: str | None = None


def validate_installation_request(request: object) -> InstallationRequest:
    """Validate a request into a bounded, secret-free :class:`InstallationRequest`.

    The forbidden-secret scan runs FIRST, so a secret-shaped field name or secret-material value is
    refused before any other field is looked at, and before the request reaches a plan, a report, or
    an evidence record.
    """
    if not isinstance(request, InstallationRequest):
        _reject("installer_request_invalid")

    _scan_request_for_secrets(request)

    role = parse_worker_role(request.role)
    require_role_capability_separation()

    if not (
        isinstance(request.controller_origin, str)
        and request.controller_origin.startswith("https://")
        and 9 < len(request.controller_origin) <= 255
    ):
        # https only: the worker's outbound leg is CA-pinned TLS and nothing else is acceptable
        _reject("installer_controller_origin_invalid")
    if not _matches(_INSTALLATION_ID, request.installation_id):
        _reject("installer_installation_id_invalid")
    if not _matches(_SHA256_DIGEST, request.release_digest):
        _reject("installer_release_digest_invalid")
    if not _matches(_TRUST_ANCHOR_HEX, request.controller_trust_anchor_hex):
        _reject("installer_trust_anchor_invalid")
    if not _matches(_ABS_POSIX, request.invitation_file):
        _reject("installer_invitation_path_invalid")
    if not _matches(_SERVICE_NAME, request.service_name):
        _reject("installer_service_name_invalid")
    if request.worker_plane not in WORKER_PLANES:
        _reject("installer_worker_plane_invalid")

    _validate_target_association(role, request.target_association)

    if (
        capabilities_for(role).infrastructure_mutation_credentials
        and request.worker_plane != "management"
    ):
        # the privileged role must reach the Proxmox API, which only the management plane can
        _reject("installer_role_plane_mismatch")

    return replace(request, role=role)


def _validate_target_association(role: WorkerRole, association: object) -> None:
    """A Proxmox target association is REQUIRED for the privileged role and FORBIDDEN for the
    ordinary one.

    The forbidden half is the one that matters. An ordinary worker carries no Proxmox credential, so
    associating it with a target cannot grant it reach — but it records an intent the separation
    denies, and an association is exactly the field a later change would read to decide what a
    worker may touch. Refusing it keeps the ordinary role's relationship to Proxmox absent rather
    than merely unused.
    """
    if capabilities_for(role).infrastructure_mutation_credentials:
        if not _matches(_TARGET_ASSOCIATION, association):
            _reject("installer_target_association_required")
    elif association is not None:
        _reject("installer_target_association_forbidden")


def _matches(pattern: re.Pattern[str], value: object) -> bool:
    return isinstance(value, str) and bool(pattern.match(value))


def _scan_request_for_secrets(request: InstallationRequest) -> None:
    """Run the shared commissioning forbidden-secret scanner over the request.

    Reused rather than reimplemented: the scanner is the same one the deployment profile and the
    independent trusted-pins file are held to, so "secret-free" means the same thing in all three
    places. A failure never echoes the offending key or value.
    """
    from secp_commissioning.descriptor import scan_forbidden

    payload = {
        "controller_origin": request.controller_origin,
        "installation_id": request.installation_id,
        "release_digest": request.release_digest,
        "role": getattr(request.role, "value", request.role),
        "worker_plane": request.worker_plane,
        "controller_trust_anchor_hex": request.controller_trust_anchor_hex,
        "invitation_file": request.invitation_file,
        "service_name": request.service_name,
        "target_association": request.target_association,
    }
    try:
        scan_forbidden(payload)
    except Exception:
        _reject("installer_request_forbidden_secret")


# --- host seams (shipped defaults are SEALED) --------------------------------------------------


class ServiceManager(Protocol):
    """The host service seam. Every method is host-local; none contacts the controller."""

    def install(self, service_name: str, *, role: str, task_queue: str) -> None: ...
    def enable(self, service_name: str) -> None: ...
    def is_active(self, service_name: str) -> bool: ...
    def disable(self, service_name: str) -> None: ...
    def restart(self, service_name: str) -> None: ...


class SealedServiceManager:
    """The shipped default: no host service manager is composed, so an installation cannot activate
    anything until a deployment wires a real one."""

    def __repr__(self) -> str:
        return "SealedServiceManager(<sealed>)"

    def install(self, service_name: str, *, role: str, task_queue: str) -> None:
        _reject("installer_service_manager_sealed")

    def enable(self, service_name: str) -> None:
        _reject("installer_service_manager_sealed")

    def is_active(self, service_name: str) -> bool:
        _reject("installer_service_manager_sealed")

    def disable(self, service_name: str) -> None:
        _reject("installer_service_manager_sealed")

    def restart(self, service_name: str) -> None:
        _reject("installer_service_manager_sealed")


class DurableIdentityStore(Protocol):
    """Persists the worker's NON-SECRET durable installation identity across restarts.

    It stores identities and digests only — never the invitation, an attestation, or key material.
    """

    def load(self) -> dict | None: ...
    def persist(self, record: dict) -> None: ...


class SealedDurableIdentityStore:
    """The shipped default: nothing can be persisted, so an installation refuses rather than
    completing without a durable identity."""

    def __repr__(self) -> str:
        return "SealedDurableIdentityStore(<sealed>)"

    def load(self) -> dict | None:
        return None

    def persist(self, record: dict) -> None:
        _reject("installer_identity_store_sealed")


class WorkerEnroller(Protocol):
    """The already-delivered worker-side enrollment seam (see
    :mod:`~secp_management.enrollment_cli`). Authenticated by proof-of-possession and the signed
    controller offer — never an operator token."""

    def enroll(
        self, invitation: dict, *, now: str, expected_controller_key_id: str | None = None
    ) -> dict: ...


class SealedWorkerEnroller:
    """The shipped default: no enrollment driver is wired, so an installation cannot report a
    worker as enrolled."""

    def __repr__(self) -> str:
        return "SealedWorkerEnroller(<sealed>)"

    def enroll(
        self, invitation: dict, *, now: str, expected_controller_key_id: str | None = None
    ) -> dict:
        _reject("installer_worker_enroller_sealed")


class InvitationLoader(Protocol):
    """Loads the bounded, NON-SECRET invitation fields from the invitation file path."""

    def load(self, path: str) -> dict: ...


class FileInvitationLoader:
    """The production loader — the SAME bounded, grammar-checked reader
    ``secpctl worker enroll`` uses, so the installer and the standalone enroll command can never
    disagree about what a valid invitation is."""

    def __repr__(self) -> str:  # never the invitation path
        return "FileInvitationLoader(<redacted>)"

    def load(self, path: str) -> dict:
        from secp_management.enrollment_cli import load_invitation_file

        return load_invitation_file(path)


@dataclass
class InstallerDeps:
    """Injected collaborators. Shipped defaults are SEALED; tests inject fakes; production composes
    the real host leaves through :func:`build_installer_deps`."""

    services: ServiceManager = field(default_factory=SealedServiceManager)
    identities: DurableIdentityStore = field(default_factory=SealedDurableIdentityStore)
    enroller: WorkerEnroller = field(default_factory=SealedWorkerEnroller)
    invitations: InvitationLoader = field(default_factory=FileInvitationLoader)
    now: Callable[[], str] = lambda: ""


# --- the plan (deterministic, secret-free, and what --dry-run reports) --------------------------


#: The ordered installation steps. The order is the contract: the trust checks all precede any host
#: mutation, so a request that would be refused never touches the host.
INSTALLATION_STEPS: tuple[str, ...] = (
    "validate_request",
    "load_invitation",
    "verify_controller_trust_anchor",
    "verify_installation_identity",
    "verify_release_digest",
    "verify_not_replayed",
    "persist_durable_identity",
    "install_service",
    "enable_service",
    "verify_service_health",
    "complete_enrollment",
    "record_installed_release_evidence",
    "verify_restart",
)

#: The steps that MUTATE the host. Everything before the first of these is a pure check, which is
#: what makes a refused installation leave no trace.
_MUTATING_STEPS = frozenset(
    {"persist_durable_identity", "install_service", "enable_service", "verify_restart"}
)


def plan_installation(
    request: InstallationRequest, *, ordinary_task_queue: str, operator_task_queue: str
) -> dict:
    """Build the deterministic, secret-free installation plan.

    Pure: validates the request and resolves the role's queue, and touches no host and no
    controller. This is what a dry run reports, so an operator sees the role, plane, queue and
    ordered steps BEFORE anything is installed. The invitation path is deliberately absent from the
    plan — the plan is quotable into a ticket.
    """
    validated = validate_installation_request(request)
    queue = resolve_role_queue(
        validated.role,
        ordinary_task_queue=ordinary_task_queue,
        operator_task_queue=operator_task_queue,
    )
    caps = capabilities_for(validated.role)
    return {
        "installation_id": validated.installation_id,
        "role": validated.role.value,
        "worker_plane": validated.worker_plane,
        "task_queue": queue,
        "service_name": validated.service_name,
        "release_digest": validated.release_digest,
        "target_association": validated.target_association,
        "capabilities": {
            "infrastructure_mutation_credentials": caps.infrastructure_mutation_credentials,
            "provisioning_execution": caps.provisioning_execution,
            "host_network_mutation": caps.host_network_mutation,
            "controlled_live_queue": caps.controlled_live_queue,
        },
        "steps": list(INSTALLATION_STEPS),
        "mutating_steps": sorted(_MUTATING_STEPS),
        "connection_direction": "worker_dials_controller",
    }


# --- the sequencer ------------------------------------------------------------------------------


def install(
    request: InstallationRequest,
    deps: InstallerDeps,
    *,
    ordinary_task_queue: str,
    operator_task_queue: str,
) -> dict:
    """Install and enroll ONE worker, failing closed at every step.

    Returns a bounded, secret-free installation record. Raises :class:`WorkerInstallerError` with a
    bounded reason code otherwise; when the failure happens after the service was activated, the
    service is rolled back BEFORE the refusal is raised.
    """
    plan = plan_installation(
        request,
        ordinary_task_queue=ordinary_task_queue,
        operator_task_queue=operator_task_queue,
    )
    validated = validate_installation_request(request)
    queue = plan["task_queue"]

    invitation = _load_invitation(deps, validated.invitation_file)
    _verify_controller_trust_anchor(validated, invitation)
    _verify_installation_identity(validated, invitation)
    _verify_release_digest(validated, invitation)
    enrollment_id = str(invitation["enrollment_id"])
    invitation_id = str(invitation["invitation_id"])
    _verify_not_replayed(deps, validated, enrollment_id, invitation_id)

    # --- first host mutation: nothing above this line has touched the host --------------------
    _persist_durable_identity(deps, validated, queue, enrollment_id, invitation_id)

    service = validated.service_name
    try:
        deps.services.install(service, role=validated.role.value, task_queue=queue)
        deps.services.enable(service)
    except WorkerInstallerError:
        raise
    except Exception:
        _reject("installer_service_install_failed")

    activated = _service_is_active(deps, service)
    if not activated:
        _rollback(deps, service)
        _reject("installer_service_not_active")

    # THE window this installer exists to close. The service is now up and enabled — it will poll
    # at every boot. If the authenticated exchange does not reach healthy, this host must not be
    # left in that state, so the service is rolled back and the installation is a FAILURE. It is
    # never reported as a partial success to be finished later.
    try:
        # The operator's out-of-band anchor, carried through to the worker's ownership gate. It was
        # already checked against the invitation at `_verify_controller_trust_anchor` above; passing
        # it on is what makes that check SURVIVE the install as a durable owner binding, instead of
        # protecting only this one run and then being forgotten.
        outcome = deps.enroller.enroll(
            invitation,
            now=deps.now(),
            expected_controller_key_id=_expected_controller_key_id(validated),
        )
    except Exception as exc:
        _rollback(deps, service)
        reason = getattr(exc, "reason_code", None)
        _reject(reason if isinstance(reason, str) else "installer_enrolled_service_unauthenticated")

    state = str(outcome.get("state")) if isinstance(outcome, dict) else ""
    if state != _STATE_HEALTHY:
        _rollback(deps, service)
        _reject("installer_enrolled_service_unauthenticated")

    record = _installed_release_evidence(validated, queue, enrollment_id, invitation_id, outcome)
    try:
        deps.identities.persist(record)
    except WorkerInstallerError:
        _rollback(deps, service)
        raise
    except Exception:
        _rollback(deps, service)
        _reject("installer_identity_not_durable")

    _verify_restart(deps, validated, service, enrollment_id)
    return record


def _load_invitation(deps: InstallerDeps, path: str) -> dict:
    try:
        invitation = deps.invitations.load(path)
    except ManagementError:
        raise
    except Exception as exc:
        reason = getattr(exc, "reason_code", None)
        _reject(reason if isinstance(reason, str) else "installer_invitation_unreadable")
    if not isinstance(invitation, dict):
        _reject("installer_invitation_unreadable")
    for key in (
        "enrollment_id",
        "invitation_id",
        "controller_installation_id",
        "controller_key_id",
        "release_digest",
    ):
        if not isinstance(invitation.get(key), str) or not invitation[key]:
            _reject("installer_invitation_unreadable")
    return invitation


def _expected_controller_key_id(request: InstallationRequest) -> str:
    """The operator-channel controller SIGNING key id.

    ``controller_trust_anchor_hex`` is a raw Ed25519 PUBLIC SIGNING key — see ``_TRUST_ANCHOR_HEX``
    and the ``key_id_for`` comparison below. It is deliberately NOT a TLS CA fingerprint, despite
    the field name, and the two must never be interchanged: one authenticates who signed the offer,
    the other authenticates who terminated the connection.
    """
    from secp_commissioning.enrollment_attestation import key_id_for

    return key_id_for(request.controller_trust_anchor_hex)


def _verify_controller_trust_anchor(request: InstallationRequest, invitation: dict) -> None:
    """The operator's EXPECTED controller trust anchor must derive the invitation's pinned key id.

    This is the check that makes the invitation hand-off channel non-load-bearing for controller
    identity. The invitation carries both the controller CA and the pinned controller key, so an
    attacker who substitutes the invitation substitutes both — and the worker would faithfully
    enroll to the impostor. The expected anchor arrives on a DIFFERENT channel (the operator typed
    or pasted it from an out-of-band source), so an invitation that does not match it is refused
    before the worker commits to anything.

    Derived with the same primitive the controller and the enrollment driver use, so the three
    cannot disagree about what a key id is.
    """
    from secp_commissioning.enrollment_attestation import key_id_for

    try:
        derived = key_id_for(request.controller_trust_anchor_hex)
    except Exception:
        _reject("installer_trust_anchor_invalid")
    if derived != invitation["controller_key_id"]:
        _reject("installer_trust_anchor_mismatch")


def _verify_installation_identity(request: InstallationRequest, invitation: dict) -> None:
    if invitation["controller_installation_id"] != request.installation_id:
        _reject("installer_installation_identity_mismatch")


def _verify_release_digest(request: InstallationRequest, invitation: dict) -> None:
    if invitation["release_digest"] != request.release_digest:
        _reject("installer_release_digest_mismatch")


def _verify_not_replayed(
    deps: InstallerDeps, request: InstallationRequest, enrollment_id: str, invitation_id: str
) -> None:
    """Refuse a REPLAYED enrollment locally, before the exchange is driven.

    The controller already treats an invitation as single-use, so this is a second, independent
    refusal rather than the only one — and it is the one that holds when the controller is the party
    being fooled. A durable record that names this invitation, or that names a DIFFERENT enrollment
    for this installation, means the material has already been spent here.
    """
    try:
        existing = deps.identities.load()
    except Exception:
        _reject("installer_identity_not_durable")
    if not isinstance(existing, dict):
        return
    if existing.get("invitation_id") == invitation_id:
        _reject("installer_enrollment_replayed")
    if existing.get("installation_id") == request.installation_id and existing.get(
        "enrollment_id"
    ) not in (None, enrollment_id):
        _reject("installer_enrollment_replayed")


def _persist_durable_identity(
    deps: InstallerDeps,
    request: InstallationRequest,
    queue: str,
    enrollment_id: str,
    invitation_id: str,
) -> None:
    """Persist the durable identity BEFORE the service is installed.

    Order matters: a host that cannot persist its identity must never reach the state where a
    service is enabled, because that worker would come back after a reboot with no durable record of
    what it is. The record is non-secret — identities, a digest and a queue name.
    """
    try:
        deps.identities.persist(
            {
                "installation_id": request.installation_id,
                "enrollment_id": enrollment_id,
                "invitation_id": invitation_id,
                "role": request.role.value,
                "worker_plane": request.worker_plane,
                "task_queue": queue,
                "release_digest": request.release_digest,
                "service_name": request.service_name,
                "target_association": request.target_association,
                "state": "installing",
            }
        )
    except WorkerInstallerError:
        raise
    except Exception:
        _reject("installer_identity_not_durable")


def _service_is_active(deps: InstallerDeps, service: str) -> bool:
    """Health verification. An unobservable service is NOT active — an unreadable state is never
    read as a healthy one."""
    try:
        return deps.services.is_active(service) is True
    except Exception:
        return False


def _rollback(deps: InstallerDeps, service: str) -> None:
    """Disable the service so a failed installation cannot leave a worker polling at boot.

    A rollback that itself fails is SWALLOWED deliberately: the caller is already refusing, and the
    reason the operator needs is the ORIGINAL failure, not the rollback's. Replacing it would hide
    why the installation failed behind a secondary symptom.
    """
    try:
        deps.services.disable(service)
    except Exception:
        return


def _installed_release_evidence(
    request: InstallationRequest,
    queue: str,
    enrollment_id: str,
    invitation_id: str,
    outcome: dict,
) -> dict:
    """The installed-release evidence record. Non-secret: identities, digests, a queue name and the
    controller-reported enrollment state. Never the invitation, an attestation, or key material."""
    caps = capabilities_for(request.role)
    return {
        "installation_id": request.installation_id,
        "enrollment_id": enrollment_id,
        "invitation_id": invitation_id,
        "role": request.role.value,
        "worker_plane": request.worker_plane,
        "task_queue": queue,
        "release_digest": request.release_digest,
        "service_name": request.service_name,
        "target_association": request.target_association,
        "state": _STATE_HEALTHY,
        "enrollment_state": str(outcome.get("state")),
        "enrollment_revision": outcome.get("revision"),
        "controlled_live_queue_consumer": caps.controlled_live_queue,
    }


def _verify_restart(
    deps: InstallerDeps, request: InstallationRequest, service: str, enrollment_id: str
) -> None:
    """Restart verification: the installation must survive a service restart.

    A worker that is healthy only until its first restart is not installed, it is running. This
    restarts the service, re-checks that it comes back active, and re-reads the durable identity to
    confirm the record that survived names THIS enrollment.
    """
    try:
        deps.services.restart(service)
    except WorkerInstallerError:
        raise
    except Exception:
        _reject("installer_restart_verification_failed")
    if not _service_is_active(deps, service):
        _reject("installer_restart_verification_failed")
    try:
        persisted = deps.identities.load()
    except Exception:
        _reject("installer_identity_not_durable")
    if not isinstance(persisted, dict):
        _reject("installer_identity_not_durable")
    if (
        persisted.get("enrollment_id") != enrollment_id
        or persisted.get("installation_id") != request.installation_id
        or persisted.get("role") != request.role.value
    ):
        _reject("installer_identity_not_durable")


# --- the secpctl command ------------------------------------------------------------------------


#: Installer reason codes that are not plain refusals, mapped onto the enrollment command's existing
#: exit categories so an operator scripting ``secpctl`` sees one consistent set.
def _exit_for(reason_code: str) -> int:
    from secp_management.enrollment_cli import (
        EXIT_CONTROLLER_UNAVAILABLE,
        EXIT_MALFORMED,
        EXIT_WORKER_HEALTH,
        exit_for,
    )
    from secp_management.transaction import EXIT_REFUSED

    specific = {
        "installer_enrolled_service_unauthenticated": EXIT_WORKER_HEALTH,
        "installer_service_not_active": EXIT_WORKER_HEALTH,
        "installer_restart_verification_failed": EXIT_WORKER_HEALTH,
        "installer_service_manager_sealed": EXIT_CONTROLLER_UNAVAILABLE,
        "installer_identity_store_sealed": EXIT_CONTROLLER_UNAVAILABLE,
        "installer_worker_enroller_sealed": EXIT_CONTROLLER_UNAVAILABLE,
        "installer_invitation_unreadable": EXIT_MALFORMED,
    }
    if reason_code in specific:
        return specific[reason_code]
    # fall through to the enrollment table so a driver/transport code keeps ITS category, and an
    # unknown code is a plain refusal rather than being rounded to a success
    mapped = exit_for(reason_code)
    return mapped if mapped != EXIT_REFUSED else EXIT_REFUSED


def worker_install(
    request: InstallationRequest,
    deps: InstallerDeps,
    *,
    ordinary_task_queue: str,
    operator_task_queue: str,
    gate: object,
) -> tuple[int, dict]:
    """``secpctl worker install`` — install and enroll this worker; dry run unless
    ``--write --confirm``.

    The dry run is a real check, not a stub: it validates the request, proves the role's queue is
    separated, and reports the ordered plan — so an operator sees exactly what would be installed,
    and a request that would be refused is refused, without the host being touched.
    """
    from secp_management.transaction import EXIT_OK

    command = "worker install"
    try:
        plan = plan_installation(
            request,
            ordinary_task_queue=ordinary_task_queue,
            operator_task_queue=operator_task_queue,
        )
        if not getattr(gate, "is_write", False):
            return EXIT_OK, {"command": command, "mode": "dry_run", "plan": plan}
        record = install(
            request,
            deps,
            ordinary_task_queue=ordinary_task_queue,
            operator_task_queue=operator_task_queue,
        )
        return EXIT_OK, {"command": command, "mode": "written", "installation": record}
    except ManagementError as exc:
        return _exit_for(exc.reason_code), {
            "command": command,
            "reason_code": exc.reason_code,
        }


def build_installer_deps(enroller: WorkerEnroller | None = None) -> InstallerDeps:
    """Compose the installer over the real worker enroller, leaving the HOST seams sealed.

    The service manager and durable identity store are deliberately still sealed here: both mutate a
    POSIX host, and neither has a reviewed real adapter in this slice. Composing a half-real
    installer that silently no-ops its host steps would report a successful installation on a host
    where nothing was installed — the failure this codebase has repeatedly paid for. Sealed, the
    command refuses with ``installer_service_manager_sealed``, which is honest.
    """
    import datetime as _dt

    from secp_management.worker_enroller import build_worker_enroller

    return InstallerDeps(
        enroller=enroller if enroller is not None else build_worker_enroller(),
        now=lambda: _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
    )


def build_supported_installer_deps(enroller: WorkerEnroller | None = None) -> InstallerDeps:
    """Compose the installer over the REAL host adapters, on a host that supports them.

    This is the composition :func:`build_installer_deps` deliberately would not make while the host
    seams had no reviewed adapter. It is a SEPARATE function rather than a change to that one so the
    sealed default keeps its meaning exactly: anything that composes ``build_installer_deps`` still
    gets sealed host seams and still refuses ``installer_service_manager_sealed``.

    On an unsupported host it refuses ``installer_host_platform_unsupported`` — the platform, named
    directly — instead of falling back to the sealed deps and reporting a seal that is not the real
    reason. Both are refusals; only one is diagnostic.
    """
    from secp_management.worker_service_adapters import build_posix_installer_deps

    return build_posix_installer_deps(enroller)


__all__ = [
    "INSTALLATION_STEPS",
    "WORKER_PLANES",
    "DurableIdentityStore",
    "FileInvitationLoader",
    "InstallationRequest",
    "InstallerDeps",
    "InvitationLoader",
    "SealedDurableIdentityStore",
    "SealedServiceManager",
    "SealedWorkerEnroller",
    "ServiceManager",
    "WorkerEnroller",
    "WorkerInstallerError",
    "build_installer_deps",
    "build_supported_installer_deps",
    "install",
    "plan_installation",
    "validate_installation_request",
    "worker_install",
]
