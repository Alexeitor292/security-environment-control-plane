"""The expected authority for a discovery run, composed from durable rows and nothing else.

:func:`secp_api.discovery_verification.verify_discovery_snapshot` takes an expected worker
registration, an expected target, an expected organization, an expected operation and an expected
generation. Until this module existed, **every one of those came from a test**: nothing in
production built an :class:`ExpectedWorkerRegistration`, so the registered-anchor verification the
whole discovery chain terminates in had no way to be reached by a real run.

That is the failure mode this repository keeps producing — correct code reached by nothing — and it
is worse here than usual, because the code reached by nothing is the part that decides whether a
signed snapshot is trustworthy.

THREE INDEPENDENTLY CONTROLLED SOURCES
--------------------------------------
The expected authority is composed, never supplied. Each source is a different row with a different
lifecycle and a different approval path, and no caller contributes any of it:

``WorkerDiscoveryAdmission``   the durable AUTHORIZED OPERATION. It already carries organization,
                              execution target, discovery job (the operation identity), the
                              selected worker registration, the authorization it descends from,
                              both version numbers, a single-use nonce, an expiry and a closed
                              lifecycle status. It is the one row that says "this worker is
                              authorized to read this target, once, now".
``WorkerIdentityRegistration``   the durable WORKER REGISTRATION — the identity label, the
                              verification anchor fingerprint, the approval state and the expiry.
``WorkerEnrollmentState``     the durable RELEASE the enrolled worker is running.
:data:`REQUIRED_WORKER_ROLE`  the PROVIDER DISCOVERY CONTRACT's role constant.

The caller supplies one thing: the admission id. Everything else is read.

WHY THE ADMISSION ROW RATHER THAN A NEW TABLE
----------------------------------------------
A new "authorized discovery operation" table would be a second system for a fact this one already
records, and it would need a migration — which is approval-gated. ``WorkerDiscoveryAdmission``
already models exactly the seven attributes the composite authority needs, is already single-use,
already expires, and is already verified against the registration's pinned anchor before it reaches
``admitted``. Extending it is the repository's rule; duplicating it is the trap.

FAIL CLOSED, WITH A REASON THAT NAMES THE ROW
----------------------------------------------
Every refusal returns a closed reason code and no authority. There is no partial success and no
"assume valid" default. The reason codes distinguish the nine conditions the operator resolves
differently — a revoked registration is a different action from an expired admission, and
collapsing them into "unauthorized" is how an operator retries the wrong thing.

**This module reads. It never writes, never contacts anything, and holds no secret.** The
credential is an opaque reference resolved later, in the worker, and it does not pass through here.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api.discovery_verification import ExpectedWorkerRegistration
from secp_api.enums import (
    LiveReadAuthorizationStatus,
    WorkerDiscoveryAdmissionStatus,
    WorkerIdentityStatus,
)
from secp_api.models import (
    ExecutionTarget,
    LiveReadAuthorization,
    WorkerDiscoveryAdmission,
    WorkerIdentityRegistration,
)

#: Bound into nothing and signed by nothing — this is a loader version for operator legibility, so
#: a refusal can be attributed to a known composition rule.
DISCOVERY_AUTHORITY_LOADER_VERSION = "secp.discovery-authority-loader/v1"

#: Every way loading can fail, closed. Each names the ROW an operator must look at, because
#: "unauthorized" tells them to retry and these tell them what to fix.
AUTHORITY_REFUSAL_REASONS: tuple[str, ...] = (
    "discovery_admission_absent",
    "discovery_admission_wrong_organization",
    "discovery_admission_not_admitted",
    "discovery_admission_expired",
    "discovery_admission_purpose_mismatch",
    "discovery_worker_registration_absent",
    "discovery_worker_registration_not_approved",
    "discovery_worker_registration_expired",
    "discovery_worker_registration_wrong_organization",
    "discovery_worker_registration_version_superseded",
    "discovery_verification_anchor_absent",
    "discovery_worker_release_absent",
    "discovery_live_read_authorization_absent",
    "discovery_live_read_authorization_not_approved",
    "discovery_live_read_authorization_expired",
    "discovery_live_read_authorization_version_superseded",
    "discovery_execution_target_absent",
    "discovery_execution_target_wrong_organization",
    "discovery_credential_reference_absent",
)

#: The admission purpose this loader will compose an authority for. An admission minted for some
#: other purpose is refused rather than reused: a purpose is a separation boundary, not a label.
DISCOVERY_ADMISSION_PURPOSE = "proxmox_readonly_discovery"


class DiscoveryAuthorityRefused(Exception):
    """Loading refused. Carries ONE closed reason code and never a row's contents."""

    def __init__(self, reason: str) -> None:
        if reason not in AUTHORITY_REFUSAL_REASONS:
            # A reason outside the closed set would reach an operator surface unreviewed.
            raise ValueError(f"unknown discovery authority refusal reason: {reason!r}")
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class AuthorizedDiscoveryOperation:
    """The durable operation, read. Every field comes from a row; none from a caller.

    ``operation_generation`` is the admission's ``authorization_version`` — the version of the
    live-read authorization it descends from. A re-authorized target produces a new version, so a
    snapshot signed under the old one no longer binds, which is the property the generation exists
    for.
    """

    admission_id: uuid.UUID
    organization_identity: str
    target_identity: str
    operation_identity: str
    operation_generation: int
    worker_installation_id: str
    #: Opaque pointer. NEVER a secret, never hashed, never logged. Resolved only in the worker.
    credential_reference: str
    target_authority_identity: str


@dataclass(frozen=True)
class DiscoveryExpectedAuthority:
    """Everything ``verify_discovery_snapshot`` needs, and nothing a caller chose."""

    operation: AuthorizedDiscoveryOperation
    registration: ExpectedWorkerRegistration

    @property
    def required_worker_role(self) -> str:
        from secp_api.discovery_verification import REQUIRED_WORKER_ROLE

        return REQUIRED_WORKER_ROLE


def load_discovery_authority(
    session: Session,
    *,
    admission_id: uuid.UUID,
    organization_id: uuid.UUID,
    now: datetime | None = None,
) -> DiscoveryExpectedAuthority:
    """Compose the expected authority from durable rows, or refuse with a closed reason.

    ``organization_id`` is passed so the caller's scope is CHECKED against the row rather than
    derived from it. Deriving the organization from the row being authorized is how a cross-tenant
    admission id authorizes itself.
    """
    moment = now or datetime.now(UTC)

    admission = session.get(WorkerDiscoveryAdmission, admission_id)
    if admission is None:
        raise DiscoveryAuthorityRefused("discovery_admission_absent")
    if admission.organization_id != organization_id:
        raise DiscoveryAuthorityRefused("discovery_admission_wrong_organization")
    if admission.purpose != DISCOVERY_ADMISSION_PURPOSE:
        raise DiscoveryAuthorityRefused("discovery_admission_purpose_mismatch")
    if admission.status is not WorkerDiscoveryAdmissionStatus.admitted:
        # Deliberately exact rather than "not consumed": challenged, consumed, expired and revoked
        # are all refusals, and a future member must fail closed rather than fall through.
        raise DiscoveryAuthorityRefused("discovery_admission_not_admitted")
    if _aware(admission.expires_at) <= moment:
        raise DiscoveryAuthorityRefused("discovery_admission_expired")

    authorization = session.get(LiveReadAuthorization, admission.live_read_authorization_id)
    if authorization is None:
        raise DiscoveryAuthorityRefused("discovery_live_read_authorization_absent")
    if authorization.status is not LiveReadAuthorizationStatus.approved:
        raise DiscoveryAuthorityRefused("discovery_live_read_authorization_not_approved")
    if _aware(authorization.authorization_expiry) <= moment:
        raise DiscoveryAuthorityRefused("discovery_live_read_authorization_expired")
    if authorization.authorization_version != admission.authorization_version:
        # The admission names a version; the authorization has since been re-issued. The admission
        # authorizes the OLD one, so it authorizes nothing now.
        raise DiscoveryAuthorityRefused("discovery_live_read_authorization_version_superseded")

    target = session.get(ExecutionTarget, admission.execution_target_id)
    if target is None:
        raise DiscoveryAuthorityRefused("discovery_execution_target_absent")
    if target.organization_id != organization_id:
        raise DiscoveryAuthorityRefused("discovery_execution_target_wrong_organization")

    credential_reference = target.provider_plan_secret_ref or ""
    if not credential_reference.strip():
        # The DEDICATED read-only provider reference, never the generic ``secret_ref`` fallback.
        # The generic one exists for the Simulator and dev paths, and a live discovery run that
        # silently fell back to it would be reading a real target with a credential nobody
        # dedicated to the purpose.
        raise DiscoveryAuthorityRefused("discovery_credential_reference_absent")

    registration = session.get(WorkerIdentityRegistration, admission.worker_registration_id)
    if registration is None:
        raise DiscoveryAuthorityRefused("discovery_worker_registration_absent")
    if registration.organization_id != organization_id:
        raise DiscoveryAuthorityRefused("discovery_worker_registration_wrong_organization")
    if registration.status is not WorkerIdentityStatus.approved:
        raise DiscoveryAuthorityRefused("discovery_worker_registration_not_approved")
    if _aware(registration.expiry) <= moment:
        raise DiscoveryAuthorityRefused("discovery_worker_registration_expired")
    if registration.identity_version != admission.identity_version:
        raise DiscoveryAuthorityRefused("discovery_worker_registration_version_superseded")
    if not registration.verification_anchor_fingerprint.strip():
        raise DiscoveryAuthorityRefused("discovery_verification_anchor_absent")

    release = _release_digest(
        session,
        organization_id=organization_id,
        worker_installation_id=registration.identity_label,
    )
    if not release:
        raise DiscoveryAuthorityRefused("discovery_worker_release_absent")

    return DiscoveryExpectedAuthority(
        operation=AuthorizedDiscoveryOperation(
            admission_id=admission.id,
            organization_identity=str(admission.organization_id),
            target_identity=str(admission.execution_target_id),
            operation_identity=str(admission.discovery_job_id),
            operation_generation=int(admission.authorization_version),
            worker_installation_id=registration.identity_label,
            credential_reference=credential_reference,
            target_authority_identity=str(target.config.get("base_url", "")),
        ),
        registration=ExpectedWorkerRegistration(
            worker_installation_id=registration.identity_label,
            worker_release_fingerprint=release,
            verification_anchor_fingerprint=registration.verification_anchor_fingerprint,
            organization_identity=str(registration.organization_id),
        ),
    )


def _release_digest(
    session: Session, *, organization_id: uuid.UUID, worker_installation_id: str
) -> str:
    """The enrolled worker's release digest, from the enrollment state row.

    It lives on ``WorkerEnrollmentState`` rather than on the identity registration because the
    registration is a TRUST anchor and the enrollment is a DEPLOYMENT fact; they are approved
    separately and expire separately. Composing them here is the whole reason this loader exists.
    """
    # Imported inside the function: the enrollment models bind ``Base`` from ``models``, and a
    # module-level from-import of their class names only resolves when ``models`` happens to have
    # been imported first. The repository's own convention for this is a module import.
    from secp_api import worker_enrollment_models as enrollment

    row = (
        session.execute(
            select(enrollment.WorkerEnrollmentState)
            .where(enrollment.WorkerEnrollmentState.organization_id == organization_id)
            .where(
                enrollment.WorkerEnrollmentState.worker_installation_id == worker_installation_id
            )
            .order_by(enrollment.WorkerEnrollmentState.revision.desc())
        )
        .scalars()
        .first()
    )
    if row is None:
        return ""
    return str(row.release_digest or "")


def _aware(value: datetime) -> datetime:
    """Naive datetimes read back from SQLite are UTC. Comparing one to an aware ``now`` raises,
    and an exception here would read as a loader bug rather than as the refusal it is not."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
