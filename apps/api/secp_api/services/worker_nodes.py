"""SECP-B8 — worker discovery node public-key publication service.

A worker generates + OWNS its SSH and Ed25519 admission keypairs (see the worker-side
``bundle_manager``). It publishes ONLY the PUBLIC halves here so the bootstrap wizard can
auto-populate the "Worker SSH public key" field (the operator never runs ``ssh-keygen``) and the
operator can register/approve the worker identity from the published anchor.

Hard invariants preserved:
  * This surface NEVER accepts or stores a private key. Every publication path runs the input
    through :func:`validate_public_ssh_key` (which rejects ``BEGIN ... PRIVATE KEY`` material and
    any non-public-key line) and requires a 32-byte (64 hex char) Ed25519 anchor.
  * It grants nothing: a published node is a convenience registry row. Live discovery still requires
    a separately-approved worker identity + live-read authorization + a valid mounted bundle.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.discovery_bootstrap_contract import (
    BootstrapContractError,
    validate_public_ssh_key,
)
from secp_api.enums import (
    AuditAction,
    Permission,
    WorkerIdentityEvidenceKind,
    WorkerIdentityEvidenceStatus,
    WorkerIdentityMechanism,
    WorkerIdentityStatus,
)
from secp_api.errors import DomainError, NotFoundError
from secp_api.models import (
    Organization,
    WorkerDiscoveryNode,
    WorkerIdentityEvidence,
    WorkerIdentityRegistration,
)
from secp_api.worker_identity_contract import (
    WorkerIdentityMetadataError,
    compute_verification_anchor_fingerprint,
    compute_worker_identity_evidence_fingerprint,
    validate_deployment_binding,
    validate_evidence_metadata,
)

_ANCHOR_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_NODE_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")


class WorkerNodePublicationError(DomainError):
    """A worker-node publication failure. Message carries only a closed reason (no secret/raw)."""

    http_status = 422
    code = "invalid_worker_node_publication"


def _fail(message: str) -> WorkerNodePublicationError:
    return WorkerNodePublicationError(message)


def _validated_public_material(
    ssh_public_key: str, admission_anchor_hex: str
) -> tuple[str, str, str, str]:
    """Validate + normalize the PUBLIC material. Returns
    (ssh_public_key, ssh_fingerprint, anchor_hex, anchor_fingerprint). Fails closed on a private key
    or malformed anchor — a private key never reaches the database."""
    try:
        normalized_ssh, ssh_fp = validate_public_ssh_key(ssh_public_key)
    except BootstrapContractError as exc:
        raise _fail(f"ssh_public_key rejected: {exc.reason_code}") from None
    anchor = (admission_anchor_hex or "").strip().lower()
    if not _ANCHOR_HEX_RE.match(anchor):
        raise _fail("admission_anchor must be a 32-byte (64 hex char) Ed25519 public anchor")
    anchor_fp = compute_verification_anchor_fingerprint(anchor)
    return normalized_ssh, ssh_fp, anchor, anchor_fp


def _link_identity_if_current(
    session: Session,
    *,
    node_id: uuid.UUID,
    organization_id: uuid.UUID,
    expected_anchor_fingerprint: str,
    expected_revision: int,
    registration_id: uuid.UUID,
) -> bool:
    """CAS the identity link only while the exact public-key publication is still current."""

    result = session.execute(
        update(WorkerDiscoveryNode)
        .where(
            WorkerDiscoveryNode.id == node_id,
            WorkerDiscoveryNode.organization_id == organization_id,
            WorkerDiscoveryNode.admission_anchor_fingerprint == expected_anchor_fingerprint,
            WorkerDiscoveryNode.revision == expected_revision,
        )
        .values(worker_identity_registration_id=registration_id)
        .returning(WorkerDiscoveryNode.id)
    ).scalar_one_or_none()
    return result == node_id


def _unlink_terminal_identity_if_current(
    session: Session,
    *,
    node_id: uuid.UUID,
    organization_id: uuid.UUID,
    expected_anchor_fingerprint: str,
    expected_revision: int,
    expected_registration_id: uuid.UUID,
) -> bool:
    """CAS-clear only the exact reviewed stale link; publication revision/key remain unchanged."""

    result = session.execute(
        update(WorkerDiscoveryNode)
        .where(
            WorkerDiscoveryNode.id == node_id,
            WorkerDiscoveryNode.organization_id == organization_id,
            WorkerDiscoveryNode.admission_anchor_fingerprint == expected_anchor_fingerprint,
            WorkerDiscoveryNode.revision == expected_revision,
            WorkerDiscoveryNode.worker_identity_registration_id == expected_registration_id,
        )
        .values(worker_identity_registration_id=None)
        .returning(WorkerDiscoveryNode.id)
    ).scalar_one_or_none()
    return result == node_id


def publish_worker_node(
    session: Session,
    *,
    organization_id: uuid.UUID,
    node_label: str,
    ssh_public_key: str,
    admission_anchor_hex: str,
    created_by: uuid.UUID | None = None,
) -> WorkerDiscoveryNode:
    """Upsert a worker node's PUBLIC key material for an organization. System/worker-facing (no
    principal): callers that cross a trust boundary (the API router) MUST enforce permission + org
    themselves first. Idempotent per (organization, node_label): re-publishing updates the row."""
    if not (isinstance(node_label, str) and _NODE_LABEL_RE.match(node_label)):
        raise _fail("node_label is invalid")
    ssh_pub, ssh_fp, anchor_hex, anchor_fp = _validated_public_material(
        ssh_public_key, admission_anchor_hex
    )
    row = session.execute(
        select(WorkerDiscoveryNode)
        .where(
            WorkerDiscoveryNode.organization_id == organization_id,
            WorkerDiscoveryNode.node_label == node_label,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if row is None:
        row = WorkerDiscoveryNode(
            organization_id=organization_id,
            node_label=node_label,
            ssh_public_key=ssh_pub,
            ssh_public_key_fingerprint=ssh_fp,
            admission_anchor_hex=anchor_hex,
            admission_anchor_fingerprint=anchor_fp,
            revision=1,
            worker_identity_registration_id=None,
            created_by=created_by,
        )
        session.add(row)
        changed = True
    else:
        changed = bool(
            row.ssh_public_key != ssh_pub
            or row.ssh_public_key_fingerprint != ssh_fp
            or row.admission_anchor_hex != anchor_hex
            or row.admission_anchor_fingerprint != anchor_fp
        )
        if changed:
            row.ssh_public_key = ssh_pub
            row.ssh_public_key_fingerprint = ssh_fp
            row.admission_anchor_hex = anchor_hex
            row.admission_anchor_fingerprint = anchor_fp
            row.revision = int(row.revision) + 1
            # A registration pinned to the prior admission anchor must never survive key rotation.
            row.worker_identity_registration_id = None
    session.flush()
    if not changed:
        return row
    audit.record(
        session,
        action=AuditAction.worker_discovery_node_published,
        resource_type="worker_discovery_node",
        resource_id=row.id,
        organization_id=organization_id,
        actor=str(created_by) if created_by else "worker",
        data={"node_label": node_label, "ssh_public_key_fingerprint": ssh_fp},
    )
    return row


def _link_worker_node_identity(
    session: Session,
    actor: Principal,
    *,
    node_id: uuid.UUID,
    registration_id: uuid.UUID,
    expected_node_revision: int,
    expected_ssh_public_key_fingerprint: str,
    expected_admission_anchor_fingerprint: str,
    expected_deployment_binding: str,
    expected_proof_id: str,
    expected_issuer: str,
) -> WorkerDiscoveryNode:
    """Internal-only link primitive for the reviewed composite transaction.

    It independently rechecks the separate approval permission, exact node label, reviewed
    deployment binding, complete evidence set + bound fingerprint, mechanism, anchor, and expiry.
    There is deliberately no direct HTTP route to this primitive.
    """
    actor.require(Permission.target_discovery_manage)
    actor.require(Permission.worker_identity_manage)
    actor.require(Permission.worker_identity_approve)
    node = session.execute(
        select(WorkerDiscoveryNode)
        .where(WorkerDiscoveryNode.id == node_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if node is None:
        raise NotFoundError("worker_discovery_node_not_found")
    actor.require_org(node.organization_id)
    if (
        node.revision != expected_node_revision
        or node.ssh_public_key_fingerprint != expected_ssh_public_key_fingerprint
        or node.admission_anchor_fingerprint != expected_admission_anchor_fingerprint
    ):
        raise _fail("worker node publication changed; reload and review it again")
    registration = session.execute(
        select(WorkerIdentityRegistration)
        .where(
            WorkerIdentityRegistration.id == registration_id,
            WorkerIdentityRegistration.organization_id == node.organization_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if registration is None:
        raise _fail("worker identity registration is unavailable")
    expiry = registration.expiry
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)
    if registration.status != WorkerIdentityStatus.approved or expiry <= datetime.now(UTC):
        raise _fail("worker identity registration is not approved and current")
    if registration.mechanism != WorkerIdentityMechanism.ed25519_signed_nonce:
        raise _fail("worker identity mechanism is not Ed25519 signed nonce")
    if registration.identity_label != node.node_label:
        raise _fail("worker identity label does not match the published node")
    if registration.deployment_binding != expected_deployment_binding:
        raise _fail("worker identity deployment binding does not match the reviewed binding")
    if registration.verification_anchor_fingerprint != node.admission_anchor_fingerprint:
        raise _fail("worker identity anchor does not match the published node")
    if not _identity_review_evidence_matches(
        session,
        registration,
        proof_id=expected_proof_id,
        issuer=expected_issuer,
    ):
        raise _fail("worker identity evidence does not match the reviewed evidence")
    if node.worker_identity_registration_id == registration.id:
        return node
    expected_anchor = node.admission_anchor_fingerprint
    expected_revision = node.revision
    if not _link_identity_if_current(
        session,
        node_id=node.id,
        organization_id=node.organization_id,
        expected_anchor_fingerprint=expected_anchor,
        expected_revision=expected_revision,
        registration_id=registration.id,
    ):
        raise _fail("worker node changed during identity link")
    session.flush()
    session.refresh(node)
    audit.record(
        session,
        action=AuditAction.worker_discovery_node_identity_linked,
        resource_type="worker_discovery_node",
        resource_id=node.id,
        organization_id=node.organization_id,
        actor=str(actor.user_id),
        data={
            "worker_identity_registration_id": str(registration.id),
            "worker_identity_version": registration.identity_version,
            "node_revision": node.revision,
        },
    )
    return node


def _identity_review_evidence_matches(
    session: Session,
    registration: WorkerIdentityRegistration,
    *,
    proof_id: str,
    issuer: str,
) -> bool:
    rows = list(
        session.execute(
            select(WorkerIdentityEvidence).where(
                WorkerIdentityEvidence.registration_id == registration.id
            )
        ).scalars()
    )
    by_kind = {row.kind: row for row in rows}
    return bool(
        registration.approved_by is not None
        and registration.approved_at is not None
        and registration.evidence_fingerprint == compute_worker_identity_evidence_fingerprint(rows)
        and len(rows) == len(WorkerIdentityEvidenceKind)
        and all(
            kind in by_kind
            and by_kind[kind].status == WorkerIdentityEvidenceStatus.verified
            and by_kind[kind].proof_id == proof_id
            and by_kind[kind].issuer == issuer
            for kind in WorkerIdentityEvidenceKind
        )
    )


def approve_and_link_worker_node_identity(
    session: Session,
    actor: Principal,
    *,
    node_id: uuid.UUID,
    expected_node_revision: int,
    expected_ssh_public_key_fingerprint: str,
    expected_admission_anchor_fingerprint: str,
    deployment_binding: str,
    proof_id: str,
    issuer: str,
    deployment_binding_review_confirmed: bool,
    verification_anchor_review_confirmed: bool,
    rotation_revocation_review_confirmed: bool,
) -> WorkerDiscoveryNode:
    """Compose the existing identity lifecycle into one explicit operator transaction.

    Publication grants nothing. The caller must hold discovery management, identity management,
    and the deliberately separate identity approval permission. All three evidence reviews must be
    explicitly confirmed. An exact current approved registration is reused only when its bound
    metadata and complete evidence rows match this request. A same-label current registration for
    an old anchor is revoked only after the explicit rotation review. An exact link to a terminal
    expired/revoked Ed25519 registration may be CAS-cleared and replaced under that same review;
    drafts, live mismatches, and every ambiguous state fail closed.
    """
    from secp_api.services import worker_identity

    actor.require(Permission.target_discovery_manage)
    actor.require(Permission.worker_identity_manage)
    actor.require(Permission.worker_identity_approve)
    if any(
        confirmed is not True
        for confirmed in (
            deployment_binding_review_confirmed,
            verification_anchor_review_confirmed,
            rotation_revocation_review_confirmed,
        )
    ):
        raise _fail("all worker identity reviews must be explicitly confirmed")
    try:
        validate_deployment_binding(deployment_binding)
        validate_evidence_metadata(proof_id=proof_id, issuer=issuer)
    except WorkerIdentityMetadataError:
        raise _fail("worker identity review metadata is invalid") from None

    node = session.execute(
        select(WorkerDiscoveryNode)
        .where(WorkerDiscoveryNode.id == node_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if node is None:
        raise NotFoundError("worker_discovery_node_not_found")
    actor.require_org(node.organization_id)
    if (
        node.revision != expected_node_revision
        or node.ssh_public_key_fingerprint != expected_ssh_public_key_fingerprint
        or node.admission_anchor_fingerprint != expected_admission_anchor_fingerprint
    ):
        raise _fail("worker node publication changed; reload and review it again")

    linked_registration: WorkerIdentityRegistration | None = None
    if node.worker_identity_registration_id is not None:
        linked_registration = session.execute(
            select(WorkerIdentityRegistration)
            .where(
                WorkerIdentityRegistration.id == node.worker_identity_registration_id,
                WorkerIdentityRegistration.organization_id == node.organization_id,
                WorkerIdentityRegistration.identity_label == node.node_label,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if linked_registration is None:
            raise _fail("worker node carries a stale or ambiguous identity link")

    active_registrations = list(
        session.execute(
            select(WorkerIdentityRegistration)
            .where(
                WorkerIdentityRegistration.organization_id == node.organization_id,
                WorkerIdentityRegistration.identity_label == node.node_label,
                WorkerIdentityRegistration.status.in_(
                    (WorkerIdentityStatus.draft, WorkerIdentityStatus.approved)
                ),
            )
            .order_by(WorkerIdentityRegistration.identity_version.desc())
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalars()
    )
    now = datetime.now(UTC)
    if any(
        row.mechanism != WorkerIdentityMechanism.ed25519_signed_nonce
        and (
            row.status == WorkerIdentityStatus.draft
            or (
                row.status == WorkerIdentityStatus.approved
                and (
                    row.expiry if row.expiry.tzinfo is not None else row.expiry.replace(tzinfo=UTC)
                )
                > now
            )
        )
        for row in active_registrations
    ):
        # A signed-nonce rotation must never revoke or reinterpret another authentication
        # mechanism that happens to use the same label.
        raise _fail("an active non-Ed25519 worker identity already uses this node label")
    registrations = [
        row
        for row in active_registrations
        if row.mechanism == WorkerIdentityMechanism.ed25519_signed_nonce
    ]
    if any(row.status == WorkerIdentityStatus.draft for row in registrations):
        raise _fail("a draft worker identity already exists for this node")

    def linked_is_terminal(row: WorkerIdentityRegistration) -> bool:
        expiry = row.expiry if row.expiry.tzinfo is not None else row.expiry.replace(tzinfo=UTC)
        return row.status in {
            WorkerIdentityStatus.expired,
            WorkerIdentityStatus.revoked,
        } or (row.status == WorkerIdentityStatus.approved and expiry <= now)

    def clear_terminal_link(row: WorkerIdentityRegistration) -> None:
        if row.mechanism != WorkerIdentityMechanism.ed25519_signed_nonce or not linked_is_terminal(
            row
        ):
            raise _fail("worker node carries a stale or ambiguous identity link")
        if not _unlink_terminal_identity_if_current(
            session,
            node_id=node.id,
            organization_id=node.organization_id,
            expected_anchor_fingerprint=node.admission_anchor_fingerprint,
            expected_revision=node.revision,
            expected_registration_id=row.id,
        ):
            raise _fail("worker node changed during identity renewal")
        session.flush()
        session.refresh(node)

    current_approved = []
    for row in registrations:
        expiry = row.expiry if row.expiry.tzinfo is not None else row.expiry.replace(tzinfo=UTC)
        if row.status == WorkerIdentityStatus.approved and expiry > now:
            current_approved.append(row)
    if len(current_approved) > 1:
        raise _fail("worker identity state is ambiguous")

    existing = current_approved[0] if current_approved else None
    if existing is not None:
        exact = bool(
            existing.mechanism == WorkerIdentityMechanism.ed25519_signed_nonce
            and existing.deployment_binding == deployment_binding
            and existing.verification_anchor_fingerprint == node.admission_anchor_fingerprint
            and _identity_review_evidence_matches(
                session, existing, proof_id=proof_id, issuer=issuer
            )
        )
        if exact:
            if node.worker_identity_registration_id not in (None, existing.id):
                if linked_registration is None:
                    raise _fail("worker node identity link is ambiguous")
                clear_terminal_link(linked_registration)
            return _link_worker_node_identity(
                session,
                actor,
                node_id=node.id,
                registration_id=existing.id,
                expected_node_revision=expected_node_revision,
                expected_ssh_public_key_fingerprint=expected_ssh_public_key_fingerprint,
                expected_admission_anchor_fingerprint=expected_admission_anchor_fingerprint,
                expected_deployment_binding=deployment_binding,
                expected_proof_id=proof_id,
                expected_issuer=issuer,
            )
        if node.worker_identity_registration_id is not None:
            raise _fail("worker node carries a stale or ambiguous identity link")
        if existing.verification_anchor_fingerprint == node.admission_anchor_fingerprint:
            raise _fail("approved worker identity does not exactly match this review")
        # The request's required literal-true confirmation is also checked above for direct service
        # callers. Only this exact same-label, old-anchor case is eligible for explicit revocation.
        worker_identity.revoke_worker_identity(
            session,
            actor,
            existing.id,
            reason_code="worker_anchor_rotated",
        )

    if node.worker_identity_registration_id is not None:
        linked = linked_registration
        if linked is None:
            raise _fail("worker node carries a stale or ambiguous identity link")
        clear_terminal_link(linked)

    if node.worker_identity_registration_id is not None:
        raise _fail("worker node carries a stale or ambiguous identity link")

    registration = worker_identity.register_worker_identity(
        session,
        actor,
        mechanism=WorkerIdentityMechanism.ed25519_signed_nonce,
        identity_label=node.node_label,
        deployment_binding=deployment_binding,
        verification_anchor_fingerprint=node.admission_anchor_fingerprint,
    )
    for kind in WorkerIdentityEvidenceKind:
        worker_identity.record_evidence(
            session,
            actor,
            registration.id,
            kind=kind,
            status=WorkerIdentityEvidenceStatus.verified,
            proof_id=proof_id,
            issuer=issuer,
        )
    approved = worker_identity.approve_worker_identity(session, actor, registration.id)
    return _link_worker_node_identity(
        session,
        actor,
        node_id=node.id,
        registration_id=approved.id,
        expected_node_revision=expected_node_revision,
        expected_ssh_public_key_fingerprint=expected_ssh_public_key_fingerprint,
        expected_admission_anchor_fingerprint=expected_admission_anchor_fingerprint,
        expected_deployment_binding=deployment_binding,
        expected_proof_id=proof_id,
        expected_issuer=issuer,
    )


def register_worker_node(
    session: Session,
    actor: Principal,
    *,
    node_label: str,
    ssh_public_key: str,
    admission_anchor_hex: str,
) -> WorkerDiscoveryNode:
    """Operator-facing publication (requires ``target_discovery:manage``, scoped to the actor org).
    A private key is rejected before anything is written."""
    actor.require(Permission.target_discovery_manage)
    return publish_worker_node(
        session,
        organization_id=actor.organization_id,
        node_label=node_label,
        ssh_public_key=ssh_public_key,
        admission_anchor_hex=admission_anchor_hex,
        created_by=actor.user_id,
    )


def list_worker_nodes(session: Session, actor: Principal) -> list[WorkerDiscoveryNode]:
    actor.require(Permission.target_discovery_manage)
    return list(
        session.execute(
            select(WorkerDiscoveryNode)
            .where(WorkerDiscoveryNode.organization_id == actor.organization_id)
            .order_by(WorkerDiscoveryNode.created_at.desc())
        ).scalars()
    )


def get_worker_node(session: Session, actor: Principal, node_id: uuid.UUID) -> WorkerDiscoveryNode:
    actor.require(Permission.target_discovery_manage)
    row = session.get(WorkerDiscoveryNode, node_id)
    if row is None:
        raise NotFoundError("worker_discovery_node_not_found")
    actor.require_org(row.organization_id)
    return row


def resolve_publication_organizations(
    session: Session, configured_org: uuid.UUID | None
) -> list[uuid.UUID]:
    """Which organization(s) a self-publishing worker writes its public node into.

    * If the deployment configured an explicit org id, use exactly that (multi-tenant safe).
    * Otherwise, if EXACTLY ONE organization exists (the first-time / single-tenant dev case), use
      it — zero-config auto-population.
    * Otherwise return [] and let the caller log that ``discovery_worker_node_organization`` must be
      set (never guess across multiple tenants).
    """
    if configured_org is not None:
        exists = session.get(Organization, configured_org)
        return [configured_org] if exists is not None else []
    org_ids = list(session.execute(select(Organization.id)).scalars())
    return org_ids if len(org_ids) == 1 else []
