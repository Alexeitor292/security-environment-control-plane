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

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.discovery_bootstrap_contract import (
    BootstrapContractError,
    validate_public_ssh_key,
)
from secp_api.enums import AuditAction, Permission
from secp_api.errors import DomainError, NotFoundError
from secp_api.models import Organization, WorkerDiscoveryNode
from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint

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


def publish_worker_node(
    session: Session,
    *,
    organization_id: uuid.UUID,
    node_label: str,
    ssh_public_key: str,
    admission_anchor_hex: str,
    worker_identity_registration_id: uuid.UUID | None = None,
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
        select(WorkerDiscoveryNode).where(
            WorkerDiscoveryNode.organization_id == organization_id,
            WorkerDiscoveryNode.node_label == node_label,
        )
    ).scalar_one_or_none()
    if row is None:
        row = WorkerDiscoveryNode(
            organization_id=organization_id,
            node_label=node_label,
            ssh_public_key=ssh_pub,
            ssh_public_key_fingerprint=ssh_fp,
            admission_anchor_hex=anchor_hex,
            admission_anchor_fingerprint=anchor_fp,
            worker_identity_registration_id=worker_identity_registration_id,
            created_by=created_by,
        )
        session.add(row)
    else:
        row.ssh_public_key = ssh_pub
        row.ssh_public_key_fingerprint = ssh_fp
        row.admission_anchor_hex = anchor_hex
        row.admission_anchor_fingerprint = anchor_fp
        if worker_identity_registration_id is not None:
            row.worker_identity_registration_id = worker_identity_registration_id
    session.flush()
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
        return [configured_org]
    org_ids = list(session.execute(select(Organization.id)).scalars())
    return org_ids if len(org_ids) == 1 else []
