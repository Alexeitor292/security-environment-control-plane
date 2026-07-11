"""Durable topology draft authoring service (SECP-B9).

Control-plane only. Every action is organization-scoped, permission-gated, and
audited. NOTHING here contacts infrastructure, involves a worker, or generates
or applies a deployment. The workflow keeps each stage strictly separate:

    local draft (client) → saved draft revision → validated revision
      → submitted revision → approved revision                (this service)
      → generated deployment plan → deployed infrastructure   (NOT here)

Approval records a decision only. Plan generation is deliberately NOT part of
this contract (see the module-level "plan-generation boundary" note): the
existing plan generator binds to an environment version, not a topology
revision, so auto- or explicit plan generation from an approved topology is a
separate, later milestone (Option B in the PR-14 brief).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import (
    AuditAction,
    Permission,
    TopologyAuthoringStatus,
    TopologyRevisionStatus,
    TopologyValidationStatus,
)
from secp_api.enums import (
    TopologyAuthoringErrorCode as EC,
)
from secp_api.errors import TopologyAuthoringError
from secp_api.models import EnvironmentVersion, Exercise
from secp_api.topology_authoring_contract import (
    CANONICAL_SCHEMA_VERSION,
    TopologyDocumentError,
    content_hash,
    derive_findings,
    reason_is_secret_shaped,
    validate_document,
)
from secp_api.topology_authoring_models import (
    TopologyAuthoringDocument,
    TopologyRevision,
    TopologyValidationResult,
)

MAX_HISTORY_PAGE = 200


def _now() -> datetime:
    return datetime.now(UTC)


def _refuse(
    session: Session,
    principal: Principal,
    code: EC,
    *,
    document_id: uuid.UUID | None = None,
    revision_id: uuid.UUID | None = None,
    action: AuditAction | None = None,
) -> TopologyAuthoringError:
    """Record a durable refusal audit and return the closed-code error to raise.

    The router commits before re-raising (durable_transition), so refusals are
    audited even though the request fails closed. Details are IDs/codes only —
    never topology content or a backend message.
    """
    if action is not None:
        audit.record(
            session,
            action=action,
            resource_type="topology_authoring_document",
            resource_id=document_id,
            actor=str(principal.user_id),
            organization_id=principal.organization_id,
            outcome="refused",
            data={
                "code": code.value,
                **({"revision_id": str(revision_id)} if revision_id else {}),
            },
        )
    err = TopologyAuthoringError(code)
    err.durable_transition = action is not None
    return err


def _require(
    principal: Principal,
    permission: Permission,
    *,
    session: Session | None = None,
    action: AuditAction | None = None,
) -> None:
    if principal.has(permission):
        return
    # Permission-denied MUTATIONS are the highest-signal refusal — audit them
    # durably (reads pass no action and simply fail closed).
    if session is not None and action is not None:
        audit.record(
            session,
            action=action,
            resource_type="topology_authoring_document",
            resource_id=None,
            actor=str(principal.user_id),
            organization_id=principal.organization_id,
            outcome="refused",
            data={"code": EC.topology_permission_denied.value, "permission": permission.value},
        )
        err = TopologyAuthoringError(EC.topology_permission_denied)
        err.durable_transition = True
        raise err
    raise TopologyAuthoringError(EC.topology_permission_denied)


def _load_document(
    session: Session,
    principal: Principal,
    document_id: uuid.UUID,
    *,
    action: AuditAction | None = None,
) -> TopologyAuthoringDocument:
    doc = session.get(TopologyAuthoringDocument, document_id)
    if doc is None:
        raise TopologyAuthoringError(EC.topology_not_found)
    if doc.organization_id != principal.organization_id:
        # Cross-org access fails closed. Mutations pass their own stage's
        # refused action so the audit log filters cleanly; reads (action=None)
        # simply fail closed, consistent with reads not being audited.
        raise _refuse(
            session,
            principal,
            EC.topology_cross_org_forbidden,
            document_id=document_id,
            action=action,
        )
    return doc


def _canonical_or_refuse(
    session: Session,
    principal: Principal,
    raw: Any,
    *,
    document_id: uuid.UUID | None,
    action: AuditAction,
) -> dict[str, Any]:
    try:
        return validate_document(raw)
    except TopologyDocumentError as exc:
        # Map the document error's closed code straight through, and audit the
        # rejection (a rejected secret/unknown-kind/schema-invalid submission is
        # a security-relevant refusal). The rejected content is NEVER audited.
        raise _refuse(
            session, principal, EC(exc.code), document_id=document_id, action=action
        ) from exc


def _empty_document() -> dict[str, Any]:
    return validate_document({"schema_version": CANONICAL_SCHEMA_VERSION})


def _document_from_version_spec(spec: dict[str, Any]) -> dict[str, Any]:
    """Deterministically derive a starting topology from an immutable definition
    version's spec (roles → host nodes, networks → network nodes, role.network →
    declared attachment edges). Fabricates no addressing; server-owned ids are
    slugified from declared names. The result is validated + canonicalized."""
    raw_spec = spec.get("spec", spec) if isinstance(spec, dict) else {}
    if not isinstance(raw_spec, dict):
        raw_spec = {}
    nodes: list[dict[str, Any]] = []
    networks: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    def slug(value: Any, prefix: str, i: int) -> str:
        base = str(value) if isinstance(value, str) else ""
        cleaned = "".join(c if c.isalnum() or c in "-_." else "-" for c in base)[:100]
        return cleaned or f"{prefix}-{i}"

    net_id_by_name: dict[str, str] = {}
    for i, net in enumerate(raw_spec.get("networks", []) or []):
        if not isinstance(net, dict):
            continue
        nid = slug(net.get("name"), "net", i)
        net_id_by_name[str(net.get("name"))] = nid
        base_cidr = net.get("baseCidr")
        networks.append(
            {
                "id": nid,
                "label": str(net.get("name") or nid)[:120],
                "cidr": base_cidr if isinstance(base_cidr, str) else None,
                "isolated": bool(net.get("isolated")) if "isolated" in net else None,
            }
        )
        # A network node so the segment appears on the canvas.
        nodes.append(
            {
                "id": nid,
                "kind": "network",
                "label": str(net.get("name") or nid)[:120],
                "role": None,
                "ip": None,
                "network": None,
                "x": 160 + i * 320,
                "y": 260,
            }
        )

    KNOWN = {"attacker", "target", "sensor"}
    for i, role in enumerate(raw_spec.get("roles", []) or []):
        if not isinstance(role, dict):
            continue
        rid = slug(role.get("name"), "node", i)
        kind = role.get("kind")
        if kind not in KNOWN:
            # Unknown role kinds are dropped from the derived start (never
            # fabricated into an unsupported node); the author can add nodes.
            continue
        node_net = role.get("network")
        nodes.append(
            {
                "id": rid,
                "kind": kind,
                "label": str(role.get("name") or rid)[:120],
                "role": kind,
                "ip": None,
                "network": str(node_net)[:200] if isinstance(node_net, str) else None,
                "x": 40 + i * 220,
                "y": 40,
            }
        )
        target_net = net_id_by_name.get(str(node_net))
        if target_net:
            edges.append(
                {
                    "id": f"edge-{rid}-{target_net}",
                    "source": rid,
                    "target": target_net,
                    "kind": "network",
                }
            )

    return validate_document(
        {
            "schema_version": CANONICAL_SCHEMA_VERSION,
            "nodes": nodes,
            "edges": edges,
            "networks": networks,
            "zones": [],
        }
    )


# --------------------------------------------------------------- create draft


def create_draft(
    session: Session,
    principal: Principal,
    *,
    display_name: str,
    source_environment_version_id: uuid.UUID | None = None,
    exercise_id: uuid.UUID | None = None,
    document: Any | None = None,
) -> TopologyAuthoringDocument:
    _require(
        principal,
        Permission.topology_draft,
        session=session,
        action=AuditAction.topology_revision_refused,
    )

    source_version: EnvironmentVersion | None = None
    if source_environment_version_id is not None:
        source_version = session.get(EnvironmentVersion, source_environment_version_id)
        if source_version is None:
            raise TopologyAuthoringError(EC.topology_source_not_found)
        if source_version.organization_id != principal.organization_id:
            raise _refuse(
                session,
                principal,
                EC.topology_cross_org_forbidden,
                action=AuditAction.topology_revision_refused,
            )

    # An optional exercise binding must belong to the caller's organization.
    if exercise_id is not None:
        ex = session.get(Exercise, exercise_id)
        if ex is None or ex.organization_id != principal.organization_id:
            raise _refuse(
                session,
                principal,
                EC.topology_cross_org_forbidden,
                action=AuditAction.topology_revision_refused,
            )

    if document is not None:
        canonical = _canonical_or_refuse(
            session,
            principal,
            document,
            document_id=None,
            action=AuditAction.topology_revision_refused,
        )
    elif source_version is not None:
        canonical = _document_from_version_spec(source_version.spec)
    else:
        canonical = _empty_document()

    doc = TopologyAuthoringDocument(
        organization_id=principal.organization_id,
        source_environment_version_id=source_environment_version_id,
        exercise_id=exercise_id,
        display_name=display_name[:200],
        status=TopologyAuthoringStatus.draft,
        revision_count=0,
        created_by=principal.user_id,
        updated_by=principal.user_id,
    )
    session.add(doc)
    session.flush()

    revision = _add_revision(
        session,
        principal,
        doc,
        canonical,
        parent_revision_id=None,
        change_note=None,
    )
    doc.current_revision_id = revision.id

    audit.record(
        session,
        action=AuditAction.topology_draft_created,
        resource_type="topology_authoring_document",
        resource_id=doc.id,
        actor=str(principal.user_id),
        organization_id=principal.organization_id,
        outcome="success",
        data={
            "revision_number": revision.revision_number,
            "content_hash": revision.content_hash,
            "node_count": len(canonical["nodes"]),
            "edge_count": len(canonical["edges"]),
            **(
                {"source_environment_version_id": str(source_environment_version_id)}
                if source_environment_version_id
                else {}
            ),
        },
    )
    return doc


def _add_revision(
    session: Session,
    principal: Principal,
    doc: TopologyAuthoringDocument,
    canonical: dict[str, Any],
    *,
    parent_revision_id: uuid.UUID | None,
    change_note: str | None,
) -> TopologyRevision:
    doc.revision_count += 1
    revision = TopologyRevision(
        organization_id=doc.organization_id,
        document_id=doc.id,
        revision_number=doc.revision_count,
        parent_revision_id=parent_revision_id,
        schema_version=canonical["schema_version"],
        document_content=canonical,
        content_hash=content_hash(canonical),
        source_environment_version_id=doc.source_environment_version_id,
        change_note=change_note[:500] if change_note else None,
        status=TopologyRevisionStatus.draft,
        created_by=principal.user_id,
    )
    session.add(revision)
    session.flush()
    return revision


# ------------------------------------------------------------- new revision


def create_revision(
    session: Session,
    principal: Principal,
    document_id: uuid.UUID,
    *,
    base_revision_number: int,
    base_content_hash: str,
    document: Any,
    change_note: str | None = None,
) -> TopologyRevision:
    _require(
        principal,
        Permission.topology_draft,
        session=session,
        action=AuditAction.topology_revision_refused,
    )
    doc = _load_document(
        session,
        principal,
        document_id,
        action=AuditAction.topology_revision_refused,
    )
    current = _current_revision(session, doc)

    # Optimistic concurrency: the client's base must be the exact current head.
    if current is None or current.revision_number != base_revision_number:
        raise _refuse(
            session,
            principal,
            EC.topology_revision_stale,
            document_id=doc.id,
            action=AuditAction.topology_revision_refused,
        )
    if current.content_hash != base_content_hash:
        raise _refuse(
            session,
            principal,
            EC.topology_hash_mismatch,
            document_id=doc.id,
            revision_id=current.id,
            action=AuditAction.topology_revision_refused,
        )

    canonical = _canonical_or_refuse(
        session,
        principal,
        document,
        document_id=doc.id,
        action=AuditAction.topology_revision_refused,
    )

    # The previous head, if still an editable draft/validated revision, is
    # superseded. A submitted/approved/rejected revision stays frozen as history.
    if current.status in (TopologyRevisionStatus.draft, TopologyRevisionStatus.validated):
        current.status = TopologyRevisionStatus.superseded

    try:
        revision = _add_revision(
            session,
            principal,
            doc,
            canonical,
            parent_revision_id=current.id,
            change_note=change_note,
        )
    except IntegrityError as exc:
        # A concurrent create_revision won the (document_id, revision_number)
        # unique constraint — this request's base is now stale. Fail closed with
        # the clean concurrency code instead of a raw 500.
        session.rollback()
        raise _refuse(
            session,
            principal,
            EC.topology_revision_stale,
            document_id=document_id,
            action=AuditAction.topology_revision_refused,
        ) from exc
    doc.current_revision_id = revision.id
    # A changed revision requires new validation and a new review decision, and
    # clears every stale pointer — including a prior approval, which no longer
    # applies to the (now changed) current revision. The old approved revision
    # stays frozen as history via its own status.
    doc.status = TopologyAuthoringStatus.draft
    doc.validated_revision_id = None
    doc.submitted_revision_id = None
    doc.approved_revision_id = None
    doc.updated_by = principal.user_id

    audit.record(
        session,
        action=AuditAction.topology_revision_created,
        resource_type="topology_authoring_document",
        resource_id=doc.id,
        actor=str(principal.user_id),
        organization_id=principal.organization_id,
        outcome="success",
        data={
            "revision_number": revision.revision_number,
            "parent_revision_number": current.revision_number,
            "content_hash": revision.content_hash,
        },
    )
    return revision


# ---------------------------------------------------------------- validation


def validate_revision(
    session: Session,
    principal: Principal,
    document_id: uuid.UUID,
    revision_id: uuid.UUID,
    *,
    expected_content_hash: str,
) -> TopologyValidationResult:
    _require(
        principal,
        Permission.topology_validate,
        session=session,
        action=AuditAction.topology_validation_refused,
    )
    doc = _load_document(
        session,
        principal,
        document_id,
        action=AuditAction.topology_validation_refused,
    )
    revision = _load_revision(session, doc, revision_id)

    # Validation binds to the exact current revision + hash and never mutates
    # content. A stale target fails closed.
    if doc.current_revision_id != revision.id:
        raise _refuse(
            session,
            principal,
            EC.topology_revision_not_current,
            document_id=doc.id,
            revision_id=revision.id,
            action=AuditAction.topology_validation_refused,
        )
    if revision.content_hash != expected_content_hash:
        raise _refuse(
            session,
            principal,
            EC.topology_hash_mismatch,
            document_id=doc.id,
            revision_id=revision.id,
            action=AuditAction.topology_validation_refused,
        )

    findings = derive_findings(revision.document_content)
    errors = [f for f in findings if f.severity == "error"]
    warnings = [f for f in findings if f.severity == "warning"]
    if errors:
        status = TopologyValidationStatus.invalid
    elif warnings:
        status = TopologyValidationStatus.valid_with_warnings
    else:
        status = TopologyValidationStatus.valid

    finding_dicts = [f.as_dict() for f in findings]
    result = TopologyValidationResult(
        organization_id=doc.organization_id,
        document_id=doc.id,
        revision_id=revision.id,
        content_hash=revision.content_hash,
        status=status,
        error_count=len(errors),
        warning_count=len(warnings),
        findings=finding_dicts,
        result_hash=_result_hash(revision.content_hash, status, finding_dicts),
        validated_by=principal.user_id,
        validated_at=_now(),
    )
    session.add(result)
    session.flush()

    # A schema-valid revision advances to 'validated' (never approval). An
    # invalid one stays a draft. The aggregate is advanced ONLY while the
    # current revision is still pre-decision (draft/validated) — re-validating
    # an already submitted/approved/rejected revision records the immutable
    # result but must never downgrade a decided aggregate back to 'validated'.
    if status in (
        TopologyValidationStatus.valid,
        TopologyValidationStatus.valid_with_warnings,
    ) and revision.status in (TopologyRevisionStatus.draft, TopologyRevisionStatus.validated):
        if revision.status == TopologyRevisionStatus.draft:
            revision.status = TopologyRevisionStatus.validated
        doc.validated_revision_id = revision.id
        doc.status = TopologyAuthoringStatus.validated
        # Flush so each status transition is individually validated by the
        # immutability transition guard (a single request may span several).
        session.flush()

    audit.record(
        session,
        action=AuditAction.topology_validation_recorded,
        resource_type="topology_validation_result",
        resource_id=result.id,
        actor=str(principal.user_id),
        organization_id=principal.organization_id,
        outcome="success",
        data={
            "revision_number": revision.revision_number,
            "content_hash": revision.content_hash,
            "status": status.value,
            "error_count": len(errors),
            "warning_count": len(warnings),
        },
    )
    return result


def _result_hash(chash: str, status: TopologyValidationStatus, findings: list[dict]) -> str:
    payload = json.dumps(
        {"content_hash": chash, "status": status.value, "findings": findings},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ submit


def submit_revision(
    session: Session,
    principal: Principal,
    document_id: uuid.UUID,
    revision_id: uuid.UUID,
    *,
    expected_content_hash: str,
) -> TopologyRevision:
    _require(
        principal,
        Permission.topology_submit,
        session=session,
        action=AuditAction.topology_submission_refused,
    )
    doc = _load_document(
        session,
        principal,
        document_id,
        action=AuditAction.topology_submission_refused,
    )
    revision = _load_revision(session, doc, revision_id)

    if doc.current_revision_id != revision.id:
        raise _refuse(
            session,
            principal,
            EC.topology_revision_not_current,
            document_id=doc.id,
            revision_id=revision.id,
            action=AuditAction.topology_submission_refused,
        )
    if revision.content_hash != expected_content_hash:
        raise _refuse(
            session,
            principal,
            EC.topology_hash_mismatch,
            document_id=doc.id,
            revision_id=revision.id,
            action=AuditAction.topology_submission_refused,
        )
    if revision.status != TopologyRevisionStatus.validated:
        raise _refuse(
            session,
            principal,
            EC.topology_validation_required,
            document_id=doc.id,
            revision_id=revision.id,
            action=AuditAction.topology_submission_refused,
        )
    # A current, matching, valid validation result must exist for this hash.
    latest = _latest_validation(session, doc.id, revision.id)
    if (
        latest is None
        or latest.content_hash != revision.content_hash
        or latest.status
        not in (TopologyValidationStatus.valid, TopologyValidationStatus.valid_with_warnings)
    ):
        raise _refuse(
            session,
            principal,
            EC.topology_validation_not_current,
            document_id=doc.id,
            revision_id=revision.id,
            action=AuditAction.topology_submission_refused,
        )

    revision.status = TopologyRevisionStatus.submitted
    doc.status = TopologyAuthoringStatus.submitted
    doc.submitted_revision_id = revision.id
    session.flush()

    audit.record(
        session,
        action=AuditAction.topology_submitted,
        resource_type="topology_authoring_document",
        resource_id=doc.id,
        actor=str(principal.user_id),
        organization_id=principal.organization_id,
        outcome="success",
        data={"revision_number": revision.revision_number, "content_hash": revision.content_hash},
    )
    return revision


# --------------------------------------------------------- approve / reject


def _decide(
    session: Session,
    principal: Principal,
    document_id: uuid.UUID,
    revision_id: uuid.UUID,
    *,
    expected_content_hash: str,
    approve: bool,
    reason: str | None,
) -> TopologyRevision:
    _require(
        principal,
        Permission.topology_decide,
        session=session,
        action=AuditAction.topology_decision_refused,
    )
    doc = _load_document(
        session,
        principal,
        document_id,
        action=AuditAction.topology_decision_refused,
    )
    revision = _load_revision(session, doc, revision_id)

    # A free-text decision reason is stored and audited — reject secret-shaped
    # reasons with the same guard applied to document content.
    if reason and reason_is_secret_shaped(reason):
        raise _refuse(
            session,
            principal,
            EC.topology_secret_field_forbidden,
            document_id=doc.id,
            revision_id=revision.id,
            action=AuditAction.topology_decision_refused,
        )

    if (
        doc.submitted_revision_id != revision.id
        or revision.status != TopologyRevisionStatus.submitted
    ):
        raise _refuse(
            session,
            principal,
            EC.topology_not_submitted,
            document_id=doc.id,
            revision_id=revision.id,
            action=AuditAction.topology_decision_refused,
        )
    if revision.content_hash != expected_content_hash:
        raise _refuse(
            session,
            principal,
            EC.topology_hash_mismatch,
            document_id=doc.id,
            revision_id=revision.id,
            action=AuditAction.topology_decision_refused,
        )

    revision.status = (
        TopologyRevisionStatus.approved if approve else TopologyRevisionStatus.rejected
    )
    revision.decided_by = principal.user_id
    revision.decided_at = _now()
    revision.decision_reason = reason[:500] if reason else None
    doc.submitted_revision_id = None
    if approve:
        # Approval records a decision only. It does NOT generate a plan, widen a
        # boundary, or contact infrastructure — live apply remains sealed.
        doc.status = TopologyAuthoringStatus.approved
        doc.approved_revision_id = revision.id
    else:
        doc.status = TopologyAuthoringStatus.rejected
    session.flush()

    audit.record(
        session,
        action=AuditAction.topology_approved if approve else AuditAction.topology_rejected,
        resource_type="topology_revision",
        resource_id=revision.id,
        actor=str(principal.user_id),
        organization_id=principal.organization_id,
        outcome="success",
        data={
            "revision_number": revision.revision_number,
            "content_hash": revision.content_hash,
            **({"reason": reason[:200]} if reason else {}),
        },
    )
    return revision


def approve_revision(
    session: Session,
    principal: Principal,
    document_id: uuid.UUID,
    revision_id: uuid.UUID,
    *,
    expected_content_hash: str,
    reason: str | None = None,
) -> TopologyRevision:
    return _decide(
        session,
        principal,
        document_id,
        revision_id,
        expected_content_hash=expected_content_hash,
        approve=True,
        reason=reason,
    )


def reject_revision(
    session: Session,
    principal: Principal,
    document_id: uuid.UUID,
    revision_id: uuid.UUID,
    *,
    expected_content_hash: str,
    reason: str | None = None,
) -> TopologyRevision:
    return _decide(
        session,
        principal,
        document_id,
        revision_id,
        expected_content_hash=expected_content_hash,
        approve=False,
        reason=reason,
    )


# ----------------------------------------------------------------- reads


def get_document(
    session: Session, principal: Principal, document_id: uuid.UUID
) -> TopologyAuthoringDocument:
    _require(principal, Permission.topology_read)
    return _load_document(session, principal, document_id)


def get_current_revision(
    session: Session, principal: Principal, document_id: uuid.UUID
) -> TopologyRevision | None:
    doc = get_document(session, principal, document_id)
    return _current_revision(session, doc)


def list_revisions(
    session: Session,
    principal: Principal,
    document_id: uuid.UUID,
    *,
    limit: int = MAX_HISTORY_PAGE,
    offset: int = 0,
) -> list[TopologyRevision]:
    doc = get_document(session, principal, document_id)
    limit = max(1, min(limit, MAX_HISTORY_PAGE))
    offset = max(0, offset)
    return list(
        session.execute(
            select(TopologyRevision)
            .where(TopologyRevision.document_id == doc.id)
            .order_by(TopologyRevision.revision_number.desc())
            .limit(limit)
            .offset(offset)
        ).scalars()
    )


def get_revision(
    session: Session, principal: Principal, document_id: uuid.UUID, revision_id: uuid.UUID
) -> TopologyRevision:
    doc = get_document(session, principal, document_id)
    return _load_revision(session, doc, revision_id)


def get_latest_validation(
    session: Session, principal: Principal, document_id: uuid.UUID, revision_id: uuid.UUID
) -> TopologyValidationResult | None:
    doc = get_document(session, principal, document_id)
    revision = _load_revision(session, doc, revision_id)
    return _latest_validation(session, doc.id, revision.id)


# --------------------------------------------------------------- internals


def _current_revision(session: Session, doc: TopologyAuthoringDocument) -> TopologyRevision | None:
    if doc.current_revision_id is None:
        return None
    return session.get(TopologyRevision, doc.current_revision_id)


def _load_revision(
    session: Session, doc: TopologyAuthoringDocument, revision_id: uuid.UUID
) -> TopologyRevision:
    revision = session.get(TopologyRevision, revision_id)
    if revision is None or revision.document_id != doc.id:
        raise TopologyAuthoringError(EC.topology_revision_not_found)
    return revision


def _latest_validation(
    session: Session, document_id: uuid.UUID, revision_id: uuid.UUID
) -> TopologyValidationResult | None:
    return session.execute(
        select(TopologyValidationResult)
        .where(
            TopologyValidationResult.document_id == document_id,
            TopologyValidationResult.revision_id == revision_id,
        )
        .order_by(TopologyValidationResult.validated_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def validation_status_for_current(
    session: Session, doc: TopologyAuthoringDocument
) -> TopologyValidationStatus:
    """Read-model helper: the validation posture of the CURRENT revision. Any
    recorded result whose hash no longer matches the current revision is
    reported as stale."""
    current = _current_revision(session, doc)
    if current is None:
        return TopologyValidationStatus.unverifiable
    latest = _latest_validation(session, doc.id, current.id)
    if latest is None:
        return TopologyValidationStatus.unverifiable
    if latest.content_hash != current.content_hash:
        return TopologyValidationStatus.stale
    return latest.status
