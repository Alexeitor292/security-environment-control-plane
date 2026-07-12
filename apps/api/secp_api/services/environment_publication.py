"""Transactional EnvironmentVersion publication service (SECP-B10 / ADR-016 PR B).

Control-plane database logic ONLY. It composes an approved topology revision + a caller's
non-topology ``controlplane.security/v1alpha2`` definition into a NEW immutable
``EnvironmentVersion``, inside one organization-scoped, fail-closed, idempotent transaction.

It takes a Session and NEVER commits (the request/session boundary owns commit/rollback); it
creates NO exercise, plan, workflow, or audit action, registers NO route, and contacts NO
infrastructure. It imports no worker/provider/transport/HTTP/subprocess/socket/secret-resolver
code. There is NO route in this slice, so the service is not externally reachable — PR C adds
the route, API schemas, success/refusal audit events, provenance read model, and HTTP mapping.

Every failure is a closed :class:`EnvironmentPublicationError` code; no ``IntegrityError`` /
``ValidationError`` / ``SchemaValidationError`` / ``KeyError`` / ``ValueError`` / database
exception text escapes the service boundary.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, TypeVar

from secp_scenario_schema.v1alpha2.models import (
    API_VERSION as V1ALPHA2,
)
from secp_scenario_schema.v1alpha2.models import (
    PUBLICATION_CONTRACT_VERSION,
)
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.enums import EnvironmentPublicationErrorCode as EC
from secp_api.enums import Permission, TopologyRevisionStatus, TopologyValidationStatus
from secp_api.environment_publication_contract import (
    PublicationContractError,
    compose_published_definition,
)
from secp_api.errors import EnvironmentPublicationError
from secp_api.models import EnvironmentTemplate, EnvironmentVersion
from secp_api.topology_authoring_contract import topology_validation_result_hash
from secp_api.topology_authoring_models import (
    TopologyAuthoringDocument,
    TopologyRevision,
    TopologyValidationResult,
)

_Row = TypeVar("_Row")

_PASSING = frozenset(
    {TopologyValidationStatus.valid.value, TopologyValidationStatus.valid_with_warnings.value}
)


@dataclass(frozen=True)
class EnvironmentPublicationResult:
    """Outcome of a publication attempt (ADR-016 PR C).

    ``created`` distinguishes a NEW inserted EnvironmentVersion (True) from an exact idempotent
    replay that returned the already-published row (False), so the API can use a truthful
    201-vs-200 status and avoid a duplicate mutation audit. The publication algorithm — hashing,
    locking, preconditions, idempotency, and IntegrityError retry — is unchanged.
    """

    version: EnvironmentVersion
    created: bool


def _val(x: Any) -> Any:
    """The string value of a str-enum OR the value itself (DB rows load enums as plain str)."""
    return getattr(x, "value", x)


def _refuse(code: EC) -> EnvironmentPublicationError:
    return EnvironmentPublicationError(code)


def _map_contract_error(err: PublicationContractError) -> EnvironmentPublicationError:
    """Map a pure PublicationContractError code onto the closed service catalog (identity:
    the pure contract already emits version_publish_* strings that are catalog values)."""
    try:
        return EnvironmentPublicationError(EC(err.code))
    except ValueError:  # unforeseen code -> fail closed as a definition invalidity
        return EnvironmentPublicationError(EC.version_publish_definition_invalid)


def _lock_row(session: Session, model: type[_Row], pk: uuid.UUID) -> _Row | None:
    """Lock + freshly read a row by id. On PostgreSQL this is SELECT ... FOR UPDATE (the
    authoritative lock); on SQLite no lock clause is emitted (writers serialize at the DB).
    ``populate_existing`` overwrites any stale identity-map state (re-read inside the lock)."""
    for_update: Any = True if session.get_bind().dialect.name == "postgresql" else None
    return session.get(model, pk, populate_existing=True, with_for_update=for_update)


def _fetch(session: Session, model: type[_Row], pk: uuid.UUID) -> _Row | None:
    """Fresh read by id that overwrites stale identity-map state (no lock)."""
    return session.get(model, pk, populate_existing=True)


def _find_published(
    session: Session, template_id: uuid.UUID, fingerprint: str
) -> EnvironmentVersion | None:
    return session.execute(
        select(EnvironmentVersion).where(
            EnvironmentVersion.template_id == template_id,
            EnvironmentVersion.publication_fingerprint == fingerprint,
        )
    ).scalar_one_or_none()


def _verify_validation_result(
    vr: TopologyValidationResult | None,
    *,
    actor: Principal,
    document_id: uuid.UUID,
    revision_id: uuid.UUID,
    revision_content_hash: str,
) -> TopologyValidationResult:
    """Independently re-verify the immutable validation result (ADR-016 §6). Any stale,
    malformed, mismatched, or internally inconsistent result fails closed. Returns the
    verified (non-None) result."""
    if vr is None:
        raise _refuse(EC.version_publish_validation_missing)
    if vr.organization_id != actor.organization_id:
        raise _refuse(EC.version_publish_cross_org_forbidden)
    if vr.document_id != document_id or vr.revision_id != revision_id:
        raise _refuse(EC.version_publish_validation_stale)
    if vr.content_hash != revision_content_hash:
        raise _refuse(EC.version_publish_validation_stale)
    status = _val(vr.status)
    if status not in _PASSING:
        raise _refuse(EC.version_publish_validation_not_passing)
    if vr.error_count != 0:
        raise _refuse(EC.version_publish_validation_not_passing)
    findings = vr.findings or []
    errors = sum(1 for f in findings if isinstance(f, dict) and f.get("severity") == "error")
    warnings = sum(1 for f in findings if isinstance(f, dict) and f.get("severity") == "warning")
    if vr.error_count != errors or vr.warning_count != warnings:
        raise _refuse(EC.version_publish_validation_stale)
    if status == TopologyValidationStatus.valid.value and vr.warning_count != 0:
        raise _refuse(EC.version_publish_validation_stale)
    if status == TopologyValidationStatus.valid_with_warnings.value and vr.warning_count < 1:
        raise _refuse(EC.version_publish_validation_stale)
    if topology_validation_result_hash(vr.content_hash, status, findings) != vr.result_hash:
        raise _refuse(EC.version_publish_validation_stale)
    return vr


def _resolve_base_version(
    session: Session,
    actor: Principal,
    *,
    document_source_id: uuid.UUID | None,
    template_id: uuid.UUID,
    base_environment_version_id: uuid.UUID | None,
) -> uuid.UUID | None:
    """Enforce the exact source/base/template reuse policy (ADR-016 §D9). No inferred ancestor,
    latest version, template default, or fallback base."""
    if document_source_id is not None:
        if base_environment_version_id is None:
            raise _refuse(EC.version_publish_base_version_required)
        if base_environment_version_id != document_source_id:
            raise _refuse(EC.version_publish_base_version_mismatch)
        base = _fetch(session, EnvironmentVersion, base_environment_version_id)
        if base is None:
            raise _refuse(EC.version_publish_base_version_not_found)
        if base.organization_id != actor.organization_id:
            raise _refuse(EC.version_publish_base_version_cross_org_forbidden)
        if base.template_id != template_id:
            raise _refuse(EC.version_publish_template_mismatch)
        return base_environment_version_id
    # No source version: base must be NULL; destination may be any org-owned template.
    if base_environment_version_id is not None:
        raise _refuse(EC.version_publish_base_version_mismatch)
    return None


def _next_version_number(session: Session, template_id: uuid.UUID) -> int:
    current = session.execute(
        select(func.coalesce(func.max(EnvironmentVersion.version_number), 0)).where(
            EnvironmentVersion.template_id == template_id
        )
    ).scalar_one()
    return int(current) + 1


def _rows_agree(existing: EnvironmentVersion, columns: dict[str, Any]) -> bool:
    """Exact agreement across every immutable published field (idempotency vs conflict)."""
    return all(getattr(existing, name) == value for name, value in columns.items())


def publish_version_with_result(
    session: Session,
    actor: Principal,
    *,
    template_id: uuid.UUID,
    definition: dict[str, Any],
    topology_document_id: uuid.UUID,
    topology_revision_id: uuid.UUID,
    expected_topology_content_hash: str,
    validation_result_id: uuid.UUID,
    base_environment_version_id: uuid.UUID | None,
) -> EnvironmentPublicationResult:
    """Publish an approved topology revision + full definition into a new immutable
    v1alpha2 EnvironmentVersion, returning the version AND whether it was newly created.
    Idempotent on the exact same inputs; fail-closed otherwise. Runs inside the caller's
    transaction and only flushes (never commits)."""
    # 1. permission — required by the service itself, not a future router.
    if not actor.has(Permission.version_publish):
        raise _refuse(EC.version_publish_permission_denied)

    # 2/4. destination template: lock (SELECT FOR UPDATE on PG) + exact org ownership.
    template = _lock_row(session, EnvironmentTemplate, template_id)
    if template is None:
        raise _refuse(EC.version_publish_template_not_found)
    if template.organization_id != actor.organization_id:
        raise _refuse(EC.version_publish_cross_org_forbidden)

    # 5. topology document: lock so a concurrent authoring revision cannot race the approved
    #    head between our read and our insert.
    document = _lock_row(session, TopologyAuthoringDocument, topology_document_id)
    if document is None:
        raise _refuse(EC.version_publish_topology_not_found)
    if document.organization_id != actor.organization_id:
        raise _refuse(EC.version_publish_cross_org_forbidden)

    # 6/7/8. re-read the revision inside the lock and enforce every binding + org check.
    revision = _fetch(session, TopologyRevision, topology_revision_id)
    if revision is None or revision.document_id != topology_document_id:
        raise _refuse(EC.version_publish_topology_not_found)
    if revision.organization_id != actor.organization_id:
        raise _refuse(EC.version_publish_cross_org_forbidden)
    if document.approved_revision_id != topology_revision_id:
        raise _refuse(EC.version_publish_topology_not_approved)
    if _val(revision.status) != TopologyValidationStatus.valid.value and (
        _val(revision.status) != TopologyRevisionStatus.approved.value
    ):
        raise _refuse(EC.version_publish_topology_not_approved)
    if revision.content_hash != expected_topology_content_hash:
        raise _refuse(EC.version_publish_topology_hash_mismatch)
    if revision.source_environment_version_id != document.source_environment_version_id:
        raise _refuse(EC.version_publish_topology_not_approved)

    # 6/8. validation result: re-read + independently re-verify (ADR-016 §6).
    validation = _verify_validation_result(
        _fetch(session, TopologyValidationResult, validation_result_id),
        actor=actor,
        document_id=topology_document_id,
        revision_id=topology_revision_id,
        revision_content_hash=revision.content_hash,
    )

    # 9. source/base/template policy.
    resolved_base = _resolve_base_version(
        session,
        actor,
        document_source_id=document.source_environment_version_id,
        template_id=template_id,
        base_environment_version_id=base_environment_version_id,
    )

    # 10/11. server-owned provenance, built ONLY from fetched records (no caller topology bytes
    #        beyond the fetched revision content; no caller provenance/fingerprint).
    provenance = {
        "topology_document_id": str(document.id),
        "topology_revision_id": str(revision.id),
        "topology_validation_result_id": str(validation.id),
        "topology_validation_result_hash": validation.result_hash,
        "base_environment_version_id": (str(resolved_base) if resolved_base is not None else None),
        "publication_contract_version": PUBLICATION_CONTRACT_VERSION,
    }

    # 11/12. compose + recompute canonical topology, final definition, content hash, fingerprint.
    try:
        composed = compose_published_definition(
            definition=definition,
            topology_document_content=revision.document_content,
            expected_topology_content_hash=expected_topology_content_hash,
            provenance=provenance,
            destination_template_id=str(template_id),
        )
    except PublicationContractError as exc:
        raise _map_contract_error(exc) from exc

    columns = {
        "organization_id": template.organization_id,
        "template_id": template_id,
        "api_version": V1ALPHA2,
        "content_hash": composed.environment_content_hash,
        "spec": composed.final_definition,
        "source_topology_document_id": document.id,
        "source_topology_revision_id": revision.id,
        "topology_content_hash": composed.topology_content_hash,
        "topology_validation_result_id": validation.id,
        "topology_validation_result_hash": validation.result_hash,
        "base_environment_version_id": resolved_base,
        "publication_contract_version": composed.publication_contract_version,
        "publication_fingerprint": composed.publication_fingerprint,
    }

    # 13/14. idempotency: an existing row for this (template_id, fingerprint) must agree exactly.
    existing = _find_published(session, template_id, composed.publication_fingerprint)
    if existing is not None:
        if _rows_agree(existing, columns):
            return EnvironmentPublicationResult(version=existing, created=False)
        raise _refuse(EC.version_publish_conflict)

    # 15/16. allocate + insert under the template lock; the savepoint keeps a uniqueness race
    #        from poisoning the caller's transaction (defense in depth behind the lock).
    try:
        with session.begin_nested():
            version = EnvironmentVersion(
                version_number=_next_version_number(session, template_id),
                created_by=actor.user_id,
                **columns,
            )
            session.add(version)
            session.flush()
    except IntegrityError:
        session.expire_all()
        existing = _find_published(session, template_id, composed.publication_fingerprint)
        if existing is not None and _rows_agree(existing, columns):
            return EnvironmentPublicationResult(version=existing, created=False)
        raise _refuse(EC.version_publish_conflict) from None
    return EnvironmentPublicationResult(version=version, created=True)


def publish_version(
    session: Session,
    actor: Principal,
    *,
    template_id: uuid.UUID,
    definition: dict[str, Any],
    topology_document_id: uuid.UUID,
    topology_revision_id: uuid.UUID,
    expected_topology_content_hash: str,
    validation_result_id: uuid.UUID,
    base_environment_version_id: uuid.UUID | None,
) -> EnvironmentVersion:
    """Backward-compatible wrapper returning only the EnvironmentVersion (unchanged behavior).

    Delegates to :func:`publish_version_with_result`; the publication implementation is not
    duplicated and no hashing/locking/precondition/retry behavior changes.
    """
    return publish_version_with_result(
        session,
        actor,
        template_id=template_id,
        definition=definition,
        topology_document_id=topology_document_id,
        topology_revision_id=topology_revision_id,
        expected_topology_content_hash=expected_topology_content_hash,
        validation_result_id=validation_result_id,
        base_environment_version_id=base_environment_version_id,
    ).version
