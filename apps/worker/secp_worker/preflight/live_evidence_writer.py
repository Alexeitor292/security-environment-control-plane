"""Worker-only sealed live-preflight evidence writer seam (SECP-B2-4.5).

The ONLY way a durable ``LivePreflightEvidence`` row is created. The shipped default
(:class:`SealedLivePreflightEvidenceWriter`) REFUSES, so no shipped runtime path persists live
evidence: the preflight collection handoff is unreached under the sealed defaults, and even if it
were reached the default writer refuses. A real :class:`DurableLivePreflightEvidenceWriter` is
supplied ONLY to the future governed collection handoff (the separately-reviewed staging-live
composition). The API/UI never create live evidence and never construct these writers.

The writer validates the proposed payload against the strict, secret-free live-evidence schema
(closed status/checks/facts only), computes a deterministic hash, and persists exactly once per
completed preflight operation. It contacts nothing, resolves no secret, and stores no endpoint,
name, raw response, certificate, credential, token, or free text.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from secp_api import audit
from secp_api.enums import AuditAction, LivePreflightEvidenceStatus
from secp_api.live_preflight_evidence_schema import (
    LIVE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
    build_live_evidence_payload,
    compute_live_evidence_hash,
)
from secp_api.models import LivePreflightEvidence
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


class LivePreflightEvidenceRefused(Exception):
    """Fail-closed refusal carrying only a closed, secret-free reason code (no value leakage)."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"live preflight evidence refused: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class LivePreflightEvidenceContext:
    """The COMPLETE authoritative operation context a live-evidence record binds. All values are
    server-generated ids / versions / pinned labels — never a secret, endpoint, name, or free text.
    """

    organization_id: uuid.UUID
    preflight_id: uuid.UUID
    execution_target_id: uuid.UUID
    onboarding_id: uuid.UUID
    live_read_authorization_id: uuid.UUID
    live_read_authorization_version: int
    resolver_activation_authorization_id: uuid.UUID
    resolver_activation_authorization_version: int
    worker_identity_registration_id: uuid.UUID
    worker_identity_version: int
    resolution_lease_id: uuid.UUID
    operation_fingerprint: str
    collector_contract_version: str
    endpoint_allowlist_version: str
    resolver_contract_version: str


@runtime_checkable
class LivePreflightEvidenceWriter(Protocol):
    """Narrow worker-only seam. ``write`` persists one live-evidence record or fails closed."""

    def write(
        self,
        session: Session,
        *,
        context: LivePreflightEvidenceContext,
        status: LivePreflightEvidenceStatus,
        facts: Mapping,
        checks: Iterable,
        now: datetime,
    ) -> LivePreflightEvidence: ...


class SealedLivePreflightEvidenceWriter:
    """The shipped default: REFUSES every write and persists NO live evidence.

    It validates nothing, contacts nothing, and creates no row. It records a secret-free refusal
    audit (closed reason + safe ids) so an attempted write behind an unauthorized composition is
    reviewable, then fails closed. No configuration/flag makes it write.
    """

    def write(
        self,
        session: Session,
        *,
        context: LivePreflightEvidenceContext,
        status: LivePreflightEvidenceStatus,
        facts: Mapping,
        checks: Iterable,
        now: datetime,
    ) -> LivePreflightEvidence:
        audit.record(
            session,
            action=AuditAction.live_preflight_evidence_write_refused,
            resource_type="live_preflight_evidence",
            resource_id=str(context.preflight_id),
            organization_id=context.organization_id,
            actor="worker",
            outcome="refused",
            data={
                "reason_code": "live_preflight_evidence_writer_sealed",
                "evidence_schema_version": LIVE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
            },
        )
        raise LivePreflightEvidenceRefused("live_preflight_evidence_writer_sealed")


class DurableLivePreflightEvidenceWriter:
    """Persists ONE strict, secret-free live-evidence record per completed preflight operation.

    NOT a shipped default — supplied only to the future governed collection handoff. It validates
    payload against the closed live-evidence schema (rejecting any unknown/secret/target/network/
    free-text value), computes a deterministic hash, and inserts exactly once (idempotent per
    ``(preflight_id, operation_fingerprint)``). It records a secret-free write audit.
    """

    def write(
        self,
        session: Session,
        *,
        context: LivePreflightEvidenceContext,
        status: LivePreflightEvidenceStatus,
        facts: Mapping,
        checks: Iterable,
        now: datetime,
    ) -> LivePreflightEvidence:
        # Validate + canonicalize the payload (strict closed schema) BEFORE persistence.
        canonical = build_live_evidence_payload(
            status=status, facts=dict(facts), checks=list(checks)
        )
        evidence_hash = compute_live_evidence_hash(canonical)

        existing = session.execute(
            select(LivePreflightEvidence).where(
                LivePreflightEvidence.preflight_id == context.preflight_id,
                LivePreflightEvidence.operation_fingerprint == context.operation_fingerprint,
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing  # exact-once: a prior record for this operation is returned unchanged

        row = LivePreflightEvidence(
            organization_id=context.organization_id,
            preflight_id=context.preflight_id,
            execution_target_id=context.execution_target_id,
            onboarding_id=context.onboarding_id,
            live_read_authorization_id=context.live_read_authorization_id,
            live_read_authorization_version=context.live_read_authorization_version,
            resolver_activation_authorization_id=context.resolver_activation_authorization_id,
            resolver_activation_authorization_version=(
                context.resolver_activation_authorization_version
            ),
            worker_identity_registration_id=context.worker_identity_registration_id,
            worker_identity_version=context.worker_identity_version,
            resolution_lease_id=context.resolution_lease_id,
            operation_fingerprint=context.operation_fingerprint,
            collector_contract_version=context.collector_contract_version,
            endpoint_allowlist_version=context.endpoint_allowlist_version,
            resolver_contract_version=context.resolver_contract_version,
            evidence_schema_version=LIVE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
            status=status,
            collected_at=now,
            evidence_hash=evidence_hash,
            payload=canonical,
        )
        session.add(row)
        try:
            session.flush()
        except IntegrityError:
            # A concurrent writer won the exact-once race; return the durable winner.
            session.rollback()
            return session.execute(
                select(LivePreflightEvidence).where(
                    LivePreflightEvidence.preflight_id == context.preflight_id,
                    LivePreflightEvidence.operation_fingerprint == context.operation_fingerprint,
                )
            ).scalar_one()
        audit.record(
            session,
            action=AuditAction.live_preflight_evidence_written,
            resource_type="live_preflight_evidence",
            resource_id=str(row.id),
            organization_id=row.organization_id,
            actor="worker",
            outcome="written",
            data={
                "preflight_id": str(row.preflight_id),
                "status": row.status.value,
                "evidence_hash": row.evidence_hash,
                "evidence_schema_version": row.evidence_schema_version,
            },
        )
        return row
