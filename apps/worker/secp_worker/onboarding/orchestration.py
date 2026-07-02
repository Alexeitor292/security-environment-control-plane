"""Worker-owned onboarding-preflight orchestration entry point (SECP-002B-1B-1, ADR-014).

This module is the ONLY place ``SimulatedTargetEvidenceCollector`` is called.
The API dispatcher routes here via the established worker-dispatch seam (ADR-005);
the API service layer never imports, instantiates, or calls any evidence collector.

Boundary
--------
* Imports ``secp_api`` models and services (worker → API dependency is permitted).
* Imports ``secp_worker.onboarding.target_evidence`` (worker-internal).
* Never imported by ``apps/api``.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session


def run_simulated_preflight(
    session: Session,
    onboarding_id: uuid.UUID,
    *,
    checks: list[dict],
    verification_level: str,
    collector_kind: str,
    collector_identity: str,
    created_by: uuid.UUID | None = None,
) -> object:  # returns TargetPreflight — typed as object to avoid circular import at module level
    """Worker-owned orchestration for simulated target-evidence collection and preflight.

    Flow:
    1. Retrieve the onboarding and target from the database.
    2. Invoke ``SimulatedTargetEvidenceCollector`` to produce observed-target evidence.
       This is the ONLY call site; the API never generates evidence.
    3. Pass the resulting payload to the API-side result recorder
       (``secp_api.services.onboarding.record_target_evidence_from_payload``) which
       validates, compares, hashes, persists, and audits — without generating anything.
    4. Record and return the ``TargetPreflight`` row via the API's
       ``record_preflight_result`` seam.
    """
    from secp_api.errors import NotFoundError
    from secp_api.models import ExecutionTarget, TargetOnboarding
    from secp_api.services.onboarding import (
        record_preflight_result,
        record_target_evidence_from_payload,
    )

    from secp_worker.onboarding.target_evidence import SimulatedTargetEvidenceCollector

    ob = session.get(TargetOnboarding, onboarding_id)
    if ob is None:
        raise NotFoundError(f"onboarding {onboarding_id} not found")
    target = session.get(ExecutionTarget, ob.execution_target_id)
    if target is None:
        raise NotFoundError("execution target no longer exists")

    # Step 1 (worker): collect simulated evidence — no API involvement.
    payload = SimulatedTargetEvidenceCollector().collect(declared_boundary=ob.declared_boundary)

    # Step 2 (API result recorder): validate, compare, hash, persist, audit.
    evidence_record = record_target_evidence_from_payload(
        session, ob, target, payload=payload, created_by=created_by
    )

    # Step 3: record the preflight bound to the already-persisted evidence record.
    return record_preflight_result(
        session,
        ob.id,
        evidence_record=evidence_record,
        checks=checks,
        verification_level=verification_level,
        collector_kind=collector_kind,
        collector_identity=collector_identity,
        created_by=created_by,
    )
