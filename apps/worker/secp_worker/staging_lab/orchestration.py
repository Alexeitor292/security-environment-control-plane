"""Worker-owned staging-lab simulation orchestration entry points (SECP-002B-1B-9).

Fake-only. The API dispatcher routes here via the established worker-dispatch seam (ADR-005);
the API service layer never imports, instantiates, or calls the executor directly. This module
runs the fake executor and hands its logical observations back to the API-side recorder, which
persists and audits. It contacts no infrastructure.

Boundary
--------
* Imports ``secp_api`` models and services (worker → API dependency is permitted).
* Imports ``secp_worker.staging_lab.executor`` (worker-internal, fake-only).
* Never imported by ``apps/api`` except lazily inside the inline dispatch seam.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session


def run_staging_lab_simulation(
    session: Session,
    staging_lab_id: uuid.UUID,
    *,
    created_by: uuid.UUID | None = None,
) -> object:
    """Worker-owned fake simulation: reconcile the plan into logical observed-state.

    Loads the durable lab, runs the fake executor against its immutable desired-state plan and
    any prior observed-state (idempotent/retry-safe), then records the result via the API seam.
    """
    from secp_api.errors import NotFoundError
    from secp_api.models import StagingLab
    from secp_api.services.staging_labs import record_staging_lab_simulation_result

    from secp_worker.staging_lab.executor import FakeStagingLabExecutor

    lab = session.get(StagingLab, staging_lab_id)
    if lab is None:
        raise NotFoundError(f"staging lab {staging_lab_id} not found")

    observed = FakeStagingLabExecutor().simulate(
        plan=lab.desired_state or {}, prior_observed=lab.simulated_observed_state
    )
    return record_staging_lab_simulation_result(
        session, lab.id, observed=observed, created_by=created_by
    )


def run_staging_lab_teardown(
    session: Session,
    staging_lab_id: uuid.UUID,
    *,
    created_by: uuid.UUID | None = None,
) -> object:
    """Worker-owned fake teardown: reconcile the plan into simulated-destroyed observed-state."""
    from secp_api.errors import NotFoundError
    from secp_api.models import StagingLab
    from secp_api.services.staging_labs import record_staging_lab_teardown_result

    from secp_worker.staging_lab.executor import FakeStagingLabExecutor

    lab = session.get(StagingLab, staging_lab_id)
    if lab is None:
        raise NotFoundError(f"staging lab {staging_lab_id} not found")

    observed = FakeStagingLabExecutor().teardown(
        plan=lab.desired_state or {}, prior_observed=lab.simulated_observed_state
    )
    return record_staging_lab_teardown_result(
        session, lab.id, observed=observed, created_by=created_by
    )
