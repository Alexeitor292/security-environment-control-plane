"""Worker-side durable runner state repository (ADR-012, SECP-002B-0).

Maps the runner's ``operation_id`` (the sha256 idempotency key written to
``ProvisioningOperation.idempotency_key`` by ``run_provisioning``) to the
persisted runner state extracted from ``ProvisioningOperation.result``.

This is the mechanism that lets a fresh ``FakeOpenTofuRunner`` instance answer
``status()`` correctly after a worker restart — without any process-local
dictionary, any new model, and without exposing the DB to the API layer.

Design
------
``DbRunnerStateStore`` is **read-only** from the runner's perspective.  All writes
to ``ProvisioningOperation`` are performed by the worker execution layer
(``execution.py`` via ``secp_api.services.provisioning``), which is the single
authoritative writer.  The runner reads persisted state only when its local
in-memory cache misses — the cache is a performance optimisation for within-request
reuse of the same runner instance.

Boundary: this module lives in ``secp_worker``; it imports ``secp_api.models`` and
``secp_api.enums``.  The API (``apps/api``) never imports this module.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from secp_api.enums import ProvisioningStatus
from secp_api.models import ProvisioningOperation
from sqlalchemy import select
from sqlalchemy.orm import Session


@runtime_checkable
class RunnerStateStore(Protocol):
    """Read persisted runner state keyed by runner operation_id.

    Returns a state dict ``{"state": str, "resources": list}`` or ``None`` if the
    operation is unknown / not yet in a terminal runner state.
    """

    def get(self, operation_id: str) -> dict | None: ...


class DbRunnerStateStore:
    """Reads runner state from ``ProvisioningOperation`` rows.

    The ``operation_id`` argument is the sha256 idempotency key (stored in
    ``ProvisioningOperation.idempotency_key``).  State is inferred from
    ``op.status`` and resources are extracted from ``op.result["resources"]``.

    Only ``applied`` and ``destroyed`` terminal states are surfaced; any
    in-progress or failed state returns ``None`` (the runner treats those as
    unknown and will re-run).
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, operation_id: str) -> dict | None:
        op = (
            self._session.execute(
                select(ProvisioningOperation).where(
                    ProvisioningOperation.idempotency_key == operation_id
                )
            )
            .scalars()
            .first()
        )
        if op is None or op.result is None:
            return None
        if op.status == ProvisioningStatus.applied:
            return {
                "state": "applied",
                "resources": op.result.get("resources", []),
            }
        if op.status == ProvisioningStatus.destroyed:
            return {
                "state": "destroyed",
                "resources": [],
            }
        return None
