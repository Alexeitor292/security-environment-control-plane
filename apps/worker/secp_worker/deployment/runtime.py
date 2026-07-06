"""Worker-side runtime loop for the deployment-operation consumer (SECP-B4 corrective).

Runs inside the worker process ONLY. Periodically drains committed, queued deployment operations by
calling the worker consumer, which invokes the deployment engine with the SHIPPED SEALED composition
— so the loop is wired end to end but fails closed before any network/SSH/host action. It contacts
no
infrastructure and imports no real provider/transport backend. The API must never import or run
this.
"""

from __future__ import annotations

import logging
import threading

from secp_worker.deployment.consumer import process_all_queued

logger = logging.getLogger("secp.worker.deployment")


def drain_once(session_scope=None) -> int:
    if session_scope is None:
        from secp_api.db import session_scope as default_scope

        session_scope = default_scope
    with session_scope() as session:
        return len(process_all_queued(session))


def run_consumer_loop(
    stop_event: threading.Event,
    *,
    interval_seconds: float = 2.0,
    session_scope=None,
    max_ticks: int | None = None,
) -> int:
    """Poll at a bounded interval, draining deployment operations until ``stop_event`` is set."""
    total = 0
    ticks = 0
    while not stop_event.is_set():
        if max_ticks is not None and ticks >= max_ticks:
            break
        ticks += 1
        try:
            total += drain_once(session_scope=session_scope)
        except Exception as exc:  # pragma: no cover - loop must survive a bad tick
            logger.error("deployment consumer tick failed: %s", type(exc).__name__)
        stop_event.wait(interval_seconds)
    return total


def run_forever(stop_event: threading.Event | None = None) -> None:  # pragma: no cover - runtime
    from secp_api.config import get_settings

    settings = get_settings()
    stop_event = stop_event or threading.Event()
    logger.info(
        "deployment consumer loop started (interval=%ss, SEALED composition, no infrastructure)",
        settings.staging_lab_poll_interval_seconds,
    )
    run_consumer_loop(stop_event, interval_seconds=settings.staging_lab_poll_interval_seconds)
    logger.info("deployment consumer loop stopped")
