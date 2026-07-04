"""Worker-side runtime loop for the fake staging-lab consumer (SECP-002B-1B-9).

FAKE-ONLY. This module runs inside the worker process only. It periodically drains committed,
queued staging-lab work items by calling the worker-owned consumer, which runs the fake executor
and writes observations/completion. It contacts no infrastructure, resolves no secret, and
imports no real provider/transport/adapter code. A later, separately reviewed real-adapter PR is
required before any provider action can occur.

The API must NEVER import or run this module: it only enqueues durable work.
"""

from __future__ import annotations

import logging
import threading

from secp_worker.staging_lab.consumer import process_all_queued

logger = logging.getLogger("secp.worker.staging_lab")


def drain_once(session_scope=None) -> int:
    """Open one authoritative session and drain all currently-queued fake work. Returns count.

    Uses the existing authoritative ``secp_api.db.session_scope`` (commit-on-success) so each
    drain runs in a real transaction. ``session_scope`` is injectable for tests.
    """
    if session_scope is None:
        from secp_api.db import session_scope as default_scope

        session_scope = default_scope
    processed = 0
    with session_scope() as session:
        processed = process_all_queued(session)
    return processed


def run_consumer_loop(
    stop_event: threading.Event,
    *,
    interval_seconds: float = 2.0,
    session_scope=None,
    max_ticks: int | None = None,
) -> int:
    """Poll at a bounded interval, draining fake staging-lab work until ``stop_event`` is set.

    Graceful: checks ``stop_event`` before each tick and uses it as an interruptible sleep, so a
    shutdown signal stops the loop promptly. ``max_ticks`` bounds the loop for tests. Returns the
    total number of work items processed. Each drain failure is logged and the loop continues.
    """
    total = 0
    ticks = 0
    while not stop_event.is_set():
        if max_ticks is not None and ticks >= max_ticks:
            break
        ticks += 1
        try:
            total += drain_once(session_scope=session_scope)
        except Exception as exc:  # pragma: no cover - defensive; loop must survive a bad tick
            logger.error("staging-lab consumer tick failed: %s", type(exc).__name__)
        # Interruptible sleep: wakes immediately when stop_event is set.
        stop_event.wait(interval_seconds)
    return total


def run_forever(stop_event: threading.Event | None = None) -> None:  # pragma: no cover - runtime
    """Entry point used by the worker process. Runs until the stop event is set."""
    from secp_api.config import get_settings

    settings = get_settings()
    stop_event = stop_event or threading.Event()
    logger.info(
        "staging-lab fake consumer loop started (interval=%ss, FAKE-ONLY, no infrastructure)",
        settings.staging_lab_poll_interval_seconds,
    )
    run_consumer_loop(stop_event, interval_seconds=settings.staging_lab_poll_interval_seconds)
    logger.info("staging-lab fake consumer loop stopped")
