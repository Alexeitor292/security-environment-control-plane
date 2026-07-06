"""Worker-side runtime loop for the read-only discovery consumer (SECP-B5).

Runs inside the worker process ONLY. Periodically drains committed, queued discovery jobs by calling
the worker consumer, which invokes the READ-ONLY discovery engine with the SHIPPED SEALED
composition
— so the loop is wired end to end but contacts nothing (the sealed probe source refuses). It imports
no mutation-capable module and contacts no infrastructure. The API must never import or run this.
"""

from __future__ import annotations

import logging
import threading

from secp_worker.target_discovery.consumer import process_all_queued

logger = logging.getLogger("secp.worker.discovery")


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
    """Poll at a bounded interval, draining read-only discovery jobs until ``stop_event`` is set."""
    total = 0
    ticks = 0
    while not stop_event.is_set():
        if max_ticks is not None and ticks >= max_ticks:
            break
        ticks += 1
        try:
            total += drain_once(session_scope=session_scope)
        except Exception as exc:  # pragma: no cover - loop must survive a bad tick
            logger.error("discovery consumer tick failed: %s", type(exc).__name__)
        stop_event.wait(interval_seconds)
    return total


def run_forever(stop_event: threading.Event | None = None) -> None:  # pragma: no cover - runtime
    from secp_api.config import get_settings

    settings = get_settings()
    stop_event = stop_event or threading.Event()
    logger.info(
        "read-only discovery consumer loop started (interval=%ss, SEALED, no infrastructure)",
        settings.staging_lab_poll_interval_seconds,
    )
    run_consumer_loop(stop_event, interval_seconds=settings.staging_lab_poll_interval_seconds)
    logger.info("read-only discovery consumer loop stopped")
