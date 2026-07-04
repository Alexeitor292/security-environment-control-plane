"""Worker process entrypoint.

In ``temporal`` mode this hosts the durable workflows/activities. Without Temporal
configured, orchestration for the legacy paths runs in-process via the inline dispatcher.

In BOTH modes the worker process additionally runs the FAKE-ONLY staging-lab consumer loop
(SECP-002B-1B-9): it drains committed, queued staging-lab work items, runs the fake executor,
and records observations/completion. This loop runs ONLY here in the worker process — never in
the API — and contacts no infrastructure. A later, separately reviewed real-adapter PR is
required before any provider action. See ADR-005 / ADR-015.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import threading

from secp_api.config import get_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secp.worker")


def _start_staging_lab_consumer(stop_event: threading.Event) -> threading.Thread:
    """Start the FAKE-ONLY staging-lab consumer loop in a daemon thread (worker process only)."""
    from secp_worker.staging_lab.runtime import run_forever

    thread = threading.Thread(
        target=run_forever, args=(stop_event,), name="staging-lab-consumer", daemon=True
    )
    thread.start()
    return thread


def _start_readonly_preflight_consumer(stop_event: threading.Event) -> threading.Thread:
    """Start the read-only preflight consumer loop in a daemon thread (worker process only).

    Fail-closed in this PR (sealed secret resolver -> credential_unavailable); contacts nothing.
    """
    from secp_worker.preflight.runtime import run_forever

    thread = threading.Thread(
        target=run_forever, args=(stop_event,), name="readonly-preflight-consumer", daemon=True
    )
    thread.start()
    return thread


def _install_signal_handlers(stop_event: threading.Event) -> None:  # pragma: no cover - signals
    def _handle(_signum, _frame):
        logger.info("shutdown signal received; stopping worker loops gracefully")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handle)
        except (ValueError, OSError):
            pass


async def _run_temporal(stop_event: threading.Event) -> None:  # pragma: no cover - needs Temporal
    from temporalio.client import Client
    from temporalio.worker import Worker

    from secp_worker.temporal_app import (
        DeployWorkflow,
        DestroyWorkflow,
        DiscoverWorkflow,
        ResetWorkflow,
        deploy_activity,
        destroy_activity,
        discover_activity,
        reset_activity,
    )

    settings = get_settings()
    client = await Client.connect(settings.temporal_host, namespace=settings.temporal_namespace)
    worker = Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[DeployWorkflow, ResetWorkflow, DestroyWorkflow, DiscoverWorkflow],
        activities=[deploy_activity, reset_activity, destroy_activity, discover_activity],
    )
    logger.info("Temporal worker started on task queue %s", settings.temporal_task_queue)
    # The fake staging-lab + read-only preflight consumers run in daemon threads alongside Temporal.
    _start_staging_lab_consumer(stop_event)
    _start_readonly_preflight_consumer(stop_event)
    await asyncio.gather(worker.run(), _run_outbox_publisher_loop())


def _publish_outbox_once() -> int:  # pragma: no cover - exercised by integration/runtime
    from secp_api.db import session_scope
    from secp_api.dispatch import WorkflowOutboxPublisher

    settings = get_settings()
    with session_scope() as session:
        return WorkflowOutboxPublisher(settings).publish_pending(session)


async def _run_outbox_publisher_loop() -> None:  # pragma: no cover - requires Temporal server
    while True:
        try:
            published = await asyncio.to_thread(_publish_outbox_once)
            if published:
                logger.info("Submitted %s committed workflow outbox record(s)", published)
        except Exception as exc:
            logger.error("Workflow outbox publisher failed: %s", exc)
        await asyncio.sleep(2.0)


def main() -> None:
    settings = get_settings()
    stop_event = threading.Event()
    _install_signal_handlers(stop_event)

    if settings.workflow_dispatch_mode == "temporal":
        try:
            asyncio.run(_run_temporal(stop_event))
            return
        except Exception as exc:  # pragma: no cover
            logger.error("Temporal worker failed to start: %s", exc)

    logger.info(
        "Worker mode '%s': legacy orchestration runs in-process via the inline dispatcher. "
        "Running the FAKE-ONLY staging-lab and read-only preflight consumer loops.",
        settings.workflow_dispatch_mode,
    )
    # Read-only preflight consumer in a daemon thread; staging-lab consumer as the foreground loop.
    _start_readonly_preflight_consumer(stop_event)
    from secp_worker.staging_lab.runtime import run_forever

    run_forever(stop_event)  # pragma: no cover - long-running loop


if __name__ == "__main__":  # pragma: no cover
    main()
