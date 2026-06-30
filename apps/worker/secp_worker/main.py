"""Worker process entrypoint.

In ``temporal`` mode this hosts the durable workflows/activities. Without Temporal
configured it logs that the inline dispatcher handles orchestration in-process
(the API runs it synchronously) and stays alive as a health-reporting no-op so the
Compose service has a stable target. See ADR-005.
"""

from __future__ import annotations

import asyncio
import logging
import time

from secp_api.config import get_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secp.worker")


async def _run_temporal() -> None:  # pragma: no cover - requires Temporal server
    from temporalio.client import Client
    from temporalio.worker import Worker

    from secp_worker.temporal_app import (
        DeployWorkflow,
        DestroyWorkflow,
        ResetWorkflow,
        deploy_activity,
        destroy_activity,
        reset_activity,
    )

    settings = get_settings()
    client = await Client.connect(settings.temporal_host, namespace=settings.temporal_namespace)
    worker = Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[DeployWorkflow, ResetWorkflow, DestroyWorkflow],
        activities=[deploy_activity, reset_activity, destroy_activity],
    )
    logger.info("Temporal worker started on task queue %s", settings.temporal_task_queue)
    await worker.run()


def main() -> None:
    settings = get_settings()
    if settings.workflow_dispatch_mode == "temporal":
        try:
            asyncio.run(_run_temporal())
            return
        except Exception as exc:  # pragma: no cover
            logger.error("Temporal worker failed to start: %s", exc)

    logger.info(
        "Worker idle: dispatch mode is '%s'. Orchestration runs in-process via the "
        "inline dispatcher. This process stays alive for Compose health.",
        settings.workflow_dispatch_mode,
    )
    while True:  # pragma: no cover - long-running idle loop
        time.sleep(3600)


if __name__ == "__main__":  # pragma: no cover
    main()
