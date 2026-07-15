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


def _start_deployment_consumer(stop_event: threading.Event) -> threading.Thread:
    """Start the deployment-operation consumer loop in a daemon thread (worker process only).

    SEALED composition in this PR: it claims queued deployment operations and invokes the engine,
    but
    fails closed at the bootstrap boundary before any network/SSH/host action. Contacts nothing.
    """
    from secp_worker.deployment.runtime import run_forever

    thread = threading.Thread(
        target=run_forever, args=(stop_event,), name="deployment-consumer", daemon=True
    )
    thread.start()
    return thread


def _start_discovery_consumer(stop_event: threading.Event) -> threading.Thread:
    """Start the read-only target-discovery consumer loop in a daemon thread (worker process only).

    DEFAULT-SEALED: it claims queued discovery jobs and invokes the READ-ONLY engine via
    ``build_discovery_composition()``, which contacts nothing unless the deployment-local,
    worker-owned controlled-integration profile is enabled AND a valid mounted bundle, host-key
    binding, approved worker identity, control-plane admission, and endpoint/authorization gates all
    pass — only then can it perform strictly READ-ONLY host contact. It imports no mutation-capable
    module and can never mutate.
    """
    from secp_worker.target_discovery.runtime import run_forever

    thread = threading.Thread(
        target=run_forever, args=(stop_event,), name="discovery-consumer", daemon=True
    )
    thread.start()
    return thread


def _start_discovery_bundle_prep(stop_event: threading.Event) -> threading.Thread:
    """Start the SECP-B8 worker-owned discovery bundle-prep loop in a daemon thread (worker only).

    Inert unless the deployment-local ``discovery_worker_managed_bundle`` profile is enabled. When
    enabled it generates + owns the worker SSH/admission keypairs (private halves never leave the
    worker), publishes ONLY the public material to the control plane, and assembles the mounted
    bundle from the secret-free descriptor. Contacts no Proxmox host and runs no probe.
    """
    from secp_worker.discovery_bundle_runtime import run_forever

    thread = threading.Thread(
        target=run_forever, args=(stop_event,), name="discovery-bundle-prep", daemon=True
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
        EligibilityPreflightWorkflow,
        PlanSecretReadinessWorkflow,
        RealPlanGenerationWorkflow,
        RemoteStateReadinessWorkflow,
        ResetWorkflow,
        ToolchainAttestationWorkflow,
        deploy_activity,
        destroy_activity,
        discover_activity,
        eligibility_preflight_activity,
        plan_secret_readiness_activity,
        real_plan_generation_activity,
        remote_state_readiness_activity,
        reset_activity,
        toolchain_attestation_activity,
    )

    settings = get_settings()
    client = await Client.connect(settings.temporal_host, namespace=settings.temporal_namespace)
    worker = Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[
            DeployWorkflow,
            ResetWorkflow,
            DestroyWorkflow,
            DiscoverWorkflow,
            EligibilityPreflightWorkflow,
            # B1B-PR4 attestation + readiness workflows are registered ONLY in the worker. The API
            # never imports them and can never execute them inline (the inline dispatcher refuses).
            ToolchainAttestationWorkflow,
            RemoteStateReadinessWorkflow,
            PlanSecretReadinessWorkflow,
            # B1B-PR5B real plan generation: worker-only. The plan-only code seal is now False, but
            # this STOPS at a redacted change set + a pending human approval — it never applies, and
            # the shipped composition is disabled so ordinary startup refuses before any execution.
            RealPlanGenerationWorkflow,
        ],
        activities=[
            deploy_activity,
            reset_activity,
            destroy_activity,
            discover_activity,
            # The plan/readiness activities below are the SHIPPED, always-SEALED default instances
            # (each constructed with its sealed composition provider in ``temporal_app``), so this
            # shipped worker refuses at the composition gate before any I/O. It polls ONLY
            # ``settings.temporal_task_queue``. A separately reviewed, deployment-local operator
            # worker (maintained OUTSIDE this repo) instead registers the controlled-live instances
            # built by ``operator_bootstrap.build_operator_activity_set`` under the SAME names, on
            # the DISTINCT ``operator_bootstrap.operator_task_queue(settings)`` queue (ADR-022 §12),
            # so controlled-live work routes deterministically to it and is never picked up here.
            eligibility_preflight_activity,
            toolchain_attestation_activity,
            remote_state_readiness_activity,
            plan_secret_readiness_activity,
            real_plan_generation_activity,
        ],
    )
    logger.info("Temporal worker started on task queue %s", settings.temporal_task_queue)
    # The fake staging-lab + read-only preflight + deployment consumers run in daemon threads.
    _start_staging_lab_consumer(stop_event)
    _start_readonly_preflight_consumer(stop_event)
    _start_deployment_consumer(stop_event)
    _start_discovery_consumer(stop_event)
    _start_discovery_bundle_prep(stop_event)
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
    # Read-only preflight + deployment consumers in daemon threads; staging-lab is the foreground
    # loop.
    _start_readonly_preflight_consumer(stop_event)
    _start_deployment_consumer(stop_event)
    _start_discovery_consumer(stop_event)
    _start_discovery_bundle_prep(stop_event)
    from secp_worker.staging_lab.runtime import run_forever

    run_forever(stop_event)  # pragma: no cover - long-running loop


if __name__ == "__main__":  # pragma: no cover
    main()
