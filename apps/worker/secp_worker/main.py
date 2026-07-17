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

# The 9 durable WORKFLOW classes come from the import-clean secp_worker.temporal_workflows (the
# module
# Temporal's workflow sandbox re-imports during validation); the ACTIVITY callables come from the
# host-only secp_worker.temporal_app (the SHIPPED, always-SEALED default instances). Keeping both
# name
# lists here — and constructing the ordinary Worker from them — is the single shipped registration.
from secp_worker.temporal_app import (
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
from secp_worker.temporal_workflows import (
    DeployWorkflow,
    DestroyWorkflow,
    DiscoverWorkflow,
    EligibilityPreflightWorkflow,
    PlanSecretReadinessWorkflow,
    RealPlanGenerationWorkflow,
    RemoteStateReadinessWorkflow,
    ResetWorkflow,
    ToolchainAttestationWorkflow,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secp.worker")

# The EXACT set the SHIPPED ordinary worker registers on ``settings.temporal_task_queue`` (only).
# The
# activities are the always-SEALED default instances — never the controlled-live operator set (which
# a
# separate, deployment-local operator worker builds via ``operator_bootstrap`` on a DISTINCT queue).
SHIPPED_WORKFLOWS: tuple = (
    DeployWorkflow,
    ResetWorkflow,
    DestroyWorkflow,
    DiscoverWorkflow,
    EligibilityPreflightWorkflow,
    # B1B-PR4 attestation + readiness workflows are registered ONLY in the worker. The API never
    # imports them and can never execute them inline (the inline dispatcher refuses).
    ToolchainAttestationWorkflow,
    RemoteStateReadinessWorkflow,
    PlanSecretReadinessWorkflow,
    # B1B-PR5B real plan generation: worker-only. The plan-only code seal is False, but this STOPS
    # at a
    # redacted change set + a pending human approval — it never applies, and the shipped composition
    # is
    # disabled so ordinary startup refuses before any execution.
    RealPlanGenerationWorkflow,
)
SHIPPED_ACTIVITIES: tuple = (
    deploy_activity,
    reset_activity,
    destroy_activity,
    discover_activity,
    # The plan/readiness activities are the SHIPPED, always-SEALED default instances (each
    # constructed
    # with its sealed composition provider in ``temporal_app``), so the shipped worker refuses at
    # the
    # composition gate before any I/O. A reviewed operator worker registers the controlled-live
    # instances under the SAME names on a DISTINCT queue — never here.
    eligibility_preflight_activity,
    toolchain_attestation_activity,
    remote_state_readiness_activity,
    plan_secret_readiness_activity,
    real_plan_generation_activity,
)


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

    from secp_worker import health

    settings = get_settings()
    # ANY failure below (client connect, workflow/activity validation inside Worker(...),
    # worker.run, or the publisher) propagates out of this coroutine; ``main`` then exits the
    # process non-zero. Nothing here falls back to legacy in-process orchestration.
    client = await Client.connect(settings.temporal_host, namespace=settings.temporal_namespace)
    # The shipped ordinary worker polls ONLY ``settings.temporal_task_queue`` (secp-orchestration)
    # and registers ONLY the SEALED default activities — never the controlled-live operator set,
    # which a separate, deployment-local operator worker builds on a DISTINCT queue
    # (``settings.temporal_operator_task_queue``; this entrypoint never reads it, so no path here —
    # success or failure — can poll or fall back to the operator queue).
    worker = Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=list(SHIPPED_WORKFLOWS),
        activities=list(SHIPPED_ACTIVITIES),
    )
    # Begin polling as a task so an IMMEDIATE ``worker.run`` failure (raising before it has entered
    # functional polling) surfaces HERE, BEFORE readiness is ever marked. If we marked ready first
    # and then awaited run(), a run() that fails immediately would leave the marker briefly visible
    # on disk while this (still-alive) process is actually dying — a health probe could observe a
    # false "ready". Yielding once lets a synchronously-immediate failure complete; we re-raise it
    # WITHOUT calling mark_ready, so on that path the marker is never written and never observable.
    worker_task = asyncio.ensure_future(worker.run())
    await asyncio.sleep(0)
    if worker_task.done():
        worker_task.result()  # re-raises an immediate startup failure; readiness never marked
        return  # a clean immediate return (no real worker does this) is a shutdown -> exit 0
    logger.info("Temporal worker started on task queue %s", settings.temporal_task_queue)
    # Only now — Worker validated, constructed on the ordinary queue, and CONFIRMED running — do the
    # sealed/fake-only daemon consumers start and readiness flip TRUE. Readiness is cleared on ANY
    # exit (finally), and flips false anyway if this process dies (the marker records our PID and
    # ``health.is_ready`` re-checks that it is still alive).
    _start_staging_lab_consumer(stop_event)
    _start_readonly_preflight_consumer(stop_event)
    _start_deployment_consumer(stop_event)
    _start_discovery_consumer(stop_event)
    _start_discovery_bundle_prep(stop_event)
    health.mark_ready(settings.temporal_task_queue)
    try:
        await asyncio.gather(worker_task, _run_outbox_publisher_loop())
    finally:
        health.clear_ready()


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
        # TEMPORAL MODE IS TERMINAL AND FAIL-CLOSED. It either runs to a clean shutdown (exit 0) or,
        # on ANY failure — Temporal client connect, workflow/activity validation, Worker
        # construction,
        # worker.run, or the outbox publisher — it exits NON-ZERO. It MUST NEVER fall back to the
        # inline dispatcher or the legacy in-process consumer loops below: a failed Temporal worker
        # has to die so the deployment restarts it, not masquerade as healthy (the exact defect this
        # hotfix closes). ``return`` is OUTSIDE the ``try`` so a clean shutdown still exits 0 and
        # the
        # legacy block is unreachable from temporal mode by construction.
        try:
            asyncio.run(_run_temporal(stop_event))
        except Exception:
            # Every required failure mode (client connect, workflow/activity validation, Worker
            # construction, worker.run, publisher) is an ``Exception`` subclass and lands here. A
            # legitimate ``SystemExit`` / ``KeyboardInterrupt`` (clean shutdown) is NOT caught and
            # propagates unchanged.
            logger.exception(
                "Temporal worker failed; refusing to fall back to legacy in-process orchestration"
            )
            stop_event.set()  # signal any daemon consumers that were started before the failure
            raise SystemExit(1) from None
        return

    # INLINE / DEV mode ONLY. This branch is reached ONLY when ``workflow_dispatch_mode`` explicitly
    # selects the reviewed development/test inline mode — NEVER as an exception fallback from
    # temporal
    # mode (that path exits non-zero above).
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
