"""The operator-runnable CONTROLLED-LIVE QUEUE ISOLATION check (SECP-WS-E).

``verify`` answers *am I prepared?* and reports queue separation as one section among many.
This module answers the narrower question an operator actually has to answer before a
controlled-live milestone, and has to be able to answer WITHOUT submitting anything:

    *Is the controlled-live operator queue isolated from the ordinary queue, is anything
    consuming it, and if a controlled-live workflow were submitted right now, what would stop
    it?*

The last part is the only honest form of a dry run for this package. A submission cannot be
"tried" — trying it is the thing that must never happen — so the answer is derived by OBSERVING
the reviewed code constants that would refuse, in the order they would be encountered along an
attempted controlled-live start. :func:`observe_submission_stops` reads those constants; it never
constructs a ``Worker``, builds a composition aggregate, calls ``run_plan_generation``, resolves a
credential, or contacts Temporal. Every ``closed`` boolean in the report is a value that was read,
not a value that was asserted in a docstring — and a stop that cannot be read at all is reported
``closed: False``, because an unobservable stop is not a stop.

THREE INDEPENDENT FACTS, NEVER MERGED. The report keeps apart what a single "the operator side is
safe" boolean would hide:

* **isolation** (dimension B) — are both queues configured, and are they DISTINCT? A shared queue
  would let the shipped sealed ordinary worker pick up controlled-live work. Built by the SAME
  :func:`~secp_operator_deployment.verify._queue_section` ``verify`` uses, deliberately, so the two
  commands can never disagree about the same fact.
* **consumer dormancy** (dimension C) — is anything actually polling the operator queue? Observed
  from the host, not from configuration.
* **submission stops** (dimensions D/E/F) — the reviewed code constants that would refuse.

Note that consumer dormancy here is NOT ``verify``'s ``operator_prepared_and_disabled`` rung. That
rung requires the operator unit to be PRESENT (a prepared host has it installed-but-disabled); this
check asks only whether anything CONSUMES the queue, and an absent unit consumes nothing. The two
answers differ on exactly one host state — unit absent — and they differ correctly.

PURE, like :mod:`~secp_operator_deployment.verify`: the builders take already-resolved, exact-typed
inputs and do no filesystem I/O. The CLI resolves those inputs from the SAME fixed root-controlled
context ``verify`` uses, so this command adds no contact surface of its own. There is no queue
argument and no queue name in the output: queue names are profile values, and this module — the one
most tempted to print them — never does.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_operator_deployment.verify import (
    REMEDIATION_OPERATOR,
    REMEDIATION_REVIEWED_CODE,
    REMEDIATION_REVIEWED_DEPLOYMENT,
    _host_section,
    _queue_section,
)

# Queue-check status classes → stable exit codes. ``queue_stops_open`` shares 20 with
# ``seals_unsafe``: both mean a reviewed stop is not where it must be, and both mean escalate.
QUEUE_EXIT_CODES = {
    "queue_isolated_and_dormant": 0,
    "queue_unverified": 10,
    "queue_not_isolated": 12,
    "queue_operator_consuming": 14,
    "queue_stops_open": 20,
}


@dataclass(frozen=True)
class SubmissionStop:
    """One reviewed code constant that would refuse an attempted controlled-live start.

    Pure metadata. ``reason_code`` is the bounded code the REAL path refuses with when the stop
    fires — the same code an operator would meet in a log — so the preview and the real refusal
    name the same thing.
    """

    id: str
    stops: str
    reason_code: str
    remediation: str


# In the order they would be encountered along an attempted controlled-live start: the fixed
# entrypoint builds the composition aggregate BEFORE it calls the run hook, and the plan-execution
# gate is only reached by a worker that already exists. Stop 2 is what keeps stop 1 closed even if
# a runtime were injected, so it is reported next to it rather than last.
SUBMISSION_STOPS: tuple[SubmissionStop, ...] = (
    SubmissionStop(
        "shipped_runtime_sealed",
        "the no-argument controlled-live composition build",
        "controlled_live_runtime_not_provisioned",
        REMEDIATION_REVIEWED_CODE,
    ),
    SubmissionStop(
        "reviewed_runtime_provider_set_empty",
        "any runtime-provisioning attestation validating",
        "attestation_provider_not_reviewed",
        REMEDIATION_REVIEWED_CODE,
    ),
    SubmissionStop(
        "operator_activation_seal",
        "the operator worker being constructed, so nothing polls the operator queue",
        "operator_activation_sealed",
        REMEDIATION_REVIEWED_CODE,
    ),
    SubmissionStop(
        "plan_execution_gate_default_disabled",
        "the shipped plan-execution composition, before any external contact",
        "plan_gate_disabled",
        REMEDIATION_REVIEWED_CODE,
    ),
)

# Raised when a stop's constant cannot be READ at all (a partial or broken install). Fail closed:
# an unobservable stop is reported open, which resolves to exit 20 — escalate. It is classified
# ``reviewed_code_change`` because there is no operator flag that makes a reviewed constant
# readable again; the resolution is a reinstall or a reviewed change, not a setting.
STOP_UNOBSERVABLE = "submission_stop_unobservable"


def _observe_shipped_runtime_sealed() -> tuple[bool, dict]:
    # Construct the SHIPPED sealed runtime class directly and ask it. Deliberately NOT through
    # ``production_context._load_installed_runtime()``: that would execute whatever runtime a
    # deployment installed, and this check must never run installed provider code.
    from secp_operator_deployment.runtime_seams import SealedControlledLiveRuntime

    provisioned = bool(SealedControlledLiveRuntime().provisioned())
    return (not provisioned), {"shipped_runtime_provisioned": provisioned}


def _observe_reviewed_provider_set_empty() -> tuple[bool, dict]:
    from secp_operator_deployment.runtime_seams import REVIEWED_RUNTIME_PROVIDERS

    count = len(REVIEWED_RUNTIME_PROVIDERS)
    return (count == 0), {"reviewed_runtime_provider_count": count}


def _observe_operator_activation_seal() -> tuple[bool, dict]:
    from secp_operator_deployment.runner import _OPERATOR_ACTIVATION_SEALED

    sealed = bool(_OPERATOR_ACTIVATION_SEALED)
    return sealed, {"operator_activation_sealed": sealed}


def _observe_plan_gate_default_disabled() -> tuple[bool, dict]:
    # The SHIPPED default of the reviewed gate dataclass — not an instance someone handed us.
    from secp_worker.plan_gen.composition import PlanExecutionGate

    enabled = bool(PlanExecutionGate().enabled)
    return (not enabled), {"shipped_plan_execution_gate_enabled": enabled}


_OBSERVERS = {
    "shipped_runtime_sealed": _observe_shipped_runtime_sealed,
    "reviewed_runtime_provider_set_empty": _observe_reviewed_provider_set_empty,
    "operator_activation_seal": _observe_operator_activation_seal,
    "plan_execution_gate_default_disabled": _observe_plan_gate_default_disabled,
}


def observe_submission_stops() -> list[dict]:
    """Read every reviewed stop constant and report what was READ.

    Contacts nothing and constructs no worker, composition aggregate, resolver or client. Each row
    carries the observed value(s) alongside the verdict, so a reader can check the verdict against
    the observation rather than taking it. A read that raises yields ``closed: False`` with
    :data:`STOP_UNOBSERVABLE` — never a silently-passed stop.
    """
    rows: list[dict] = []
    for spec in SUBMISSION_STOPS:
        try:
            closed, observed = _OBSERVERS[spec.id]()
            unobservable: str | None = None
        except Exception:
            closed, observed, unobservable = False, {}, STOP_UNOBSERVABLE
        rows.append(
            {
                "id": spec.id,
                "closed": bool(closed),
                "stops": spec.stops,
                "refusal_reason_code": spec.reason_code,
                "remediation": spec.remediation,
                "observed": observed,
                "reason_code": unobservable,
            }
        )
    return rows


@dataclass(frozen=True)
class QueueRung:
    """One rung of the queue check, in the SAME priority order :func:`_resolve_queue_status`
    evaluates. ``status_when_unmet`` is the EXACT status returned when this is the first unmet
    rung — an invariant proven exhaustively over the whole fact vector, not asserted here."""

    id: str
    dimension: str
    status_when_unmet: str
    remediation: str


QUEUE_LADDER: tuple[QueueRung, ...] = (
    QueueRung("submission_stops_closed", "F", "queue_stops_open", REMEDIATION_REVIEWED_CODE),
    QueueRung("isolation_observable", "B", "queue_unverified", REMEDIATION_REVIEWED_DEPLOYMENT),
    QueueRung("queues_isolated", "B", "queue_not_isolated", REMEDIATION_REVIEWED_DEPLOYMENT),
    QueueRung("consumer_observable", "C", "queue_unverified", REMEDIATION_OPERATOR),
    QueueRung("operator_consumer_dormant", "C", "queue_operator_consuming", REMEDIATION_OPERATOR),
)


def _resolve_queue_status(
    *,
    stops_closed: bool,
    isolation_observable: bool,
    queues_isolated: bool,
    consumer_observable: bool,
    consumer_dormant: bool,
) -> str:
    """Resolve the queue status. The guard ORDER is the contract, and is proven against
    :data:`QUEUE_LADDER` over every combination of the five facts."""
    if not stops_closed:
        return "queue_stops_open"  # a reviewed stop is open or unreadable — escalate
    if not isolation_observable:
        return "queue_unverified"  # no parsed profile: isolation cannot be judged at all
    if not queues_isolated:
        return "queue_not_isolated"  # the configuration itself is unsafe
    if not consumer_observable:
        return "queue_unverified"  # the host could not be observed coherently
    if not consumer_dormant:
        return "queue_operator_consuming"
    return "queue_isolated_and_dormant"


def build_queue_report(
    *,
    profile: object | None = None,
    host_observation: object | None = None,
    stops: list[dict] | None = None,
) -> dict:
    """Build the deterministic, secret-free CONTROLLED-LIVE QUEUE report.

    PURE + exact-typed: ``profile`` and ``host_observation`` are pre-resolved exact types (or
    ``None``) and a foreign object is refused without attribute access. ``stops`` is injectable so
    a test can drive an OPEN stop without touching a reviewed constant; the production CLI never
    passes it, so the real command always observes.
    """
    from secp_operator_deployment.profile import DeploymentProfile

    if profile is not None and type(profile) is not DeploymentProfile:
        profile = None
    profile_parsed = profile is not None

    isolation = _queue_section(profile_parsed, profile)
    host = _host_section(host_observation)
    stop_rows = observe_submission_stops() if stops is None else [dict(r) for r in stops]

    first_open = next((r["id"] for r in stop_rows if not r["closed"]), None)
    first_closed = next((r for r in stop_rows if r["closed"]), None)
    stops_closed = first_open is None and bool(stop_rows)

    consumer_observable = bool(
        host.get("attempted") and host.get("inspected") and host.get("coherent")
    )
    # Dormant = nothing polls the queue and nothing will at boot. Deliberately NOT the same as
    # verify's ``operator_prepared_and_disabled``, which also requires the unit to be PRESENT.
    enabled = bool(host.get("operator_enabled"))
    running = bool(host.get("operator_running"))
    consumer_dormant = consumer_observable and not enabled and not running

    consumer = {
        "observed": consumer_observable,
        "unit_present": bool(host.get("operator_present")) if consumer_observable else None,
        "unit_enabled": enabled if consumer_observable else None,
        "unit_running": running if consumer_observable else None,
        "dormant": consumer_dormant,
        "reason_code": _consumer_reason(consumer_observable, consumer_dormant, host),
    }

    status = _resolve_queue_status(
        stops_closed=stops_closed,
        isolation_observable=profile_parsed,
        queues_isolated=bool(isolation["ok"]),
        consumer_observable=consumer_observable,
        consumer_dormant=consumer_dormant,
    )

    return {
        "phase": "queue",
        "status": status,
        "exit_code": QUEUE_EXIT_CODES[status],
        "isolation": isolation,
        "operator_consumer": consumer,
        "submission_stops": {
            "ladder": stop_rows,
            "all_closed": stops_closed,
            "first_open": first_open,
            "first_open_reason_code": "submission_stop_open" if first_open else None,
            "closed_count": sum(1 for r in stop_rows if r["closed"]),
            "total_count": len(stop_rows),
        },
        # The only honest dry run available here: what WOULD refuse, derived from the observations
        # above. Nothing was submitted to find out — see ``effects_of_this_queue_check``.
        "submission_preview": {
            "submission_performed": False,
            "would_be_refused": first_closed is not None,
            "first_refusing_stop": first_closed["id"] if first_closed else None,
            "refusal_reason_code": first_closed["refusal_reason_code"] if first_closed else None,
            "consumer_would_poll_operator_queue": (not consumer_dormant)
            if consumer_observable
            else None,
            "basis": "observed_reviewed_code_constants",
        },
        "effects_of_this_queue_check": {
            "worker_constructed": False,
            "workflow_submitted": False,
            "run_plan_generation_called": False,
            "secret_resolver_constructed": False,
            "composition_aggregate_built": False,
            "external_contact_performed": False,
            "host_mutated": False,
        },
    }


def _consumer_reason(observable: bool, dormant: bool, host: dict) -> str | None:
    if not observable:
        return host.get("reason_code") or "operator_consumer_unobservable"
    if not dormant:
        return "operator_consumer_active"
    return None
