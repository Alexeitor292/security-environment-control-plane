"""The operator-runnable CONTROLLED-LIVE QUEUE ISOLATION check (SECP-WS-E).

``verify`` answers *am I prepared?* and reports queue separation as one section among many.
This module answers the narrower question an operator actually has to answer before a
controlled-live milestone, and has to be able to answer WITHOUT submitting anything:

    *Is the controlled-live operator queue isolated from the queue the shipped worker polls, is
    the packaged operator unit dormant, and if a controlled-live workflow were submitted right
    now, what would stop it?*

The last part is the only honest form of a dry run for this package. A submission cannot be
"tried" — trying it is the thing that must never happen — so the answer is derived by OBSERVING
the reviewed code constants that would refuse, in the order they would be encountered along an
attempted controlled-live start. :func:`observe_submission_stops` reads those constants; it never
constructs a ``Worker``, builds a composition aggregate, calls ``run_plan_generation``, resolves a
credential, or contacts Temporal. Every ``closed`` boolean in the report is a value that was read,
not a value that was asserted in a docstring — and a stop that cannot be read at all is reported
``closed: False``, because an unobservable stop is not a stop.

FOUR INDEPENDENT FACTS, NEVER MERGED. The report keeps apart what a single "the operator side is
safe" boolean would hide:

* **isolation** (dimension B) — are both profile queues configured, and are they DISTINCT? A shared
  queue would let the shipped sealed ordinary worker pick up controlled-live work. Built by the SAME
  :func:`~secp_operator_deployment.verify._queue_section` ``verify`` uses, deliberately, so the two
  commands can never disagree about the same fact. It reads the **deployment profile** pair, and
  the report says so in ``isolation.authority`` — see below for why that distinction matters.
* **queue authority** (dimension B) — does the profile match the independent root-controlled pins,
  and do those pins name the queue the shipped worker is constructed to poll?
* **consumer dormancy** (dimension C) — is the packaged operator unit enabled or running? Observed
  from the host, not from configuration. This does not claim to discover arbitrary consumers.
* **submission stops** (dimensions D/E/F) — the reviewed code constants that would refuse.

Note that consumer dormancy here is NOT ``verify``'s ``operator_prepared_and_disabled`` rung. That
rung requires the operator unit to be PRESENT (a prepared host has it installed-but-disabled); this
check asks only whether that packaged unit is dormant, and an absent unit is dormant. The two
answers differ on exactly one host state — unit absent — and they differ correctly.

THE SAME TWO NAMES APPEAR IN THREE ARTEFACTS. This package's deployment
profile carries ``ordinary_task_queue`` / ``operator_task_queue``; the management plane's worker
EVIDENCE DOCUMENT carries the same two names for a different component; and a RUNNING worker
process polls ``Settings.temporal_task_queue`` / ``Settings.temporal_operator_task_queue``. This
check reports the profile-only fact in ``isolation`` and independently gates overall success on
``queue_authority``: profile == trusted pins, and trusted ordinary pin == shipped worker setting.

A green ``isolation`` section therefore describes the deployment MATERIAL, not the process. A green
overall status additionally requires the queue-authority binding above. The runtime
pair also differs IN KIND: this package requires a non-empty operator queue, while the runtime one
is empty by default AND the shipped worker entrypoint never reads it on any path — there, the
operator queue is disabled by STRUCTURAL ABSENCE rather than by configuration. So "operator queue
not configured" is a fault in this artefact and the correct, safe state in that one.

This is exactly why isolation, authority, and packaged-unit dormancy are separate facts here.

PURE, like :mod:`~secp_operator_deployment.verify`: the builders take already-resolved, exact-typed
inputs and do no filesystem I/O. The CLI resolves those inputs from the SAME fixed root-controlled
context ``verify`` uses, so this command adds no contact surface BEYOND ``verify``'s. There is no
queue argument and no queue name in the output: queue names are profile values, and this module —
the one most tempted to print them — never does.

WHAT "NO CONTACT SURFACE OF ITS OWN" DOES NOT MEAN. Resolving that context on a provisioned POSIX
host is not inert: it runs ``systemctl show`` and ``docker inspect``, and the health probe runs
``docker exec <ordinary-container> <health argv>``. Those are read-only and cannot submit, but they
ARE contact, and an earlier version of this report declared ``external_contact_performed: False``
unconditionally — false on precisely the host that matters. The report now DERIVES its contact
statement from a count taken while the commands run
(:class:`~secp_operator_deployment.production_context._CountingCommandRunner`), and the effects
section separates what was measured this invocation from what holds structurally.

One limit worth stating rather than leaving to be discovered: the health probe executes the
PROFILE-CONFIGURED health command inside the ordinary container. What that command does is outside
this package's control, so no claim here — measured or structural — extends to its side effects.
This report accounts for the commands THIS package runs, not for what they run in turn.
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
    QueueRung(
        "queue_authority_validated", "B", "queue_unverified", REMEDIATION_REVIEWED_DEPLOYMENT
    ),
    QueueRung("consumer_observable", "C", "queue_unverified", REMEDIATION_OPERATOR),
    QueueRung("operator_consumer_dormant", "C", "queue_operator_consuming", REMEDIATION_OPERATOR),
)


def _resolve_queue_status(
    *,
    stops_closed: bool,
    isolation_observable: bool,
    queues_isolated: bool,
    queue_authority_validated: bool,
    consumer_observable: bool,
    consumer_dormant: bool,
) -> str:
    """Resolve the queue status. The guard ORDER is the contract, and is proven against
    :data:`QUEUE_LADDER` over every combination of the six facts."""
    if not stops_closed:
        return "queue_stops_open"  # a reviewed stop is open or unreadable — escalate
    if not isolation_observable:
        return "queue_unverified"  # no parsed profile: isolation cannot be judged at all
    if not queues_isolated:
        return "queue_not_isolated"  # the configuration itself is unsafe
    if not queue_authority_validated:
        return "queue_unverified"  # profile/pins/worker binding was not established
    if not consumer_observable:
        return "queue_unverified"  # the host could not be observed coherently
    if not consumer_dormant:
        return "queue_operator_consuming"
    return "queue_isolated_and_dormant"


def build_queue_report(
    *,
    profile: object | None = None,
    expected: object | None = None,
    host_observation: object | None = None,
    stops: list[dict] | None = None,
    host_commands_executed: int = 0,
) -> dict:
    """Build the deterministic, secret-free CONTROLLED-LIVE QUEUE report.

    PURE + exact-typed: ``profile``, ``expected`` and ``host_observation`` are pre-resolved exact
    types (or ``None``), and foreign objects are refused without attribute access. ``stops`` is
    injectable so a test can drive an OPEN stop without touching a reviewed constant; the
    production CLI never passes it, so the real command always observes.
    """
    from secp_operator_deployment.profile import DeploymentProfile

    if profile is not None and type(profile) is not DeploymentProfile:
        profile = None
    profile_parsed = profile is not None

    isolation = _queue_section(profile_parsed, profile)
    authority = _queue_authority_section(profile_parsed, profile, expected)
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
        queue_authority_validated=bool(authority["validated"]),
        consumer_observable=consumer_observable,
        consumer_dormant=consumer_dormant,
    )

    return {
        "phase": "queue",
        "status": status,
        "exit_code": QUEUE_EXIT_CODES[status],
        "isolation": isolation,
        "queue_authority": authority,
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
        # Split because the two halves have DIFFERENT epistemic status, and merging them is how a
        # measured fact lends its credibility to an assumed one.
        "effects_of_this_queue_check": {
            # COUNTED during this invocation — see production_context._CountingCommandRunner.
            "measured_this_invocation": {
                "host_commands_executed": int(host_commands_executed),
                "local_host_contact_performed": int(host_commands_executed) > 0,
            },
            # NOT measured, and no longer LABELLED as though it were. These are properties of the
            # SHIPPED SOURCE, not observations of this invocation: nothing reaching this builder
            # carries them, so a literal here can only ever restate the author's belief. They are
            # kept because they are the properties an operator actually needs — but each one now
            # names the guard that OWNS its proof, so a reader can go read that proof instead of
            # trusting this dict. ``owning_guards`` is keyed by property for exactly that reason: a
            # single blanket citation would let one guard's credibility cover properties it never
            # touches, which is the substitution this whole module exists to refuse.
            "code_structural_properties": {
                "worker_constructed": False,
                "workflow_submitted": False,
                "run_plan_generation_called": False,
                "secret_resolver_constructed": False,
                "composition_aggregate_built": False,
                "basis": "shipped_source_structure_not_this_invocation",
                "owning_guards": {
                    "worker_constructed": (
                        "test_deployment_boundary."
                        "test_runner_and_compositions_never_construct_a_worker"
                    ),
                    "workflow_submitted": (
                        "test_deployment_boundary.test_no_temporalio_imports_anywhere"
                    ),
                    "run_plan_generation_called": (
                        "test_deployment_r4_regressions."
                        "test_no_apply_destroy_or_run_plan_generation_in_package"
                    ),
                    "secret_resolver_constructed": (
                        "test_deployment_boundary.test_all_seals_remain_as_required"
                    ),
                    "composition_aggregate_built": (
                        "test_operator_queue_isolation."
                        "test_the_queue_command_submits_nothing_and_starts_no_consumer"
                    ),
                },
            },
            # ``host_mutated: False`` WAS a sixth literal here and is REMOVED, not relabelled.
            # It was the one actively MISLEADING value in this report. This package does spawn
            # subprocesses, and one argv tail — ``profile.ordinary_health_command``, executed as
            # ``exec <container> <health argv>`` — is DEPLOYMENT-SUPPLIED. Whether that command
            # mutates the host is outside this package's competence to answer, and the
            # expected-identities pin does not close it: that pin constrains DRIFT from the expected
            # argv, never what the expected argv DOES. So no claim is made, and the absence of a
            # claim is itself reported rather than left as a silently missing key.
            "host_mutation": {
                "claimed": None,
                "basis": "health_argv_is_deployment_supplied_and_not_inspectable_here",
            },
        },
    }


def _queue_authority_section(
    profile_parsed: bool, profile: object | None, expected: object | None
) -> dict:
    """Prove profile == independent pins == the ordinary queue the shipped worker polls."""
    from secp_operator_deployment.identities import (
        ExpectedDeploymentIdentities,
        require_queue_authority,
    )

    expected_provided = type(expected) is ExpectedDeploymentIdentities
    validated = False
    reason: str | None = None
    if not profile_parsed:
        reason = "queue_separation_unavailable"
    elif not expected_provided:
        reason = "expected_identities_not_provisioned"
    else:
        try:
            require_queue_authority(profile, expected)  # type: ignore[arg-type]
            validated = True
        except Exception as exc:
            reason = getattr(exc, "reason_code", "identity_mismatch")

    return {
        "validated": validated,
        "expected_provided": expected_provided,
        "authority": "deployment_profile_expected_pins_and_worker_setting",
        "reason_code": reason,
    }


def _consumer_reason(observable: bool, dormant: bool, host: dict) -> str | None:
    if not observable:
        return host.get("reason_code") or "operator_consumer_unobservable"
    if not dormant:
        return "operator_consumer_active"
    return None
