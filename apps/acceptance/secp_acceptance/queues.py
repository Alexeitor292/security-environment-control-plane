"""The queues stage: ordinary-queue execution, and operator-queue isolation.

This is the most safety-sensitive of the nine evidence stages, and the one an adversarial reader
will attack hardest. Three attacks in particular shaped every decision below, and each is named at
the place it is answered:

1. **Queue confusion.** There is no single "operator queue". THREE artefacts own a name, in three
   different planes, and they are not interchangeable:

   * ``Settings.temporal_operator_task_queue`` — the RUNTIME setting. Its default is the empty
     string AND ``secp_worker.main._run_temporal`` never reads it on any path, so the runtime
     operator queue is disabled by STRUCTURAL ABSENCE. There is nothing here to probe.
   * ``secp_management.topology.OPERATOR_TASK_QUEUE`` — a PRODUCT constant, and the name
     ``real_adapters._observe_queue_containment`` actually tests the worker's self-report against.
   * the deployment profile's ``operator_task_queue`` — DEPLOYMENT-LOCAL, required non-empty and
     distinct from the ordinary queue.

   A harness that pinned one literal would prove isolation for a queue the deployment may not use —
   which is the confusion attack, dressed as a passing test. So this module probes the UNION of the
   last two, restates neither (one is imported, the other is read off the installed host), and
   refuses to conclude anything from an empty union.

2. **Dormancy inferred from configuration agreement.** Two constants agreeing with each other is
   not an observation of a host. Every claim here about what is or is not polling comes from the
   Temporal server — an authority that is neither the worker nor the deployment artefact — or, for
   the operator unit, from ``systemctl`` on the worker host, classified by the PRODUCT's own
   classifiers rather than by a table restated here.

3. **A green result that would stay green if the worker really did poll the operator queue.** The
   defence is structural: :func:`observe_pollers` takes the queue as an ARGUMENT and compares it
   against no constant, so the same code path answers for both queues and the container tier can
   swap the two arguments and require the answers to differ. Hermetically,
   :func:`resolve_operator_isolation` is proven to return ``violated`` on a projection that reports
   a poller, so the check demonstrably CAN fail.

WHY THE VERDICT VOCABULARY IS THE PRODUCT'S
-------------------------------------------
:data:`VERDICT_HELD` / :data:`VERDICT_VIOLATED` / :data:`VERDICT_UNPROVABLE` are ALIASES bound to
``secp_management.adapters.CONTAINMENT_*``. They are not copies. The containment probe's verdict
therefore passes through this module with no translation at all, and a product-side rename breaks
the harness build instead of silently detaching the harness's vocabulary from the plane it is
supposed to be describing.

The three words generalise cleanly to all six checks, which is why every producer here returns one
of them: *the positive claim held* / *the claim was observed FALSE* / *the claim could not be
observed*. ``violated`` is a POSITIVE observation of the bad thing and is emphatically not the same
as ``unprovable`` — collapsing them would make the most serious finding this stage can produce
indistinguishable from a transport error.

Each of the three now reaches its OWN evidence outcome (``observed`` / ``violated`` / ``unproven``),
so that distinction survives all the way into the document. It did not always: ``violated`` and
``unprovable`` briefly shared ``unproven``, separated only by reason code, because the contract had
no outcome for a proven breach. Worth knowing that the fix was not merely adding the fourth outcome
— both pass predicates were DENYLISTS ("no unproven"), so any outcome added to the closed set
became a passing one by default, and a proven violation sealed and loaded clean as ``passed``. The
allowlist over ``PASSING_OUTCOMES`` is what makes the fourth outcome safe, and it is why nothing
here checks for "not unproven" by hand.

WHAT THIS MODULE DOES NOT DO
----------------------------
It starts no worker, submits nothing to any operator queue, contacts no provider, and runs no
OpenTofu. It is PURE: every function takes an already-captured bounded projection or a typed seam,
and performs no I/O of its own. Submitting harmless work to the operator queue to watch it sit
unclaimed WOULD be a stronger functional proof of non-polling, and it is deliberately not done: if
an operator consumer did exist, that submission is precisely the controlled-live execution this
whole program exists to prevent.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from secp_acceptance import AcceptanceError
from secp_acceptance.evidence import observation_digest
from secp_acceptance.reasons import (
    ALL_REASONS,
    CHECKS_BY_STAGE,
    OUTCOME_OBSERVED,
    OUTCOME_UNPROVEN,
    OUTCOME_VIOLATED,
    STAGE_QUEUES,
)

# --------------------------------------------------------------------------- the verdict vocabulary


def _product_containment_verdicts() -> tuple[str, str, str]:
    """Bind the harness vocabulary to the PRODUCT's, rather than copying its three strings.

    Imported through a function so the binding is re-evaluated (and re-provable) rather than frozen
    into a literal at authoring time. A rename in ``secp_management.adapters`` fails here — loudly,
    at import of this module — instead of leaving the harness quietly describing a vocabulary the
    plane no longer uses.
    """
    from secp_management.adapters import (
        CONTAINMENT_BREACHED,
        CONTAINMENT_CONTAINED,
        CONTAINMENT_UNPROVABLE,
    )

    return CONTAINMENT_CONTAINED, CONTAINMENT_BREACHED, CONTAINMENT_UNPROVABLE


#: ``held`` — the check's positive claim was observed to hold (the product says ``contained``).
#: ``violated`` — the observation was MADE and the claim is false (the product: ``breached``).
#: ``unprovable`` — the observation could not be made. Never a pass, and never a violation.
VERDICT_HELD, VERDICT_VIOLATED, VERDICT_UNPROVABLE = _product_containment_verdicts()

#: The closed set, in the product's own order.
VERDICTS: tuple[str, ...] = (VERDICT_HELD, VERDICT_VIOLATED, VERDICT_UNPROVABLE)


@dataclass(frozen=True)
class QueueVerdict:
    """One check's outcome: a verdict, its bounded cause, and the projection it was derived from.

    ``cause`` is REQUIRED for ``violated`` and ``unprovable`` and FORBIDDEN for ``held`` — the same
    coherence rule :class:`~secp_acceptance.evidence.CheckRecord` applies, enforced at construction
    so an incoherent verdict cannot travel as far as the recorder.
    """

    verdict: str
    cause: str | None = None
    observation: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise AcceptanceError("acceptance_evidence_invalid")
        if self.verdict == VERDICT_HELD:
            if self.cause is not None:
                raise AcceptanceError("acceptance_evidence_invalid")
        else:
            if self.cause is None:
                raise AcceptanceError("acceptance_evidence_invalid")
            if self.cause not in ALL_REASONS:
                raise AcceptanceError("acceptance_evidence_unknown_reason")


# --------------------------------------------------------------------------- THE encoding table
#
# THE single point of change for how a verdict becomes an evidence record: one table, one function,
# one recorder call. ``violated`` used to share ``unproven`` here, because the contract had no
# outcome meaning "a positive observation of the bad thing"; the contract now has one, and adopting
# it moved exactly the row below and nothing else in the stage.
#
# Why the ``violated`` reason is FIXED rather than the producer's own code: the contract carries a
# single ``acceptance_prohibited_state_observed`` for every violated check, on the reasoning that
# the CHECK ID already names the property that was violated and a per-check code set would grow
# past review. The producer's more specific cause is not discarded, though — ``record_verdict``
# puts it in the bounded observation, so it survives into what the check asserted on rather than
# being silently dropped on the way to the document.

#: verdict -> (evidence outcome, fixed reason code, or None meaning "the producer supplies it").
VERDICT_ENCODING: dict[str, tuple[str, str | None]] = {
    VERDICT_HELD: (OUTCOME_OBSERVED, None),
    VERDICT_VIOLATED: (OUTCOME_VIOLATED, "acceptance_prohibited_state_observed"),
    # The cause is whatever stopped the observation, so it comes from the producer, not from here.
    VERDICT_UNPROVABLE: (OUTCOME_UNPROVEN, None),
}

#: verdict -> the recorder/run verb that records it. Kept beside the table rather than as a chain
#: of ``if``s so that adding an outcome means adding a row in two adjacent dicts, and a verdict with
#: no verb fails loudly instead of falling through to a default.
VERDICT_VERB: dict[str, str] = {
    VERDICT_HELD: "observe",
    VERDICT_VIOLATED: "violated",
    VERDICT_UNPROVABLE: "unproven",
}


def encode_verdict(verdict: QueueVerdict) -> tuple[str, str | None]:
    """Map ONE verdict to its ``(outcome, reason_code)`` evidence encoding.

    The only place in the stage that decides what a verdict means to a reader. ``held`` is the only
    verdict that can produce a pass; every other row resolves to an outcome outside
    :data:`~secp_acceptance.reasons.PASSING_OUTCOMES`.
    """
    if verdict.verdict not in VERDICT_ENCODING:  # pragma: no cover - QueueVerdict already refuses
        raise AcceptanceError("acceptance_evidence_invalid")
    outcome, fixed_reason = VERDICT_ENCODING[verdict.verdict]
    if outcome == OUTCOME_OBSERVED:
        return outcome, None
    return outcome, fixed_reason or verdict.cause


def record_verdict(
    run: object, check: str, verdict: QueueVerdict, *, stage: str = STAGE_QUEUES
) -> None:
    """Record ONE check through the encoding above. The queues stage's only recording call.

    ``run`` is duck-typed on the verb surface deliberately: :class:`AcceptanceRecorder` and
    :class:`~secp_acceptance.run.AcceptanceRun` expose the same ``observe`` / ``violated`` /
    ``unproven`` signatures, so the stage works against either without this module having to know
    which layer it was handed.

    ``stage`` defaults to the queues stage but is a parameter because
    :func:`resolve_operator_unit_dormant` is genuinely wanted by the worker-install stage for
    ``worker_operator_unit_present_disabled_stopped`` — the same observation, asked at a different
    point in the run. A second implementation of operator-unit dormancy is exactly the duplicate
    this program refuses, so the funnel takes the stage instead. The check-belongs-to-stage guard
    below still bites: a check may only be filed under the stage that declares it.

    (If a third stage adopts this machinery, the verdict types belong in their own module rather
    than in ``queues``; two callers do not yet justify the move.)
    """
    if stage not in CHECKS_BY_STAGE:
        raise AcceptanceError("acceptance_evidence_unknown_stage")
    if check not in CHECKS_BY_STAGE[stage]:
        raise AcceptanceError("acceptance_evidence_unknown_check")
    outcome, reason = encode_verdict(verdict)
    observation = dict(verdict.observation)
    if verdict.verdict == VERDICT_VIOLATED and verdict.cause is not None:
        # The specific tell, kept where a reader of the projection can still see it. The document's
        # reason_code is the contract's single violated code; this is what was actually observed.
        observation["observed_cause"] = verdict.cause
    verb = getattr(run, VERDICT_VERB[verdict.verdict])
    if outcome == OUTCOME_OBSERVED:
        verb(check, stage, observation)
        return
    verb(check, stage, reason_code=reason, observation=observation)


# --------------------------------------------------------------------------- queue identities


class ProfileReader(Protocol):
    """Reads the deployment profile's operator queue name off the INSTALLED worker host.

    A seam, not a path: the harness never composes a host path here. The reader raises
    :class:`~secp_acceptance.AcceptanceError` when the profile cannot be read, which downgrades the
    isolation claim to the management constant alone AND raises a gap — it never silently narrows.
    """

    def operator_task_queue(self) -> str: ...


#: Role labels for the queues under test. The evidence never carries a queue NAME — only a role and
#: a digest — so a reader learns WHICH plane owned the name that was probed without the document
#: growing a deployment value.
ROLE_ORDINARY = "ordinary"
ROLE_OPERATOR_MANAGEMENT = "operator_management"
ROLE_OPERATOR_PROFILE = "operator_profile"


def ordinary_queue_name() -> str:
    """The ONE code-owned ordinary queue authority: the queue the shipped worker is constructed on.

    Delegates to ``secp_operator_deployment.identities.worker_ordinary_task_queue``, which reads the
    ``Settings`` field default that ``secp_worker.main._run_temporal`` hands to
    ``Worker(task_queue=...)``. Deliberately NOT ``activation_probe.ORDINARY_TASK_QUEUE``, which is
    a second copy of the same string: binding to the value the worker actually polls is what makes
    this follow a change to the worker instead of having to be remembered alongside one.
    """
    from secp_operator_deployment.identities import worker_ordinary_task_queue

    return worker_ordinary_task_queue()


def management_operator_queue_name() -> str:
    """The operator queue name the MANAGEMENT plane's containment probe tests against.

    Imported, never restated. ``real_adapters._observe_queue_containment`` asks whether this exact
    name appears in the ordinary worker's self-reported queues, so it is a name that must have zero
    pollers for that probe's ``contained`` verdict to mean anything.
    """
    from secp_management.topology import OPERATOR_TASK_QUEUE

    return OPERATOR_TASK_QUEUE


def resolve_operator_queues(
    *, ordinary: str, profile_reader: ProfileReader | None
) -> tuple[dict[str, str], str | None]:
    """The operator queue names to probe, keyed by the ROLE that owns each.

    Returns ``(role -> queue, degradation_cause)``. ``degradation_cause`` is not None whenever the
    deployment-local name is unavailable: the union then covers the management constant only, the
    isolation claim is genuinely narrower, and the caller MUST declare that as a gap rather than
    letting a narrower proof wear the same green as a complete one.

    On a host installed by the supported path that is ALWAYS — no product code writes a deployment
    profile (see :data:`PROFILE_UNREADABLE_WHY`). Passing ``profile_reader=None`` is therefore the
    accurate call for a real run today, not a degraded one, and it reports
    :data:`PROFILE_NOT_INSTALLED` rather than an observation failure. The seam is kept because the
    check is written for the product as it should be: if a profile ever ships, the union widens with
    no change here.

    A name equal to the ordinary queue is DROPPED rather than probed. "Zero pollers on the operator
    queue" is not a well-posed question when that queue IS the queue the worker polls, and a
    projection reporting zero for it would otherwise be read as isolation. The profile validator
    refuses ordinary == operator upstream; this is defence in depth, and it fails toward an empty
    union, which :func:`resolve_operator_isolation` treats as unprovable.
    """
    queues: dict[str, str] = {}
    management = management_operator_queue_name()
    if management and management != ordinary:
        queues[ROLE_OPERATOR_MANAGEMENT] = management
    degradation: str | None = None
    if profile_reader is None:
        # No reader supplied: the caller is stating that this host has no deployment profile, which
        # is the truthful state of every supported installation today.
        degradation = PROFILE_NOT_INSTALLED
    else:
        try:
            declared = profile_reader.operator_task_queue()
        except AcceptanceError as exc:
            degradation = exc.reason_code
        except Exception:  # noqa: BLE001 - a foreign reader failure is still an unread profile
            degradation = "acceptance_observation_unavailable"
        else:
            if isinstance(declared, str) and declared and declared != ordinary:
                queues[ROLE_OPERATOR_PROFILE] = declared
            else:
                degradation = "acceptance_observation_malformed"
    return queues, degradation


#: The gap a run declares when the deployment-local operator queue name is unavailable. Named here
#: so the caller cannot invent a softer wording for the same substitution.
#:
#: THE WHY IS STRUCTURAL, NOT A READ FAILURE, and the wording matters. ``FIXED_PROFILE_PATH`` and
#: ``read_deployment_profile`` are real product code with a real ``operator_task_queue`` field — but
#: NOTHING IN THE PRODUCT EVER WRITES THAT FILE. Verified: the only non-test references are the
#: constant's definition (``profile.py:34``), the reader's default argument (``profile.py:309``),
#: and test fixtures that seed it. What ``secpctl bootstrap worker`` actually installs into
#: ``/etc/secp/operator-deployment`` is the deployment package zip (``layout.py:50``).
#:
#: So this gap fires on EVERY run against a host installed by the supported path, and it is a
#: permanent property of the product rather than an incident on one host. An earlier wording here
#: said the profile "could not be read", which describes a transient failure that in fact never
#: happens — a gap that misdescribes its own cause is worse than no gap, because the next reader
#: goes looking for a broken host instead of a missing writer.
PROFILE_UNREADABLE_GAP = "operator_queue_union_incomplete"
PROFILE_UNREADABLE_SUBSTITUTE = (
    "operator-queue isolation was proven against the management plane's code-owned operator queue "
    "name only, not against a deployment-declared name"
)
PROFILE_UNREADABLE_WHY = (
    "no supported installation path writes a deployment profile, so there is no deployment-local "
    "operator queue name on the host to probe; the product defines the file and a reader for it "
    "but never writes it"
)

#: The bounded cause meaning "the profile is absent because the product installs none". Distinct
#: from a read/parse failure: the remediations are opposite. This one says the harness is looking at
#: a correctly-installed host and the value genuinely does not exist there; a read failure says the
#: host is not what it should be. Collapsing them would send a reader hunting a host defect that is
#: not there — the same observed-false/could-not-look confusion this stage refuses everywhere else.
PROFILE_NOT_INSTALLED = "acceptance_proof_would_be_vacuous"


def declare_profile_gap(recorder: object, *, weakens: tuple[str, ...]) -> None:
    """Declare the narrowed-isolation gap on the recorder that will seal the run."""
    recorder.declare_gap(  # type: ignore[attr-defined]
        gap=PROFILE_UNREADABLE_GAP,
        stage=STAGE_QUEUES,
        substitute=PROFILE_UNREADABLE_SUBSTITUTE,
        why=PROFILE_UNREADABLE_WHY,
        weakens=weakens,
    )


# --------------------------------------------------------------------------- poller observations

#: Bounds on a poller projection. A server answer larger than this is malformed, not interesting.
MAX_POLLERS = 64
MAX_IDENTITY_CHARS = 200


@dataclass(frozen=True)
class PollerObservation:
    """What the Temporal server said about the pollers of ONE task queue.

    Carries the queue's ROLE and a digest of its name, never the name: this is the module most
    tempted to print a queue name into an evidence document, and it never does.
    """

    role: str
    queue_digest: str
    answered: bool
    poller_identities: tuple[str, ...] = ()
    cause: str | None = None

    @property
    def poller_count(self) -> int:
        return len(self.poller_identities)

    def projection(self) -> dict[str, object]:
        """The bounded, secret-free projection recorded for this observation."""
        return {
            "role": self.role,
            "queue_digest": self.queue_digest,
            "answered": self.answered,
            "poller_count": self.poller_count,
            "poller_digests": tuple(
                observation_digest({"poller": identity}) for identity in self.poller_identities
            ),
            "cause": self.cause,
        }


def observe_pollers(queue: str, role: str, raw: object) -> PollerObservation:
    """Reduce ONE ``DescribeTaskQueue`` answer to a bounded poller observation.

    THE QUEUE IS AN ARGUMENT AND IS COMPARED AGAINST NO CONSTANT. That is the property the whole
    isolation proof rests on: the ordinary queue and every operator queue travel the identical code
    path, so the container tier can call this with the two names SWAPPED and require the answers to
    differ. A probe that were blind (always empty) or keyed to a name could not produce that
    difference on a live server.

    ``raw`` is the projection the probe emits: ``{"answered": bool, "pollers": [identity, ...]}``.
    Anything else — a missing key, a wrong type, an over-long identity list — is MALFORMED and
    yields ``answered=False``. A malformed answer is never read as "zero pollers": those are the two
    outcomes it would be most damaging to confuse, because one is safety and the other is silence.
    """
    digest = observation_digest({"queue": queue})
    if not isinstance(queue, str) or not queue:
        return PollerObservation(
            role=role, queue_digest=digest, answered=False, cause="acceptance_observation_malformed"
        )
    if not isinstance(raw, Mapping):
        return PollerObservation(
            role=role, queue_digest=digest, answered=False, cause="acceptance_observation_malformed"
        )
    answered = raw.get("answered")
    if answered is not True:
        # The probe itself reported it could not ask. Its bounded cause is preferred over a generic
        # one, but only if it is a code the evidence vocabulary admits.
        cause = raw.get("cause")
        if not isinstance(cause, str) or cause not in ALL_REASONS:
            cause = "acceptance_observation_unavailable"
        return PollerObservation(role=role, queue_digest=digest, answered=False, cause=cause)
    pollers = raw.get("pollers")
    if not isinstance(pollers, Sequence) or isinstance(pollers, str | bytes):
        return PollerObservation(
            role=role, queue_digest=digest, answered=False, cause="acceptance_observation_malformed"
        )
    if len(pollers) > MAX_POLLERS:
        return PollerObservation(
            role=role, queue_digest=digest, answered=False, cause="acceptance_observation_malformed"
        )
    identities: list[str] = []
    for identity in pollers:
        if not isinstance(identity, str) or not identity or len(identity) > MAX_IDENTITY_CHARS:
            return PollerObservation(
                role=role,
                queue_digest=digest,
                answered=False,
                cause="acceptance_observation_malformed",
            )
        identities.append(identity)
    return PollerObservation(
        role=role, queue_digest=digest, answered=True, poller_identities=tuple(identities)
    )


def resolve_ordinary_poller(
    observation: PollerObservation, *, worker_identities: Sequence[str]
) -> QueueVerdict:
    """The ordinary queue must have a LIVE poller, and it must be the worker we installed.

    Binding the poller to an identity observed independently on the WORKER host is what makes this a
    two-sided fact rather than a claim about an anonymous connection: the Temporal server (running
    on the controller host) names an identity that a different host confirms belongs to the ordinary
    worker process. Without that binding the check would pass for any poller at all, including one
    belonging to something the acceptance never installed.

    ``violated`` — the server answered and there is no such poller. That is an observation of a bad
    state, not a failure to observe, and it must not be recorded as ``unprovable``.
    """
    if not observation.answered:
        return QueueVerdict(
            VERDICT_UNPROVABLE,
            cause=observation.cause or "acceptance_observation_unavailable",
            observation=observation.projection(),
        )
    expected = {
        identity for identity in worker_identities if isinstance(identity, str) and identity
    }
    projection = dict(observation.projection())
    projection["worker_identity_supplied"] = bool(expected)
    if not expected:
        # Nothing to bind to. A poller count alone would pass for a poller that is not the worker,
        # so this refuses rather than accepting the weaker fact under the stronger check's name.
        return QueueVerdict(
            VERDICT_UNPROVABLE,
            cause="acceptance_proof_would_be_vacuous",
            observation=projection,
        )
    matched = sorted(expected.intersection(observation.poller_identities))
    projection["matched_worker_pollers"] = len(matched)
    if not matched:
        return QueueVerdict(
            VERDICT_VIOLATED,
            cause="acceptance_observation_unavailable",
            observation=projection,
        )
    return QueueVerdict(VERDICT_HELD, observation=projection)


def resolve_operator_isolation(observations: Sequence[PollerObservation]) -> QueueVerdict:
    """Every operator queue must have ZERO pollers, and each must have been genuinely ASKED.

    Precedence is deliberate and is the opposite of fail-closed-by-default: a POSITIVE observation
    of a poller wins over an unanswered probe elsewhere. A run that saw a poller on one operator
    queue and could not reach another has observed a violation, and reporting that as merely
    "unprovable" would bury the finding under the outage.

    An EMPTY sequence is ``unprovable``, never ``held``. Zero queues probed is the shape a
    vacuous pass takes here: nothing was asked, so nothing was learned, and "no operator queue had a
    poller" would be true of a run that probed nothing at all.
    """
    if not observations:
        return QueueVerdict(
            VERDICT_UNPROVABLE,
            cause="acceptance_proof_would_be_vacuous",
            observation={"operator_queues_probed": 0},
        )
    projection: dict[str, object] = {
        "operator_queues_probed": len(observations),
        "queues": tuple(obs.projection() for obs in observations),
    }
    violated = [obs for obs in observations if obs.answered and obs.poller_count]
    if violated:
        projection["roles_with_pollers"] = tuple(sorted(obs.role for obs in violated))
        return QueueVerdict(
            VERDICT_VIOLATED,
            cause="worker_ordinary_polls_operator_queue",
            observation=projection,
        )
    unanswered = [obs for obs in observations if not obs.answered]
    if unanswered:
        projection["roles_unanswered"] = tuple(sorted(obs.role for obs in unanswered))
        return QueueVerdict(
            VERDICT_UNPROVABLE,
            cause=unanswered[0].cause or "acceptance_observation_unavailable",
            observation=projection,
        )
    return QueueVerdict(VERDICT_HELD, observation=projection)


# --------------------------------------------------------------------------- execution history

#: Terminal Temporal workflow statuses. A workflow still running has not finished executing, so it
#: proves the queue was SERVED but not that the run completed; the check requires terminality so a
#: hung workflow cannot pass as an execution.
TERMINAL_STATUSES: frozenset[str] = frozenset(
    {"COMPLETED", "FAILED", "CANCELED", "TERMINATED", "TIMED_OUT", "CONTINUED_AS_NEW"}
)


def resolve_ordinary_execution(raw: object, *, expected_queue: str) -> QueueVerdict:
    """ONE workflow, submitted through the supported controller path, ran on the ORDINARY queue.

    The claim is EXECUTION, not success. A workflow that reached a sealed refusal was still polled,
    dispatched, and worked by the ordinary worker — which is exactly what this check names — and it
    is the contact-free outcome, so a refusal is as good a proof here as a completion. What is
    required is that the execution exists, that its task queue is the ordinary one, that it reached
    a terminal state, and that a worker identity actually completed a workflow task for it.

    ``violated`` — the execution exists but ran on a DIFFERENT queue, or no worker ever completed a
    task for it. Both are observations, and neither is an outage.
    """
    if not isinstance(raw, Mapping):
        return QueueVerdict(
            VERDICT_UNPROVABLE,
            cause="acceptance_observation_malformed",
            observation={"execution_observed": False},
        )
    if raw.get("answered") is not True:
        cause = raw.get("cause")
        if not isinstance(cause, str) or cause not in ALL_REASONS:
            cause = "acceptance_observation_unavailable"
        return QueueVerdict(
            VERDICT_UNPROVABLE, cause=cause, observation={"execution_observed": False}
        )
    queue = raw.get("task_queue")
    status = raw.get("status")
    workers = raw.get("task_completed_by")
    if (
        not isinstance(queue, str)
        or not queue
        or not isinstance(status, str)
        or not isinstance(workers, Sequence)
        or isinstance(workers, str | bytes)
    ):
        return QueueVerdict(
            VERDICT_UNPROVABLE,
            cause="acceptance_observation_malformed",
            observation={"execution_observed": False},
        )
    identities = [w for w in workers if isinstance(w, str) and w]
    projection: dict[str, object] = {
        "execution_observed": True,
        "ran_on_expected_queue": queue == expected_queue,
        "queue_digest": observation_digest({"queue": queue}),
        "expected_queue_digest": observation_digest({"queue": expected_queue}),
        "terminal": status in TERMINAL_STATUSES,
        "status": status if status in TERMINAL_STATUSES else "non_terminal",
        "workflow_tasks_completed_by": len(identities),
    }
    if queue != expected_queue:
        return QueueVerdict(
            VERDICT_VIOLATED, cause="acceptance_observation_unavailable", observation=projection
        )
    if not identities:
        return QueueVerdict(
            VERDICT_VIOLATED, cause="acceptance_observation_unavailable", observation=projection
        )
    if status not in TERMINAL_STATUSES:
        # Not a violation: the workflow may simply still be running. Nothing was observed about
        # whether it finishes, so the honest verdict is that the proof was not completed.
        return QueueVerdict(
            VERDICT_UNPROVABLE, cause="acceptance_observation_unavailable", observation=projection
        )
    return QueueVerdict(VERDICT_HELD, observation=projection)


def resolve_operator_executions(raw: object, *, ordinary_control: object = None) -> QueueVerdict:
    """ZERO workflow executions ever existed on any operator queue — with a vacuity control.

    A query that returns nothing proves nothing on its own: a broken filter, a wrong namespace, or
    an empty visibility store all look exactly like isolation. ``ordinary_control`` is the SAME
    query aimed at the ordinary queue, and it must return at least one execution — the one this
    stage submitted. Only a query that demonstrably CAN return rows makes a zero-row answer mean
    something, so a control that comes back empty makes this ``unprovable`` rather than ``held``.
    """
    if not isinstance(raw, Mapping) or raw.get("answered") is not True:
        cause = raw.get("cause") if isinstance(raw, Mapping) else None
        if not isinstance(cause, str) or cause not in ALL_REASONS:
            cause = "acceptance_observation_unavailable"
        return QueueVerdict(
            VERDICT_UNPROVABLE, cause=cause, observation={"operator_executions_observed": False}
        )
    count = raw.get("execution_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        return QueueVerdict(
            VERDICT_UNPROVABLE,
            cause="acceptance_observation_malformed",
            observation={"operator_executions_observed": False},
        )
    control_count = None
    if isinstance(ordinary_control, Mapping) and ordinary_control.get("answered") is True:
        raw_control = ordinary_control.get("execution_count")
        if isinstance(raw_control, int) and not isinstance(raw_control, bool) and raw_control >= 0:
            control_count = raw_control
    projection: dict[str, object] = {
        "operator_executions_observed": True,
        "operator_execution_count": count,
        "control_execution_count": control_count,
        "control_can_return_rows": bool(control_count),
    }
    if count:
        return QueueVerdict(
            VERDICT_VIOLATED,
            cause="worker_ordinary_polls_operator_queue",
            observation=projection,
        )
    if not control_count:
        return QueueVerdict(
            VERDICT_UNPROVABLE,
            cause="acceptance_proof_would_be_vacuous",
            observation=projection,
        )
    return QueueVerdict(VERDICT_HELD, observation=projection)


# --------------------------------------------------------------------------- the operator unit

#: The systemd properties the operator-unit observation reads. The first three are CLASSIFIED by the
#: product's own classifiers; the last three are generation/never-started facts compared verbatim.
OPERATOR_UNIT_PROPERTIES: tuple[str, ...] = (
    "LoadState",
    "ActiveState",
    "UnitFileState",
    "InvocationID",
    "StateChangeTimestampMonotonic",
    "NRestarts",
)


def _product_unit_classifiers() -> tuple[object, object, object]:
    """The PRODUCT's systemd classifiers, imported rather than restated.

    Restating them would have been wrong, not merely duplicative: the shipped operator unit is
    rendered WITHOUT an ``[Install]`` section, so systemd reports ``UnitFileState=static`` — not
    ``disabled`` — and a harness that checked for ``disabled`` would fail a correctly prepared host.
    ``host_adapters`` already encodes that (``static`` classifies as NOT enabled, ``indirect`` stays
    conservatively enabled), and its table is the authority.
    """
    from secp_operator_deployment.host_adapters import (
        _classify_active,
        _classify_load,
        _classify_unit_file_state,
    )

    return _classify_load, _classify_active, _classify_unit_file_state


def resolve_operator_unit_dormant(before: object, after: object) -> QueueVerdict:
    """The packaged operator unit was present, never activated, and did not move during the stage.

    Observed from the HOST, twice, and the two readings must agree. A single snapshot would be
    satisfied by a unit that was started and stopped again while the queue stage ran, which is
    exactly the window this check exists to cover. The generation fact is
    ``StateChangeTimestampMonotonic``: it is reported even for a never-started unit, unlike
    ``InvocationID``, which systemd leaves EMPTY until the first start — so an empty InvocationID is
    a positive statement that the unit has never run, not a missing observation.

    An ABSENT unit is ``unprovable``, not ``held``. It is trivially dormant, but this check's claim
    is about the PACKAGED operator unit; if that unit is not installed, the run has a different
    problem and this proof must not absorb it.
    """
    classify_load, classify_active, classify_enabled = _product_unit_classifiers()
    readings = []
    for reading in (before, after):
        if not isinstance(reading, Mapping):
            return QueueVerdict(
                VERDICT_UNPROVABLE,
                cause="acceptance_observation_malformed",
                observation={"operator_unit_observed": False},
            )
        fields = {}
        for prop in OPERATOR_UNIT_PROPERTIES:
            value = reading.get(prop)
            if not isinstance(value, str):
                return QueueVerdict(
                    VERDICT_UNPROVABLE,
                    cause="acceptance_observation_malformed",
                    observation={"operator_unit_observed": False},
                )
            fields[prop] = value
        readings.append(fields)
    first, second = readings

    present = classify_load(first["LoadState"])  # type: ignore[operator]
    running = classify_active(first["ActiveState"])  # type: ignore[operator]
    enabled = classify_enabled(first["UnitFileState"])  # type: ignore[operator]
    stamp = first["StateChangeTimestampMonotonic"]
    projection: dict[str, object] = {
        "operator_unit_observed": True,
        "present": present,
        "enabled": enabled,
        "running": running,
        "invocation_id_empty": first["InvocationID"] == "",
        "restarts": first["NRestarts"],
        "generation_unchanged": (stamp != "" and stamp == second["StateChangeTimestampMonotonic"]),
        "state_agrees_across_readings": (
            first["ActiveState"] == second["ActiveState"]
            and first["UnitFileState"] == second["UnitFileState"]
            and first["InvocationID"] == second["InvocationID"]
        ),
    }
    if None in (present, running, enabled):
        # An unrecognised systemd state. The product's classifiers return None precisely so an
        # unknown value is never guessed at, and neither is it here.
        return QueueVerdict(
            VERDICT_UNPROVABLE, cause="acceptance_observation_malformed", observation=projection
        )
    if not present:
        return QueueVerdict(
            VERDICT_UNPROVABLE, cause="acceptance_proof_would_be_vacuous", observation=projection
        )
    if not projection["generation_unchanged"]:
        return QueueVerdict(
            VERDICT_UNPROVABLE, cause="acceptance_observation_malformed", observation=projection
        )
    if enabled or running or first["InvocationID"] != "" or first["NRestarts"] != "0":
        # Observed activation. The operator unit ran, or is set to run at boot — a positive finding,
        # and the one this stage exists to make impossible.
        return QueueVerdict(
            VERDICT_VIOLATED,
            cause="worker_operator_not_disabled_stopped",
            observation=projection,
        )
    if not projection["state_agrees_across_readings"]:
        return QueueVerdict(
            VERDICT_VIOLATED,
            cause="worker_operator_not_disabled_stopped",
            observation=projection,
        )
    return QueueVerdict(VERDICT_HELD, observation=projection)


# --------------------------------------------------------------------------- the self-report


def resolve_self_reported_queues(raw: object) -> QueueVerdict:
    """The management plane's three-valued containment verdict, passed through UNTRANSLATED.

    ``real_adapters._observe_queue_containment`` already answers in exactly this vocabulary, so this
    function maps nothing — it validates the shape and adopts the product's verdict. That is the
    point of binding the harness vocabulary to the product's constants: a translation layer here
    would be one more place for the three values to collapse into two.

    THE WEAKEST OF THE SIX CHECKS, stated plainly so its green is not read as more than it is:
    ``health.served_queues()`` disclaims independence in its own docstring — it reports the queue
    the worker RECORDED at ``mark_ready``, not an enumeration of what its poller serves. It is
    a self-report, and a self-report is not isolation evidence. The Temporal-side checks carry that
    claim; this one must never stand in for them.
    """
    if not isinstance(raw, Mapping):
        return QueueVerdict(
            VERDICT_UNPROVABLE,
            cause="acceptance_observation_malformed",
            observation={"containment_observed": False},
        )
    verdict = raw.get("containment")
    cause = raw.get("containment_reason")
    if not isinstance(verdict, str) or verdict not in VERDICTS:
        return QueueVerdict(
            VERDICT_UNPROVABLE,
            cause="acceptance_observation_malformed",
            observation={"containment_observed": False},
        )
    projection: dict[str, object] = {"containment_observed": True, "containment": verdict}
    if verdict == VERDICT_HELD:
        return QueueVerdict(VERDICT_HELD, observation=projection)
    if verdict == VERDICT_VIOLATED:
        return QueueVerdict(
            VERDICT_VIOLATED,
            cause="worker_ordinary_polls_operator_queue",
            observation=projection,
        )
    # unprovable: keep the product's OWN bounded cause, because the two causes it distinguishes have
    # different remediations — a probe that ran and exited non-zero is not a runtime that could not
    # be invoked at all.
    if not isinstance(cause, str) or cause not in ALL_REASONS:
        cause = "acceptance_observation_unavailable"
    projection["containment_reason"] = cause
    return QueueVerdict(VERDICT_UNPROVABLE, cause=cause, observation=projection)


__all__ = [
    "MAX_IDENTITY_CHARS",
    "MAX_POLLERS",
    "OPERATOR_UNIT_PROPERTIES",
    "PROFILE_UNREADABLE_GAP",
    "PROFILE_UNREADABLE_SUBSTITUTE",
    "PROFILE_UNREADABLE_WHY",
    "ROLE_OPERATOR_MANAGEMENT",
    "ROLE_OPERATOR_PROFILE",
    "ROLE_ORDINARY",
    "TERMINAL_STATUSES",
    "VERDICTS",
    "VERDICT_ENCODING",
    "VERDICT_VERB",
    "VERDICT_HELD",
    "VERDICT_UNPROVABLE",
    "VERDICT_VIOLATED",
    "PollerObservation",
    "ProfileReader",
    "QueueVerdict",
    "declare_profile_gap",
    "encode_verdict",
    "management_operator_queue_name",
    "observe_pollers",
    "ordinary_queue_name",
    "record_verdict",
    "resolve_operator_executions",
    "resolve_operator_isolation",
    "resolve_operator_unit_dormant",
    "resolve_ordinary_execution",
    "resolve_ordinary_poller",
    "resolve_operator_queues",
    "resolve_self_reported_queues",
]
