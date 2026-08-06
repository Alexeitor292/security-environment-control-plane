"""Worker liveness as an OBSERVATION, kept structurally distinct from enrollment state.

The control plane has never had a liveness signal. What it has is
``WorkerEnrollmentStateName.healthy`` — a terminal enrollment transition reached once, when a
worker's signed result attested a successful install. Reading that as "the worker is running" is
the substitution this module exists to prevent, and it is an easy one to make because the state is
literally called ``healthy``.

The two facts answer different questions and are never merged:

===================  ==========================================================================
Enrollment state     Did this worker complete the enrollment exchange? Durable, monotonic, and
                     still true a month after the process died.
Liveness observation  When did the control plane last hear from this worker, and how long ago was
                     that? Non-durable, decays, and is ``unobserved`` far more often than not.
===================  ==========================================================================

**This projection is deliberately non-persistent.** Observations live in a process-local registry
and are gone after a controller restart, which is the honest answer: a fresh process has not heard
from anybody. Reconstructing an observation from durable enrollment rows would manufacture a
liveness claim out of a fact that carries no timing, and would read as fresh to an operator. A
durable heartbeat is a separate, post-MVP capability with its own migration and its own review;
see ``docs/`` and the module-level note in :func:`record_observation`.

The vocabulary contains no ``online``, ``offline`` or ``healthy``. Those words assert a current
state of the world; what the control plane actually has is a timestamp and an age, and
``test_worker_observation_honesty.py`` fails if any of the three appears in this module's output
vocabulary.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta

#: The closed set of liveness readings. Four values, none of which claims a current state.
#:
#: ``fresh`` and ``stale`` are both OBSERVATIONS with an age attached; the difference is only
#: whether the age is within the configured threshold. Neither says the worker is up now — the
#: strongest true statement available is "it was there at T".
OBSERVATION_UNOBSERVED = "unobserved"
OBSERVATION_FRESH = "fresh"
OBSERVATION_STALE = "stale"
OBSERVATION_ERROR = "observation_error"

#: How long an observation may be before it stops being called ``fresh``. A threshold, not a
#: timeout: nothing expires, and a stale observation is still reported with its exact age, because
#: "last seen 40 minutes ago" is far more useful to an operator than "stale".
DEFAULT_FRESHNESS_THRESHOLD = timedelta(seconds=90)

#: Where an observation came from. Recorded per observation rather than assumed globally, because
#: two sources can disagree about what they prove: an enrollment exchange proves the worker's key
#: was live at that instant, while a future heartbeat would prove the Temporal worker was polling.
#: Collapsing them into one "observed" would lose exactly the distinction an operator needs.
SOURCE_ENROLLMENT_EXCHANGE = "enrollment_exchange"
SOURCE_UNKNOWN = "unknown"


@dataclass(frozen=True)
class WorkerObservation:
    """One recorded sighting of a worker. Inert data; it asserts nothing about *now*."""

    worker_installation_id: str
    worker_key_fingerprint: str
    worker_role: str
    release_fingerprint: str
    #: The queue the worker itself reported serving. A SELF-REPORT — the control plane does not
    #: independently enumerate what the Temporal poller subscribes to, and calling this "the queue
    #: it serves" without that qualifier would overstate it.
    observed_task_queue: str
    observation_source: str
    observed_at: datetime
    #: Set when a worker was heard from but its report could not be used. An error is still an
    #: observation — it proves contact — so it carries ``observed_at`` like any other.
    error: str = ""


@dataclass(frozen=True)
class WorkerLivenessProjection:
    """What an operator or a manifest may truthfully be told.

    Every field an operator reads is here, including the ones that qualify the answer: the source,
    the age, and the threshold the age was compared against. A projection that reported only
    ``fresh`` would be a conclusion without its premise.
    """

    state: str
    worker_installation_id: str = ""
    worker_key_fingerprint: str = ""
    worker_role: str = ""
    release_fingerprint: str = ""
    observed_task_queue: str = ""
    observation_source: str = SOURCE_UNKNOWN
    observed_at: datetime | None = None
    age_seconds: float | None = None
    freshness_threshold_seconds: float = DEFAULT_FRESHNESS_THRESHOLD.total_seconds()
    error: str = ""

    @property
    def is_observed(self) -> bool:
        """True when the control plane has heard from this worker at all in this process."""
        return self.state != OBSERVATION_UNOBSERVED

    @property
    def unreported_fields(self) -> tuple[str, ...]:
        """Facts this observation's SOURCE could not supply, as distinct from facts that are empty.

        The distinction is load-bearing and was discovered rather than designed. The enrollment
        exchange — the only source that exists today — carries the worker's installation id, key
        fingerprint and release fingerprint, but its health evidence is ``dict[str, bool]``, so it
        conveys no task queue and no role at all.

        An empty ``observed_task_queue`` rendered as a blank cell reads as "this worker serves no
        queue", which is a claim. Naming the field here lets a manifest say "task queue: not
        reported by enrollment_exchange", which is the true statement. A future heartbeat source
        would supply both and this tuple would shrink — without anything else needing to change.
        """
        if self.state == OBSERVATION_UNOBSERVED:
            return ()
        return tuple(
            name
            for name, value in (
                ("worker_role", self.worker_role),
                ("observed_task_queue", self.observed_task_queue),
                ("release_fingerprint", self.release_fingerprint),
            )
            if not value
        )


def project_liveness(
    observation: WorkerObservation | None,
    *,
    now: datetime,
    threshold: timedelta = DEFAULT_FRESHNESS_THRESHOLD,
) -> WorkerLivenessProjection:
    """Derive the reading from an observation and the current time.

    Pure: same observation and same ``now`` always give the same answer, and no clock is read here.
    ``now`` is a parameter for that reason, not for testability alone.
    """
    if observation is None:
        return WorkerLivenessProjection(
            state=OBSERVATION_UNOBSERVED,
            freshness_threshold_seconds=threshold.total_seconds(),
        )

    age = (now - observation.observed_at).total_seconds()
    # A negative age means the observation is stamped in the future — clock skew between the
    # controller and the worker, or a bad clock somewhere. It is NOT freshness. Reporting it as
    # `fresh` would turn a broken clock into a liveness guarantee, which is the wrong direction to
    # fail in, so it is surfaced as an error that still carries its timestamp.
    if age < 0:
        return WorkerLivenessProjection(
            state=OBSERVATION_ERROR,
            worker_installation_id=observation.worker_installation_id,
            worker_key_fingerprint=observation.worker_key_fingerprint,
            worker_role=observation.worker_role,
            release_fingerprint=observation.release_fingerprint,
            observed_task_queue=observation.observed_task_queue,
            observation_source=observation.observation_source,
            observed_at=observation.observed_at,
            age_seconds=age,
            freshness_threshold_seconds=threshold.total_seconds(),
            error="observation is stamped in the future; check controller/worker clock skew",
        )

    if observation.error:
        state = OBSERVATION_ERROR
    elif age <= threshold.total_seconds():
        state = OBSERVATION_FRESH
    else:
        state = OBSERVATION_STALE

    return WorkerLivenessProjection(
        state=state,
        worker_installation_id=observation.worker_installation_id,
        worker_key_fingerprint=observation.worker_key_fingerprint,
        worker_role=observation.worker_role,
        release_fingerprint=observation.release_fingerprint,
        observed_task_queue=observation.observed_task_queue,
        observation_source=observation.observation_source,
        observed_at=observation.observed_at,
        age_seconds=age,
        freshness_threshold_seconds=threshold.total_seconds(),
        error=observation.error,
    )


class WorkerObservationRegistry:
    """A process-local, explicitly non-durable store of the most recent sighting per worker.

    Non-durability is the CONTRACT, not an implementation shortcut. Three properties follow from
    it, and each is asserted by a test rather than left to the reader:

    * a fresh registry reports ``unobserved`` for every worker;
    * nothing here is written to, or read from, a database;
    * an observation is replaced by a newer one and never merged with it, so an old sighting cannot
      contribute freshness to a new reading.

    Keyed by worker installation id, which is the durable worker identity — not by enrollment id,
    because a worker can be re-enrolled and it is the same running process either way.

    The lock is held only for dict access. Projection happens outside it, so a slow reader cannot
    delay a worker's report.
    """

    def __init__(self) -> None:
        self._observations: dict[str, WorkerObservation] = {}
        self._lock = threading.Lock()

    def record(self, observation: WorkerObservation) -> None:
        """Record a sighting, replacing any earlier one for the same worker.

        Out-of-order arrivals are dropped rather than applied: two authenticated calls can be
        handled by different threads and land in the wrong order, and letting an older sighting
        overwrite a newer one would make a live worker look staler than it is.
        """
        with self._lock:
            existing = self._observations.get(observation.worker_installation_id)
            if existing is not None and existing.observed_at > observation.observed_at:
                return
            self._observations[observation.worker_installation_id] = observation

    def get(self, worker_installation_id: str) -> WorkerObservation | None:
        with self._lock:
            return self._observations.get(worker_installation_id)

    def project(
        self,
        worker_installation_id: str,
        *,
        now: datetime,
        threshold: timedelta = DEFAULT_FRESHNESS_THRESHOLD,
    ) -> WorkerLivenessProjection:
        return project_liveness(self.get(worker_installation_id), now=now, threshold=threshold)

    def clear(self) -> None:
        """Drop every observation.

        Exists so a test can simulate a controller restart honestly — by emptying the registry the
        same way a new process starts — rather than by monkeypatching the projection.
        """
        with self._lock:
            self._observations.clear()


#: The process-local registry. A module-level singleton because it models a property OF THIS
#: PROCESS: what this controller has heard. A second instance would answer a different question and
#: neither would be wrong, which is exactly the confusion to avoid.
#:
#: NOT a cache in front of durable storage. There is no durable storage behind it, and adding one
#: is a separate capability requiring its own migration and review — a change that must not happen
#: by someone quietly giving this dict a database.
_REGISTRY = WorkerObservationRegistry()


def registry() -> WorkerObservationRegistry:
    return _REGISTRY


def record_observation(observation: WorkerObservation) -> None:
    """Record a sighting in the process-local registry.

    Called from the authenticated worker-facing paths the controller already serves. Deliberately
    not a new endpoint: an endpoint a worker calls to say "I am alive" proves only that something
    holding the worker's credentials made a request, which is what the existing authenticated calls
    already prove — with the advantage of being calls the worker makes for a reason.
    """
    _REGISTRY.record(observation)
