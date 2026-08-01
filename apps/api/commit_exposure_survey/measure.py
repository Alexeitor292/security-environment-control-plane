"""Runtime instrument: does a request's write commit before or after its response is sent?

The census in ``census.py`` says which routes *could* be exposed. This says which ones **are**, by
running them over a real TCP socket and comparing two timestamps taken from the same
``time.perf_counter`` clock in the same process:

* when the last byte of the response was handed to the transport (an ASGI wrapper around the real
  app — the app itself is never modified), and
* when the session that carried the request's writes actually committed (SQLAlchemy session events).

If the writing commit lands *after* the response, the client can hold a 2xx for a row no other
connection can yet read. That ordering is engine-independent, which is why measuring it on SQLite
is sound.

An earlier version of this docstring added that "the *consequence* — a follow-up read seeing
nothing — is PostgreSQL-specific". **That is now known to be false and has been withdrawn.** It
rested on the same unmeasured claim that SQLite's write lock serialises the race away; it does not
(the lock serialises *writers*, not a reader against an uncommitted writer). Measured since: the
socket gate's own body reproduces the violation on SQLite **110/110 with 0 inconclusive** across 50
serial and 60 four-way-concurrent runs, and the enrollment revoke path shows 40/40 stale reads at a
widened window with reader latency p50 0.0 ms against a 200 ms hold.

This strengthens rather than weakens the survey: the ordering it measures was always the
engine-independent part, and the consequence is now known to follow on both engines rather than
only on the one this instrument does not use.

Two details decide whether this instrument tells the truth:

* **What counts as a write.** ``session.new`` is already empty by ``before_commit`` whenever the
  service called ``flush()`` — which the services here do — so asking there would report almost
  every write as a read. The flag is set from ``after_flush``, where the pending objects are still
  visible, and it is stored on the *connection* so concurrent sessions cannot borrow each other's.
* **What counts as a commit.** The ORM's ``SessionEvents.after_commit`` is **not** usable for this:
  it fires for a SAVEPOINT release too. Measured directly —

      with session.begin_nested():   ->  after_transaction_end(nested=False, parent=yes)
          session.add(row)               SESSION.after_commit          <- fires
          session.flush()                after_transaction_end(nested=True, parent=yes)
                                         ENGINE commit                 <- DOES NOT fire

  — so an endpoint whose only in-request "commit" is a savepoint release would have been reported
  as safe, which is the direction that understates exposure. ``secp_api.services.worker_identity``
  contains exactly that shape (``with session.begin_nested():`` around the insert), and it is what
  exposed the flaw. This recorder therefore keys on the **engine-level ``commit`` event**, which
  fires only for a real DBAPI COMMIT. The ORM-level count is still kept, purely so the divergence
  between the two is visible in the report rather than inferred.
"""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import FrameType

import secp_api.db as secp_db
from sqlalchemy import event
from sqlalchemy.orm import Session as OrmSession

_GET_DB_CODE = secp_db.get_db.__code__

# Bounded, generous, and never a behaviour under test: how long to wait for a request's teardown
# commit to arrive on the server's worker thread before declaring it absent.
COMMIT_WAIT_SECONDS = 20.0

_WROTE_KEY = "secp_survey_wrote"


class MeasurementError(RuntimeError):
    """The instrument could not measure, as distinct from measuring and finding nothing.

    Deliberately not an ``AssertionError``: an unmeasurable endpoint must be reported as unmeasured,
    never folded into "measured and found safe".
    """


def _inside_get_db() -> bool:
    """True when ``secp_api.db.get_db``'s own code object is on the calling stack."""
    frame: FrameType | None = sys._getframe()
    while frame is not None:
        if frame.f_code is _GET_DB_CODE:
            return True
        frame = frame.f_back
    return False


@dataclass(frozen=True)
class CommitEvent:
    at: float
    wrote: bool
    in_dependency_teardown: bool


@dataclass
class RequestObservation:
    label: str
    method: str
    path: str
    template: str = ""
    status: int | None = None
    response_completed_at: float | None = None
    commits: list[CommitEvent] = field(default_factory=list)
    note: str = ""

    @property
    def writing_commits(self) -> list[CommitEvent]:
        return [c for c in self.commits if c.wrote]

    def verdict(self) -> str:
        """One of EXPOSED / NOT_EXPOSED / NO_WRITE / NOT_MEASURED.

        ``NOT_MEASURED`` is returned wherever the instrument lacks the two timestamps it compares.
        It is never merged with ``NOT_EXPOSED``: an endpoint that could not be driven is not an
        endpoint shown to be safe.
        """
        if self.status is None or not (200 <= self.status < 300):
            return "NOT_MEASURED"
        if self.response_completed_at is None:
            return "NOT_MEASURED"
        writing = self.writing_commits
        if not writing:
            return "NO_WRITE"
        if any(commit.at > self.response_completed_at for commit in writing):
            return "EXPOSED"
        return "NOT_EXPOSED"

    def detail(self) -> str:
        if self.response_completed_at is None:
            return self.note or "no response timestamp"
        parts = []
        for commit in self.commits:
            delta = (commit.at - self.response_completed_at) * 1000.0
            side = "after" if delta > 0 else "before"
            parts.append(
                f"{'write' if commit.wrote else 'read'} commit {abs(delta):.1f}ms {side} response"
                f"{' (teardown)' if commit.in_dependency_teardown else ' (in-request)'}"
            )
        return "; ".join(parts) or "no commit observed"


class CommitRecorder:
    """Record every REAL (DBAPI-level) commit in this process, with time, write-ness and call site.

    ``orm_commit_events`` counts the ORM's ``after_commit`` separately. It is deliberately not used
    for any verdict: it over-counts by firing on SAVEPOINT releases, and keeping both makes that
    divergence an observation in the report instead of a footnote nobody can check.
    """

    def __init__(self) -> None:
        self.events: list[CommitEvent] = []
        self.orm_commit_events = 0
        self._arrived = threading.Event()
        self._lock = threading.Lock()

    # -- listeners (run on the server's worker thread) -------------------------------------------

    def after_flush(self, session: OrmSession, _ctx: object) -> None:
        if session.new or session.dirty or session.deleted:
            # Stored on the CONNECTION, not the Session: the connection is what the engine-level
            # commit event receives, and it keeps concurrent sessions from borrowing each other's
            # write flag.
            session.connection().info[_WROTE_KEY] = True

    def after_orm_commit(self, _session: OrmSession) -> None:
        with self._lock:
            self.orm_commit_events += 1

    def engine_commit(self, conn: object) -> None:
        wrote = bool(conn.info.pop(_WROTE_KEY, False))  # type: ignore[attr-defined]
        with self._lock:
            self.events.append(
                CommitEvent(
                    at=time.perf_counter(),
                    wrote=wrote,
                    in_dependency_teardown=_inside_get_db(),
                )
            )
            self._arrived.set()

    # -- control (runs on the driving thread) ----------------------------------------------------

    def reset(self) -> None:
        with self._lock:
            self.events = []
            self.orm_commit_events = 0
            self._arrived.clear()

    def drain(self) -> list[CommitEvent]:
        """Wait for at least one commit, then for the burst to settle. Bounded; never spins free.

        Every request that resolves ``db_session`` produces a teardown commit even when it wrote
        nothing, so an absent commit is itself a reportable observation rather than a timeout to
        paper over.
        """
        if not self._arrived.wait(COMMIT_WAIT_SECONDS):
            return []
        deadline = time.perf_counter() + 1.0
        last = -1
        while time.perf_counter() < deadline:
            with self._lock:
                count = len(self.events)
            if count == last:
                break
            last = count
            time.sleep(0.05)
        with self._lock:
            return list(self.events)

    @contextmanager
    def installed(self, engine: object) -> Iterator[CommitRecorder]:
        event.listen(OrmSession, "after_flush", self.after_flush)
        event.listen(OrmSession, "after_commit", self.after_orm_commit)
        event.listen(engine, "commit", self.engine_commit)
        try:
            yield self
        finally:
            event.remove(engine, "commit", self.engine_commit)
            event.remove(OrmSession, "after_commit", self.after_orm_commit)
            event.remove(OrmSession, "after_flush", self.after_flush)


class ResponseCompletionTimer:
    """ASGI wrapper recording when the final response byte was handed to the transport.

    A wrapper, never an edit: the application object underneath is the shipped composition, and the
    dependency teardown it performs after ``send`` is exactly the behaviour under measurement.
    """

    def __init__(self, app: Callable) -> None:
        self.app = app
        self.completed_at: float | None = None

    def reset(self) -> None:
        self.completed_at = None

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        async def timed_send(message: dict) -> None:
            await send(message)
            if message.get("type") == "http.response.body" and not message.get("more_body", False):
                self.completed_at = time.perf_counter()

        await self.app(scope, receive, timed_send)


def timed_asgi_app(app: Callable) -> tuple[Callable, ResponseCompletionTimer]:
    """Wrap ``app`` and return ``(asgi3_callable, timer)``.

    The returned callable is a plain ``async def`` rather than the instance itself: uvicorn's
    ``interface="auto"`` detection routes a non-function object through its ASGI2 adapter, which
    would call the wrapper with one argument and fail at request time instead of at startup.
    """
    timer = ResponseCompletionTimer(app)

    async def asgi(scope: dict, receive: Callable, send: Callable) -> None:
        await timer(scope, receive, send)

    return asgi, timer


def verify_instrument(recorder: CommitRecorder, timer: ResponseCompletionTimer) -> list[str]:
    """Prove the instrument can register a commit and a response before believing any zero."""
    problems: list[str] = []
    if not recorder.events:
        problems.append(
            "the commit recorder observed no commit at all during the probe request; every "
            "db_session request commits at teardown, so silence here means the listener is not "
            "attached and no endpoint's result can be believed"
        )
    if timer.completed_at is None:
        problems.append(
            "the ASGI timer recorded no response completion; the wrapper is not in the served "
            "stack, so no ordering can be computed"
        )
    if recorder.events and not any(e.in_dependency_teardown for e in recorder.events):
        problems.append(
            "no observed commit was attributed to secp_api.db.get_db; the call-site attribution "
            "is not engaging"
        )
    return problems


def verify_writes_were_seen(observations: list[RequestObservation]) -> list[str]:
    """End-to-end counterpart to ``verify_write_detection``: writes must have been SEEN as writes.

    The in-process check proves the flag works on a synthetic session. This proves it engaged on
    the real application, over the socket, for the requests this survey actually made. A ``201
    Created`` that produced no writing commit anywhere is not a harmless endpoint — it is an
    instrument that stopped detecting writes, and the whole report would silently read as zero
    exposure.
    """
    problems: list[str] = []
    created = [
        obs for obs in observations if obs.status == 201 and obs.response_completed_at is not None
    ]
    if not created:
        problems.append(
            "no 201-Created request was observed at all, so nothing here demonstrates that write "
            "detection engaged against the real application"
        )
    silent = [obs.label for obs in created if not obs.writing_commits]
    if silent:
        problems.append(
            f"{len(silent)} request(s) returned 201 Created but produced NO writing commit: "
            f"{silent}. Either the write flag is not engaging or those endpoints commit nothing — "
            "both make every verdict in this report unsafe to read."
        )
    return problems


def verify_write_detection() -> tuple[bool, str]:
    """Prove, in-process and in BOTH directions, that the write flag actually tracks writes.

    ``verdict()`` branches entirely on ``wrote``, and ``wrote`` comes from one condition in
    ``after_flush``. Neutralise that condition and the survey reports **zero exposure with every
    other guard still green** — six 201-Created endpoints classified harmless, exit 0. That is the
    clean-looking zero this whole instrument exists to prevent, in the direction that understates a
    blast radius.

    Hand-built ``CommitEvent(wrote=...)`` objects cannot catch it: they bypass the flag path
    entirely. So this drives a real INSERT through a real session and asserts the flag is set, and
    drives a real no-op commit and asserts it is not. Both halves are required — a mutation pinning
    ``wrote`` to ``True`` would pass the first alone.
    """
    from sqlalchemy import Column, Integer, create_engine
    from sqlalchemy.orm import declarative_base, sessionmaker

    base = declarative_base()

    class _Probe(base):  # type: ignore[misc, valid-type]
        __tablename__ = "secp_write_detection_probe"
        id = Column(Integer, primary_key=True)

    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, future=True)
    probe = CommitRecorder()
    try:
        with probe.installed(engine):
            writing = factory()
            writing.add(_Probe())
            writing.commit()
            writing.close()
            after_write = list(probe.events)

            probe.reset()
            reading = factory()
            reading.execute(select_probe_count(_Probe))
            reading.commit()
            reading.close()
            after_read = list(probe.events)
    finally:
        engine.dispose()

    if len(after_write) != 1 or not after_write[0].wrote:
        return False, (
            f"a real INSERT+commit produced {len(after_write)} event(s) with "
            f"wrote={[e.wrote for e in after_write]}; expected exactly one with wrote=True. The "
            "write flag is not tracking writes, so every endpoint would read as harmless."
        )
    if any(event.wrote for event in after_read):
        return False, (
            f"a read-only commit was flagged as writing ({[e.wrote for e in after_read]}); the "
            "flag no longer discriminates, so this check would pass whatever it was pinned to"
        )
    return True, (
        f"INSERT+commit -> 1 event, wrote=True; read-only commit -> "
        f"{len(after_read)} event(s), wrote=False"
    )


def select_probe_count(model: object):
    """A trivial SELECT against the probe table (kept separate so the import stays local)."""
    from sqlalchemy import func, select

    return select(func.count()).select_from(model)  # type: ignore[arg-type]


def verify_savepoint_discrimination(recorder: CommitRecorder) -> tuple[bool, str]:
    """Prove, in-process, that the recorder still tells a real COMMIT from a SAVEPOINT release.

    Without this the whole instrument could silently regress to the ORM-level event it started on —
    which fires for both — and every endpoint whose in-request work is a savepoint would flip from
    EXPOSED to NOT_EXPOSED with no other visible change. So the property is re-derived at runtime
    rather than trusted from a comment.
    """
    from sqlalchemy import Column, Integer, create_engine
    from sqlalchemy.orm import declarative_base, sessionmaker

    base = declarative_base()

    class _Probe(base):  # type: ignore[misc, valid-type]
        __tablename__ = "secp_savepoint_probe"
        id = Column(Integer, primary_key=True)

    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, future=True)
    probe = CommitRecorder()
    try:
        with probe.installed(engine):
            session = factory()
            with session.begin_nested():
                session.add(_Probe())
                session.flush()
            savepoint_only = len(probe.events)
            orm_after_savepoint = probe.orm_commit_events
            session.commit()
            after_real = len(probe.events)
            session.close()
    finally:
        engine.dispose()

    if savepoint_only != 0:
        return False, f"a SAVEPOINT release was recorded as {savepoint_only} real commit(s)"
    if after_real != 1:
        return False, f"a real commit produced {after_real} recorded commit(s), expected 1"
    if orm_after_savepoint != 1:
        return False, (
            "the ORM after_commit did NOT fire for the savepoint release, so this check no longer "
            "demonstrates the divergence it exists to guard against"
        )
    return True, (
        f"savepoint release -> 0 recorded commits (ORM event fired {orm_after_savepoint}x and "
        "would have miscounted it); real commit -> exactly 1"
    )
