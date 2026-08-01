"""PostgreSQL + real-socket read-after-write gate for the control-plane API.

The defect this gate exists to catch
------------------------------------
``secp_api.deps.db_session`` (``apps/api/secp_api/deps.py``) is a plain generator dependency, so the
``session.commit()`` in ``secp_api.db.get_db`` runs on FastAPI's **request** exit stack — which is
closed *after* the response has been sent. A client can therefore be handed ``201 Created`` for a
row that no subsequent request can yet read.

Why nothing caught it
---------------------
**One** blind spot, not two: the socket. Every API test drives the app through ``TestClient``, which
runs the ASGI app to completion in-process, so the request scope — and every ``Depends``-with-yield
teardown — is always closed before the assertion. Read-your-writes cannot fail there regardless of
which database is underneath.

An earlier version of this file claimed a second blind spot: that SQLite "serialises the race away
at its database-level write lock", making the defect invisible to the dev loop. **That is wrong, and
it was never measured — it was inherited from the original defect report and restated here as
though established.** It conflates writer-serialisation with reader-visibility. SQLite's write lock
serialises *writers*; it does not block a reader against an uncommitted writer. In this flow
``secp_api.services.catalog.create_template`` calls ``session.flush()`` and never commits, so the
INSERT is live in an open transaction on pooled connection A while the follow-up GET checks out
connection B and reads the database file without the pending row — the same read-your-writes
violation MVCC produces, by a different route.

Measured here, running this module's own body against SQLite with only the engine-scope guards
removed: **110/110 ``ReadAfterWriteViolation``, 0 inconclusive, 0 pass** — 50 runs serial and 60
runs at 4-way concurrency (the shard layout). Independently, the PR #77 reviewer measured 5/5
through this harness, and the PR #72 reviewer measured 40/40 stale reads on the enrollment revoke
path at a 200 ms widened window with reader latency p50 0.0 ms / max 93 ms, where a reader waiting
on a lock would have shown ~200 ms.

The module is still scoped to PostgreSQL below, but for a different and much narrower reason — see
the note on ``pytestmark``.

This module supplies the missing socket. It is deliberately NOT the fix: migrating the
``Depends(db_session)`` call sites to ``Depends(db_session, scope="function")`` is separate, owned
work. This is the gate that would have failed before that work was needed.

How the assertion is made deterministic
---------------------------------------
The window between "response sent" and "teardown commits" is normally microseconds, which is a race,
not a test. So the window is **widened, never reordered**: a SQLAlchemy ``before_commit`` listener
holds the commit for a fixed interval, and it fires only when ``secp_api.db.get_db``'s own code
object is on the calling stack — that is, only for the production teardown commit, never for
anything a request handler does. Nothing about the ordering under test is altered: the production
dependency object is untouched, there is no ``dependency_overrides`` entry, and the route, the
session and the commit are exactly the shipped ones. With the window open for whole seconds, both
outcomes are decided rather than raced:

* teardown after the response (today)   -> the follow-up read cannot see the row  -> RED
* teardown before the response (fixed)  -> the POST itself cannot return in under the delay -> GREEN

Every other combination is refused as inconclusive rather than reported as a pass.
"""

from __future__ import annotations

import os

os.environ.setdefault("SECP_APP_ENV", "test")
os.environ.setdefault("SECP_WORKFLOW_DISPATCH_MODE", "inline")

import socket  # noqa: E402
import sys  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import uuid  # noqa: E402
from collections.abc import Iterator  # noqa: E402
from types import FrameType  # noqa: E402

import httpx  # noqa: E402
import pytest  # noqa: E402
import secp_api.db as secp_db  # noqa: E402
import secp_api.immutability  # noqa: E402,F401  (registers ORM immutability guards)
from secp_api.db import get_sessionmaker, reset_engine_for_tests  # noqa: E402
from secp_api.models import Base  # noqa: E402
from secp_api.seed import bootstrap_dev  # noqa: E402
from sqlalchemy import event  # noqa: E402
from sqlalchemy.engine import Engine  # noqa: E402
from sqlalchemy.orm import Session as OrmSession  # noqa: E402

from socket_gate_tests.live_api_server import live_api_server  # noqa: E402

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

# Scoped to PostgreSQL — but NOT because SQLite cannot show the defect. It demonstrably can: 110/110
# violations, 0 inconclusive, across 50 serial and 60 4-way-concurrent runs (module docstring).
# The scoping is a deliberate, temporary CI-coupling decision awaiting an owner's call: this job
# feeds the required aggregate on every PR in the program, so the SQLite leg's run-to-run stability
# had to be characterised before it could enter the shards, where an intermittent inconclusive would
# go red for every stream and look like their change. That characterisation is now done and shows no
# instability; widening the scope is the expected next step, and it is an owner decision rather than
# this module's to take.
#
# That makes this scoping a KNOWN, MEASURED gap in the dev loop rather than a property of the
# engine: a developer running the suite locally today does not see this regression even though it
# would fire. Removing the scoping is the expected end state once the stability data supports it.
# The dedicated CI job refuses a plain skip outright, so this can never hide the gate where
# PostgreSQL is present.
pytestmark = pytest.mark.skipif(
    not PG_URL,
    reason="set SECP_TEST_POSTGRES_URL to run the PostgreSQL live-socket read-after-write gate",
)

# Seconds the production teardown commit is held open. Only has to dwarf a loopback HTTP round trip
# on a loaded CI runner; it is not a timeout and nothing races against it.
TEARDOWN_DELAY_SECONDS = 3.0
# A latency landing inside [DELAY - MARGIN, DELAY) tells us nothing about which side of the response
# the teardown ran on. Such a run is REFUSED, never guessed at.
AMBIGUITY_MARGIN_SECONDS = 0.5
# Bounded waits, both generous, both covering scheduling rather than behaviour: how long the gate
# will wait for the armed hold to BEGIN, and for it to finish once its sleep elapses. Exceeding
# either means the gate could not open its window and it says so, rather than guessing.
HOLD_START_TIMEOUT_SECONDS = 30.0
RELEASE_GRACE_SECONDS = 30.0
# Must comfortably exceed TEARDOWN_DELAY_SECONDS: once fixed, the POST legitimately blocks for it.
HTTP_TIMEOUT_SECONDS = 60.0

# The exact loaded code object of the production teardown commit site. Identity on the loaded
# function, not a source string or a name match: a rename, a copy, or a same-named helper elsewhere
# cannot satisfy it, and if this attribute ever disappears the module fails at import.
_GET_DB_CODE = secp_db.get_db.__code__


class ReadAfterWriteViolation(AssertionError):
    """The API answered 2xx for a create that the very next request could not read.

    A dedicated type, and the ONLY thing the expected-failure marker below accepts: a broken
    harness, an unreachable server, the wrong database or an unexplained timing must never be
    absorbed as "the known defect".
    """


class LiveGateInconclusive(AssertionError):
    """The gate could not measure what it claims to measure, so it refuses to report a verdict.

    Never matched by the expected-failure marker: an inconclusive run fails loudly. Silence is not
    success, and an unexplained pass is not a pass.
    """


# --- widening the observation window ------------------------------------------------------------


def _inside_production_teardown_commit() -> bool:
    """True when ``secp_api.db.get_db`` is on the calling stack.

    During a request that frame is *suspended* (the generator is parked at its ``yield``), so it is
    absent; it is on the stack only while the dependency's teardown is resuming — which is exactly
    the commit whose position relative to the response is under test.
    """
    frame: FrameType | None = sys._getframe()
    while frame is not None:
        if frame.f_code is _GET_DB_CODE:
            return True
        frame = frame.f_back
    return False


class TeardownCommitDelay:
    """Hold the production teardown commit open, once, for a fixed interval.

    Widens the pre-existing gap between the response and the commit. It does not move the commit,
    does not replace the dependency, and does not touch the request path: a commit issued by a route
    or a service is left entirely alone.

    The listener is registered ONCE for the module and is inert until armed. It is deliberately not
    attached and detached around each measurement: ``sqlalchemy.event.remove`` mutates the listener
    collection the dispatcher is iterating, so detaching while a held commit is still sleeping
    raises ``RuntimeError: deque mutated during iteration`` inside the request teardown — which
    aborts the very commit under observation. (Observed, not theorised: it is what the first draft
    of this probe did.)
    """

    def __init__(self) -> None:
        self.seconds = 0.0
        self.delayed_commits = 0
        self.declined_commits = 0
        # Both read from the same `time.perf_counter` clock the tests use, so an observation can be
        # placed inside or outside the window rather than merely assumed to be inside it.
        self.hold_started_at = 0.0
        self.hold_ended_at = 0.0
        self._armed = threading.Event()
        self._holding = threading.Event()
        self._released = threading.Event()

    @property
    def held_for(self) -> float:
        """How long the production commit was actually parked. 0.0 if it never was."""
        if not self._released.is_set():
            return 0.0
        return self.hold_ended_at - self.hold_started_at

    # -- listener (runs on the server's worker thread) ------------------------------------------

    def before_commit(self, _session: OrmSession) -> None:
        if not self._armed.is_set():
            return
        if not _inside_production_teardown_commit():
            self.declined_commits += 1
            return
        # One-shot: disarm before sleeping so exactly one commit is ever held, and so the follow-up
        # read's own teardown runs at full speed.
        self._armed.clear()
        self.delayed_commits += 1
        self.hold_started_at = time.perf_counter()
        self._holding.set()
        try:
            time.sleep(self.seconds)
        finally:
            self.hold_ended_at = time.perf_counter()
            self._released.set()

    # -- control (runs on the test thread) ------------------------------------------------------

    def arm(self, seconds: float) -> None:
        """Zero the counters and hold the next production teardown commit for ``seconds``."""
        self.seconds = seconds
        self.delayed_commits = 0
        self.declined_commits = 0
        self.hold_started_at = 0.0
        self.hold_ended_at = 0.0
        self._holding.clear()
        self._released.clear()
        self._armed.set()

    def disarm(self) -> None:
        self._armed.clear()

    def wait_until_holding(self) -> None:
        """Block until the armed hold has actually BEGUN on the server's worker thread.

        This is what makes the measurement deterministic rather than probable. The teardown commit
        is scheduled after the response is written, so at the instant the client has the response
        the hold may not have started yet. Reading the counters then, or issuing the follow-up
        request then, would be a race against the server — and a one-shot hold could even be claimed
        by the follow-up request's own teardown instead of the create's. Waiting here means the
        window is provably open before anything is observed through it.
        """
        if not self._holding.wait(HOLD_START_TIMEOUT_SECONDS):
            self.disarm()
            raise LiveGateInconclusive(
                f"no production teardown commit was held within {HOLD_START_TIMEOUT_SECONDS}s of "
                "arming, so the observation window was never opened"
            )

    def wait_for_release(self) -> None:
        """Block until a held commit has finished being held (no-op if none was ever held).

        Leaving a measurement while its commit is still parked would leave the row uncommitted and
        the transaction open for whichever test ran next.
        """
        if not self._holding.is_set():
            return
        if not self._released.wait(self.seconds + RELEASE_GRACE_SECONDS):
            raise LiveGateInconclusive(
                f"the held teardown commit was still parked "
                f"{self.seconds + RELEASE_GRACE_SECONDS}s after the hold began"
            )


# --- fixtures -------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pg_engine() -> Iterator[Engine]:
    """Rebind the process-global engine to real PostgreSQL, on a freshly created schema."""
    assert PG_URL
    engine = reset_engine_for_tests(PG_URL)
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        conn.exec_driver_sql("CREATE SCHEMA public")
    Base.metadata.create_all(engine)
    factory = get_sessionmaker()
    with factory() as session:
        bootstrap_dev(session)
        session.commit()
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(scope="module")
def commit_delay() -> Iterator[TeardownCommitDelay]:
    """One listener for the whole module; detached only once every live server has stopped."""
    probe = TeardownCommitDelay()
    event.listen(OrmSession, "before_commit", probe.before_commit)
    try:
        yield probe
    finally:
        probe.disarm()
        event.remove(OrmSession, "before_commit", probe.before_commit)


@pytest.fixture
def built_app(pg_engine: Engine) -> object:
    """The real, shipped application composition, bound to the live PostgreSQL engine."""
    from secp_api.main import create_app

    app = create_app()
    # The schema and the dev seed are created explicitly above, so the dev bootstrap hook has
    # nothing left to do; clearing it keeps startup deterministic. No route, dependency, middleware
    # or error handler is altered — the app under test is the shipped composition.
    app.router.on_startup.clear()
    return app


@pytest.fixture
def live_base_url(built_app: object) -> Iterator[str]:
    """The real application object, served over a real ephemeral-port TCP socket."""
    with live_api_server(built_app) as server:
        yield server.base_url


def _require_postgresql(engine: Engine) -> None:
    """Refuse an engine this gate is not currently scoped to.

    This is a SCOPE assertion, not a claim that other engines cannot show the defect — SQLite
    demonstrably can. It exists so a mis-set ``SECP_TEST_POSTGRES_URL`` cannot silently run the
    gate somewhere its CI accounting was not calibrated for, which would be a green that nobody
    calibrated rather than a green that was earned.
    """
    if engine.dialect.name != "postgresql":
        raise LiveGateInconclusive(
            f"this gate is currently scoped to PostgreSQL; the live engine is "
            f"{engine.dialect.name!r}. That scoping is a CI-coupling decision pending stability "
            "data, NOT a claim that this engine hides the defect — see the module docstring."
        )


# --- the harness must work, and must be seen to work ----------------------------------------------


def test_the_harness_serves_the_real_app_over_a_real_tcp_socket(
    pg_engine: Engine, live_base_url: str
) -> None:
    """Proves the gate below is not vacuous.

    If the server never started, or answered something other than the real application, the
    expected-failure marker on the gate would happily absorb the resulting error and the whole job
    would read as "the known defect, still pending". This test carries no marker: it fails loudly.
    """
    _require_postgresql(pg_engine)

    port = httpx.URL(live_base_url).port
    assert port is not None and port > 0, f"no ephemeral port was bound: {live_base_url!r}"

    with httpx.Client(base_url=live_base_url, timeout=HTTP_TIMEOUT_SECONDS) as client:
        health = client.get("/health")
        assert health.status_code == 200, health.text
        # A route only the real composed application serves, reached over that same socket, with the
        # real dependency chain (session + principal) behind it.
        listed = client.get("/api/v1/templates")
        assert listed.status_code == 200, listed.text
        assert isinstance(listed.json(), list)
        # The client really did talk to the ephemeral port, not to an in-process ASGI shortcut.
        assert listed.request.url.port == port


def test_the_harness_releases_the_port_when_it_stops(built_app: object) -> None:
    """No leaked listener: once the block exits, the ephemeral port stops answering.

    A harness that left a server running would make every later measurement in this process
    ambiguous — and the whole point of this module is that an absent signal must not look like a
    passing one.
    """
    with live_api_server(built_app) as server:
        host, port = server.host, server.port
        with socket.create_connection((host, port), timeout=10.0):
            pass  # a real TCP connection to a real listener

    deadline = time.perf_counter() + 10.0
    while True:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                pass
        except OSError:
            break  # refused: the listener is gone
        if time.perf_counter() >= deadline:
            raise AssertionError(
                f"{host}:{port} still accepted a connection after the harness "
                "stopped; the live server leaked"
            )
        time.sleep(0.05)

    assert not [t for t in threading.enumerate() if t.name == "secp-live-api-server"]


def test_the_teardown_delay_fires_only_for_the_production_commit_site(
    pg_engine: Engine, live_base_url: str, commit_delay: TeardownCommitDelay
) -> None:
    """Proves the widening mechanism is neither inert nor indiscriminate.

    Count-based and in both directions: a commit through the same production API is declined when it
    is not the dependency teardown, and exactly one commit is held when it is.
    """
    _require_postgresql(pg_engine)

    # Disarmed: the listener is installed but must do nothing at all.
    commit_delay.disarm()
    commit_delay.delayed_commits = 0
    commit_delay.declined_commits = 0
    with get_sessionmaker()() as session:
        session.commit()
    assert commit_delay.delayed_commits == 0
    assert commit_delay.declined_commits == 0

    # Armed, but committing from the test's own session: ``get_db`` is not on this stack, so the
    # listener must decline it and stay armed for the real thing.
    commit_delay.arm(0.05)
    with get_sessionmaker()() as session:
        session.commit()
    assert commit_delay.delayed_commits == 0
    assert commit_delay.declined_commits == 1

    # Armed, and a real request over the socket through the real teardown: held exactly once.
    with httpx.Client(base_url=live_base_url, timeout=HTTP_TIMEOUT_SECONDS) as client:
        assert client.get("/api/v1/templates").status_code == 200
    commit_delay.wait_until_holding()
    commit_delay.wait_for_release()
    assert commit_delay.delayed_commits == 1, (
        "the production teardown commit was never held, so the gate below would measure nothing"
    )
    assert commit_delay.declined_commits == 1
    # ...and held for real, not merely counted. A probe that records a hold it did not perform
    # would leave the gate's window closed while its bookkeeping still looked right.
    assert commit_delay.held_for >= 0.05, f"the commit was parked for {commit_delay.held_for:.4f}s"
    assert commit_delay.hold_started_at < commit_delay.hold_ended_at
    commit_delay.disarm()


# --- the gate ------------------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    raises=ReadAfterWriteViolation,
    reason=(
        "secp_api.deps.db_session is a plain generator dependency, so secp_api.db.get_db's commit "
        "runs on FastAPI's request exit stack, after the response is sent. Expected to fail until "
        "Depends(db_session, scope='function') (or an equivalent fix) lands; strict=True then "
        "turns the unexpected pass into a failure, so this marker cannot outlive the defect."
    ),
)
def test_a_created_template_is_readable_by_the_immediately_following_request(
    pg_engine: Engine, live_base_url: str, commit_delay: TeardownCommitDelay
) -> None:
    _require_postgresql(pg_engine)

    slug = f"socket-gate-{uuid.uuid4().hex[:12]}"

    with httpx.Client(base_url=live_base_url, timeout=HTTP_TIMEOUT_SECONDS) as client:
        commit_delay.arm(TEARDOWN_DELAY_SECONDS)
        try:
            started = time.perf_counter()
            created = client.post("/api/v1/templates", json={"name": "socket gate", "slug": slug})
            response_latency = time.perf_counter() - started
            if created.status_code != 201:
                raise LiveGateInconclusive(
                    f"the create did not succeed ({created.status_code}): {created.text}"
                )
            created_id = created.json()["id"]

            # The latency above is already recorded, so this barrier cannot flatter the timing. It
            # only guarantees the window is open before the follow-up read looks through it — see
            # ``wait_until_holding``. Once the fix lands the hold has already happened during the
            # POST, so this returns immediately and the ordering is measured the same way.
            commit_delay.wait_until_holding()

            listed = client.get("/api/v1/templates")
            read_finished_at = time.perf_counter()
            if listed.status_code != 200:
                raise LiveGateInconclusive(
                    f"the follow-up read did not succeed ({listed.status_code}): {listed.text}"
                )
            observed = [t["id"] for t in listed.json()].count(created_id)
        finally:
            commit_delay.wait_for_release()
            commit_delay.disarm()

    # --- post-conditions: exact counts, and a refusal wherever the measurement is not decisive ---
    if commit_delay.delayed_commits != 1:
        raise LiveGateInconclusive(
            f"expected exactly 1 held production teardown commit, observed "
            f"{commit_delay.delayed_commits}; the observation window was never opened, so neither "
            "outcome below would mean anything"
        )

    window_was_open = response_latency <= TEARDOWN_DELAY_SECONDS - AMBIGUITY_MARGIN_SECONDS
    teardown_preceded_response = response_latency >= TEARDOWN_DELAY_SECONDS
    if not window_was_open and not teardown_preceded_response:
        raise LiveGateInconclusive(
            f"the create returned in {response_latency:.3f}s against a {TEARDOWN_DELAY_SECONDS}s "
            "held commit, which does not decide whether the teardown ran before or after the "
            "response"
        )

    if window_was_open:
        # The window has to have been genuinely open for the duration claimed, and the read has to
        # have happened INSIDE it. Without these two, a hold that never actually held (or a read
        # that landed after the commit) could still produce an absent row for some unrelated
        # reason and be reported as the defect.
        if commit_delay.held_for < TEARDOWN_DELAY_SECONDS - AMBIGUITY_MARGIN_SECONDS:
            raise LiveGateInconclusive(
                f"the production commit was parked for only {commit_delay.held_for:.3f}s of the "
                f"{TEARDOWN_DELAY_SECONDS}s asked for, so there was no window to observe through"
            )
        if not commit_delay.hold_started_at < read_finished_at < commit_delay.hold_ended_at:
            raise LiveGateInconclusive(
                f"the follow-up read completed at {read_finished_at:.3f} but the commit was parked "
                f"from {commit_delay.hold_started_at:.3f} to {commit_delay.hold_ended_at:.3f}, so "
                "the read did not take place inside the open window"
            )
        # The client held a 201 while the transaction that produced it was still demonstrably open.
        if observed == 0:
            raise ReadAfterWriteViolation(
                f"the API returned 201 for template {created_id} in {response_latency:.3f}s, "
                f"then the immediately following read — issued inside the "
                f"{commit_delay.held_for:.3f}s during which secp_api.db.get_db had provably not "
                f"committed — saw {observed} matching row(s). A client can act on a create the "
                "control plane cannot yet read back."
            )
        raise LiveGateInconclusive(
            f"the response ({response_latency:.3f}s) preceded the held commit, and the read landed "
            f"inside the {commit_delay.held_for:.3f}s window, yet the row was already readable "
            f"{observed} time(s). The delay did not hold the transaction it appeared to."
        )

    # The response waited for the teardown, i.e. the commit is no longer request-scoped. The create
    # must then be readable exactly once — the property this gate was written to defend.
    if observed != 1:
        raise LiveGateInconclusive(
            f"the create waited {response_latency:.3f}s for its commit, so it was committed before "
            f"the response, yet the follow-up read saw {observed} matching row(s) rather than 1"
        )
