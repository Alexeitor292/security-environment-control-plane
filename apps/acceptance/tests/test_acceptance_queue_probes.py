"""The seam between the probe and the judge, closed WITHOUT a host.

``queue_probes`` obtains observations; ``queues`` decides what they mean. Between them is a
projection shape, and a mismatch there is the most expensive defect available to this stage: the
probe would run correctly against a real fleet for twenty minutes and the validator would refuse
its output as malformed, or — far worse — read a shape it half-recognises as "no pollers".

So the seam is tested by running the REAL probe against a stubbed Temporal client and feeding its
ACTUAL stdout to the REAL validator. Nothing here needs a container, and the container tier
therefore never has to discover a schema disagreement.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import textwrap

import pytest
from secp_acceptance import AcceptanceError
from secp_acceptance.queue_probes import (
    FORBIDDEN_PROBE_VERBS,
    assert_probe_is_read_only,
    parse_probe_output,
    probe_request,
    probe_source,
)
from secp_acceptance.queues import (
    ROLE_OPERATOR_MANAGEMENT,
    ROLE_ORDINARY,
    VERDICT_HELD,
    VERDICT_UNPROVABLE,
    VERDICT_VIOLATED,
    observe_pollers,
    resolve_operator_isolation,
    resolve_ordinary_poller,
)

WORKER_IDENTITY = "41@secp-ordinary-worker"


# --------------------------------------------------------------------------- the probe is inert


def test_the_probe_contains_no_verb_that_could_start_or_submit_anything():
    """STRUCTURAL, not documentary. On the operator queue, submitting is the one act this whole
    program exists to prevent, so the probe must not contain the means."""
    assert_probe_is_read_only()


def test_the_read_only_guard_can_actually_fail():
    """CONTROL. A guard that cannot fire would make the assertion above decorative."""
    for verb in FORBIDDEN_PROBE_VERBS:
        with pytest.raises(AcceptanceError):
            assert_probe_is_read_only(f"await client.{verb})")


@pytest.mark.parametrize(
    "innocent",
    [
        'entry["pollers"] = [p.identity for p in described.pollers]',
        "poller_count = len(pollers)",
        "# the worker polls this queue",
        "signalling_is_not_signal_workflow = True",
    ],
)
def test_the_read_only_guard_does_not_cry_wolf(innocent: str):
    """THE OTHER DIRECTION, and it is why the list holds call-shaped tokens rather than words.

    This guard once carried a bare ``"poll"``, which matched ``pollers`` — the read-only field the
    probe exists to read — and refused the very probe it was written to protect. A guard that
    cannot distinguish data from an act is as broken as one that never fires; it just fails in the
    direction someone notices, which is the lucky direction.
    """
    assert_probe_is_read_only(innocent)


def test_the_probe_source_holds_no_run_specific_value():
    """The script is a CONSTANT delivered on stdin. Queue names are values the harness READ, so
    interpolating them would break the property ``exec_as_script`` exists to keep — they travel in
    a file instead. The only substitution is a harness-owned path."""
    source = probe_source()
    for leaked in ("secp-orchestration", "secp-controlled-live-v1", "localhost:7233"):
        assert leaked not in source


def test_the_probe_parses_as_python():
    """It is executed by the host's system interpreter, so a syntax error is discovered on a real
    fleet twenty minutes in unless it is discovered here."""
    compile(probe_source(), "<probe>", "exec")


# --------------------------------------------------------------------------- the request document


def test_the_request_carries_every_queue_the_caller_asked_about():
    raw = probe_request(
        temporal_host="controller.secp.test:7233",
        namespace="default",
        queues={ROLE_ORDINARY: "q-ord", ROLE_OPERATOR_MANAGEMENT: "q-op"},
    )
    document = json.loads(raw)
    assert set(document["queues"]) == {ROLE_ORDINARY, ROLE_OPERATOR_MANAGEMENT}


def test_an_empty_queue_set_is_refused_rather_than_probed():
    """A probe of nothing returns nothing, and "no operator queue had a poller" is trivially true
    of a run that asked about none. Refused here as well as downstream."""
    with pytest.raises(AcceptanceError):
        probe_request(temporal_host="h", namespace="default", queues={})


# --------------------------------------------------------------------------- THE SEAM

_STUB = """
import sys, types

pollers = __POLLERS__

class _Poller:
    def __init__(self, identity):
        self.identity = identity

class _Described:
    def __init__(self, names):
        self.pollers = [_Poller(n) for n in names]

class _Service:
    async def describe_task_queue(self, request):
        name = request["task_queue"]["name"]
        if name not in pollers:
            raise RuntimeError("no such queue")
        return _Described(pollers[name])

class _Client:
    workflow_service = _Service()
    @classmethod
    async def connect(cls, host, namespace=None):
        return cls()

client_mod = types.ModuleType("temporalio.client")
client_mod.Client = _Client
service_mod = types.ModuleType("temporalio.service")
class RPCError(Exception):
    pass
service_mod.RPCError = RPCError
root = types.ModuleType("temporalio")
root.client = client_mod
root.service = service_mod
sys.modules["temporalio"] = root
sys.modules["temporalio.client"] = client_mod
sys.modules["temporalio.service"] = service_mod
"""


def _run_probe(tmp_path: pathlib.Path, queues: dict[str, str], pollers: dict[str, list]) -> str:
    """Run the REAL probe source in a subprocess against a stubbed temporalio."""
    request = tmp_path / "input.json"
    request.write_bytes(probe_request(temporal_host="h:7233", namespace="default", queues=queues))
    script = tmp_path / "probe.py"
    script.write_text(
        _STUB.replace("__POLLERS__", repr(pollers))
        + textwrap.dedent(probe_source(input_path=request.as_posix())),
        encoding="utf-8",
    )
    done = subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True, timeout=120
    )
    assert done.returncode == 0, done.stderr[-2000:]
    return done.stdout


def test_the_probes_real_output_is_accepted_by_the_real_validator(tmp_path: pathlib.Path):
    """THE SEAM TEST. Real probe source, real validator, no host.

    A shape disagreement between the two would otherwise surface only on a live fleet, where it
    costs a twenty-minute run and reads as an infrastructure problem rather than a schema one.
    """
    stdout = _run_probe(
        tmp_path,
        {ROLE_ORDINARY: "q-ord", ROLE_OPERATOR_MANAGEMENT: "q-op"},
        {"q-ord": [WORKER_IDENTITY], "q-op": []},
    )
    projections = parse_probe_output(stdout)
    assert set(projections) == {ROLE_ORDINARY, ROLE_OPERATOR_MANAGEMENT}

    ordinary = observe_pollers("q-ord", ROLE_ORDINARY, projections[ROLE_ORDINARY])
    operator = observe_pollers(
        "q-op", ROLE_OPERATOR_MANAGEMENT, projections[ROLE_OPERATOR_MANAGEMENT]
    )
    assert ordinary.answered is True and ordinary.poller_count == 1
    assert operator.answered is True and operator.poller_count == 0

    assert (
        resolve_ordinary_poller(ordinary, worker_identities=[WORKER_IDENTITY]).verdict
        == VERDICT_HELD
    )
    assert resolve_operator_isolation([operator]).verdict == VERDICT_HELD


def test_a_poller_on_the_operator_queue_travels_the_seam_as_a_violation(tmp_path: pathlib.Path):
    """The seam must carry the BAD news too. A probe that could only ever report isolation would
    satisfy the test above and prove nothing."""
    stdout = _run_probe(
        tmp_path,
        {ROLE_OPERATOR_MANAGEMENT: "q-op"},
        {"q-op": ["999@somewhere"]},
    )
    observed = observe_pollers(
        "q-op", ROLE_OPERATOR_MANAGEMENT, parse_probe_output(stdout)[ROLE_OPERATOR_MANAGEMENT]
    )
    assert resolve_operator_isolation([observed]).verdict == VERDICT_VIOLATED


def test_a_queue_the_server_refuses_travels_the_seam_as_unprovable(tmp_path: pathlib.Path):
    """An RPC failure must not arrive as "zero pollers" — those are the two outcomes it would be
    most damaging to confuse, and the confusion would happen HERE if anywhere."""
    stdout = _run_probe(
        tmp_path,
        {ROLE_OPERATOR_MANAGEMENT: "absent-queue"},
        {"q-op": []},  # the requested queue is not in the stub, so the stub raises
    )
    observed = observe_pollers(
        "absent-queue",
        ROLE_OPERATOR_MANAGEMENT,
        parse_probe_output(stdout)[ROLE_OPERATOR_MANAGEMENT],
    )
    assert observed.answered is False
    assert resolve_operator_isolation([observed]).verdict == VERDICT_UNPROVABLE


def test_an_unimportable_client_yields_unanswered_not_empty(tmp_path: pathlib.Path):
    """With no ``temporalio`` on the host the probe must say so. Reporting an empty poller list
    would turn a missing dependency into a clean isolation result."""
    request = tmp_path / "input.json"
    request.write_bytes(
        probe_request(temporal_host="h", namespace="default", queues={ROLE_ORDINARY: "q"})
    )
    script = tmp_path / "probe.py"
    script.write_text(probe_source(input_path=request.as_posix()), encoding="utf-8")
    done = subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True, timeout=120
    )
    assert done.returncode == 0
    with pytest.raises(AcceptanceError):
        parse_probe_output(done.stdout)


# --------------------------------------------------------------------------- parser refusals


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "[]",
        json.dumps({"answered": False, "cause": "acceptance_observation_unavailable"}),
        json.dumps({"answered": True}),
        json.dumps({"answered": True, "queues": []}),
    ],
)
def test_unusable_probe_output_is_refused_rather_than_half_read(raw: str):
    with pytest.raises(AcceptanceError):
        parse_probe_output(raw)


def test_an_over_long_poller_list_is_malformed_not_truncated():
    """Silently truncating would under-report pollers on the operator queue — the one direction
    that turns a breach into an isolation result."""
    raw = json.dumps(
        {
            "answered": True,
            "queues": {ROLE_ORDINARY: {"answered": True, "pollers": ["p"] * 5000}},
        }
    )
    assert parse_probe_output(raw)[ROLE_ORDINARY]["answered"] is False
