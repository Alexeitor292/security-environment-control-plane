"""The container tier: build the disposable two-host fleet, prove it, destroy it.

This is the first module that touches real infrastructure. Everything here is gated by
:mod:`secp_acceptance.tier`: without ``SECP_ACCEPTANCE_TIER=container`` these tests are DESELECTED
(absent from the report, not a green tick), and with it an absent container runtime is a hard
refusal rather than a skip.

WHAT THIS TIER ESTABLISHES
--------------------------
The premise every later stage rests on: two hosts that are genuinely two machines. A host is a
privileged container running systemd as PID 1 with its OWN Docker Engine inside, so the management
adapters get real ``systemctl`` answers and talk to a daemon belonging to that host alone. If the
two hosts shared one daemon, "the worker host installed the worker" and "the controller host runs
the API" would be statements about one machine wearing two names, and the operator-queue isolation
proof — the security property this program exists for — would be measuring a single Docker world.

Every stage witnesses itself. A body that does not run leaves no witness, and the session-final hook
in ``conftest.py`` fails the run even when every collected test passed.

TEARDOWN IS NOT OPTIONAL
------------------------
The fixture destroys the fleet on every path including failure, and the teardown REPORTS what it
could not remove rather than assuming success — a leaked privileged container with a nested Docker
daemon is the most expensive thing this harness could leave behind.
"""

from __future__ import annotations

import pathlib
import uuid

import pytest
from secp_acceptance.hosts import ROLE_CONTROLLER, ROLE_WORKER, HostFleet
from secp_acceptance.reasons import STAGE_FLEET
from secp_acceptance.recorder import AcceptanceRecorder
from secp_acceptance.tier import require_container_runtime_or_refuse, witness

pytestmark = pytest.mark.container_tier


def _repo_root() -> pathlib.Path:
    here = pathlib.Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file() and (parent / "infra").is_dir():
            return parent
    raise AssertionError("repository root not found from the test file location")


@pytest.fixture(scope="module")
def runtime_version() -> str:
    """Prove the outer container runtime before anything is built.

    REFUSES when Docker is absent. This is the point in the harness where "Docker is down" becomes
    a loud, bounded, attributable failure instead of a quiet skip.
    """
    return require_container_runtime_or_refuse()


@pytest.fixture(scope="module")
def fleet(runtime_version: str):
    """The run-scoped disposable fleet. Always destroyed, including on the failure paths."""
    prefix = f"secp-acc-{uuid.uuid4().hex[:10]}"
    built = HostFleet(prefix=prefix)
    infra = _repo_root() / "infra" / "acceptance"
    try:
        built.build_image(context=str(infra), dockerfile=str(infra / "Dockerfile.host"))
        built.create()
        witness("fleet_created")
        yield built
    finally:
        clean, residual = built.destroy()
        witness("fleet_destroyed")
        # Reported, not swallowed. A teardown that could not finish is a real problem for the next
        # run on this machine, and it must not be discoverable only by noticing a slow disk.
        assert clean, f"the disposable fleet did not fully tear down: {residual}"


# --------------------------------------------------------------------------- the fleet premise


def test_the_outer_container_runtime_serves_linux_containers(runtime_version: str):
    """A Windows-container daemon cannot run any part of this harness. Established first, so a
    wrong daemon fails here rather than forty confusing lines into an image build."""
    assert runtime_version
    assert runtime_version[0].isdigit()


@pytest.mark.parametrize("role", [ROLE_CONTROLLER, ROLE_WORKER])
def test_each_host_booted_systemd_and_its_own_docker_daemon(fleet: HostFleet, role: str):
    """Real systemd, real nested daemon — the two things that make this an acceptance rather than
    a simulation."""
    observed = fleet.observe_readiness(fleet.hosts[role])
    assert observed["role"] == role
    assert observed["systemd_state"] in ("running", "degraded")
    assert observed["dockerd_answers"] is True
    assert observed["systemd_major"]


def test_the_two_hosts_do_not_share_a_container_runtime(fleet: HostFleet):
    """THE premise of a two-host acceptance. Every later isolation claim is a claim about one
    machine unless this holds."""
    distinct, observation = fleet.daemons_are_distinct()
    assert distinct is True, "both hosts answered from the same Docker daemon"
    assert observation["controller_daemon"] != observation["worker_daemon"]
    witness("fleet_proved")


def test_the_hosts_resolve_each_other_by_name(fleet: HostFleet):
    """The worker must be able to reach the controller by DNS name for enrollment to be real. The
    names are under the RFC 6761 reserved ``.test`` suffix, so they can never collide with a
    resolvable host."""
    worker = fleet.hosts[ROLE_WORKER]
    probe = worker.exec(("getent", "hosts", fleet.hosts[ROLE_CONTROLLER].dns_name), timeout=60)
    assert probe.ok, "the worker host cannot resolve the controller host by name"


def test_the_fleet_record_is_nonsecret_and_records_what_was_built(fleet: HostFleet):
    """The fleet's contribution to the evidence document carries digests and counts only — never a
    container id, an address, or an image list."""
    record = fleet.record()
    assert record.hosts_created == 2
    assert record.nested_container_runtime is True
    assert record.real_service_manager is True
    for value in record.canonical().values():
        if isinstance(value, str):
            assert "/" not in value or value.startswith("sha256:")


def test_a_fleet_stage_can_be_recorded_into_the_evidence_document(fleet: HostFleet):
    """The tier and the evidence contract meet here: real observations, recorded through the same
    recorder the hermetic tests pin, so the container tier cannot produce a document shape the
    loader would refuse."""
    recorder = AcceptanceRecorder()
    recorder.open_stage(STAGE_FLEET)
    for role, checks in (
        (ROLE_CONTROLLER, ("controller_host_systemd_running", "controller_host_dockerd_active")),
        (ROLE_WORKER, ("worker_host_systemd_running", "worker_host_dockerd_active")),
    ):
        observed = fleet.observe_readiness(fleet.hosts[role])
        recorder.observe(checks[0], STAGE_FLEET, {"systemd_state": observed["systemd_state"]})
        recorder.observe(checks[1], STAGE_FLEET, {"dockerd": observed["dockerd_answers"]})
    distinct, observation = fleet.daemons_are_distinct()
    recorder.observe("hosts_are_distinct", STAGE_FLEET, observation)
    # `fleet_destroyed` is deliberately NOT recorded here: the fleet is still up. Recording it now
    # would put a claim in the document that the run has not yet earned.
    assert "fleet_destroyed" in recorder.missing()


# --------------------------------------------------------------------------- teardown


def test_destroy_is_idempotent_and_reports_residual_honestly(runtime_version: str):
    """A destroy of a fleet that was never created must be clean and must not raise.

    Runs against a fleet with a name nothing was ever built under, so it exercises the exact path
    the failure-teardown takes when creation died partway.

    It takes ``runtime_version`` even though it never touches the fleet, and that is load-bearing:
    with the daemon down, every removal fails and every existence probe answers "no" for the same
    reason, so an ungated version of this test reports a clean teardown having done nothing. It
    passed exactly that way once. The fixture makes an absent runtime a refusal instead.
    """
    never_built = HostFleet(prefix=f"secp-acc-absent-{uuid.uuid4().hex[:8]}")
    clean, residual = never_built.destroy()
    assert clean is True
    assert residual["residual"] == []
