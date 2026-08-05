"""Readiness must be probed from a vantage point the worker can actually reach.

A range published on ``127.0.0.1`` is bound to the DAEMON HOST's loopback. When the worker itself
runs in a container -- which is what the shipped Compose path does -- its own ``127.0.0.1`` is a
different, private namespace, so the probe is refused while the service is up and answering the
operator perfectly well. The range then failed with ``readiness_not_observed`` after having
genuinely deployed.

Measured on Docker Desktop 29.4.0, one juice-shop container, one published port: from the host
``127.0.0.1:<p>`` answered HTTP 200; from the shipped Compose worker the same address was refused
and ``host.docker.internal:<p>`` answered HTTP 200.

What must NOT change while fixing that:

* the range stays PUBLISHED on loopback only -- that is a security property, not a detail;
* the address recorded in the observation and shown to the operator stays ``127.0.0.1``;
* a worker running on the host keeps probing exactly what it always did, first;
* ``readiness_not_observed`` stays reachable. Widening where the worker LOOKS must not widen what
  counts as an answer.
"""

from __future__ import annotations

import secp_api.range_models  # noqa: F401
import secp_worker.range.local_docker as local_docker
from secp_api.range_enums import RangeResourceKind
from secp_api.range_providers.base import ComponentSpec, ResourceObservation
from secp_worker.range.local_docker import BIND_HOST, PROBE_HOSTS, LocalDockerProvider

HOST_PORT = 50921


def _component() -> ComponentSpec:
    return ComponentSpec(
        key="juice-shop",
        name="OWASP Juice Shop",
        role="target",
        image="bkimminich/juice-shop:v17.1.0",
        container_port=3000,
        readiness_timeout_seconds=2,
    )


def _observation() -> ResourceObservation:
    return ResourceObservation(
        kind=RangeResourceKind.container,
        name="secp-range-24408a-juice-shop",
        component_key="juice-shop",
        host_port=HOST_PORT,
    )


def _running(monkeypatch) -> None:
    """The container is up throughout; only reachability is in question."""
    monkeypatch.setattr(
        local_docker, "inspect_json", lambda kind, ref: {"State": {"Status": "running"}}
    )
    monkeypatch.setattr(local_docker.time, "sleep", lambda _s: None)


def _probe(monkeypatch, answers: dict[str, tuple[bool, str]]) -> list[str]:
    """Install a probe that answers per HOST, and record every URL attempted, in order."""
    attempted: list[str] = []

    def fake(url: str, timeout: float = 5.0) -> tuple[bool, str]:
        attempted.append(url)
        host = url.split("://", 1)[1].split(":", 1)[0]
        return answers.get(host, (False, "[Errno 111] Connection refused"))

    monkeypatch.setattr(local_docker, "_probe_http", fake)
    return attempted


# --- the publish address is untouched -------------------------------------------------------------


def test_the_published_bind_host_is_still_loopback_only():
    """The fix must not have been "make the probe work by widening the bind"."""
    assert BIND_HOST == "127.0.0.1"


def test_the_primary_probe_vantage_is_the_published_address():
    """A host-run worker must probe exactly what it always did, on the FIRST attempt.

    If an alternate were tried first, every host-run deployment would pay a failed lookup before
    its normal success, and the common path would change to fix an uncommon one.
    """
    assert PROBE_HOSTS[0] == BIND_HOST


# --- containerized worker: the defect this closes -------------------------------------------------


def test_readiness_is_observed_when_only_the_alternate_vantage_can_reach_the_app(monkeypatch):
    """The exact shipped-Compose condition: 127.0.0.1 refused, host.docker.internal answers."""
    _running(monkeypatch)
    attempted = _probe(monkeypatch, {"host.docker.internal": (True, "HTTP 200")})

    ok, detail = LocalDockerProvider()._verify_component(_component(), _observation())

    assert ok, "the app answered on a reachable vantage point but readiness was not observed"
    assert f"http://{BIND_HOST}:{HOST_PORT}/" == attempted[0], (
        "the published address must be tried first"
    )
    assert any("host.docker.internal" in u for u in attempted)
    assert "HTTP 200" in detail
    assert "host.docker.internal" in detail, (
        "a fallback vantage point must be named; otherwise the log claims the worker reached "
        "127.0.0.1 when it could not, which is the fact a person debugging this needs"
    )


def test_a_host_run_worker_is_unchanged(monkeypatch):
    """When the published address answers, nothing about the result mentions a fallback."""
    _running(monkeypatch)
    attempted = _probe(monkeypatch, {BIND_HOST: (True, "HTTP 200")})

    ok, detail = LocalDockerProvider()._verify_component(_component(), _observation())

    assert ok
    assert detail == "HTTP 200", "the host-run detail string changed"
    assert attempted == [f"http://{BIND_HOST}:{HOST_PORT}/"], (
        "a worker that could reach the published address probed something else as well"
    )


def test_every_vantage_point_addresses_the_same_published_port(monkeypatch):
    """Widening WHERE we look must not become looking at a different thing.

    Every candidate must name the port Docker actually published for this container; a probe that
    drifted to another port could report readiness for a service that is not the range's.
    """
    _running(monkeypatch)
    attempted = _probe(monkeypatch, {})

    LocalDockerProvider()._verify_component(_component(), _observation())

    assert attempted, "no probe was attempted at all"
    for url in attempted:
        assert url.endswith(f":{HOST_PORT}/"), f"probe drifted off the published port: {url}"


# --- no invented success --------------------------------------------------------------------------


def test_unreachable_from_every_vantage_point_is_still_not_ready(monkeypatch):
    """The whole point of the seal: readiness must remain falsifiable.

    If widening the vantage list had made readiness unconditional, this is the test that would have
    caught it.
    """
    _running(monkeypatch)
    _probe(monkeypatch, {})

    ok, detail = LocalDockerProvider()._verify_component(_component(), _observation())

    assert not ok, "readiness was reported for an app that answered nowhere"
    assert "refused" in detail.lower()


def test_a_container_that_exits_is_never_ready_however_it_is_probed(monkeypatch):
    """A dead container short-circuits before any vantage point is consulted."""
    monkeypatch.setattr(
        local_docker,
        "inspect_json",
        lambda kind, ref: {"State": {"Status": "exited", "ExitCode": 1}},
    )
    monkeypatch.setattr(local_docker.time, "sleep", lambda _s: None)
    attempted = _probe(monkeypatch, {h: (True, "HTTP 200") for h in PROBE_HOSTS})

    ok, detail = LocalDockerProvider()._verify_component(_component(), _observation())

    assert not ok
    assert "exited" in detail
    assert not attempted, "a probe was attempted against an exited container"


def test_a_component_without_a_published_port_still_uses_the_running_state_check(monkeypatch):
    """Unchanged behaviour for a component with no HTTP surface."""
    _running(monkeypatch)
    attempted = _probe(monkeypatch, {h: (True, "HTTP 200") for h in PROBE_HOSTS})
    observation = ResourceObservation(
        kind=RangeResourceKind.container,
        name="secp-range-24408a-sidecar",
        component_key="sidecar",
        host_port=None,
    )

    ok, detail = LocalDockerProvider()._verify_component(_component(), observation)

    assert ok
    assert detail == "running"
    assert not attempted, "a port-less component was probed over HTTP"
