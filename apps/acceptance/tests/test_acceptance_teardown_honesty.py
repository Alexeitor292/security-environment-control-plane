"""A teardown that could not reach the runtime must not report success.

This is a hermetic regression test for a false green found in this harness itself, by running the
container tier against a genuinely stopped Docker daemon rather than a mocked one.

WHAT WENT WRONG
---------------
``HostFleet.destroy`` removed each object and then asked ``_exists`` whether it was still there.
With the daemon down, every removal failed AND every existence probe answered "no" — for the same
reason, which is that nothing could be reached at all. ``destroy`` concluded that no object
remained and reported a clean teardown, having done nothing.

That is the most expensive false green available to this harness: the caller's whole reason for
reading the teardown result is to find out whether it leaked a privileged container with a nested
Docker daemon inside, and the answer was "no" precisely when it could not know.

The fix probes the daemon FIRST and reports ``runtime_unreachable`` as residual. These tests pin
both directions, because a fix that made ``destroy`` always report residual would be equally wrong
and equally green.
"""

from __future__ import annotations

import pytest
from secp_acceptance.hosts import HostFleet
from secp_acceptance.shell import Result


class _DeadDaemon:
    """Every docker invocation fails, exactly as it does when the daemon is stopped."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, *args: str, timeout: int = 0, check: bool = False) -> Result:
        self.calls.append(args)
        return Result(exit_code=1, stdout="", stderr="")


class _LiveDaemonNothingPresent:
    """The daemon answers; the named objects genuinely do not exist.

    ``version`` succeeds, removals fail (nothing to remove), and ``inspect`` fails (not found) —
    which is the ordinary idempotent-teardown case and must still report clean.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, *args: str, timeout: int = 0, check: bool = False) -> Result:
        self.calls.append(args)
        if args[0] == "version":
            return Result(exit_code=0, stdout="linux\n", stderr="")
        return Result(exit_code=1, stdout="", stderr="")


def test_a_teardown_that_cannot_reach_the_runtime_reports_residual(monkeypatch):
    """The regression. Clean must be False and the reason must be nameable."""
    dead = _DeadDaemon()
    monkeypatch.setattr("secp_acceptance.hosts.docker", dead)

    clean, report = HostFleet(prefix="secp-acc-test").destroy()

    assert clean is False, "a teardown that reached nothing must never report success"
    assert report["residual"] == ["runtime_unreachable"]


def test_the_unreachable_teardown_stops_immediately(monkeypatch):
    """It must not grind through every removal and probe against a dead daemon.

    Each of those calls waits out its own timeout, which turned a fast failure into an eight-minute
    one. Bounded here by counting the calls: exactly one probe, then the refusal.
    """
    dead = _DeadDaemon()
    monkeypatch.setattr("secp_acceptance.hosts.docker", dead)

    HostFleet(prefix="secp-acc-test").destroy()

    assert len(dead.calls) == 1
    assert dead.calls[0][0] == "version"


def test_an_ordinary_idempotent_teardown_still_reports_clean(monkeypatch):
    """The control, and the half a naive fix would break.

    The daemon is up and the objects are genuinely absent — a second ``destroy``, or a teardown
    after a creation that died before building anything. That must still be clean, or every run
    would end by reporting a leak it does not have.
    """
    live = _LiveDaemonNothingPresent()
    monkeypatch.setattr("secp_acceptance.hosts.docker", live)

    clean, report = HostFleet(prefix="secp-acc-test").destroy()

    assert clean is True
    assert report["residual"] == []
    # and it did the work rather than short-circuiting: probe, removals, and existence checks
    assert len(live.calls) > 1
    assert any(call[0] == "rm" for call in live.calls)
    assert any(call[0] == "network" for call in live.calls)


def test_a_surviving_object_is_reported_as_residual(monkeypatch):
    """The other direction: the daemon is up, removal fails, and the object IS still there. That
    must be reported — it is the actual leak the caller is looking for."""

    class _StubbornContainer:
        def __call__(self, *args: str, timeout: int = 0, check: bool = False) -> Result:
            if args[0] == "version":
                return Result(exit_code=0, stdout="linux\n", stderr="")
            if args[0] == "container" and args[1] == "inspect":
                return Result(exit_code=0, stdout="{}", stderr="")  # still present
            return Result(exit_code=1, stdout="", stderr="")

    monkeypatch.setattr("secp_acceptance.hosts.docker", _StubbornContainer())

    clean, report = HostFleet(prefix="secp-acc-test").destroy()

    assert clean is False
    assert report["residual"] == ["container:controller", "container:worker"]


@pytest.mark.parametrize("probe_exit", [0, 1])
def test_the_probe_decides_and_nothing_else_does(monkeypatch, probe_exit: int):
    """Attribute the behaviour to the daemon probe alone. With every other call identical, the
    probe's exit status alone flips the verdict — so neither result is an artefact of the removals
    happening to fail."""

    class _ProbeControlled:
        def __call__(self, *args: str, timeout: int = 0, check: bool = False) -> Result:
            if args[0] == "version":
                return Result(exit_code=probe_exit, stdout="linux\n", stderr="")
            return Result(exit_code=1, stdout="", stderr="")

    monkeypatch.setattr("secp_acceptance.hosts.docker", _ProbeControlled())

    clean, report = HostFleet(prefix="secp-acc-test").destroy()

    assert clean is (probe_exit == 0)
    assert report["residual"] == ([] if probe_exit == 0 else ["runtime_unreachable"])
