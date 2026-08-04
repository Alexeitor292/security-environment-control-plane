"""The evidence document's two fleet-nature booleans must be measured, not stated.

REGRESSION
----------
``HostFleet.record()`` returned ``nested_container_runtime=True, real_service_manager=True`` as
literals, and the container-tier test asserted the same two constants. Both comparisons were a
constant against itself and could not fail: a fleet that created nothing still reported both true.

That matters more than an ordinary tautological test, because the evidence document is this
harness's actual product. A degraded or non-nested run would have emitted
``nested_container_runtime: true`` to a later reader with no way to know it was never observed —
the document asserting its two defining facts without measuring either.

The properties were genuinely measured NEXT DOOR (``daemons_are_distinct``,
``observe_readiness()["dockerd_answers"]``), which is exactly what made the gap easy to miss: the
harness knew these facts and the document still did not carry them.

These are hermetic. They construct fleets directly and never build a host, so every case below —
including the ones that must report False — executes without Docker.
"""

from __future__ import annotations

from secp_acceptance.hosts import ROLE_CONTROLLER, ROLE_WORKER, HostFleet

_OUTER = "OUTER-DAEMON-ID"
_CONTROLLER_DAEMON = "CONTROLLER-DAEMON-ID"
_WORKER_DAEMON = "WORKER-DAEMON-ID"
_SYSTEMD = "systemd 255 (255.4-1ubuntu8)"


def _fleet(**overrides) -> HostFleet:
    fleet = HostFleet(prefix="secp-acc-derivation")
    fleet.outer_daemon = overrides.pop("outer_daemon", _OUTER)
    fleet.inner_daemons = overrides.pop(
        "inner_daemons",
        {ROLE_CONTROLLER: _CONTROLLER_DAEMON, ROLE_WORKER: _WORKER_DAEMON},
    )
    fleet.service_managers = overrides.pop(
        "service_managers", {ROLE_CONTROLLER: _SYSTEMD, ROLE_WORKER: _SYSTEMD}
    )
    fleet.created = overrides.pop("created", 2)
    assert not overrides, overrides
    return fleet


# --------------------------------------------------------------------------- the regression


def test_a_fleet_that_built_nothing_reports_neither_fact():
    """THE regression. This is the exact case the old literals got wrong.

    Nothing was created, nothing was observed — and the document must say so rather than carry two
    cheerful constants.
    """
    record = HostFleet(prefix="secp-acc-empty").record()
    assert record.hosts_created == 0
    assert record.nested_container_runtime is False
    assert record.real_service_manager is False


def test_a_fully_observed_fleet_reports_both():
    record = _fleet().record()
    assert record.nested_container_runtime is True
    assert record.real_service_manager is True


# --------------------------------------------------------------------------- nesting


def test_nesting_is_false_when_the_two_hosts_share_one_daemon():
    """Two hosts answering the same daemon id are one machine wearing two names, and every later
    isolation claim would be about that one machine."""
    fleet = _fleet(
        inner_daemons={ROLE_CONTROLLER: _CONTROLLER_DAEMON, ROLE_WORKER: _CONTROLLER_DAEMON}
    )
    assert fleet.nesting_is_proven() is False
    assert fleet.record().nested_container_runtime is False


def test_nesting_is_false_when_a_host_answers_the_outer_daemon():
    """The subtler failure: the hosts differ from each other, but one of them IS the developer's
    own Docker — so nothing was nested at all."""
    fleet = _fleet(inner_daemons={ROLE_CONTROLLER: _OUTER, ROLE_WORKER: _WORKER_DAEMON})
    assert fleet.nesting_is_proven() is False


def test_nesting_is_false_when_the_outer_daemon_was_never_identified():
    """Without the outer id there is no reference to claim nesting AGAINST, so the honest answer is
    "not proven" rather than "true because the two inner ids differ"."""
    fleet = _fleet(outer_daemon="")
    assert fleet.nesting_is_proven() is False


def test_nesting_is_false_when_a_host_never_answered():
    for missing in (ROLE_CONTROLLER, ROLE_WORKER):
        daemons = {ROLE_CONTROLLER: _CONTROLLER_DAEMON, ROLE_WORKER: _WORKER_DAEMON}
        del daemons[missing]
        assert _fleet(inner_daemons=daemons).nesting_is_proven() is False


# --------------------------------------------------------------------------- service manager


def test_the_service_manager_fact_requires_every_host_to_have_answered():
    for missing in (ROLE_CONTROLLER, ROLE_WORKER):
        managers = {ROLE_CONTROLLER: _SYSTEMD, ROLE_WORKER: _SYSTEMD}
        del managers[missing]
        fleet = _fleet(service_managers=managers)
        assert fleet.service_manager_is_proven() is False
        assert fleet.record().real_service_manager is False


def test_an_empty_version_string_does_not_count_as_an_answer():
    fleet = _fleet(service_managers={ROLE_CONTROLLER: _SYSTEMD, ROLE_WORKER: ""})
    assert fleet.service_manager_is_proven() is False


# --------------------------------------------------------------------------- attribution


def test_the_two_facts_are_independent():
    """Each boolean tracks its OWN witness. If one were derived from the other — or from a shared
    "the fleet came up" flag — the document would report two facts while measuring one."""
    nesting_only = _fleet(service_managers={})
    assert nesting_only.record().nested_container_runtime is True
    assert nesting_only.record().real_service_manager is False

    systemd_only = _fleet(inner_daemons={})
    assert systemd_only.record().nested_container_runtime is False
    assert systemd_only.record().real_service_manager is True


def test_neither_boolean_is_a_literal_in_record():
    """Structural. The regression was a literal `True` in ``record()``; this fails if one returns.

    Checked over the parsed AST of the method, so the prose explaining the old bug cannot satisfy
    it and a keyword whose value is a constant is caught wherever it sits in the call.
    """
    import ast
    import inspect
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(HostFleet.record)))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg in ("nested_container_runtime", "real_service_manager"):
                assert not isinstance(keyword.value, ast.Constant), (
                    f"{keyword.arg} is a literal again; it must be derived from an observation"
                )
