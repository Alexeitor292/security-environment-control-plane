"""The provenance path constructs no command runner — proven, not stated (WS-E).

``verify`` and ``queue`` COUNT host commands as they run, and report the count. ``provenance``
cannot: it does filesystem reads and spawns no process, so there is nothing to count. An earlier
version papered over that asymmetry by giving ``build_provenance_report`` a
``host_commands_executed`` parameter and rendering it under ``measured_this_invocation`` — but **no
caller ever supplied it**. The zero under a "measured" label was a signature default that nothing
set: the same hardcoded zero, moved from a dict literal into a parameter, and a test comment even
described it as "measured rather than assumed" because the command ran through the real path.
Running through the real path does not make a value measured when nothing supplies it.

The number was never wrong — the reviewer confirmed the path spawns no process. What was wrong was
the label, and the fact that nothing would have noticed if it stopped being true.

Instrumenting a path that provably never execs is weight for no information, so the claim is
restated as what it actually rests on — ``basis: no_command_runner_is_constructed_on_this_path`` —
and made EXECUTABLE here:

* :func:`test_provenance_completes_without_constructing_a_command_runner` tripwires every seam
  through which a runner could be constructed or an adapter reached, and requires the command to
  complete anyway.
* :func:`test_the_tripwires_do_fire_for_a_path_that_constructs_a_runner` proves the tripwires are
  live, by driving ``verify`` — which does construct one — into the same traps. Without this, the
  test above would pass just as happily if the tripwires were misattached.

The scenario this closes: if ``provenance`` ever grew a host command (a ``docker image inspect`` to
corroborate the installed aggregate, say), the report would otherwise keep saying zero because
nothing counts. Now the guard fires first.
"""

from __future__ import annotations

import json

from _deploy_support import seeded_production_fs


def _arm(monkeypatch) -> list[str]:  # noqa: ANN001
    """Trap every seam a command runner could be constructed or reached through.

    The tripwires RECORD as well as raise, and the assertions are made on the record. That is not
    belt-and-braces: ``load_verify_context`` wraps its host-observation step in ``except
    Exception``, which is correct fail-closed behaviour and also swallows a raising tripwire whole.
    A guard that only expected a raise to propagate would have been silently unable to fire — the
    exact vacuity this file exists to rule out, one level up.
    """
    from secp_operator_deployment import host_adapters, host_process, production_context

    reached: list[str] = []

    def _trip(name: str):  # noqa: ANN202
        def _fail(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
            reached.append(name)
            raise AssertionError(f"reached {name}")

        return _fail

    monkeypatch.setattr(production_context, "_command_runner", _trip("_command_runner"))
    monkeypatch.setattr(
        host_adapters, "build_real_host_adapters", _trip("build_real_host_adapters")
    )
    monkeypatch.setattr(
        host_process.RealCommandRunner, "run", _trip("RealCommandRunner.run"), raising=False
    )
    monkeypatch.setattr(
        production_context._CountingCommandRunner,
        "run",
        _trip("_CountingCommandRunner.run"),
        raising=False,
    )
    return reached


def test_provenance_completes_without_constructing_a_command_runner(monkeypatch, capsys):
    """The claim the report now makes, executed."""
    from secp_operator_deployment.cli import main

    reached = _arm(monkeypatch)

    code = main(["provenance", "--json"])  # must not trip anything
    payload = json.loads(capsys.readouterr().out)

    assert reached == [], f"the provenance path reached a runner seam: {reached}"
    assert payload["phase"] == "provenance"
    assert code == payload["exit_code"]

    contact = payload["effects_of_this_provenance_check"]["host_contact"]
    assert contact["host_commands_executed"] == 0
    assert contact["local_host_contact_performed"] is False
    assert contact["basis"] == "no_command_runner_is_constructed_on_this_path"


def test_the_tripwires_do_fire_for_a_path_that_constructs_a_runner(monkeypatch, capsys):
    """Guard the guard: the test above is only worth anything if the traps are live.

    ``verify`` resolves the full production context and DOES construct a runner once a profile and
    pins are present, so the same arming must be seen to catch it. Without this, misattached
    tripwires would make the provenance test vacuously green.

    Asserted on the RECORD, not on a propagating exception: ``load_verify_context`` catches
    ``Exception`` around this step, so the raise never escapes. It is caught here anyway — which is
    the point of recording.

    ONE LIMIT, stated because this file exists to rule out vacuity and would otherwise be implying
    more than it shows: ``_command_runner`` trips FIRST and aborts the observation, so the other
    three traps are never exercised here. Their liveness rests on inspection — they are attached by
    the same ``_arm`` helper, in the same way, verified by reading — not on demonstration. Proving
    each independently would need a separate fixture per trap, arranged so the earlier ones cannot
    fire; that is real work for a small gain, and it is not done. What IS demonstrated is that the
    arming mechanism works at all, which is the property the provenance test above depends on.
    """
    from secp_operator_deployment import production_context
    from secp_operator_deployment.cli import main

    # A resolvable deployment, so the context loader reaches the host-observation step at all.
    monkeypatch.setattr(production_context, "_production_fs", lambda: seeded_production_fs())
    reached = _arm(monkeypatch)

    main(["verify", "--json"])
    capsys.readouterr()

    assert "_command_runner" in reached, (
        "the tripwires did not catch a path that does construct a runner — they are misattached, "
        "and the provenance guard above would be vacuous"
    )


def test_the_provenance_report_exposes_no_settable_contact_count():
    """The dead parameter is gone, not merely unused.

    While it existed, a caller could have supplied any number and the report would have rendered it
    under a measured-sounding label. Removing it means the zero cannot be set to anything else.
    """
    import inspect

    from secp_operator_deployment.verify import build_provenance_report

    params = inspect.signature(build_provenance_report).parameters
    assert "host_commands_executed" not in params


def test_the_provenance_section_is_not_labelled_measured():
    """``measured_this_invocation`` means COUNTED in the other two reports. Reusing the name here
    would borrow their credibility for a value nothing counts."""
    from _deploy_support import valid_expected
    from secp_operator_deployment.verify import build_provenance_report

    effects = build_provenance_report(
        source_aggregate="sha256:" + "a" * 64, expected=valid_expected()
    )["effects_of_this_provenance_check"]

    assert set(effects) == {"host_contact", "structural_invariants"}
    assert "measured_this_invocation" not in effects
