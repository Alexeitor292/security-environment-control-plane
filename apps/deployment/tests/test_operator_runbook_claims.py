"""The operator runbook's checkable claims (WS-E).

Most of a runbook is prose and cannot be tested. A few of its claims are not prose: when it tells
an operator *which command to run*, that is a factual assertion about another package's CLI, and it
is exactly the kind of claim that rots silently — the command gets renamed, the runbook keeps
naming the old one, and the operator meets an argparse error in the middle of a supervised
installation sequence.

So the command names are pinned three ways, and a drift in any direction fails:

* the set the runbook NAMES,
* the set ``secp_commissioning`` actually EXPOSES,
* the set ``secp_operator_deployment`` actually exposes.

Two of the runbook's *descriptive* claims are pinned as well, because they are **safety defaults**
of another package and a runbook that misstated them would be an operator-facing defect rather than
a docs nit: that `install-prepared` is dry-run by default, and that nothing in `secp_commissioning`
can enable or start the operator unit. Neither pin duplicates `secp_commissioning`'s own suite —
that suite tests its *behaviour*; these assert the *declared surface* my runbook describes, by
introspection and by absence, so the two cannot drift apart silently.

Still narrow, and the remaining gaps stated rather than implied. It does not check the rest of the
runbook's descriptions, its step ordering, its JSON examples, or the dry-run *semantics* (that the
gate actually precedes the writes) — that last one is `secp_commissioning`'s to test, and
reasserting it here would be the duplication this file exists to avoid. Those remain unpoliced
prose, and saying so is cheaper than implying a coverage that does not exist.

One further limit on the zero-match pin, stated because it is the sort of thing that decays into a
false alarm: `secp_commissioning` delegates service observation to an INJECTED
`ServiceStateAdapter`, so "no enable path here" is necessary but not sufficient on its own. The
real adapter lives in this package and its absence of mutation verbs is pinned separately by
``test_deployment_r4_regressions.py::test_adapters_expose_no_mutation_verb``. Together they cover
the claim; either alone does not.

Nothing here runs a command; parsers are built, signatures introspected, sources read.
"""

from __future__ import annotations

import argparse
import pathlib

_RUNBOOK = (
    pathlib.Path(__file__).resolve().parents[3] / "docs" / "runbooks" / "operator-productization.md"
)

# The install ACTUATION surface the runbook points an operator at (§1.1). Install actuation lives
# in secp_commissioning, never in this package — see the section for why the split exists.
_COMMISSIONING_COMMANDS = frozenset(
    {
        "inspect",
        "plan",
        "render",
        "verify",
        "install-prepared",
        "status",
        "rollback-prepared",
        "evidence",
    }
)

# The three read-only commands this package exposes.
_DEPLOYMENT_COMMANDS = frozenset({"verify", "provenance", "queue"})


def _subcommands(parser: argparse.ArgumentParser) -> set[str]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    raise AssertionError("parser exposes no subcommands")


def _runbook() -> str:
    return _RUNBOOK.read_text(encoding="utf-8")


def test_the_runbook_exists_where_the_package_docstrings_say_it_does():
    assert _RUNBOOK.is_file(), _RUNBOOK


def test_every_commissioning_command_the_runbook_names_actually_exists():
    """The runbook sends an operator to these mid-installation. A renamed command would surface as
    an argparse error during a supervised sequence, which is the worst possible moment."""
    from secp_commissioning.cli import build_parser

    actual = _subcommands(build_parser())
    missing = sorted(_COMMISSIONING_COMMANDS - actual)
    assert not missing, f"the runbook names commissioning commands that do not exist: {missing}"


def test_the_runbook_names_the_whole_commissioning_surface_not_a_convenient_subset():
    """A partial table would read as complete. If a command is added there, it belongs here."""
    from secp_commissioning.cli import build_parser

    actual = _subcommands(build_parser())
    assert actual == set(_COMMISSIONING_COMMANDS), (
        "the commissioning command surface moved — update the runbook §1.1 table and this set"
    )


def test_each_named_actuation_command_appears_in_the_runbook_text():
    text = _runbook()
    for command in sorted(_COMMISSIONING_COMMANDS):
        assert f"`{command}`" in text, f"runbook §1.1 no longer names `{command}`"


def test_the_runbook_points_at_the_actuation_package_by_name():
    """`There is no install command` must read as a design split, not a missing feature — which it
    only does if the runbook says where installation DOES happen."""
    text = _runbook()
    assert "python -m secp_commissioning" in text
    assert "pr5d-operator-deployment.md" in text


def test_the_runbook_names_exactly_this_packages_commands():
    from secp_operator_deployment.cli import build_parser

    assert _subcommands(build_parser()) == set(_DEPLOYMENT_COMMANDS)
    text = _runbook()
    for command in sorted(_DEPLOYMENT_COMMANDS):
        assert f"python -m secp_operator_deployment {command}" in text, command


# --------------------------------------------------------------------------- the safety defaults
#
# These two are the runbook's claims about ANOTHER package's safety posture. An operator believes
# "dry-run by default" without checking it, so it must not be able to rot silently.


def test_install_prepared_is_dry_run_by_default_as_the_runbook_claims():
    """Introspect the REAL signature — not a restatement of it.

    Scoped to the declared defaults. Whether the gate actually precedes the writes is
    ``secp_commissioning``'s behaviour to test, and reasserting it here would duplicate its suite.
    """
    import inspect

    from secp_commissioning.install import install_prepared

    params = inspect.signature(install_prepared).parameters
    for name in ("write", "confirm"):
        assert name in params, f"runbook §1.1 names --{name}, which no longer exists"
        assert params[name].default is False, (
            f"install_prepared({name}=...) no longer defaults to False — "
            "the runbook's dry-run-by-default claim is now wrong"
        )
        # Keyword-only: a positional caller cannot switch on writes by argument order.
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY, name


_ENABLE_MECHANISMS = (
    r"systemctl",  # the only binary that could enable a unit
    r"\.enable\(",
    r"\.start\(",  # NB: excludes `.startswith(` by the paren — there are real uses of that
    r"enable_unit",
    r"start_unit",
)


def test_secp_commissioning_contains_no_mechanism_to_enable_or_start_the_operator():
    """The runbook says the unit is installed **disabled**. That reads as a default something could
    later flip unless the stronger fact is pinned: there is no enable path to flip.

    Known false-positive risk, recorded rather than hidden: ``\\.start\\(`` would also match a regex
    match object's ``.start()``. There are none today. If one appears, the fix is to narrow the
    pattern — never to delete the check.
    """
    import pathlib
    import re

    pkg = (
        pathlib.Path(__file__).resolve().parents[3]
        / "apps"
        / "commissioning"
        / "secp_commissioning"
    )
    sources = sorted(pkg.glob("*.py"))
    assert sources, f"no sources found under {pkg} — the check would vacuously pass"

    offenders: list[str] = []
    for source in sources:
        text = source.read_text(encoding="utf-8")
        for pattern in _ENABLE_MECHANISMS:
            if re.search(pattern, text):
                offenders.append(f"{source.name}: {pattern}")

    assert not offenders, (
        "secp_commissioning gained something that could enable or start the operator unit: "
        f"{offenders} — the runbook's 'installed disabled' claim is no longer structural"
    )


def test_the_enable_detector_actually_detects():
    """Guard the guard. A zero-match assertion passes just as happily when the patterns are broken
    as when the property holds, so the detector is shown to fire on each mechanism it claims to
    catch — and to stay silent on the ``.startswith(`` uses that really exist."""
    import re

    for pattern, offending in (
        (r"systemctl", 'runner.run("/usr/bin/systemctl", ["enable", unit])'),
        (r"\.enable\(", "service.enable(unit)"),
        (r"\.start\(", "service.start(unit)"),
        (r"enable_unit", "enable_unit(name)"),
        (r"start_unit", "start_unit(name)"),
    ):
        assert pattern in _ENABLE_MECHANISMS, pattern
        assert re.search(pattern, offending), f"{pattern} failed to catch {offending!r}"

    # The real code is full of these; none may trip the check.
    benign = 'if not value.startswith("sha256:") and path.startswith("/"):'
    for pattern in _ENABLE_MECHANISMS:
        assert not re.search(pattern, benign), f"{pattern} false-positives on .startswith("


def test_the_runbook_never_advertises_a_command_that_would_activate():
    """The package's whole value is that it cannot activate. A runbook that names an `activate`,
    `apply`, `destroy` or `start` command — even to describe one — is where an operator would go
    looking for it."""
    text = _runbook()
    for forbidden in (
        "python -m secp_operator_deployment activate",
        "python -m secp_operator_deployment start",
        "python -m secp_operator_deployment apply",
        "python -m secp_operator_deployment destroy",
        "python -m secp_operator_deployment install",
    ):
        assert forbidden not in text, forbidden
