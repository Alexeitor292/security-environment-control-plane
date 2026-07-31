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

This is deliberately narrow. It does not check that the runbook's *descriptions* are accurate, that
its steps are in the right order, or that its JSON examples match the real payload shapes — those
remain unpoliced prose, and saying so here is cheaper than implying a coverage that does not exist.

Nothing here runs a command; the parsers are built and inspected.
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
