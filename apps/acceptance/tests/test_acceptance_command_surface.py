"""Every command the acceptance STAGES will drive must exist in the shipped parser.

This is not a documentation guard. ``tests/test_runbook_cli_commands.py`` (PR #78) owns the runbook
sweep, and it reads only ``docs/runbooks/*.md`` so the "is an ADR a documented command?" question
cannot arise by construction. Nothing here duplicates it.

What this file owns is narrower and belongs to the harness: the acceptance stages are written
against a specific set of ``secpctl`` invocations, and a stage written against a verb that does not
exist is a scenario that can never run. The failure mode is quiet — the stage would refuse at
argparse, the harness would record ``acceptance_expected_refusal_absent`` or an unexpected reason
code, and the run would look like a product defect rather than a harness defect.

The pin that matters most is UPGRADE. ``docs/adr/ADR-028`` designs ``secpctl upgrade worker``, and
it is the obvious thing to write an upgrade stage against — but that verb is unbuilt. The supported
upgrade today is a second ``bootstrap worker`` against a linear successor bundle, which the engine
classifies as a managed upgrade. A stage that reached for ``upgrade`` would be written against a
design document rather than against the product.
"""

from __future__ import annotations

import contextlib
import io

import pytest

#: The exact invocations the acceptance stages drive, by the stage that drives them. Placeholders
#: are value-shaped stand-ins: this checks the command GRAMMAR, not whether a path exists here.
STAGE_COMMANDS: dict[str, tuple[tuple[str, ...], ...]] = {
    "worker_install": (
        ("bootstrap", "worker", "--bundle", "BUNDLE"),
        ("bootstrap", "worker", "--bundle", "BUNDLE", "--write", "--confirm"),
        ("status", "worker"),
        ("evidence", "worker"),
    ),
    "enrollment": (
        # `invite`, NOT `invitation` — the runbook said the latter and PR #78 fixes the runbook.
        # The harness must drive the verb the parser actually has.
        ("enrollment", "invite", "create", "--site", "SITE", "--write", "--confirm"),
        ("enrollment", "status", "--enrollment-id", "ID"),
        ("worker", "enroll", "--invitation", "FILE"),
        ("worker", "enroll", "--invitation", "FILE", "--write", "--confirm"),
        ("worker", "enrollment", "status", "--invitation", "FILE"),
        ("worker", "enrollment", "retry", "--invitation", "FILE", "--write", "--confirm"),
    ),
    "lifecycle": (
        # The upgrade stage drives a SECOND bootstrap against a linear successor bundle. There is
        # no `upgrade` verb; see test_the_upgrade_stage_may_not_be_written_against_an_unbuilt_verb.
        ("bootstrap", "worker", "--bundle", "SUCCESSOR", "--write", "--confirm"),
        ("adopt", "worker", "--bundle", "BUNDLE"),
        ("rollback", "worker"),
        ("rollback", "worker", "--write", "--confirm"),
    ),
    "packages": (
        ("release", "verify", "--bundle", "BUNDLE"),
        ("host", "inspect"),
    ),
}

#: Verbs ADR-028 designs and marks NEW/EXTEND. They are unbuilt, and no stage may be written
#: against one. Their absence is not a defect — it is work that has not happened.
UNBUILT_VERBS: tuple[str, ...] = ("auth", "upgrade", "install", "verify")


def _parses(argv: tuple[str, ...]) -> str | None:
    """None when the shipped parser accepts ``argv``, else its bounded error line."""
    from secp_management.cli import build_parser

    captured = io.StringIO()
    try:
        with contextlib.redirect_stderr(captured), contextlib.redirect_stdout(captured):
            build_parser().parse_args(list(argv))
    except SystemExit:
        lines = [ln for ln in captured.getvalue().strip().splitlines() if ln.strip()]
        return lines[-1] if lines else "parser exited without a message"
    return None


# --------------------------------------------------------------------------- controls


def test_the_parser_probe_can_actually_fail():
    """Without this, a ``_parses`` that always returned None would make every assertion below
    vacuously true."""
    assert _parses(("definitely-not-a-verb",)) is not None
    assert _parses(("status", "worker")) is None


def test_the_stage_command_table_is_not_empty():
    assert STAGE_COMMANDS
    for stage, commands in STAGE_COMMANDS.items():
        assert commands, f"stage {stage} drives no commands, so pinning it proves nothing"


# --------------------------------------------------------------------------- the surface


@pytest.mark.parametrize(
    ("stage", "argv"),
    [(stage, argv) for stage, commands in STAGE_COMMANDS.items() for argv in commands],
    ids=lambda value: " ".join(value) if isinstance(value, tuple) else value,
)
def test_every_command_an_acceptance_stage_drives_exists(stage: str, argv: tuple[str, ...]):
    error = _parses(argv)
    assert error is None, (
        f"the {stage} stage is written against `secpctl {' '.join(argv)}`, which the shipped "
        f"parser refuses:\n    {error}\n"
        f"A stage written against a command that does not exist can never run, and its failure "
        f"would read as a product defect rather than a harness defect."
    )


def test_the_enrollment_stage_drives_invite_not_invitation():
    """Attribution, kept because it is the harness's own dependency rather than a doc claim.

    The runbook said ``invitation`` (PR #78 fixes it). The harness drives ``invite``, and if a
    later edit "corrects" the harness to match the old runbook, the enrollment stage stops working.
    """
    assert (
        _parses(("enrollment", "invite", "create", "--site", "S", "--write", "--confirm")) is None
    )
    assert _parses(("enrollment", "invitation", "create", "--site", "S")) is not None
    driven = STAGE_COMMANDS["enrollment"]
    assert any("invite" in argv for argv in driven)
    assert not any("invitation" in argv for argv in driven)


# --------------------------------------------------------------------------- unbuilt verbs


@pytest.mark.parametrize("verb", UNBUILT_VERBS)
def test_no_acceptance_stage_is_written_against_an_unbuilt_verb(verb: str):
    """The stage table must not reach for a designed-but-unbuilt verb.

    Checked against the table itself, not against the parser: the point is what the HARNESS drives.
    A stage naming ``upgrade`` would be written against ADR-028 rather than against the product.
    """
    for stage, commands in STAGE_COMMANDS.items():
        for argv in commands:
            assert argv[0] != verb, f"the {stage} stage drives the unbuilt verb `{verb}`"


@pytest.mark.parametrize("verb", UNBUILT_VERBS)
def test_those_verbs_are_genuinely_absent_from_the_parser(verb: str):
    """The premise of the test above, measured rather than assumed.

    If one of these ships, this fails and the stage table should be revisited to use it — that is
    the intended signal, not a nuisance.
    """
    assert _parses((verb,)) is not None


def test_the_upgrade_stage_may_not_be_written_against_an_unbuilt_verb():
    """The specific trap, spelled out because it is the one a reader would most likely fall into.

    ``secpctl upgrade worker`` does not exist. The supported upgrade is a second ``bootstrap
    worker`` against a linear successor bundle, and that is what the lifecycle stage drives.
    """
    assert _parses(("upgrade", "worker", "--to", "RELEASE")) is not None
    assert ("bootstrap", "worker", "--bundle", "SUCCESSOR", "--write", "--confirm") in (
        STAGE_COMMANDS["lifecycle"]
    )
    # and the engine must still have a non-linear-successor refusal for the failure-injection stage
    # to assert on, or the upgrade path would accept any bundle as a successor
    from secp_acceptance.reasons import PRODUCT_REASONS

    assert "worker_upgrade_not_linear_successor" in PRODUCT_REASONS
