"""ACCEPTANCE FINDING — a runbook command an operator is told to type does not exist.

The two-host acceptance drives the SUPPORTED path, and the supported path is defined by the
runbooks: they are what an operator reads and types. A runbook command that the shipped parser
refuses is an outage of the supported path even when every library underneath it is correct, so the
harness checks the runbooks against the REAL ``secpctl`` parser rather than against a transcription
of it.

FINDING C — ``secpctl enrollment invitation create`` is not a command
--------------------------------------------------------------------
``docs/runbooks/ws-b-worker-installation.md:84`` tells the controller operator to run::

    secpctl enrollment invitation create --site <site-label> --write --confirm

``cli.py`` registers the noun as ``invite`` (``_add_enrollment_parser``) and dispatches on
``args.action == "invite"``. There is no ``invitation`` action, so argparse exits 2 with
``invalid choice: 'invitation'`` before any product code runs. This is step 4 of the worker
installation runbook — the step that produces the invitation every later step consumes — so an
operator following the document cannot proceed past it.

The CLI is SELF-consistent (its own help string says ``enrollment invite create|status|revoke``);
the runbook is the side that drifted. This test does not encode which side should move — it asserts
only that every command a runbook tells an operator to type is one the shipped parser accepts.

WHY NOTHING ELSE CATCHES IT
---------------------------
No existing test parses documentation. The CLI suites construct argv in Python, so they exercise the
verb the parser actually has, and the runbook is prose to every one of them.

SCOPE OF THE MEASUREMENT
------------------------
This sweeps every fenced ``secpctl`` line in ``docs/runbooks/`` and finds EXACTLY ONE refusal. It
says nothing about ``docs/adr/``, which is deliberate: ADR-028 documents verbs marked "NEW"/"EXTEND"
(``secpctl auth login``, ``upgrade worker``, ``install worker``, ``verify controller``) that are
designed but not yet built. Those are proposals, not instructions, and asserting on them would
convert a design document into a false defect report.
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import re
import shlex

import pytest

#: A ``<placeholder>`` token in a documented command line. Replaced with a value-shaped stand-in:
#: the harness is checking the COMMAND GRAMMAR, not whether a path exists on this machine.
_PLACEHOLDER = re.compile(r"^<.*>$")

#: ``controller|worker`` in a synopsis line. Expanded to one concrete command per alternative rather
#: than skipped — a synopsis is exactly where a verb typo would hide, and skipping the five synopsis
#: lines in the bootstrap runbook would silently drop them from the measurement.
_ALTERNATION = re.compile(r"^[a-z]+(\|[a-z]+)+$")

#: An OPTIONAL group in a synopsis, e.g. ``[--write --confirm]``. It spans several whitespace-
#: separated tokens, so it has to be resolved on the raw line BEFORE shlex splits it — otherwise it
#: arrives as the two unparseable tokens ``[--write`` and ``--confirm]``. Each group is expanded
#: into BOTH readings (present and absent), because "optional" claims the command works either way
#: and a sweep that only ever tried one of them would under-report.
_OPTIONAL_GROUP = re.compile(r"\[([^\]]*)\]")


def _repo_root() -> pathlib.Path:
    here = pathlib.Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file() and (parent / "docs").is_dir():
            return parent
    raise AssertionError("repository root not found from the test file location")


def _documented_commands() -> list[tuple[str, int, str]]:
    """Every ``secpctl ...`` line in every runbook, with its source location."""
    root = _repo_root()
    runbooks = root / "docs" / "runbooks"
    found: list[tuple[str, int, str]] = []
    for path in sorted(runbooks.glob("*.md")):
        rel = path.relative_to(root).as_posix()
        for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = raw.strip()
            if stripped.startswith("secpctl ") or stripped == "secpctl":
                found.append((rel, number, stripped))
    return found


def _resolve_optional_groups(body: str) -> list[str]:
    """``a [b] c`` -> ``["a  c", "a b c"]``. Applied leftmost-first until no group remains."""
    match = _OPTIONAL_GROUP.search(body)
    if match is None:
        return [body]
    without = body[: match.start()] + body[match.end() :]
    with_it = body[: match.start()] + match.group(1) + body[match.end() :]
    return _resolve_optional_groups(without) + _resolve_optional_groups(with_it)


def _expand(command: str) -> list[list[str]]:
    """One documented line -> every concrete argv list it instructs an operator to run."""
    body = command.split("#", 1)[0].strip()  # drop a trailing explanatory comment
    variants: list[list[str]] = []
    for resolved in _resolve_optional_groups(body):
        forms: list[list[str]] = [[]]
        for token in shlex.split(resolved)[1:]:  # drop the "secpctl" program name itself
            if _PLACEHOLDER.fullmatch(token):
                for form in forms:
                    form.append("PLACEHOLDER")
            elif _ALTERNATION.fullmatch(token):
                forms = [[*form, alternative] for form in forms for alternative in token.split("|")]
            else:
                for form in forms:
                    form.append(token)
        variants.extend(forms)
    return variants


def _parses(argv: list[str]) -> str | None:
    """Return None when the shipped parser accepts ``argv``, else its bounded error line."""
    from secp_management.cli import build_parser

    captured = io.StringIO()
    try:
        with contextlib.redirect_stderr(captured), contextlib.redirect_stdout(captured):
            build_parser().parse_args(argv)
    except SystemExit:
        lines = [ln for ln in captured.getvalue().strip().splitlines() if ln.strip()]
        return lines[-1] if lines else "parser exited without a message"
    return None


# --------------------------------------------------------------------------- premise guards


def test_the_runbook_sweep_is_not_vacuous():
    """If the sweep found nothing, every assertion below would pass while proving nothing."""
    commands = _documented_commands()
    assert len(commands) >= 20, (
        f"expected a substantial runbook command surface, got {len(commands)}"
    )
    files = {rel for rel, _, _ in commands}
    assert "docs/runbooks/ws-b-worker-installation.md" in files
    assert "docs/runbooks/pr5e-management-bootstrap.md" in files


def test_the_synopsis_expansion_covers_both_alternatives_and_both_optional_readings():
    """CONTROL for ``_expand``. A synopsis line carries an alternation AND an optional group; if
    either were mishandled the sweep would quietly test fewer commands than it claims to.

    The bug this pins is real and was hit while writing this file: ``[--write --confirm]`` spans two
    whitespace-separated tokens, so resolving it AFTER shlex leaves ``[--write`` and ``--confirm]``
    and every synopsis line reports a phantom refusal.
    """
    expanded = _expand("secpctl bootstrap controller|worker --bundle DIR   [--write --confirm]")
    assert sorted(expanded) == [
        ["bootstrap", "controller", "--bundle", "DIR"],
        ["bootstrap", "controller", "--bundle", "DIR", "--write", "--confirm"],
        ["bootstrap", "worker", "--bundle", "DIR"],
        ["bootstrap", "worker", "--bundle", "DIR", "--write", "--confirm"],
    ]
    # and every one of those four is a command the shipped parser accepts
    assert [_parses(argv) for argv in expanded] == [None, None, None, None]


def test_the_sweep_expands_more_commands_than_it_reads_lines():
    """The synopsis lines must actually multiply. If ``_expand`` collapsed to one argv per line,
    the alternation branches would never be tested and this file's coverage claim would be wider
    than its measurement."""
    commands = _documented_commands()
    total = sum(len(_expand(command)) for _, _, command in commands)
    assert total > len(commands)


def test_the_parser_probe_can_actually_fail():
    """CONTROL for the probe itself: it must refuse a command that genuinely does not exist.

    Without this, a ``_parses`` that returned None unconditionally — a swallowed SystemExit, a
    parser that never validates — would make every assertion below vacuously true.
    """
    assert _parses(["definitely-not-a-verb"]) is not None
    assert _parses(["enrollment", "invitation", "create"]) is not None
    # and it must ACCEPT a command that does exist, or it would report defects everywhere
    assert _parses(["status", "worker"]) is None


# --------------------------------------------------------------------------- finding C


def test_finding_c_the_documented_invitation_command_is_refused_by_the_shipped_parser():
    """FINDING C. The exact string a controller operator is told to type at step 4."""
    error = _parses(
        ["enrollment", "invitation", "create", "--site", "PLACEHOLDER", "--write", "--confirm"]
    )
    assert error is not None, "expected the shipped parser to refuse the documented command"
    assert "invalid choice: 'invitation'" in error


def test_finding_c_control_only_the_noun_is_wrong():
    """CONTROL. With ``invitation`` replaced by ``invite`` and every other token byte-identical,
    the same parser accepts — so the refusal is attributable to that one word and not to the site
    argument, the write/confirm pair, or the placeholder substitution."""
    assert (
        _parses(["enrollment", "invite", "create", "--site", "PLACEHOLDER", "--write", "--confirm"])
        is None
    )


def test_finding_c_the_cli_is_self_consistent_and_the_runbook_is_the_drifted_side():
    """Attribute the drift. The parser registers ``invite`` and its own help text says ``invite``;
    only the runbook says ``invitation``. Recorded so a reader does not "fix" the CLI and break
    every caller that already uses the real verb."""
    import inspect

    from secp_management import cli

    source = inspect.getsource(cli._add_enrollment_parser)
    assert '"invite"' in source
    assert "invite create|status|revoke" in source
    assert '"invitation"' not in source


# --------------------------------------------------------------------------- the whole surface


def test_every_runbook_command_is_accepted_by_the_shipped_parser():
    """The general contract. Reported as a full list so a second drift is visible in one run
    instead of appearing only after the first is fixed."""
    seen: dict[str, None] = {}  # ordered, deduplicated: one entry per (location, error)
    for rel, number, command in _documented_commands():
        for argv in _expand(command):
            if not argv:
                continue
            error = _parses(argv)
            if error is not None:
                seen[f"{rel}:{number}  `{command}`\n    -> {error}"] = None
    failures = list(seen)
    assert failures == [
        "docs/runbooks/ws-b-worker-installation.md:84  "
        "`secpctl enrollment invitation create --site <site-label> --write --confirm`\n"
        "    -> secpctl enrollment: error: argument action: invalid choice: 'invitation' "
        "(choose from 'invite', 'status', 'revoke')"
    ], (
        "The set of refused runbook commands changed. Exactly one is known (Finding C); a new "
        "entry is a new drift, and a shorter list means Finding C was fixed and this expectation "
        "must be narrowed to the empty list.\n\n" + "\n".join(failures)
    )


@pytest.mark.parametrize(
    "verb",
    ["auth", "upgrade", "install", "verify"],
)
def test_adr_only_verbs_are_deliberately_absent_from_the_parser(verb: str):
    """The boundary of the measurement above, made explicit.

    ADR-028 designs these verbs and marks each "NEW"/"EXTEND". They are absent from the shipped
    parser, and that absence is NOT a defect — it is unbuilt work. Pinning it here stops a later
    reader from widening the runbook sweep to the ADRs and reporting four phantom defects, and it
    fails honestly if one of them ships without this note being revisited.
    """
    assert _parses([verb]) is not None
