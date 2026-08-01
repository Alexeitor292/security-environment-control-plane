"""Every ``secpctl`` command the runbooks instruct an operator to run must actually parse.

WHY THIS GUARD EXISTS
---------------------
``docs/runbooks/ws-b-worker-installation.md`` told the operator to run ``secpctl enrollment
invitation create`` at the first enrollment step. The parser registers that subcommand as
``invite``. The documented command did not exist, so an operator following the runbook got an
argparse error before reaching the controller — measured, not inferred: the real parser answered
``invalid choice: 'invitation' (choose from 'invite', 'status', 'revoke')``.

Nothing could have caught it. The runbook is prose to every test in the tree, and the CLI suite
exercises the parser with argv the CLI suite itself writes. The two were never compared.

WHY IT IS KEYED ON THE PARSER
-----------------------------
A list of known-good command strings checked against the runbooks would be the SAME defect one
level up: a third copy of the command vocabulary, agreeing with the docs, drifting from the parser
in exactly the way the original pair did. So the authority here is ``build_parser()`` itself — the
object ``main`` dispatches on. A subcommand rename moves this guard automatically; a rename that
forgot the runbook fails it.

WHY THE EXTRACTOR IS ASSERTED, NOT TRUSTED
------------------------------------------
An extractor that silently matched nothing would make every assertion below vacuously true, which
is the failure mode a docs guard is most prone to. So the sweep's own reach is measured:
:func:`test_the_extractor_actually_reaches_the_runbooks` requires commands from every runbook that
contains one, and :func:`test_the_harness_can_reject` drives a deliberately invalid command through
the SAME code path and requires a refusal. Without that pair, "all documented commands parse" would
also be the reading produced by a broken regex.

SHELL PLACEHOLDERS ARE EXPANDED, NOT SKIPPED
--------------------------------------------
The runbooks write ``controller|worker`` and ``[--write --confirm]`` as human notation. Skipping
those lines would drop five of the twenty-three invocations — a fifth of the corpus — and the guard
would report green over a hole. They are expanded into their concrete alternatives instead, so the
optional-flag and role variants are each parsed on their own.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import itertools
import pathlib
import re
import shlex

import pytest
from secp_management.cli import build_parser

REPO = pathlib.Path(__file__).resolve().parents[1]
RUNBOOKS = sorted((REPO / "docs" / "runbooks").glob("*.md"))

#: Stand-in for operator-supplied values. The runbooks write these as ``<site-label>``,
#: ``/path/to/x`` or a bare ``DIR``; argparse only needs a token, and no path is opened at
#: parse time (asserted by the corpus parsing at all).
_PLACEHOLDER = "PLACEHOLDER"

_FENCE = re.compile(r"^```")
_ANGLE = re.compile(r"<[^>]+>")
_OPTIONAL = re.compile(r"\[([^\]]+)\]")
_BARE_DIR = re.compile(r"(?<![\w/-])DIR(?![\w-])")
#: A backtick-delimited span in PROSE that starts with ``secpctl``.
_INLINE = re.compile(r"`(secpctl [^`]+)`")

#: Command-FAMILY references, not invocations. Prose says "no --url argument on any `secpctl
#: worker` command" — a noun phrase naming a group of commands, which has no argv to check.
#:
#: This list is the guard's one escape hatch, so it is constrained rather than trusted:
#: :func:`test_every_family_reference_exemption_is_justified` requires each entry to still appear
#: in the docs (a stale exemption fails) AND to fail parsing for an INCOMPLETE-PATH reason
#: ("required"), never for "invalid choice" or "unrecognized arguments". A real defect produces
#: the latter, so an exemption cannot be used to silence one.
_FAMILY_REFERENCES = frozenset({"secpctl worker"})


def _fenced_secpctl_lines(text: str) -> list[tuple[int, str]]:
    """Every documented secpctl invocation: fenced block lines AND inline prose commands.

    Inline commands were originally excluded as noise. That was wrong, and the exclusion hid two
    real defects: ``pr5e-management-bootstrap.md`` documented ``secpctl status controller --json``
    and ``secpctl status worker --json`` in prose only, and ``--json`` is a ROOT-level flag that
    must precede the subcommand — the trailing form exits 2 with "unrecognized arguments: --json".
    Neither appeared inside a fence, so no fenced-only sweep could ever see them.
    """
    out: list[tuple[int, str]] = []
    inside = False
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if _FENCE.match(raw.strip()):
            inside = not inside
            continue
        if inside:
            if raw.strip().startswith("secpctl "):
                out.append((lineno, raw.strip()))
            continue
        for match in _INLINE.finditer(raw):
            # Trailing sentence punctuation belongs to the prose, not to the argv.
            command = match.group(1).strip().rstrip(".,;")
            if command in _FAMILY_REFERENCES:
                continue
            out.append((lineno, command))
    return out


def _expand(command: str) -> list[str]:
    """Expand human notation into every concrete argv the line documents."""
    command = command.split("#", 1)[0].strip()
    command = _ANGLE.sub(_PLACEHOLDER, command)
    command = _BARE_DIR.sub(_PLACEHOLDER, command)

    # ``[--write --confirm]`` documents two supported forms; check BOTH.
    optional_groups = _OPTIONAL.findall(command)
    skeleton = _OPTIONAL.sub("\x00", command)
    variants = []
    for keep in itertools.product([True, False], repeat=len(optional_groups)):
        text = skeleton
        for group, included in zip(optional_groups, keep, strict=True):
            text = text.replace("\x00", group if included else "", 1)
        variants.append(" ".join(text.split()))

    # ``controller|worker`` documents one command per alternative.
    expanded: list[str] = []
    for variant in variants:
        tokens = variant.split()
        choices = [tok.split("|") if "|" in tok else [tok] for tok in tokens]
        expanded.extend(" ".join(combo) for combo in itertools.product(*choices))
    return sorted(set(expanded))


def _documented_commands() -> list[tuple[str, int, str]]:
    """(runbook name, line number, concrete command) for every documented invocation."""
    rows: list[tuple[str, int, str]] = []
    for runbook in RUNBOOKS:
        for lineno, line in _fenced_secpctl_lines(runbook.read_text(encoding="utf-8")):
            rows.extend((runbook.name, lineno, cmd) for cmd in _expand(line))
    return rows


def _parse(command: str) -> str | None:
    """Run one command through the REAL parser. Returns None on success, else argparse's message.

    argparse writes to stderr and raises SystemExit; both are captured so a failure is reported as
    the operator's own error text rather than as a swallowed exception.
    """
    parser = build_parser()
    buffer = io.StringIO()
    argv = shlex.split(command)[1:]  # drop the "secpctl" program name
    try:
        with contextlib.redirect_stderr(buffer), contextlib.redirect_stdout(buffer):
            parser.parse_args(argv)
    except SystemExit:
        lines = buffer.getvalue().strip().splitlines()
        return lines[-1] if lines else "argparse exited without a message"
    return None


# ----------------------------------------------------------------- the load-bearing assertion


@pytest.mark.parametrize(
    ("runbook", "lineno", "command"),
    _documented_commands(),
    ids=lambda v: str(v).replace(" ", "_") if isinstance(v, str) else str(v),
)
def test_every_documented_secpctl_command_parses(runbook: str, lineno: int, command: str) -> None:
    """Parametrised per command so a failure names the exact runbook line to fix."""
    error = _parse(command)
    assert error is None, f"{runbook}:{lineno} documents a command the CLI rejects: {error}"


# ------------------------------------------------------------------------- non-vacuity of the sweep


def test_the_extractor_actually_reaches_the_runbooks() -> None:
    """A regex that matched nothing would make the corpus test vacuously green.

    Asserted as reach rather than as an exact total, so ordinary documentation edits do not fail
    the guard while a silently-empty extractor still does.
    """
    assert RUNBOOKS, "no runbooks were discovered at all"
    rows = _documented_commands()
    assert len(rows) >= 20, (
        f"the extractor found only {len(rows)} commands; it has stopped reaching"
    )

    # Every runbook that contains a fenced invocation must contribute at least one command.
    seen = {name for name, _, _ in rows}
    for runbook in RUNBOOKS:
        if _fenced_secpctl_lines(runbook.read_text(encoding="utf-8")):
            assert runbook.name in seen, f"{runbook.name} has invocations but contributed none"


def test_the_harness_can_reject() -> None:
    """Prove the checker's discriminating power instead of asserting it.

    The exact defect this guard was written for is driven through the SAME ``_parse`` used above
    and must be refused, with argparse naming the real subcommand. If this passed, "everything
    parses" would be a statement about a harness that cannot fail.
    """
    error = _parse("secpctl enrollment invitation create --site X --write --confirm")
    assert error is not None, "the harness accepted a command the CLI does not define"
    assert "invalid choice: 'invitation'" in error
    assert "invite" in error  # the real subcommand is named in the operator's error text

    # Control: the corrected form of that same command is accepted, so the refusal above is about
    # the wrong token and not about this command shape being unparseable.
    assert _parse("secpctl enrollment invite create --site X --write --confirm") is None


def test_every_family_reference_exemption_is_justified() -> None:
    """The one escape hatch must not be able to hide a real defect.

    Each exemption has to (a) still appear in the docs, so a stale entry fails rather than lingers,
    and (b) fail parsing because its command PATH is incomplete — argparse's "required" message —
    never because a flag or subcommand is wrong. A genuinely broken documented command produces
    "invalid choice" or "unrecognized arguments", so it can never be exempted by this list.
    """
    corpus = "\n".join(rb.read_text(encoding="utf-8") for rb in RUNBOOKS)
    assert _FAMILY_REFERENCES, "the exemption list is empty; this test is checking nothing"
    for fragment in _FAMILY_REFERENCES:
        assert f"`{fragment}`" in corpus, (
            f"exemption {fragment!r} no longer appears in any runbook — remove it"
        )
        error = _parse(fragment)
        assert error is not None, f"{fragment!r} parses fine and needs no exemption"
        assert "required" in error, (
            f"{fragment!r} is exempted but fails for a NON-structural reason ({error}); that is a "
            "real defect being silenced, not a command-family reference"
        )


def test_inline_prose_commands_are_swept_not_just_fenced_ones() -> None:
    """Pin the reach that the two ``--json`` defects proved was missing.

    Keyed on a known inline-only command, so a regression to fenced-only extraction fails here
    rather than silently shrinking the corpus.
    """
    rows = _documented_commands()
    inline = {
        (name, lineno)
        for name, lineno, _ in rows
        if name == "pr5e-management-bootstrap.md" and lineno in {80, 98}
    }
    assert inline == {("pr5e-management-bootstrap.md", 80), ("pr5e-management-bootstrap.md", 98)}, (
        "the inline-prose commands at pr5e-management-bootstrap.md:80/:98 are no longer swept; "
        "those two lines are the ones a fenced-only extractor missed"
    )


def test_the_expander_produces_both_optional_and_alternative_forms() -> None:
    """The expansion is what keeps five invocations from being skipped; check it directly."""
    expanded = _expand("secpctl bootstrap controller|worker --bundle DIR   [--write --confirm]")
    assert set(expanded) == {
        f"secpctl bootstrap {role} --bundle {_PLACEHOLDER}{suffix}"
        for role in ("controller", "worker")
        for suffix in ("", " --write --confirm")
    }
    # A line with no notation is passed through unchanged rather than mangled.
    assert _expand("secpctl status worker") == ["secpctl status worker"]


def test_the_guard_is_keyed_on_the_parser_not_on_a_command_list() -> None:
    """The authority must be the shipped parser object.

    Keyed on the parser's own declared choices rather than on a copy of them: this reads the
    subcommand vocabulary OUT of ``build_parser()``, so it cannot drift from what ``main``
    dispatches on. A hardcoded expectation here would be the third copy the docstring warns about.
    """
    parser = build_parser()
    actions = [
        a for a in parser._subparsers._group_actions if isinstance(a, argparse._SubParsersAction)
    ]
    assert actions, "the parser no longer exposes subcommands"
    top_level = set(actions[0].choices)
    # Every documented command's subcommand must be one the parser really declares. Root-level
    # flags may precede it (``secpctl --json status worker``), so skip leading options rather than
    # assuming argv[1] — that assumption held only while the sweep missed the inline commands.
    documented = set()
    for _, _, cmd in _documented_commands():
        for token in shlex.split(cmd)[1:]:
            if not token.startswith("-"):
                documented.add(token)
                break
    assert documented <= top_level, (
        f"runbooks document unknown subcommands: {documented - top_level}"
    )
