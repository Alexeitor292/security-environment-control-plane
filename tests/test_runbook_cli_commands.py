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
#: A backtick-delimited span in PROSE that starts with ``secpctl``. Matched against a WRAPPED
#: paragraph (see :func:`_prose_units`), not a single line: two real invocations
#: (``pr5e-management-bootstrap.md`` 46 and 51) open their span on one line and close it on the
#: next, and a per-line regex cannot see either.
_INLINE = re.compile(r"`(secpctl [^`]+)`")
#: Every place a prose backtick span OPENS with the command. Used to prove the sweep accounted for
#: all of them — the count of openings must equal swept + exempted, so a span shape the matcher
#: cannot handle fails LOUDLY instead of being silently skipped.
_INLINE_OPENING = re.compile(r"`secpctl ")

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
    for unit, offsets in _prose_units(text):
        for match in _INLINE.finditer(unit):
            # Trailing sentence punctuation belongs to the prose, not to the argv.
            command = " ".join(match.group(1).split()).rstrip(".,;")
            if command in _FAMILY_REFERENCES:
                continue
            out.append((_line_at(offsets, match.start()), command))
    out.extend(_fenced_units(text))
    return sorted(out)


def _line_at(offsets: list[tuple[int, int]], position: int) -> int:
    """The source line a match STARTS on, for a paragraph joined from several lines.

    Reported against the opening line rather than the paragraph start so a failure names the line an
    operator would actually edit — including for a span that wraps onto the next line.
    """
    line = offsets[0][1]
    for offset, lineno in offsets:
        if offset <= position:
            line = lineno
        else:
            break
    return line


def _fenced_units(text: str) -> list[tuple[int, str]]:
    """Lines inside a fenced block that begin an invocation."""
    out: list[tuple[int, str]] = []
    inside = False
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if _FENCE.match(raw.strip()):
            inside = not inside
            continue
        if inside and raw.strip().startswith("secpctl "):
            out.append((lineno, raw.strip()))
    return out


def _prose_units(text: str) -> list[tuple[str, list[tuple[int, int]]]]:
    """Non-fenced text grouped into PARAGRAPHS, with an offset->line map for each.

    Grouped rather than scanned line-by-line because a backtick span may open on one line and close
    on the next — markdown wraps prose freely. ``pr5e-management-bootstrap.md`` 46 and 51 are both
    real invocations written that way, and a per-line matcher sees neither.

    Each unit is ``(joined_text, [(char_offset, source_line), ...])`` so a match can be reported
    against the line it actually starts on rather than the paragraph's first line.
    """
    units: list[tuple[str, list[tuple[int, int]]]] = []
    inside = False
    buffer: list[str] = []
    offsets: list[tuple[int, int]] = []
    width = 0

    def flush() -> None:
        nonlocal buffer, offsets, width
        if buffer:
            units.append((" ".join(buffer), offsets))
        buffer, offsets, width = [], [], 0

    for lineno, raw in enumerate(text.splitlines(), start=1):
        if _FENCE.match(raw.strip()):
            inside = not inside
            flush()
            continue
        if inside:
            continue
        stripped = raw.strip()
        if not stripped:
            flush()
            continue
        offsets.append((width, lineno))
        buffer.append(stripped)
        width += len(stripped) + 1  # the joining space
    flush()
    return units


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


def _independently_documented_lines(runbook: pathlib.Path) -> set[int]:
    """A SECOND, deliberately dumb reading of where the corpus documents a command.

    Shares no code with the extractor — its own fence tracking, its own line scan, no call into
    ``_fenced_units`` or ``_prose_units``. That independence is the whole point and was learned the
    hard way: an earlier version of this check derived its expectation BY CALLING ``_fenced_units``,
    so mutating that function shrank the expectation and the sweep together and the check passed
    while half the corpus silently vanished. A verification that shares a failure mode with the
    thing it verifies cannot detect that failure.

    Prose openings are found per-RAW-LINE (a span opens on exactly one line even when it wraps), so
    this is also independent of the paragraph joining.
    """
    lines: set[int] = set()
    inside = False
    for lineno, raw in enumerate(runbook.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith("```"):
            inside = not inside
            continue
        if inside:
            if stripped.startswith("secpctl "):
                lines.add(lineno)
        elif "`secpctl " in raw:
            lines.add(lineno)
    return lines


def test_the_extractor_actually_reaches_the_runbooks() -> None:
    """A regex that matched nothing would make the corpus test vacuously green.

    Asserted as reach rather than as an exact total, so ordinary documentation edits do not fail
    the guard while a silently-empty extractor still does.
    """
    assert RUNBOOKS, "no runbooks were discovered at all"
    rows = _documented_commands()

    # DERIVED, not typed. A hardcoded floor is calibrated against the corpus it was written for:
    # this one said ">= 20" against 23 commands, and when the sweep widened to 40 the slack
    # silently doubled — the guard would then tolerate losing HALF the documented commands while
    # every number in the report went up. Deriving the expectation from a second, independent
    # reading of the source means widening the corpus TIGHTENS the guard instead of loosening it.
    expected: set[tuple[str, int]] = set()
    for runbook in RUNBOOKS:
        expected |= {(runbook.name, lineno) for lineno in _independently_documented_lines(runbook)}

    # PROVE THE INDEPENDENT READING ACTUALLY SPOKE, before comparing anything to it. An empty
    # ``expected`` makes ``missing`` empty too, and two empty sets compare equal — so a broken
    # second reading would report a perfectly healthy sweep. Deriving from a different source and
    # proving that source answered are SEPARABLE requirements and both are needed; an independent
    # reading that can silently return nothing is not independent, it is a second way to say yes.
    assert expected, "the independent reading found nothing — it is broken, not the corpus clean"
    for runbook in RUNBOOKS:
        if "secpctl" in runbook.read_text(encoding="utf-8"):
            assert any(name == runbook.name for name, _ in expected), (
                f"{runbook.name} mentions secpctl but the independent reading saw nothing in it"
            )

    swept = {(name, lineno) for name, lineno, _ in rows}
    # Family references are exempt by design and contribute no argv.
    exempt = {
        (runbook.name, lineno)
        for runbook in RUNBOOKS
        for lineno, raw in enumerate(runbook.read_text(encoding="utf-8").splitlines(), start=1)
        if any(f"`{fragment}`" in raw for fragment in _FAMILY_REFERENCES)
    }
    missing = expected - swept - exempt
    assert missing == set(), (
        f"the sweep no longer reaches every place the corpus documents a command: {sorted(missing)}"
    )

    # Every runbook that contains a fenced invocation must contribute at least one command.
    seen = {name for name, _, _ in rows}
    for runbook in RUNBOOKS:
        if _fenced_units(runbook.read_text(encoding="utf-8")):
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


def test_every_prose_span_opening_is_accounted_for() -> None:
    """Accounting, not sampling: openings == swept + exempted, per paragraph.

    The widening moved WHERE the rule looks, not the rule — a span shape the matcher cannot close
    (it wraps, or is nested oddly) would still be skipped in silence. Counting the OPENINGS is
    independent of the matcher's ability to parse them, so an unhandled shape shows up as an
    unaccounted opening rather than as a smaller corpus nobody notices.

    This is the check that would have caught the wrapped spans at ``pr5e-management-bootstrap.md``
    46 and 51 before a reviewer had to find them by hand.
    """
    for runbook in RUNBOOKS:
        for unit, offsets in _prose_units(runbook.read_text(encoding="utf-8")):
            openings = len(_INLINE_OPENING.findall(unit))
            if not openings:
                continue
            closed = len(_INLINE.findall(unit))
            assert closed == openings, (
                f"{runbook.name}:{_line_at(offsets, 0)} opens {openings} `secpctl` span(s) but the "
                f"matcher closed {closed} — an unhandled span shape is being skipped silently"
            )


def test_the_wrapped_prose_spans_are_swept() -> None:
    """The two live WRAPPING spans, pinned by the line their span opens on.

    Both PARSE, so neither is a defect — but a per-line matcher could not see them at all, and that
    invisibility is the thing being fixed. If paragraph joining regresses, these disappear.
    """
    swept = {
        command
        for name, _, command in _documented_commands()
        if name == "pr5e-management-bootstrap.md"
    }
    assert swept, "no commands swept from pr5e-management-bootstrap.md — the reading is broken"
    # Keyed on CONTENT, not on line number. An earlier version pinned (46, 51) and went red the
    # moment an unrelated edit inserted a table above them: a line number is a typed literal that
    # drifts, which is the defect this file exists to catch, committed by this file.
    # Only a WRAPPING span carries the long absolute bundle path; the short forms sit inside fences.
    for needle in (
        "secpctl release verify --bundle /var/lib/secp/bootstrap/release/",
        "secpctl bootstrap controller --bundle",
    ):
        assert any(c.startswith(needle) for c in swept), (
            f"no swept command starts with {needle!r} — a wrapped `secpctl` span is no longer "
            "swept, so the paragraph joining has regressed to per-line matching"
        )


def test_inline_prose_commands_are_swept_not_just_fenced_ones() -> None:
    """Pin the reach that the two ``--json`` defects proved was missing.

    Keyed on a known inline-only command, so a regression to fenced-only extraction fails here
    rather than silently shrinking the corpus.
    """
    swept = {
        command
        for name, _, command in _documented_commands()
        if name == "pr5e-management-bootstrap.md"
    }
    assert swept, "no commands swept from pr5e-management-bootstrap.md — the reading is broken"
    # Keyed on CONTENT for the same reason as the wrapped-span test above: these two lines moved
    # when an unrelated exit-code table was added to the runbook, and a line-number pin went red on
    # a correct change. The commands themselves are what must stay swept.
    expected = {"secpctl --json status controller", "secpctl --json status worker"}
    assert expected <= swept, (
        f"missing from the sweep: {sorted(expected - swept)} — these are inline-prose commands, "
        "the exact shape a fenced-only extractor missed, and they carried two real defects"
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
