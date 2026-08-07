"""The audit ledger's ``outcome`` column has a closed vocabulary, proved against the live tree.

WHY THIS EXISTS
----------------
``audit.record`` used to take ``outcome: str = "success"``. Nothing named the permitted values, so
the ledger accumulated them by accident:

* ``failed`` and ``failure`` -- the same disposition, spelled two ways, three sites apart;
* ``written`` -- not a disposition at all, on an action already called ``..._written``;
* ``worker_key_rotated`` -- a *reason code* in the disposition column, passed positionally through
  a local helper so that a grep for ``outcome="`` could not see it;
* every value of :class:`EligibilityOutcome` -- an entire foreign closed set, two of whose members
  (``expired``, ``refused``) collide with this one's while meaning something else.

The column is append-only, so none of those rows can be repaired. This guard exists to stop the
tenth spelling, not to pretend the first nine did not happen.

HOW IT AVOIDS BEING A RESTATEMENT OF ITSELF
--------------------------------------------
The permitted set is read from :class:`AuditOutcome` at run time and the call sites are read from
the source tree at run time. Neither is a list maintained here. A list written by the same author,
from the same mental model, at the same moment as the thing it checks cannot notice that the thing
drifted -- so this file contains no inventory of values, no inventory of files, and no expected
count.

Three independent methods are crossed against each other so that a broken scan cannot pass by
finding nothing:

1. **Git** says which Python files exist (``git ls-files``), not a second directory walk written
   the same way as the first.
2. **The AST** finds the call sites.
3. **The token stream** counts the same call sites a completely different way. If the AST walk
   silently stops matching -- a renamed helper, a changed import shape, a visitor that stops
   recursing -- the two disagree and the scan refuses to report a verdict instead of reporting
   green.

THE SECOND READING WAS A REGEX AND THE REGEX WAS WRONG
------------------------------------------------------
It counted ``audit.record(`` as *text*, so it also counted the three occurrences inside **this
file's own fixture strings** -- the planted sources the red-direction tests parse. Locally that
was invisible, because this file was still untracked and ``git ls-files`` did not hand it to the
scan; it fired the moment the file was committed. AST 163, text 166, and the scan correctly
refused rather than reporting a verdict.

That is §3 of the guard rules on the instrument rather than the subject: **key on the thing, not
on its spelling.** ``tokenize`` sees ``NAME . NAME (`` as four tokens and sees a string literal as
one ``STRING`` token, so prose and fixtures cannot inflate it. It remains genuinely independent of
the AST walk in the way that matters here -- it cannot be shrunk by a bug in the visitor -- while
no longer being fooled by anything that merely *looks* like a call.
"""

from __future__ import annotations

import ast
import inspect
import io
import subprocess
import token as token_module
import tokenize
import typing
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest
from secp_api import audit
from secp_api.enums import AuditAction, AuditOutcome
from secp_api.models import AuditEvent
from secp_api.schemas import AuditEventOut

REPO_ROOT = Path(__file__).resolve().parents[3]


def _tokenized_call_count(text: str) -> int:
    """Count ``audit.record(`` in the TOKEN stream, ignoring comments and string contents.

    The independent second reading. A text search counts anything shaped like the call, including
    this file's own fixture strings and any prose that mentions it; the token stream sees a string
    literal as a single ``STRING`` token and a comment as a single ``COMMENT`` token, so neither
    can inflate the count.
    """
    interesting = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type in {token_module.NAME, token_module.OP}:
                interesting.append(tok.string)
    except (tokenize.TokenError, IndentationError, SyntaxError):  # pragma: no cover - defensive
        return -1
    return sum(
        1
        for i in range(len(interesting) - 3)
        if interesting[i : i + 4] == ["audit", ".", "record", "("]
    )


class AuditScanUnmeasurable(AssertionError):
    """The scan could not establish what it covered, so it refuses to return a verdict.

    Distinct from a plain failure on purpose: "there are no bad outcomes" and "I could not tell"
    must not share an exit path, or the second silently becomes the first.
    """


@dataclass(frozen=True)
class OutcomeArgument:
    """One ``outcome=`` argument at one ``audit.record`` call."""

    path: str
    lineno: int
    #: ``AuditOutcome.<member>`` referenced here, or ``None`` when the argument is not a direct
    #: member reference (a conditional expression, a variable, a literal).
    member: str | None
    #: The source text, for a message that names what is actually wrong.
    source: str
    literal: str | None


def _tracked_python_files() -> list[Path]:
    """What Git says exists. A ``.gitignore`` rule can swallow a whole directory and leave
    ``git status`` silent, so a filesystem walk is not evidence about the committed tree."""
    try:
        completed = subprocess.run(
            ["git", "ls-files", "--", "*.py"],
            capture_output=True,
            check=True,
            cwd=REPO_ROOT,
        )
    except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover - defensive
        raise AuditScanUnmeasurable(
            "git ls-files could not be run, so this guard cannot establish which files it covers"
        ) from exc
    files = [
        REPO_ROOT / line.strip()
        for line in completed.stdout.decode("utf-8").splitlines()
        if line.strip()
    ]
    if not files:
        raise AuditScanUnmeasurable("Git reports no tracked Python files; this scan proves nothing")
    return files


def _outcome_arguments(paths: list[Path]) -> tuple[list[OutcomeArgument], int, int]:
    """Every ``outcome=`` argument at an ``audit.record`` call, plus both call counts.

    Returns ``(arguments, ast_calls, token_calls)`` so the caller can compare the two counts. A
    call with no ``outcome=`` takes the default and contributes to ``ast_calls`` only.
    """
    found: list[OutcomeArgument] = []
    ast_calls = 0
    token_calls = 0
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):  # pragma: no cover - defensive
            continue
        counted = _tokenized_call_count(text)
        if counted > 0:
            token_calls += counted
        try:
            tree = ast.parse(text)
        except SyntaxError:  # pragma: no cover - defensive
            continue
        try:
            rel = str(path.relative_to(REPO_ROOT)).replace("\\", "/")
        except ValueError:  # a planted file in tmp_path, used by the red-direction tests
            rel = str(path).replace("\\", "/")
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_record = (
                isinstance(func, ast.Attribute)
                and func.attr == "record"
                and isinstance(func.value, ast.Name)
                and func.value.id == "audit"
            )
            if not is_record:
                continue
            ast_calls += 1
            argument = next((kw.value for kw in node.keywords if kw.arg == "outcome"), None)
            if argument is None:
                continue
            member = None
            if (
                isinstance(argument, ast.Attribute)
                and isinstance(argument.value, ast.Name)
                and argument.value.id == "AuditOutcome"
            ):
                member = argument.attr
            literal = (
                argument.value
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str)
                else None
            )
            found.append(
                OutcomeArgument(
                    path=rel,
                    lineno=argument.lineno,
                    member=member,
                    source=ast.unparse(argument),
                    literal=literal,
                )
            )
    return found, ast_calls, token_calls


def _scan() -> list[OutcomeArgument]:
    paths = _tracked_python_files()
    arguments, ast_calls, token_calls = _outcome_arguments(paths)
    if ast_calls == 0:
        raise AuditScanUnmeasurable(
            f"the AST walk found no audit.record calls across {len(paths)} tracked Python files; "
            "the walk is broken, not the tree"
        )
    if ast_calls != token_calls:
        raise AuditScanUnmeasurable(
            f"the AST walk found {ast_calls} audit.record call(s) but the token stream of the "
            f"same files found {token_calls}. The two methods disagree, so neither result can be "
            "trusted; fix the scan before trusting a verdict from it."
        )
    return arguments


# --------------------------------------------------------------------------- the closed set


def test_no_audit_outcome_is_written_as_a_bare_string() -> None:
    """A string literal at an ``outcome=`` argument is the shape that produced every defect above.

    This forbids the SHAPE, not merely the known-bad values. Checking values would have accepted
    a tenth misspelling as long as it was new.
    """
    offenders = [arg for arg in _scan() if arg.literal is not None]
    assert not offenders, (
        f"{len(offenders)} audit.record call(s) pass a string literal as the outcome. Use an "
        f"AuditOutcome member -- a literal is how `failure`, `written` and `worker_key_rotated` "
        f"reached an append-only column:\n  "
        + "\n  ".join(f"{arg.path}:{arg.lineno}  outcome={arg.source}" for arg in offenders)
    )


def test_every_audit_outcome_member_is_actually_produced() -> None:
    """A member nobody writes is a claim about the system that nothing backs.

    Enumerated from the live enum, so ADDING a member without a producer turns this red. That
    direction is the one a hand-maintained list cannot cover: a list the author also wrote cannot
    notice the member the author forgot.
    """
    produced = {arg.member for arg in _scan() if arg.member is not None}
    # `success` is overwhelmingly written by omission -- it is the parameter default -- so its
    # producers are the calls that pass nothing. Take that from the live signature rather than
    # assuming which member the default is.
    default = inspect.signature(audit.record).parameters["outcome"].default
    assert isinstance(default, AuditOutcome), (
        "audit.record's outcome default is no longer an AuditOutcome member, so this guard can no "
        f"longer tell which member the implicit calls produce: {default!r}"
    )
    produced.add(default.name)

    missing = {member.name for member in AuditOutcome} - produced
    assert not missing, (
        f"AuditOutcome member(s) {sorted(missing)} are never written anywhere in the tree. Either "
        "a caller should be using them, or the enum is claiming a disposition this system cannot "
        "produce. An unproduced member is a vocabulary nobody speaks."
    )


def test_every_referenced_member_exists_on_the_enum() -> None:
    """The other direction: a call site naming a member the enum does not have.

    ``AuditOutcome.suceeded`` is an ``AttributeError`` at run time on a path that may only execute
    during an incident -- exactly when nobody wants to discover it.
    """
    names = {member.name for member in AuditOutcome}
    bogus = [arg for arg in _scan() if arg.member is not None and arg.member not in names]
    assert not bogus, (
        "audit.record call(s) name an AuditOutcome member that does not exist:\n  "
        + "\n  ".join(f"{arg.path}:{arg.lineno}  outcome={arg.source}" for arg in bogus)
    )


def test_record_does_not_accept_a_bare_string() -> None:
    """The union is what let the vocabulary drift; re-widening it must fail loudly.

    Read from the live signature. ``action`` still carries ``AuditAction | str`` and that is
    asserted too -- not because it is good, but so that this guard is honest about what it does
    NOT yet protect, and so that fact is a checked statement rather than a comment.
    """
    hints = typing.get_type_hints(audit.record)
    assert hints["outcome"] is AuditOutcome, (
        "audit.record's outcome parameter is no longer exactly AuditOutcome "
        f"({hints['outcome']!r}). A union with str reopens the hole this enum closed."
    )
    assert hints["action"] == AuditAction | str, (
        "audit.record's action parameter changed shape. It is deliberately still a union -- the "
        "action vocabulary has the same defect and is NOT fixed by this change. Update this "
        "assertion when it is closed, so nobody reads the outcome fix as covering both."
    )


# --------------------------------------------------------------------------- append-only reads


def test_a_historical_value_outside_the_enum_still_reads(session) -> None:
    """The read path must stay open, or the endpoint 500s on its own history.

    ``failure`` rows are permanent. Closing the READ side would mean the ledger could not show the
    very rows that record the inconsistency -- an audit trail that only renders when it is tidy.
    """
    event = AuditEvent(
        organization_id=None,
        actor="system",
        action="enrollment.page_integrity_failed",
        resource_type="worker_enrollment",
        resource_id=str(uuid.uuid4()),
        outcome="failure",  # written before AuditOutcome existed; never rewritten
        data={"reason": "page_integrity"},
    )
    session.add(event)
    session.flush()

    projected = AuditEventOut.model_validate(event)
    assert projected.outcome == "failure"
    assert projected.outcome not in {member.value for member in AuditOutcome}


def test_the_recorder_persists_the_enum_value_not_its_repr(session) -> None:
    """``str(AuditOutcome.success)`` is ``'AuditOutcome.success'`` on some enum shapes.

    The column is ``String(40)``; a repr would fit, persist, and be wrong forever.
    """
    event = audit.record(
        session,
        action=AuditAction.organization_created,
        resource_type="organization",
        resource_id=uuid.uuid4(),
        outcome=AuditOutcome.refused,
    )
    session.flush()
    assert event.outcome == "refused"
    assert type(event.outcome) is str


# --------------------------------------------------------------------------- the guard's own eyes


def test_the_scan_sees_a_planted_literal(tmp_path: Path) -> None:
    """Red-direction: prove the scanner can fail.

    A guard that has only ever been observed passing is indistinguishable from one that cannot
    fail, and the assertion above is worth exactly as much as this one.
    """
    planted = tmp_path / "planted.py"
    planted.write_text(
        "from secp_api import audit\n"
        "def go(session):\n"
        "    audit.record(session, action='x', resource_type='y', outcome='suceeded')\n",
        encoding="utf-8",
    )
    arguments, ast_calls, token_calls = _outcome_arguments([planted])
    assert ast_calls == token_calls == 1
    assert [arg.literal for arg in arguments] == ["suceeded"]


def test_the_token_reading_ignores_strings_and_comments() -> None:
    """The specific defect that made CI red, pinned so the regex cannot come back.

    Both directions: a real call counts, and neither a fixture string nor a comment mentioning the
    same text does. Without the second half this guard is unmeasurable on its own source, which is
    exactly how it failed.
    """
    real_only = "def go(s):\n    audit.record(s, action='x')\n"
    decorated = (
        "# audit.record(s) in a comment\nSAMPLE = \"    audit.record(s, action='x')\"\n" + real_only
    )
    assert _tokenized_call_count(real_only) == 1
    assert _tokenized_call_count(decorated) == 1, (
        "the token reading counted a comment or a string literal; that is the regex behaviour "
        "this reading exists to replace"
    )
    assert _tokenized_call_count("# audit.record(s)\n") == 0


def test_the_scan_sees_a_planted_bogus_member(tmp_path: Path) -> None:
    planted = tmp_path / "planted_member.py"
    planted.write_text(
        "from secp_api import audit\n"
        "from secp_api.enums import AuditOutcome\n"
        "def go(session):\n"
        "    audit.record(session, action='x', resource_type='y', outcome=AuditOutcome.suceeded)\n",
        encoding="utf-8",
    )
    arguments, _, _ = _outcome_arguments([planted])
    assert [arg.member for arg in arguments] == ["suceeded"]
    assert "suceeded" not in {member.name for member in AuditOutcome}


def test_the_scan_refuses_when_its_two_methods_disagree(tmp_path: Path, monkeypatch) -> None:
    """Red-direction on the cross-check itself, which is the part that makes an empty scan safe."""
    planted = tmp_path / "shadowed.py"
    planted.write_text(
        "from secp_api import audit\ndef go(s):\n    audit.record(s, action='x')\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("test_audit_outcome_vocabulary._tracked_python_files", lambda: [planted])
    # Break the AST half only; the token half still counts the call.
    monkeypatch.setattr(
        "test_audit_outcome_vocabulary._outcome_arguments",
        lambda paths: ([], 0, 1),
    )
    with pytest.raises(AuditScanUnmeasurable, match="found no audit.record calls"):
        _scan()


def test_the_scan_covers_the_real_tree() -> None:
    """The positive control: the scan must actually reach the modules that write audit rows.

    Not a magic floor -- the assertion is that specific known writers were visited, so a scan that
    collapses to a handful of files cannot report green. The names come from the tree, and if one
    of them is legitimately deleted this test names it rather than silently covering less.
    """
    seen = {arg.path for arg in _scan()}
    for expected in (
        "apps/api/secp_api/services/worker_enrollment.py",
        "apps/worker/secp_worker/preflight/consumer.py",
    ):
        assert expected in seen, (
            f"{expected} writes audit outcomes but the scan never saw an outcome argument in it. "
            "Either it stopped writing them, or the scan is not reaching it."
        )
