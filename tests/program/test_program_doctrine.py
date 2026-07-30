"""The doctrine documents must stay structurally sound and honest.

These three files are what a Program Lead and its specialists read instead of guessing. The
failure mode they exist to prevent -- a confident document that has quietly stopped matching
the code -- is exactly the failure mode they could themselves develop, so their load-bearing
properties are asserted rather than trusted.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PROGRAM_DIR = REPO_ROOT / "docs" / "program"

SAFETY = PROGRAM_DIR / "SAFETY_INVARIANTS.md"
OWNERSHIP = PROGRAM_DIR / "FILE_OWNERSHIP.md"
OPERATING = PROGRAM_DIR / "AGENT_OPERATING_MODEL.md"

DOCTRINE = (SAFETY, OWNERSHIP, OPERATING)


@pytest.mark.parametrize("path", DOCTRINE, ids=lambda p: p.name)
def test_doctrine_document_exists_and_is_substantive(path: Path) -> None:
    assert path.is_file(), f"{path} is missing"
    assert len(path.read_text(encoding="utf-8")) > 2000, f"{path.name} is too thin to be useful"


@pytest.mark.parametrize("path", DOCTRINE, ids=lambda p: p.name)
def test_doctrine_document_is_anchored_to_an_observed_commit(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert re.search(r"[Oo]bserved at:|observed at\b", text), (
        f"{path.name} must state the commit it was observed at, so staleness is computable"
    )
    assert re.search(r"\b[0-9a-f]{7,40}\b", text), f"{path.name} must cite a commit SHA"


def test_safety_invariants_declares_append_only_and_is_hook_protected() -> None:
    text = SAFETY.read_text(encoding="utf-8")
    assert "append-only" in text.lower()
    guard = (REPO_ROOT / ".claude" / "hooks" / "guard_writes.py").read_text(encoding="utf-8")
    assert "docs/program/SAFETY_INVARIANTS.md" in guard, (
        "SAFETY_INVARIANTS.md claims to be append-only; guard_writes.py must enforce it"
    )


def test_safety_invariants_opens_with_the_seal_census_caveat() -> None:
    """The seal list is not the infrastructure-contact surface -- state it first, not never."""
    text = SAFETY.read_text(encoding="utf-8")
    assert "SI-000" in text
    head = text[: text.find("## 1.")]
    assert "discover_activity" in head, (
        "the ungated legacy provider-contact path must be named before any seal table, "
        "or the document teaches the wrong mental model"
    )


ROW_PATTERN = re.compile(r"^\|\s*SI-\d+\s*\|", re.MULTILINE)


def test_safety_invariant_rows_carry_enforcement_and_breakability() -> None:
    text = SAFETY.read_text(encoding="utf-8")
    rows = ROW_PATTERN.findall(text)
    assert len(rows) >= 40, f"expected a substantive invariant catalogue, found {len(rows)} rows"
    for header in ("enforcedAt", "kind", "breakableBy"):
        assert header in text, f"invariant tables must carry a {header!r} column"


def test_safety_invariants_uses_the_declared_enforcement_vocabulary() -> None:
    text = SAFETY.read_text(encoding="utf-8")
    for kind in (
        "code-seal",
        "settings-validator",
        "db-constraint",
        "db-trigger",
        "boundary-test",
        "ci-gate",
        "import-guard",
        "repo-ruleset",
        "convention-only",
    ):
        assert kind in text, f"enforcement vocabulary is missing {kind!r}"


def test_safety_invariants_records_the_containment_boundary() -> None:
    """SECP deploys deliberately vulnerable systems; Invariant 17 is the containment rule."""
    text = SAFETY.read_text(encoding="utf-8")
    assert "Invariant 17" in text
    assert "public networks" in text


OPERATING_SECTIONS = (
    "Roles and authority",
    "Hook denials are decisions",
    "Escalate to Juan",
    "Preventing a second system",
    "Collision control",
    "Worktree scheduling",
    "Evidence and completion",
    "Model policy",
)


@pytest.mark.parametrize("section", OPERATING_SECTIONS)
def test_operating_model_covers_section(section: str) -> None:
    assert section in OPERATING.read_text(encoding="utf-8"), f"missing section: {section}"


def test_operating_model_states_the_honest_authority_boundary() -> None:
    lowered = OPERATING.read_text(encoding="utf-8").lower()
    assert "full host authority" in lowered
    assert "not an operating-system security boundary" in lowered


def test_operating_model_claims_only_transcript_proven_model_facts() -> None:
    """Per the model-truth policy: claim Opus/xhigh only when proven, never 1M, never Ultracode."""
    text = OPERATING.read_text(encoding="utf-8")
    assert "transcript-proven" in text
    assert "context-1m-2025-08-07" in text, "1M is claimed only via the observed beta header"
    assert re.search(r"[Nn]ever claimed", text), (
        "the document must state that Ultracode inheritance is never claimed for children"
    )
    assert "CLAUDE_CODE_SUBAGENT_MODEL" in text
    assert "Explore" in text, "the built-in Explore model cap must be recorded"


def test_operating_model_records_that_help_is_not_authoritative() -> None:
    text = OPERATING.read_text(encoding="utf-8")
    assert "not authoritative" in text
    assert "ultracode" in text.lower()


def test_git_authority_is_stated_without_ambiguity() -> None:
    text = OPERATING.read_text(encoding="utf-8")
    for rule in ("No force push", "No push to `main`", "No merge"):
        assert rule in text, f"git authority must state: {rule}"
    assert "exact base SHA" in text


def test_infrastructure_invalid_ci_does_not_block_local_work() -> None:
    text = OPERATING.read_text(encoding="utf-8")
    assert "infrastructure_invalid" in text
    assert "mark-ready and merge" in text


@pytest.mark.parametrize("path", DOCTRINE, ids=lambda p: p.name)
def test_doctrine_document_contains_no_real_endpoint(path: Path) -> None:
    """docs/ is scanned repo-wide for real endpoints; keep the Brain clean by construction."""
    text = path.read_text(encoding="utf-8")
    for pattern in (
        re.compile(r"https?://(?!localhost|127\.0\.0\.1|example\.|docs\.|json\.schemastore)"),
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ):
        for match in pattern.finditer(text):
            candidate = match.group(0)
            if candidate.startswith(("10.", "127.", "192.168.", "0.")):
                continue
            pytest.fail(f"{path.name} contains a possible real endpoint: {candidate!r}")
