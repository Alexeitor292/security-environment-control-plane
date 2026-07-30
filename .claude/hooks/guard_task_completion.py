"""TaskCompleted guard: a task may not be declared done without recorded evidence.

Rule: if the working tree carries uncommitted modifications to tracked files and the
session has recorded no passing validation run, completion is blocked.

Rationale (docs/program/SAFETY_INVARIANTS.md): the repository's own capability ledger
drifted two shipped milestones because prose asserted completion that no check verified.
Evidence here means a command that actually ran and passed, recorded by
``record_evidence.py`` -- never a claim in a report.

A local run is never accepted as proof of the FULL gate: only the named CI contexts are.
This guard enforces the weaker, always-checkable property that *something* was validated.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import block, git, guard, read_event, read_evidence, repo_root  # noqa: E402

FOCUSED = "uv run pytest tests/program -q"
LINT = "uv run ruff check tests scripts && uv run ruff format --check tests scripts"


def main() -> None:
    event = read_event()
    session_id = str(event.get("session_id") or "")

    root = repo_root()
    dirty = git(root, "status", "--porcelain")
    if not dirty.strip():
        return  # Nothing uncommitted: there is no unverified change to gate.

    records = read_evidence(session_id)
    if any(record.get("status") == "passed" for record in records):
        return

    attempted = [r.get("command", "")[:80] for r in records if r.get("status") != "passed"]
    detail = ""
    if attempted:
        detail = " Recorded but not passing: " + "; ".join(attempted[:3]) + "."

    changed = [line[3:] for line in dirty.splitlines()[:5] if len(line) > 3]
    block(
        "BLOCKED: this task cannot be completed. The working tree has uncommitted changes "
        f"({', '.join(changed)}{'…' if len(dirty.splitlines()) > 5 else ''}) and no passing "
        f"validation has been recorded in this session.{detail} "
        f"Run the focused suite first: {FOCUSED} -- and the lint gate: {LINT}. "
        "Completion must be earned by a command that ran, not asserted in prose."
    )


if __name__ == "__main__":
    guard(main)
