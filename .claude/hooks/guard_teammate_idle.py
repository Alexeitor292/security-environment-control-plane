"""TeammateIdle guard: a teammate may not go idle holding incomplete assigned work.

Incomplete work is detected two ways:

1. ``docs/program/ACTIVE_WORK.md`` lists an open task contract owned by this teammate.
   (That file arrives with the Project Brain in PR 2; until then this check is inert.)
2. The working tree carries uncommitted modifications -- work that exists nowhere durable
   and would be silently lost when the teammate stops.

Blocking here is real: the client honours it ("TeammateIdle hook prevented continuation").
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import block, git, guard, read_event, repo_root  # noqa: E402

ACTIVE_WORK = "docs/program/ACTIVE_WORK.md"
OPEN_STATES = ("status: open", "status: in_progress", "status: in-progress")


def _open_contracts(root: Path) -> list[str]:
    path = root / ACTIVE_WORK
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [line.strip() for line in text.splitlines() if line.strip().lower() in OPEN_STATES]


def main() -> None:
    event = read_event()
    root = repo_root()

    contracts = _open_contracts(root)
    if contracts:
        block(
            f"BLOCKED: {len(contracts)} task contract(s) in {ACTIVE_WORK} are still open. "
            "Finish the assigned work, or hand it back explicitly by closing the contract "
            "with its current state and what remains. Do not go idle holding it."
        )

    dirty = git(root, "status", "--porcelain")
    if dirty.strip():
        files = [line[3:] for line in dirty.splitlines()[:6] if len(line) > 3]
        more = "…" if len(dirty.splitlines()) > 6 else ""
        teammate = event.get("agentId") or event.get("agent_id") or "this teammate"
        block(
            f"BLOCKED: {teammate} is going idle with uncommitted changes ({', '.join(files)}"
            f"{more}). That work exists nowhere durable and would be lost. Commit it to the "
            "assigned feature branch, or explicitly state what is unfinished and why."
        )


if __name__ == "__main__":
    guard(main)
