"""TeammateIdle guard: a teammate may not go idle holding an OPEN ASSIGNED contract.

Ownership must be provable. An earlier version blocked whenever the shared checkout was
dirty, which inferred ownership from working-tree state -- and that inference is simply
wrong in a shared checkout: it blocked read-only review agents over changes the lead had
made, twice, during this PR's own review. A guard that punishes an agent for someone
else's work teaches agents to route around guards.

Durable, agent-bound task contracts arrive with the Project Brain in PR 2. Until then this
hook is deliberately INERT when ``docs/program/ACTIVE_WORK.md`` is absent, and it makes no
attempt to attribute uncommitted changes to whoever happens to be idling. That is a real
gap, stated plainly rather than papered over with a heuristic that is wrong more often
than it is right.

Blocking here is genuinely enforced by the client ("TeammateIdle hook prevented
continuation"), so it is reserved for the case where ownership is recorded.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import block, guard, read_event, repo_root  # noqa: E402

ACTIVE_WORK = "docs/program/ACTIVE_WORK.md"
OPEN_STATES = ("status: open", "status: in_progress", "status: in-progress")


def _open_contracts(root: Path) -> list[str]:
    """Open task contracts recorded in ACTIVE_WORK.md, or [] when the file is absent."""
    path = root / ACTIVE_WORK
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [line.strip() for line in text.splitlines() if line.strip().lower() in OPEN_STATES]


def main() -> None:
    read_event()
    contracts = _open_contracts(repo_root())
    if not contracts:
        return  # No recorded ownership: nothing this hook can honestly assert.

    block(
        f"BLOCKED: {len(contracts)} task contract(s) in {ACTIVE_WORK} are still open. "
        "Finish the assigned work, or hand it back explicitly by closing the contract with "
        "its current state and what remains. Do not go idle holding it."
    )


if __name__ == "__main__":
    guard(main)
