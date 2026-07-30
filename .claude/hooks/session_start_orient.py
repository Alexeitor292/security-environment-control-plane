"""SessionStart orientation: inject observed repository state, not remembered state.

Emits the facts an agent would otherwise guess or take from stale prose: the exact HEAD,
the branch, whether the tree is clean, the real sole Alembic head computed from the
migration files themselves, and -- critically -- how far ``docs/STATUS.md`` has drifted
behind HEAD.

That drift warning is the control that would have caught the current state of this
repository, where the self-declared "Current Capability Ledger" sits two shipped
milestones behind the code and names an Alembic head that is two revisions stale.

Read-only and fast: no network, no database, no package import.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import add_context, git, guard, repo_root  # noqa: E402

VERSIONS_DIR = "apps/api/migrations/versions"
STATUS_DOC = "docs/STATUS.md"

# Migrations declare typed module globals, e.g. `revision: str = '09a75fd21cf8'` and
# `down_revision: str | None = None`, so the annotation must be skipped before the value.
_REVISION = re.compile(r"^revision\s*(?::[^=\n]*)?=\s*['\"]([^'\"]+)['\"]", re.MULTILINE)
_DOWN_REVISION = re.compile(
    r"^down_revision\s*(?::[^=\n]*)?=\s*['\"]([^'\"]+)['\"]", re.MULTILINE
)


def alembic_heads(root: Path) -> list[str]:
    """Compute head revisions from the migration files (revisions never used as a parent)."""
    directory = root / VERSIONS_DIR
    if not directory.is_dir():
        return []
    revisions: set[str] = set()
    parents: set[str] = set()
    for path in directory.glob("*.py"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = _REVISION.search(text)
        if match:
            revisions.add(match.group(1))
        for parent in _DOWN_REVISION.findall(text):
            parents.add(parent)
    return sorted(revisions - parents)


def main() -> None:
    root = repo_root()
    lines: list[str] = ["## SECP observed state (session start, read-only)"]

    head = git(root, "rev-parse", "HEAD")
    branch = git(root, "rev-parse", "--abbrev-ref", "HEAD")
    subject = git(root, "log", "-1", "--format=%s")
    dirty = git(root, "status", "--porcelain")

    lines.append(f"- HEAD: `{head[:12] or 'unknown'}` on `{branch or 'unknown'}` — {subject}")
    lines.append(f"- Working tree: {'DIRTY' if dirty.strip() else 'clean'}")

    heads = alembic_heads(root)
    if len(heads) == 1:
        lines.append(f"- Sole Alembic head (computed from migration files): `{heads[0]}`")
    elif len(heads) > 1:
        lines.append(
            f"- **BRANCHING ALEMBIC HEADS DETECTED: {', '.join(heads)}** — CI cannot catch this "
            "on a single branch. Stop and escalate to Juan before writing any migration."
        )

    status_commit = git(root, "log", "-1", "--format=%H", "--", STATUS_DOC)
    if status_commit and head:
        behind = git(root, "rev-list", "--count", f"{status_commit}..HEAD")
        if behind.isdigit() and int(behind) > 0:
            lines.append(
                f"- **DRIFT: `{STATUS_DOC}` was last updated {behind} commit(s) ago "
                f"(`{status_commit[:12]}`).** Treat its claims as unverified prose: published "
                "code and exact GitHub state are authoritative."
            )
        else:
            lines.append(f"- `{STATUS_DOC}` is current with HEAD.")

    lines.append(
        "- Authority rule: published code and exact GitHub state are authoritative. "
        "Documentation prose is a claim to verify, never evidence of completion."
    )

    add_context("\n".join(lines))


if __name__ == "__main__":
    guard(main)
