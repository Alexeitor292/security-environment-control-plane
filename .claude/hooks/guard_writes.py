"""PreToolUse(Edit/Write/NotebookEdit) guard: protected paths and append-only records.

Unconditional hard-deny on every branch:

* ``.github/**`` and ``infra/ci/**`` -- the trusted-ancestry rule and the required CI
  gate must not be weakened, repaired, special-cased, skipped or warned through by an
  agent. The controlled runner is separate, operator-owned work.
* production trust roots and release-signing anchors;
* secrets material (``.env``, ``*.pem``, ``*.key``);
* the operator-owned migration unlock directory;
* edits that flip a named safety seal inside product source.

Branch-scoped:

* on a program-foundation branch, all product source (``apps/`` ``contracts/``
  ``plugins/`` ``infra/`` ``.ci/``) and all non-program documentation is denied, because
  that work belongs in a product PR rather than in the guardrail spine.

Append-only records reject any edit that removes an existing line.

Migration files are deliberately NOT handled here -- ``guard_migration_unlock.py`` owns
them so that a valid operator-issued token can authorise the write.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import (  # noqa: E402
    current_branch,
    deny,
    edited_paths,
    guard,
    matches_any,
    read_event,
    relative_posix,
    repo_root,
    written_text,
)

MIGRATION_GLOBS = ("apps/api/migrations/versions/**",)

ALWAYS_DENY: tuple[tuple[str, str], ...] = (
    (
        ".github/**",
        "CI workflow definitions are operator-owned. The trusted-ancestry rule must not be "
        "weakened, repaired, special-cased, skipped or warned through.",
    ),
    (
        "infra/ci/**",
        "The trusted-ancestry attestation is a security control and is operator-owned.",
    ),
    (
        "apps/management/secp_management/production.py",
        "This is the production trust-root loader.",
    ),
    (
        "apps/management/secp_management/signing.py",
        "This holds the release-signing trust anchor.",
    ),
    (".env", "Secrets material is never edited by an agent."),
    ("**/*.pem", "Key material is never edited by an agent."),
    ("**/*.key", "Key material is never edited by an agent."),
)

PROGRAM_BRANCH_MARKERS = ("secp-program-", "program-orchestration", "program-spine")

PRODUCT_SOURCE_GLOBS = (
    "apps/**",
    "contracts/**",
    "plugins/**",
    "infra/**",
    ".ci/**",
)

# Documentation outside docs/program/ is product documentation on a program branch.
DOC_GLOBS = ("docs/**",)
DOC_ALLOWED = ("docs/program/**",)

SEAL_LITERALS = (
    "_B1A_SUBPROCESS_SEALED",
    "_PLAN_ONLY_PROCESS_SEALED",
    "PlanExecutionGate",
    "SHIPPED_TRUST_ROOT",
    "assert_inline_execution_allowed",
    "SealState",
    "read_seals",
)

SEAL_SCOPE_GLOBS = ("apps/**", "plugins/**", "contracts/**")

APPEND_ONLY = ("docs/program/SAFETY_INVARIANTS.md",)

UNLOCK_MARKERS = ("secp-migration-unlock", "secp_migration_unlock")


def _is_program_branch(branch: str) -> bool:
    lowered = branch.lower()
    return any(marker in lowered for marker in PROGRAM_BRANCH_MARKERS)


def _check_append_only(rel_path: str, root: Path, tool_input: dict) -> None:
    if matches_any(rel_path, APPEND_ONLY) is None:
        return
    target = root / rel_path
    if not target.is_file():
        return  # Creating the file is fine; only removal from an existing record is denied.
    try:
        existing = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    content = tool_input.get("content")
    if isinstance(content, str):
        missing = [
            line
            for line in existing.splitlines()
            if line.strip() and line not in content.splitlines()
        ]
        if missing:
            deny(
                f"BLOCKED: '{rel_path}' is an append-only record and this write removes "
                f"{len(missing)} existing line(s), starting with: {missing[0][:120]!r}. "
                "Append a new entry with a 'supersedes:' pointer instead of editing history."
            )
        return

    old_string = tool_input.get("old_string")
    new_string = tool_input.get("new_string")
    if isinstance(old_string, str) and isinstance(new_string, str):
        new_lines = new_string.splitlines()
        removed = [
            line for line in old_string.splitlines() if line.strip() and line not in new_lines
        ]
        if removed:
            deny(
                f"BLOCKED: '{rel_path}' is an append-only record and this edit removes "
                f"{len(removed)} existing line(s), starting with: {removed[0][:120]!r}. "
                "Append a new entry with a 'supersedes:' pointer instead of editing history."
            )


def _check_path(rel_path: str, root: Path, branch: str, tool_input: dict) -> None:
    if matches_any(rel_path, MIGRATION_GLOBS) is not None and not _is_program_branch(branch):
        return  # guard_migration_unlock.py owns this path.

    hit = matches_any(rel_path, tuple(glob for glob, _ in ALWAYS_DENY))
    if hit is not None:
        reason = next(why for glob, why in ALWAYS_DENY if glob == hit)
        deny(f"BLOCKED: '{rel_path}' is an unconditional hard-deny in SECP. {reason}")

    if _is_program_branch(branch):
        if matches_any(rel_path, PRODUCT_SOURCE_GLOBS) is not None:
            deny(
                f"BLOCKED: '{rel_path}' is product source and branch '{branch}' is a "
                "program-foundation branch, which must contain no product behaviour. "
                "Open a separate product PR for this change."
            )
        if (
            matches_any(rel_path, DOC_GLOBS) is not None
            and matches_any(rel_path, DOC_ALLOWED) is None
        ):
            deny(
                f"BLOCKED: '{rel_path}' is product documentation and branch '{branch}' is a "
                "program-foundation branch. Only docs/program/ may be written here."
            )

    _check_append_only(rel_path, root, tool_input)


def _check_seal_literals(rel_path: str, tool_input: dict) -> None:
    if matches_any(rel_path, SEAL_SCOPE_GLOBS) is None:
        return
    text = written_text(tool_input)
    if not text:
        return
    for literal in SEAL_LITERALS:
        if literal in text:
            deny(
                f"BLOCKED: this edit to '{rel_path}' touches the safety seal '{literal}'. "
                "Changing a safety seal is an unconditional hard-deny in SECP."
            )


def main() -> None:
    event = read_event()
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return

    root = repo_root()
    branch = current_branch(root)

    for raw_path in edited_paths(tool_input):
        lowered = raw_path.replace("\\", "/").lower()
        if any(marker in lowered for marker in UNLOCK_MARKERS):
            deny(
                "BLOCKED: the migration unlock directory is operator-owned. Agents may never "
                "create, modify, copy, rename, delete or self-issue an unlock token."
            )

        rel_path = relative_posix(raw_path, root)
        if rel_path is None:
            continue  # Outside the repository; other guards and the sandbox apply.
        _check_path(rel_path, root, branch, tool_input)
        _check_seal_literals(rel_path, tool_input)


if __name__ == "__main__":
    guard(main)
