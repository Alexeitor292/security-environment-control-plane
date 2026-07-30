"""PreToolUse(Edit/Write/NotebookEdit/MultiEdit) guard: protected paths and append-only records.

The path policy itself lives in ``_common.protected_write_reason`` because ``guard_bash.py``
must enforce exactly the same rules for shell write channels. If the two ever disagree, an
agent blocked here simply reaches for ``cat >`` instead.

Unconditional hard-deny on every branch: ``.github/**`` and ``infra/ci/**`` (the
trusted-ancestry rule must not be weakened, repaired, special-cased, skipped or warned
through), production trust roots and release-signing anchors, secrets material, the
operator-owned unlock directory, and edits that CHANGE a named safety seal in product source.

Branch-scoped: on a program-foundation branch, all product source and all non-program
documentation is denied.

Migration files are handled by ``guard_migration_unlock.py`` so a valid operator-issued token
can authorise the write.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import (  # noqa: E402
    MIGRATION_GLOBS,
    current_branch,
    deny,
    edited_paths,
    guard,
    is_program_branch,
    matches_any,
    protected_write_reason,
    read_event,
    relative_posix,
    repo_root,
)

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


def _edit_pairs(tool_input: dict) -> list[tuple[str, str]]:
    """Every (old, new) text pair a write-shaped call would apply.

    MultiEdit carries its pairs in ``edits``; reading only the top-level keys let a
    MultiEdit silently bypass both the append-only record and the seal check.
    """
    pairs: list[tuple[str, str]] = []
    old = tool_input.get("old_string")
    new = tool_input.get("new_string")
    if isinstance(old, str) or isinstance(new, str):
        pairs.append((old if isinstance(old, str) else "", new if isinstance(new, str) else ""))
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        for edit in edits:
            if isinstance(edit, dict):
                eold = edit.get("old_string")
                enew = edit.get("new_string")
                if isinstance(eold, str) or isinstance(enew, str):
                    pairs.append(
                        (
                            eold if isinstance(eold, str) else "",
                            enew if isinstance(enew, str) else "",
                        )
                    )
    return pairs


def _removed_lines(old: str, new: str) -> list[str]:
    new_lines = new.splitlines()
    return [line for line in old.splitlines() if line.strip() and line not in new_lines]


def _check_append_only(rel_path: str, root: Path, tool_input: dict) -> None:
    if matches_any(rel_path, APPEND_ONLY) is None:
        return
    target = root / rel_path
    if not target.is_file():
        return  # Creating the record is fine; only removal from an existing one is denied.

    def refuse(removed: list[str]) -> None:
        deny(
            f"BLOCKED: '{rel_path}' is an append-only record and this call removes "
            f"{len(removed)} existing line(s), starting with: {removed[0][:120]!r}. "
            "Append a new entry with a 'supersedes:' pointer instead of editing history."
        )

    content = tool_input.get("content")
    if isinstance(content, str):
        try:
            existing = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        removed = _removed_lines(existing, content)
        if removed:
            refuse(removed)

    for old, new in _edit_pairs(tool_input):
        removed = _removed_lines(old, new)
        if removed:
            refuse(removed)


def _check_seal_literals(rel_path: str, root: Path, tool_input: dict) -> None:
    """Deny only a CHANGE to a seal, never a mention of one.

    Denying on presence refused pure appends that merely quote a seal name in unchanged
    context -- and `_B1A_SUBPROCESS_SEALED` alone appears in dozens of files, so that
    false-deny was broad enough to push agents into routing around the guards entirely.
    """
    if matches_any(rel_path, SEAL_SCOPE_GLOBS) is None:
        return

    def refuse(literal: str) -> None:
        deny(
            f"BLOCKED: this edit to '{rel_path}' changes the safety seal '{literal}'. "
            "Changing a safety seal is an unconditional hard-deny in SECP."
        )

    content = tool_input.get("content")
    if isinstance(content, str):
        existing = ""
        target = root / rel_path
        if target.is_file():
            try:
                existing = target.read_text(encoding="utf-8", errors="replace")
            except OSError:
                existing = ""
        for literal in SEAL_LITERALS:
            if content.count(literal) != existing.count(literal):
                refuse(literal)

    for old, new in _edit_pairs(tool_input):
        for literal in SEAL_LITERALS:
            if old.count(literal) != new.count(literal):
                refuse(literal)


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

        if matches_any(rel_path, MIGRATION_GLOBS) is not None and not is_program_branch(branch):
            continue  # guard_migration_unlock.py owns this path.

        reason = protected_write_reason(rel_path, branch)
        if reason is not None:
            deny(f"BLOCKED: {reason}")

        _check_append_only(rel_path, root, tool_input)
        _check_seal_literals(rel_path, root, tool_input)


if __name__ == "__main__":
    guard(main)
