"""Shared helpers for SECP Claude Code guard hooks.

Design constraints (see docs/program/AGENT_OPERATING_MODEL.md):

* Standard library only. Hooks must run before/without the project virtualenv and
  must behave identically on Windows and POSIX.
* Self-locating. Each hook lives at ``<repo>/.claude/hooks/<name>.py`` so the repo
  root is ``parents[2]`` of the script. ``CLAUDE_PROJECT_DIR`` is preferred when
  present but is never required.
* Fail closed. A guard that cannot evaluate its input denies rather than allows.
  A denied action is recoverable; a silently permitted force-push is not.

These hooks reduce accidental project-policy violations by agents. They are NOT an
operating-system security boundary: anything running under the operator's identity
can edit or bypass them.
"""

from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import sys
from pathlib import Path, PurePosixPath

# --------------------------------------------------------------------------------------
# Repository location
# --------------------------------------------------------------------------------------


def repo_root() -> Path:
    """Return the SECP checkout root.

    Resolution order: this file's own location (deterministic, env-independent),
    then CLAUDE_PROJECT_DIR, then cwd. The first candidate that looks like the SECP
    repository wins; otherwise the script-relative root is returned.
    """
    candidates = [Path(__file__).resolve().parents[2]]
    env_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if env_dir:
        candidates.append(Path(env_dir))
    candidates.append(Path.cwd())
    for candidate in candidates:
        try:
            if is_secp_repo(candidate):
                return candidate.resolve()
        except OSError:
            continue
    return candidates[0]


def is_secp_repo(path: Path) -> bool:
    """True when ``path`` is the SECP monorepo root (not merely any git repo)."""
    pyproject = path / "pyproject.toml"
    if not pyproject.is_file():
        return False
    try:
        text = pyproject.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return 'name = "secp"' in text and (path / "docs" / "PROJECT_CHARTER.md").is_file()


# --------------------------------------------------------------------------------------
# Hook I/O
# --------------------------------------------------------------------------------------


def read_event() -> dict:
    """Read the hook payload from stdin. Returns {} when stdin is empty/unparsable."""
    try:
        raw = sys.stdin.read()
    except (OSError, UnicodeDecodeError):
        return {}
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()


def deny(reason: str, event_name: str = "PreToolUse") -> None:
    """Deny a tool call and exit. The reason is shown to the agent."""
    _emit(
        {
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    )
    raise SystemExit(0)


def allow_silently() -> None:
    """Emit nothing and exit 0, leaving normal permission handling in place."""
    raise SystemExit(0)


def block(reason: str) -> None:
    """Block a non-PreToolUse event (Stop / TaskCompleted / TeammateIdle)."""
    _emit({"decision": "block", "reason": reason})
    raise SystemExit(0)


def add_context(text: str, event_name: str = "SessionStart") -> None:
    """Inject additional context (SessionStart / UserPromptSubmit)."""
    _emit(
        {
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "additionalContext": text,
            }
        }
    )
    raise SystemExit(0)


def guard(main) -> None:
    """Run ``main`` fail-closed.

    An unexpected exception denies the action rather than allowing it, and names the
    hook so the failure is diagnosable instead of silent.
    """
    try:
        main()
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - deliberate catch-all, fail closed
        hook = Path(sys.argv[0]).name or "secp-hook"
        deny(f"SECP guard '{hook}' failed to evaluate this action ({exc!r}); denied fail-closed.")


# --------------------------------------------------------------------------------------
# Command parsing
# --------------------------------------------------------------------------------------

_UNQUOTED_BREAKS = ("&&", "||", ";;", ";", "|", "\n", "&", "`", "$(", ")")


def command_segments(command: str) -> list[str]:
    """Split a shell command into individually inspectable segments.

    Chaining, substitution and redirection are flattened so that
    ``echo hi && git push --force`` cannot hide a denied verb behind a benign prefix.

    The split is QUOTE-AWARE. Breaking inside a quoted string would wrongly deny ordinary
    work -- for example ``git commit -m "handle a && b"`` must not be read as a second
    command, and a commit message or grep pattern that merely mentions a denied verb must
    not trip the guard. Quoted text is preserved inside its own segment, where the first
    token is not a denied binary, so it cannot smuggle a command either.
    """
    if not command:
        return []

    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    index = 0
    length = len(command)

    while index < length:
        char = command[index]

        if quote is not None:
            current.append(char)
            if char == "\\" and quote == '"' and index + 1 < length:
                current.append(command[index + 1])
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue

        if char in ("'", '"'):
            quote = char
            current.append(char)
            index += 1
            continue

        matched = None
        for token in _UNQUOTED_BREAKS:
            if command.startswith(token, index):
                matched = token
                break
        if matched is not None:
            segments.append("".join(current))
            current = []
            index += len(matched)
            continue

        current.append(char)
        index += 1

    segments.append("".join(current))
    return [segment.strip() for segment in segments if segment.strip()]


def tokenize(segment: str) -> list[str]:
    """Best-effort argv tokenisation that never raises."""
    try:
        import shlex

        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def normalized(segment: str) -> str:
    """Whitespace-normalised lowercase form for substring checks."""
    return " ".join(segment.lower().split())


# --------------------------------------------------------------------------------------
# Path helpers
# --------------------------------------------------------------------------------------


def relative_posix(path_value: str, root: Path) -> str | None:
    """Return ``path_value`` as a repo-relative POSIX path, or None if outside the repo."""
    if not path_value:
        return None
    try:
        candidate = Path(path_value)
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = candidate.resolve()
        relative = resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    return PurePosixPath(relative.as_posix()).as_posix()


def matches_any(rel_path: str, patterns: tuple[str, ...]) -> str | None:
    """Return the first glob in ``patterns`` matching ``rel_path``, else None."""
    for pattern in patterns:
        if fnmatch.fnmatch(rel_path, pattern):
            return pattern
        # Allow "dir/**" to match "dir/file" as well as "dir/a/b".
        if pattern.endswith("/**") and fnmatch.fnmatch(rel_path, pattern[:-3] + "/*"):
            return pattern
    return None


def edited_paths(tool_input: dict) -> list[str]:
    """Collect every filesystem path a write-shaped tool call would touch."""
    paths: list[str] = []
    for key in ("file_path", "notebook_path", "path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            paths.append(value)
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        for edit in edits:
            if isinstance(edit, dict):
                value = edit.get("file_path")
                if isinstance(value, str) and value:
                    paths.append(value)
    return paths


def written_text(tool_input: dict) -> str:
    """Concatenate the text a write-shaped tool call would introduce or remove."""
    chunks: list[str] = []
    for key in ("content", "new_string", "old_string", "new_source"):
        value = tool_input.get(key)
        if isinstance(value, str):
            chunks.append(value)
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        for edit in edits:
            if isinstance(edit, dict):
                for key in ("new_string", "old_string"):
                    value = edit.get(key)
                    if isinstance(value, str):
                        chunks.append(value)
    return "\n".join(chunks)


# --------------------------------------------------------------------------------------
# Git helpers
# --------------------------------------------------------------------------------------


def git(root: Path, *args: str, timeout: float = 10.0) -> str:
    """Run a read-only git command, returning stripped stdout ('' on any failure)."""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", *args],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def git_succeeds(root: Path, *args: str, timeout: float = 10.0) -> bool:
    """True when a git command exits 0.

    Required for predicates that signal through the EXIT CODE and print nothing --
    ``git merge-base --is-ancestor`` being the important one. Reading its stdout would
    return '' whether or not the ancestry holds, making the check silently vacuous.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", *args],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def current_branch(root: Path) -> str:
    return git(root, "rev-parse", "--abbrev-ref", "HEAD")


# --------------------------------------------------------------------------------------
# Evidence ledger (kept outside the repository)
# --------------------------------------------------------------------------------------


def evidence_dir(session_id: str) -> Path:
    import tempfile

    safe = "".join(ch for ch in (session_id or "nosession") if ch.isalnum() or ch in "-_")
    path = Path(tempfile.gettempdir()) / "secp-program" / (safe or "nosession")
    path.mkdir(parents=True, exist_ok=True)
    return path


def evidence_path(session_id: str) -> Path:
    return evidence_dir(session_id) / "evidence.jsonl"


def read_evidence(session_id: str) -> list[dict]:
    path = evidence_path(session_id)
    if not path.is_file():
        return []
    records: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                records.append(parsed)
    except OSError:
        return []
    return records
