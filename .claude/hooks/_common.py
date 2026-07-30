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


# --------------------------------------------------------------------------------------
# Shared protected-path policy
#
# guard_writes.py enforces this for the editing tools, and guard_bash.py enforces the same
# rules for shell write channels. They MUST share one definition: a shell redirection into
# a protected path is the same policy violation as an Edit of it, and an agent blocked by
# one guard must not simply reach for the other.
# --------------------------------------------------------------------------------------

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
)

PROGRAM_BRANCH_MARKERS = ("secp-program-", "program-orchestration", "program-spine")

PRODUCT_SOURCE_GLOBS = ("apps/**", "contracts/**", "plugins/**", "infra/**", ".ci/**")

DOC_GLOBS = ("docs/**",)
DOC_ALLOWED = ("docs/program/**",)

SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx")

APPEND_ONLY_GLOBS = ("docs/program/SAFETY_INVARIANTS.md",)

# Literal path fragments for the shell MENTION scan. Detecting "does this shell command
# write to X" is undecidable in general, so for this small absolute set the rule is
# inverted: mentioning one of these at all is denied unless every segment is a known
# reader. The set is deliberately tiny -- these paths are operator-owned and an agent has
# no routine reason to name them in a shell command.
ABSOLUTE_PREFIXES = (
    ".github/",
    "infra/ci/",
    "apps/management/secp_management/production.py",
    "apps/management/secp_management/signing.py",
    "docs/program/SAFETY_INVARIANTS.md",
    "apps/api/migrations/versions/",
)


def is_program_branch(branch: str) -> bool:
    lowered = (branch or "").lower()
    return any(marker in lowered for marker in PROGRAM_BRANCH_MARKERS)


def is_secret_path(rel_path: str) -> bool:
    """Secrets are matched on BASENAME.

    fnmatch has no ``**`` semantics -- ``*`` already crosses ``/`` -- so a pattern like
    ``**/*.pem`` requires a literal slash and silently fails to match a repo-root
    ``server.pem``. Matching the basename closes that hole for every depth.
    """
    name = PurePosixPath(rel_path).name.lower()
    if name == ".env" or name.startswith(".env."):
        return True
    return name.endswith(SECRET_SUFFIXES)


def absolute_protection_reason(rel_path: str, *, shell: bool = False) -> str | None:
    """Protections that apply on every branch, independent of the program-branch fence.

    ``shell=True`` adds the two protections a shell call can never satisfy: an append-only
    record (a shell write cannot be shown to be an append) and a migration (a shell call
    cannot present an unlock token).
    """
    if is_secret_path(rel_path):
        return f"'{rel_path}' is secrets or key material and is never written by an agent."

    hit = matches_any(rel_path, tuple(glob for glob, _ in ALWAYS_DENY))
    if hit is not None:
        reason = next(why for glob, why in ALWAYS_DENY if glob == hit)
        return f"'{rel_path}' is an unconditional hard-deny in SECP. {reason}"

    if shell:
        if matches_any(rel_path, APPEND_ONLY_GLOBS) is not None:
            return (
                f"'{rel_path}' is an append-only record. A shell write cannot be shown to be "
                "an append, so it is refused; use the editing tools to append an entry."
            )
        if matches_any(rel_path, MIGRATION_GLOBS) is not None:
            return (
                f"'{rel_path}' is an Alembic migration and a shell call cannot present an "
                "unlock token. Migration authoring must go through the editing tools."
            )
    return None


def branch_fence_reason(rel_path: str, branch: str) -> str | None:
    """The broad, branch-scoped fence: no product source or product docs on a program branch."""
    if is_program_branch(branch):
        if matches_any(rel_path, PRODUCT_SOURCE_GLOBS) is not None:
            return (
                f"'{rel_path}' is product source and branch '{branch}' is a program-foundation "
                "branch, which must contain no product behaviour. Open a separate product PR."
            )
        if matches_any(rel_path, DOC_GLOBS) is not None and (
            matches_any(rel_path, DOC_ALLOWED) is None
        ):
            return (
                f"'{rel_path}' is product documentation and branch '{branch}' is a "
                "program-foundation branch. Only docs/program/ may be written here."
            )
    return None


def protected_write_reason(rel_path: str, branch: str) -> str | None:
    """Full editing-tool policy: absolute protections plus the branch fence."""
    return absolute_protection_reason(rel_path) or branch_fence_reason(rel_path, branch)


# --------------------------------------------------------------------------------------
# Shell write-channel extraction
# --------------------------------------------------------------------------------------

_REDIRECTS = (">>", ">", "1>", "2>", "&>", ">|")

_WRITE_BINARIES = {
    "cp", "mv", "rm", "unlink", "truncate", "shred", "dd", "install", "ln", "tee",
    "chmod", "chown", "touch", "mkdir", "rmdir", "patch",
    "tar", "unzip", "rsync", "busybox", "vim", "vi", "ex", "ed", "7z", "gzip", "xz",
    "copy-item", "move-item", "remove-item", "set-content", "add-content", "out-file",
    "new-item", "clear-content", "rename-item",
}

# Flags whose VALUE is a destination (tar -C, unzip -d, dd of=, gzip -o).
_DESTINATION_FLAGS = {"-C", "-d", "--directory", "-o", "--output", "--target-directory", "-t"}

_GIT_WRITE_SUBCOMMANDS = {"checkout", "restore", "apply", "clean", "mv", "rm"}


def shell_write_targets(tokens: list[str]) -> list[str]:
    """Best-effort extraction of filesystem paths a shell segment would WRITE.

    Deliberately over-collects: a candidate is only ever compared against the protected
    glob set, so an ordinary path costs nothing while a missed one defeats every
    write-side guard.
    """
    if not tokens:
        return []
    targets: list[str] = []

    # Output redirection, both `> path` and `>path`.
    for index, token in enumerate(tokens):
        if token in _REDIRECTS:
            if index + 1 < len(tokens):
                targets.append(tokens[index + 1])
            continue
        for redirect in _REDIRECTS:
            if token.startswith(redirect) and len(token) > len(redirect):
                targets.append(token[len(redirect) :])
                break

    head = PurePosixPath(tokens[0].replace("\\", "/")).name.lower().removesuffix(".exe")
    positionals = [t for t in tokens[1:] if not t.startswith("-")]

    # `dd of=path`, `--output=path`: the destination is glued to the flag. Only a
    # destination-shaped flag or a path-shaped value counts -- otherwise an ordinary
    # `--grep=needle` would be mistaken for a write target.
    for token in tokens[1:]:
        if "=" not in token:
            continue
        name, _, value = token.partition("=")
        if not value:
            continue
        destination_flag = name.lower().lstrip("-") in {
            "of", "o", "output", "file", "target", "directory", "dest", "destination",
        }
        if destination_flag or "/" in value or "\\" in value:
            targets.append(value)

    # A destination flag's value is a target wherever it appears.
    for index, token in enumerate(tokens[1:], start=1):
        if token in _DESTINATION_FLAGS and index + 1 < len(tokens):
            targets.append(tokens[index + 1])

    if head in _WRITE_BINARIES:
        targets.extend(positionals)
    elif head in {"git", "git.exe"}:
        lowered = [t.lower() for t in tokens[1:]]
        for sub in _GIT_WRITE_SUBCOMMANDS:
            if sub in lowered:
                targets.extend(positionals)
                break
    elif head == "sed" and any(t == "-i" or t.startswith("-i") for t in tokens[1:]):
        targets.extend(positionals)
    elif head == "find" and any(
        t in {"-delete", "-exec", "-execdir", "-ok"} for t in tokens[1:]
    ):
        targets.extend(positionals)

    return [t for t in targets if t and not t.startswith("-")]


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
