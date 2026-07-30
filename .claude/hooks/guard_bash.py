"""PreToolUse(Bash|PowerShell) guard: unconditional hard-deny boundaries for SECP.

Denies, with no unlock path:

* force push and any rewriting of published history;
* any push to ``main``;
* marking a pull request ready, and merging;
* OpenTofu / Terraform ``apply`` or ``destroy``;
* running Alembic migrations against a database;
* mutating management-plane CLI invocations (``--write`` + ``--confirm``);
* remote host contact and mutating ``gh api`` calls;
* manipulation of the migration unlock directory;
* **shell writes to any path guard_writes protects** -- a redirection, ``sed -i``, ``cp``,
  ``rm`` or ``git checkout -- <path>`` is the same policy violation as an Edit, and without
  this an agent blocked by guard_writes would simply reach for ``cat >``.

A denied verb must not be reachable by dressing it up: leading environment assignments,
wrapper binaries, shell keywords and grouping punctuation are stripped, and nested
``sh -c`` / ``Invoke-Expression`` payloads are re-analysed.

Ordinary work -- status, log, diff, add, commit, push to a feature branch,
``gh pr create --draft`` -- is untouched, so no approval prompt is ever required.

This is an agent-error guardrail, not an operating-system security boundary.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import (  # noqa: E402
    MIGRATION_GLOBS,
    command_segments,
    current_branch,
    deny,
    guard,
    matches_any,
    protected_write_reason,
    read_event,
    relative_posix,
    repo_root,
    shell_write_targets,
    tokenize,
)

PROTECTED_BRANCHES = ("main", "master")

HISTORY_REWRITE_SUBCOMMANDS = {
    "filter-branch": "rewrites published history",
    "filter-repo": "rewrites published history",
    "replace": "rewrites object history",
    "update-ref": "moves refs directly, bypassing normal history",
}

GH_DENIED = (
    ("pr", "merge", "merging is reserved to Juan"),
    ("pr", "ready", "marking a pull request ready is reserved to Juan"),
    ("repo", "delete", "repository deletion"),
    ("ruleset", "delete", "branch-protection mutation"),
)

# gh global flags that take a value; their value must not be mistaken for a subcommand.
GH_VALUE_FLAGS = {"-R", "--repo", "--hostname"}

# gh api sends POST implicitly when a field flag is present, so --method is not the only
# signal that a call mutates.
GH_API_FIELD_FLAGS = {"-f", "-F", "--field", "--raw-field", "--input"}
MUTATING_HTTP_METHODS = {"post", "put", "patch", "delete"}
READ_HTTP_METHODS = {"get", "head"}

IAC_BINARIES = {"tofu", "terraform", "opentofu"}
IAC_DENIED_SUBCOMMANDS = {"apply", "destroy"}

ALEMBIC_DENIED_SUBCOMMANDS = {"upgrade", "downgrade", "stamp", "merge"}

MANAGEMENT_CLIS = {"secpctl", "secp-discovery-activation", "secp-admission-proxy"}

REMOTE_SHELLS = {"ssh", "sftp"}

UNLOCK_MARKERS = ("secp-migration-unlock", "secp_migration_unlock")

_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

_WRAPPERS = {
    "env", "sudo", "doas", "nohup", "time", "command", "exec", "xargs", "stdbuf", "nice",
    "timeout", "setsid", "builtin",
}

# After splitting on `;`, a compound statement leaves a keyword as the head token.
_SHELL_KEYWORDS = {
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case",
    "esac", "in", "function", "select", "!",
}

_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "pwsh", "powershell", "cmd"}
_SHELL_COMMAND_FLAGS = {"-c", "-lc", "-ic", "-lic", "-command", "--command", "/c", "/k"}
_PS_INDIRECTION = {"invoke-expression", "iex", "start-process", "invoke-command"}

_MAX_DEPTH = 5


def _strip_grouping(token: str) -> str:
    return token.lstrip("({").rstrip(")}")


def _unwrap(tokens: list[str]) -> list[str]:
    """Reduce a segment to the command it actually runs."""
    remaining = list(tokens)
    changed = True
    while changed and remaining:
        changed = False

        if remaining:
            stripped = _strip_grouping(remaining[0])
            if stripped != remaining[0]:
                if stripped:
                    remaining[0] = stripped
                else:
                    remaining.pop(0)
                changed = True
                continue

        while remaining and _ENV_ASSIGNMENT.match(remaining[0]):
            remaining.pop(0)
            changed = True
        if not remaining:
            break

        head = PurePosixPath(remaining[0].replace("\\", "/")).name.lower().removesuffix(".exe")
        if head in _SHELL_KEYWORDS:
            remaining.pop(0)
            changed = True
            continue
        if head in _WRAPPERS:
            remaining.pop(0)
            changed = True
            while remaining and (remaining[0].startswith("-") or remaining[0].isdigit()):
                remaining.pop(0)
    return remaining


def _binary(tokens: list[str]) -> str:
    if not tokens:
        return ""
    return PurePosixPath(tokens[0].replace("\\", "/")).name.lower().removesuffix(".exe")


def _nested_commands(tokens: list[str]) -> list[str]:
    """Command strings handed to a nested shell or PowerShell indirection."""
    if not tokens:
        return []
    head = _binary(tokens)
    if head in _SHELLS:
        for index in range(1, len(tokens)):
            if tokens[index].lower() in _SHELL_COMMAND_FLAGS and index + 1 < len(tokens):
                return [tokens[index + 1]]
        return []
    if head in _PS_INDIRECTION:
        positional = [t for t in tokens[1:] if not t.startswith("-")]
        if positional:
            # -ArgumentList takes a comma-separated array; shlex glues the quoted elements
            # into one token, so commas become separators for re-analysis.
            return [" ".join(positional).replace(",", " ")]
    return []


def _git_parts(tokens: list[str]) -> tuple[str, list[str]] | None:
    if _binary(tokens) != "git":
        return None
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        break
    if index >= len(tokens):
        return None
    return tokens[index].lower(), tokens[index + 1 :]


def _check_git_push(args: list[str]) -> None:
    lowered = [a.lower() for a in args]

    for flag in ("--force", "--force-with-lease", "--mirror", "--delete"):
        if any(a == flag or a.startswith(flag + "=") for a in lowered):
            deny(
                f"BLOCKED: 'git push {flag}' is an unconditional hard-deny in SECP. "
                "Force-pushing and deleting remote refs are never permitted. "
                "Push an ordinary fast-forward to your feature branch instead."
            )
    for arg in args:
        if arg.startswith("-") and not arg.startswith("--"):
            letters = set(arg[1:])
            if "f" in letters:
                deny(
                    "BLOCKED: 'git push -f' (force push) is an unconditional hard-deny in "
                    "SECP. Push an ordinary fast-forward to your feature branch instead."
                )
            if "d" in letters:
                deny("BLOCKED: 'git push -d' deletes a remote ref and is a hard-deny.")

    positional = [a for a in args if not a.startswith("-")]
    refspecs = positional[1:] if len(positional) > 1 else []

    for refspec in refspecs:
        # A leading '+' forces the push, with or without an explicit source:destination.
        if refspec.startswith("+"):
            deny(
                f"BLOCKED: refspec '{refspec}' begins with '+', which forces the push. "
                "Forced refspecs are an unconditional hard-deny in SECP."
            )
        target = refspec.split(":")[-1].lstrip("+").rsplit("/", 1)[-1]
        if target.lower() in PROTECTED_BRANCHES:
            deny(
                f"BLOCKED: pushing to '{target}' is an unconditional hard-deny in SECP. "
                "Every change reaches main through a reviewed pull request."
            )

    if not refspecs:
        branch = current_branch(repo_root()).lower()
        if branch in PROTECTED_BRANCHES:
            deny(
                f"BLOCKED: the current branch is '{branch}' and a bare 'git push' would push "
                "to it. Pushing to main is an unconditional hard-deny in SECP."
            )


def _check_git(tokens: list[str]) -> None:
    parsed = _git_parts(tokens)
    if parsed is None:
        return
    subcommand, args = parsed
    lowered = [a.lower() for a in args]

    if subcommand == "push":
        _check_git_push(args)
        return
    if subcommand in HISTORY_REWRITE_SUBCOMMANDS:
        deny(
            f"BLOCKED: 'git {subcommand}' {HISTORY_REWRITE_SUBCOMMANDS[subcommand]}. "
            "History rewriting is an unconditional hard-deny in SECP."
        )
    if subcommand == "rebase":
        deny(
            "BLOCKED: 'git rebase' rewrites history. Create a new commit on your feature "
            "branch instead."
        )
    if subcommand == "commit" and "--amend" in lowered:
        deny("BLOCKED: 'git commit --amend' rewrites an existing commit. Create a new commit.")
    if subcommand == "reset" and any(a in {"--hard", "--merge", "--keep"} for a in lowered):
        deny("BLOCKED: 'git reset --hard' discards work and can rewrite branch history.")
    if subcommand == "reflog" and any(a in {"delete", "expire"} for a in lowered):
        deny("BLOCKED: rewriting the reflog is an unconditional hard-deny in SECP.")
    if subcommand == "branch" and any(a in {"-d", "-D", "--delete"} for a in args):
        targets = [a for a in args if not a.startswith("-")]
        if any(t.lower() in PROTECTED_BRANCHES for t in targets):
            deny("BLOCKED: deleting a protected branch is an unconditional hard-deny.")
    if subcommand == "worktree" and "remove" in lowered:
        if any(a in {"--force", "-f"} for a in lowered):
            deny("BLOCKED: 'git worktree remove --force' can discard uncommitted agent work.")


def _gh_subcommands(tokens: list[str]) -> list[str]:
    """Positional gh subcommands, skipping global flags AND their values."""
    result: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in GH_VALUE_FLAGS:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        result.append(token.lower())
        index += 1
    return result


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"", "true", "1", "yes", "on"}


def _check_gh(tokens: list[str]) -> None:
    if _binary(tokens) != "gh":
        return
    rest = _gh_subcommands(tokens)

    for first, second, why in GH_DENIED:
        if len(rest) >= 2 and rest[0] == first and rest[1] == second:
            deny(f"BLOCKED: 'gh {first} {second}' is an unconditional hard-deny in SECP ({why}).")

    if len(rest) >= 2 and rest[0] == "pr" and rest[1] == "create":
        drafted = False
        for token in tokens:
            lowered = token.lower()
            if lowered == "--draft" or lowered == "-d":
                drafted = True
            elif lowered.startswith("--draft="):
                drafted = _truthy(lowered.split("=", 1)[1])
        if not drafted:
            deny(
                "BLOCKED: 'gh pr create' without --draft opens a ready-for-review PR, which is "
                "equivalent to marking ready. SECP agents may only open draft PRs."
            )

    if rest and rest[0] == "api":
        method = ""
        has_field = False
        for index, token in enumerate(tokens):
            lowered = token.lower()
            if lowered in {"--method", "-x"} and index + 1 < len(tokens):
                method = tokens[index + 1].lower()
            elif lowered.startswith("--method="):
                method = lowered.split("=", 1)[1]
            if lowered in GH_API_FIELD_FLAGS or any(
                lowered.startswith(flag + "=") for flag in GH_API_FIELD_FLAGS
            ):
                has_field = True
        if method in MUTATING_HTTP_METHODS:
            deny(
                f"BLOCKED: 'gh api --method {method.upper()}' mutates GitHub state. "
                "Repository, ruleset and PR mutation are reserved to Juan."
            )
        if has_field and method not in READ_HTTP_METHODS:
            deny(
                "BLOCKED: 'gh api' with a field flag (-f/-F/--field/--input) sends POST by "
                "default and mutates GitHub state. Reserved to Juan."
            )


def _check_infrastructure(tokens: list[str]) -> None:
    if not tokens:
        return
    head = _binary(tokens)
    rest = [t.lower() for t in tokens[1:] if not t.startswith("-")]

    if head in IAC_BINARIES and rest and rest[0] in IAC_DENIED_SUBCOMMANDS:
        deny(
            f"BLOCKED: '{head} {rest[0]}' mutates real infrastructure. OpenTofu/Terraform "
            "apply and destroy are an unconditional hard-deny in SECP."
        )

    # Alembic may be reached through uv, poetry, docker compose run, or an explicit -c.
    for index, token in enumerate(tokens):
        name = PurePosixPath(token.replace("\\", "/")).name.lower().removesuffix(".exe")
        if name != "alembic":
            continue
        following = [t.lower() for t in tokens[index + 1 :] if not t.startswith("-")]
        for candidate in following:
            if candidate in ALEMBIC_DENIED_SUBCOMMANDS:
                deny(
                    f"BLOCKED: 'alembic {candidate}' runs a migration against a database. "
                    "Running migrations is not authorised; authoring is gated separately."
                )

    if head in MANAGEMENT_CLIS:
        flags = {t.lower() for t in tokens[1:]}
        if "--write" in flags and "--confirm" in flags:
            deny(
                f"BLOCKED: '{head} --write --confirm' performs a real host mutation. "
                "Provider and host mutation are an unconditional hard-deny in SECP."
            )

    if head in REMOTE_SHELLS or head == "scp":
        deny(f"BLOCKED: '{head}' contacts a remote host. Agents may not contact managed hosts.")

    if head == "rsync":
        remote = any(re.match(r"^[^/\\\s]*:", t) and not re.match(r"^[A-Za-z]:[\\/]", t)
                     for t in tokens[1:] if not t.startswith("-"))
        if remote or any(t in {"-e", "--rsh"} for t in tokens[1:]):
            deny("BLOCKED: 'rsync' to a remote host contacts a managed host.")


_QUOTE_SPLIT = re.compile(r"['\"]")

_INTERPRETER_BINARIES = {"python", "python3", "py", "node", "perl", "ruby", "php", "deno", "bun"}


def _interpreter_path_candidates(tokens: list[str], segment: str) -> list[str]:
    """Paths referenced by inline interpreter code.

    `python -c "open('.github/workflows/ci.yml','w')"` writes a protected file without any
    shell redirection. Inline code is not worth parsing, so every quoted string in such a
    segment is treated as a candidate write target.
    """
    if _binary(tokens) not in _INTERPRETER_BINARIES:
        return []
    if not any(t in {"-c", "-e", "--eval", "--exec"} for t in tokens[1:]):
        return []
    # Split on quote characters rather than pairing them: quote pairing mis-associates
    # nested quotes (`"open('path','w')"` yields `open(` instead of the path).
    pieces = _QUOTE_SPLIT.split(segment)
    return [p.strip() for p in pieces if ("/" in p or "\\" in p or "." in p) and len(p) > 2]


def _check_write_targets(tokens: list[str], root: Path, branch: str, segment: str = "") -> None:
    """Apply the guard_writes path policy to shell write channels."""
    candidates = shell_write_targets(tokens) + _interpreter_path_candidates(tokens, segment)
    for raw in candidates:
        lowered = raw.replace("\\", "/").lower()
        if any(marker in lowered for marker in UNLOCK_MARKERS):
            deny(
                "BLOCKED: the migration unlock directory is operator-owned. Agents may never "
                "create, modify, copy, rename, delete or self-issue an unlock token."
            )
        rel_path = relative_posix(raw, root)
        if rel_path is None:
            continue
        if matches_any(rel_path, MIGRATION_GLOBS) is not None:
            deny(
                f"BLOCKED: '{rel_path}' is an Alembic migration and this is a shell write, "
                "which cannot present an unlock token. Migration authoring requires an "
                "operator-issued token and must go through the editing tools."
            )
        reason = protected_write_reason(rel_path, branch)
        if reason is not None:
            deny(f"BLOCKED: this shell command writes to a protected path. {reason}")


def main() -> None:
    event = read_event()
    tool_name = event.get("tool_name")
    if isinstance(tool_name, str) and tool_name not in {"Bash", "PowerShell"}:
        return

    tool_input = event.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str) or not command.strip():
        # Fail closed: a shell call this guard cannot read is a shell call it cannot clear.
        deny(
            "BLOCKED: this shell call carries no readable 'command' string, so the SECP "
            "guards cannot evaluate it. Denied fail-closed."
        )

    root = repo_root()
    branch = current_branch(root)

    pending = [command]
    depth = 0
    while pending and depth < _MAX_DEPTH:
        nested: list[str] = []
        for text in pending:
            for segment in command_segments(text):
                tokens = _unwrap(tokenize(segment))
                _check_git(tokens)
                _check_gh(tokens)
                _check_infrastructure(tokens)
                _check_write_targets(tokens, root, branch, segment)
                nested.extend(_nested_commands(tokens))
        pending = nested
        depth += 1


if __name__ == "__main__":
    guard(main)
