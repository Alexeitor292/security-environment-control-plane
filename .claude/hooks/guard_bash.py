"""PreToolUse(Bash) guard: unconditional hard-deny boundaries for SECP.

Denies, with no unlock path:

* force push and any history rewriting of published history;
* any push to ``main``;
* marking a pull request ready, and merging;
* OpenTofu / Terraform ``apply`` or ``destroy``;
* running Alembic migrations against a database;
* mutating management-plane CLI invocations (``--write`` + ``--confirm``);
* SSH/SCP host contact and mutating ``gh api`` calls;
* any manipulation of the migration unlock directory.

Ordinary work -- status, log, diff, add, commit, push to a feature branch,
``gh pr create --draft`` -- is untouched, so no approval prompt is ever required.

This is an agent-error guardrail, not an operating-system security boundary.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import (  # noqa: E402
    command_segments,
    current_branch,
    deny,
    guard,
    normalized,
    read_event,
    repo_root,
    tokenize,
)

PROTECTED_BRANCHES = ("main", "master")

# git subcommands that rewrite history or otherwise mutate published refs.
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

MUTATING_HTTP_METHODS = {"post", "put", "patch", "delete"}

IAC_BINARIES = {"tofu", "terraform", "opentofu"}
IAC_DENIED_SUBCOMMANDS = {"apply", "destroy"}

MANAGEMENT_CLIS = {"secpctl", "secp-discovery-activation", "secp-admission-proxy"}


# A denied verb must not be reachable by dressing it up. Leading environment assignments and
# wrapper binaries are stripped, and `sh -c "..."` style invocations are re-analysed, so that
# `GIT_DIR=x git push --force`, `xargs git push --force` and `sh -c 'git push --force'` are all
# evaluated as the command they actually run.
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

_WRAPPERS = {
    "env",
    "sudo",
    "doas",
    "nohup",
    "time",
    "command",
    "exec",
    "xargs",
    "stdbuf",
    "nice",
    "timeout",
    "setsid",
    "builtin",
}

_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "pwsh", "powershell", "cmd"}
_SHELL_COMMAND_FLAGS = {"-c", "-lc", "-ic", "-lic", "-command", "--command", "/c", "/k"}

_MAX_UNWRAP_DEPTH = 5


def _unwrap(tokens: list[str]) -> list[str]:
    """Strip environment assignments and wrapper binaries to reach the real command."""
    remaining = list(tokens)
    changed = True
    while changed and remaining:
        changed = False
        while remaining and _ENV_ASSIGNMENT.match(remaining[0]):
            remaining.pop(0)
            changed = True
        if not remaining:
            break
        head = Path(remaining[0]).name.lower().removesuffix(".exe")
        if head in _WRAPPERS:
            remaining.pop(0)
            changed = True
            # Consume the wrapper's own flags and numeric arguments (timeout 60, xargs -n1).
            while remaining and (remaining[0].startswith("-") or remaining[0].isdigit()):
                remaining.pop(0)
    return remaining


def _nested_shell_commands(tokens: list[str]) -> list[str]:
    """Return command strings passed to a nested shell via -c / -Command."""
    if not tokens:
        return []
    head = Path(tokens[0]).name.lower().removesuffix(".exe")
    if head not in _SHELLS:
        return []
    for index in range(1, len(tokens)):
        if tokens[index].lower() in _SHELL_COMMAND_FLAGS and index + 1 < len(tokens):
            return [tokens[index + 1]]
    return []


def _git_parts(tokens: list[str]) -> tuple[str, list[str]] | None:
    """Return (subcommand, remaining args) when the segment invokes git."""
    if not tokens:
        return None
    head = Path(tokens[0]).name.lower()
    if head not in {"git", "git.exe"}:
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


def _check_git_push(args: list[str], root: Path) -> None:
    lowered = [a.lower() for a in args]

    for flag in ("--force", "--force-with-lease", "--mirror", "--delete"):
        if any(a == flag or a.startswith(flag + "=") for a in lowered):
            deny(
                f"BLOCKED: 'git push {flag}' is an unconditional hard-deny in SECP. "
                "Force-pushing and deleting remote refs are never permitted. "
                "Push an ordinary fast-forward to your feature branch instead."
            )
    # Short flags, including bundled forms such as -fu.
    for arg in args:
        if arg.startswith("-") and not arg.startswith("--"):
            letters = set(arg[1:])
            if "f" in letters:
                deny(
                    "BLOCKED: 'git push -f' (force push) is an unconditional hard-deny in SECP. "
                    "Push an ordinary fast-forward to your feature branch instead."
                )
            if "d" in letters:
                deny("BLOCKED: 'git push -d' deletes a remote ref and is an unconditional hard-deny.")

    # A leading '+' on a refspec is a force push.
    for arg in args:
        if arg.startswith("+") and ":" in arg:
            deny(
                f"BLOCKED: refspec '{arg}' begins with '+', which forces the push. "
                "Forced refspecs are an unconditional hard-deny in SECP."
            )

    positional = [a for a in args if not a.startswith("-")]
    refspecs = positional[1:] if len(positional) > 1 else []
    for refspec in refspecs:
        target = refspec.split(":")[-1]
        target = target.rsplit("/", 1)[-1]
        if target.lower() in PROTECTED_BRANCHES:
            deny(
                f"BLOCKED: pushing to '{target}' is an unconditional hard-deny in SECP. "
                "Every change reaches main through a reviewed pull request."
            )

    if not refspecs:
        branch = current_branch(root).lower()
        if branch in PROTECTED_BRANCHES:
            deny(
                f"BLOCKED: the current branch is '{branch}' and a bare 'git push' would "
                "push to it. Pushing to main is an unconditional hard-deny in SECP."
            )


def _check_git(tokens: list[str], root: Path) -> None:
    parsed = _git_parts(tokens)
    if parsed is None:
        return
    subcommand, args = parsed
    lowered = [a.lower() for a in args]

    if subcommand == "push":
        _check_git_push(args, root)
        return

    if subcommand in HISTORY_REWRITE_SUBCOMMANDS:
        deny(
            f"BLOCKED: 'git {subcommand}' {HISTORY_REWRITE_SUBCOMMANDS[subcommand]}. "
            "History rewriting is an unconditional hard-deny in SECP."
        )

    if subcommand == "rebase":
        deny(
            "BLOCKED: 'git rebase' rewrites history. SECP agents may not rebase published "
            "history. Create a new commit on your feature branch instead."
        )

    if subcommand == "commit" and any(a == "--amend" for a in lowered):
        deny(
            "BLOCKED: 'git commit --amend' rewrites an existing commit. "
            "Create a new commit instead."
        )

    if subcommand == "reset" and any(a in {"--hard", "--merge", "--keep"} for a in lowered):
        deny(
            "BLOCKED: 'git reset --hard' discards work and can rewrite branch history. "
            "This is an unconditional hard-deny in SECP."
        )

    if subcommand == "reflog" and any(a in {"delete", "expire"} for a in lowered):
        deny("BLOCKED: rewriting the reflog is an unconditional hard-deny in SECP.")

    if subcommand == "branch" and any(a in {"-d", "-D", "--delete"} for a in args):
        targets = [a for a in args if not a.startswith("-")]
        if any(t.lower() in PROTECTED_BRANCHES for t in targets):
            deny("BLOCKED: deleting a protected branch is an unconditional hard-deny in SECP.")

    if subcommand == "worktree" and "remove" in lowered:
        if any(a in {"--force", "-f"} for a in lowered):
            deny("BLOCKED: 'git worktree remove --force' can discard uncommitted agent work.")


def _check_gh(tokens: list[str]) -> None:
    if not tokens or Path(tokens[0]).name.lower() not in {"gh", "gh.exe"}:
        return
    rest = [t.lower() for t in tokens[1:] if not t.startswith("-")]

    for first, second, why in GH_DENIED:
        if len(rest) >= 2 and rest[0] == first and rest[1] == second:
            deny(f"BLOCKED: 'gh {first} {second}' is an unconditional hard-deny in SECP ({why}).")

    if len(rest) >= 2 and rest[0] == "pr" and rest[1] == "create":
        if not any(t.lower() == "--draft" or t == "-d" for t in tokens):
            deny(
                "BLOCKED: 'gh pr create' without --draft opens a ready-for-review PR, which is "
                "equivalent to marking ready. SECP agents may only open draft PRs: add --draft."
            )

    if rest and rest[0] == "api":
        for index, token in enumerate(tokens):
            lowered = token.lower()
            value = ""
            if lowered in {"--method", "-x"} and index + 1 < len(tokens):
                value = tokens[index + 1].lower()
            elif lowered.startswith("--method="):
                value = lowered.split("=", 1)[1]
            if value in MUTATING_HTTP_METHODS:
                deny(
                    f"BLOCKED: 'gh api --method {value.upper()}' mutates GitHub state. "
                    "Repository, ruleset and PR mutation are reserved to Juan."
                )


def _check_infrastructure(tokens: list[str], segment: str) -> None:
    if not tokens:
        return
    binary = Path(tokens[0]).name.lower().removesuffix(".exe")
    rest = [t.lower() for t in tokens[1:] if not t.startswith("-")]

    if binary in IAC_BINARIES and rest and rest[0] in IAC_DENIED_SUBCOMMANDS:
        deny(
            f"BLOCKED: '{binary} {rest[0]}' mutates real infrastructure. "
            "OpenTofu/Terraform apply and destroy are an unconditional hard-deny in SECP."
        )

    if binary == "alembic" and rest and rest[0] in {"upgrade", "downgrade"}:
        deny(
            f"BLOCKED: 'alembic {rest[0]}' runs a migration against a database. "
            "Running migrations is not authorised; migration authoring is gated separately."
        )

    if "alembic" in normalized(segment) and (" upgrade " in f" {normalized(segment)} "):
        if "-m alembic" in normalized(segment) or "python -m alembic" in normalized(segment):
            deny(
                "BLOCKED: running Alembic via 'python -m alembic upgrade' executes a migration "
                "against a database. This is not authorised."
            )

    if binary in MANAGEMENT_CLIS:
        flags = {t.lower() for t in tokens[1:]}
        if "--write" in flags and "--confirm" in flags:
            deny(
                f"BLOCKED: '{binary} --write --confirm' performs a real host mutation "
                "(Docker Compose, systemd, filesystem). Provider and host mutation are an "
                "unconditional hard-deny in SECP."
            )

    if binary in {"ssh", "scp", "sftp", "rsync"}:
        deny(
            f"BLOCKED: '{binary}' contacts a remote host. SECP agents may not contact "
            "providers, hypervisors or managed hosts."
        )


def _check_unlock_directory(segment: str) -> None:
    lowered = normalized(segment)
    if "secp-migration-unlock" in lowered or "secp_migration_unlock" in lowered:
        deny(
            "BLOCKED: the migration unlock directory is operator-owned. Agents may never "
            "create, modify, copy, rename, delete or self-issue an unlock token. "
            "Ask Juan to run scripts/program/New-MigrationUnlock.ps1."
        )


def main() -> None:
    event = read_event()
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return

    root = repo_root()
    pending = [command]
    depth = 0
    while pending and depth < _MAX_UNWRAP_DEPTH:
        nested: list[str] = []
        for text in pending:
            for segment in command_segments(text):
                tokens = _unwrap(tokenize(segment))
                _check_unlock_directory(segment)
                _check_git(tokens, root)
                _check_gh(tokens)
                _check_infrastructure(tokens, segment)
                nested.extend(_nested_shell_commands(tokens))
        pending = nested
        depth += 1


if __name__ == "__main__":
    guard(main)
