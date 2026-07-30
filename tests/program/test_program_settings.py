"""Committed Claude Code configuration must be valid, complete, and secret-free.

`.claude/settings.json` is the enforcement surface for the multi-agent operating model:
it wires every guard hook and carries the hard-deny list. If it silently stops parsing,
stops wiring a hook, or starts carrying a machine-specific path, the guardrails degrade
without anything failing. These tests make that loud.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CLAUDE_DIR = REPO_ROOT / ".claude"
SETTINGS_PATH = CLAUDE_DIR / "settings.json"
HOOKS_DIR = CLAUDE_DIR / "hooks"

REQUIRED_HOOK_EVENTS = (
    "SessionStart",
    "PreToolUse",
    "PostToolUse",
    "TaskCompleted",
    "TeammateIdle",
)

REQUIRED_HOOK_FILES = (
    "_common.py",
    "guard_bash.py",
    "guard_writes.py",
    "guard_migration_unlock.py",
    "record_evidence.py",
    "guard_task_completion.py",
    "guard_teammate_idle.py",
    "session_start_orient.py",
)

# Every hard boundary that must appear in the deny list as defence in depth.
REQUIRED_DENY_SUBSTRINGS = (
    "git push --force",
    "git push -f",
    "git push origin main",
    "git rebase",
    "git reset --hard",
    "git commit --amend",
    "git filter-branch",
    "gh pr merge",
    "gh pr ready",
    "tofu apply",
    "tofu destroy",
    "terraform apply",
    "terraform destroy",
    "alembic upgrade",
    "alembic downgrade",
    ".github/**",
    "infra/ci/**",
    "production.py",
    "signing.py",
)


@pytest.fixture(scope="module")
def settings() -> dict:
    assert SETTINGS_PATH.is_file(), f"{SETTINGS_PATH} is missing"
    return json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))


def test_settings_json_parses(settings: dict) -> None:
    assert isinstance(settings, dict)
    assert "hooks" in settings
    assert "permissions" in settings


@pytest.mark.parametrize("event", REQUIRED_HOOK_EVENTS)
def test_required_hook_event_is_wired(settings: dict, event: str) -> None:
    assert event in settings["hooks"], f"hook event {event!r} is not wired"
    assert settings["hooks"][event], f"hook event {event!r} is wired but empty"


@pytest.mark.parametrize("hook_file", REQUIRED_HOOK_FILES)
def test_required_hook_file_exists(hook_file: str) -> None:
    assert (HOOKS_DIR / hook_file).is_file(), f".claude/hooks/{hook_file} is missing"


def _hook_commands(settings: dict) -> list[str]:
    commands: list[str] = []
    for matchers in settings["hooks"].values():
        for matcher in matchers:
            for hook in matcher.get("hooks", []):
                command = hook.get("command")
                if isinstance(command, str):
                    commands.append(command)
    return commands


def test_every_wired_hook_command_points_at_an_existing_file(settings: dict) -> None:
    referenced = []
    for command in _hook_commands(settings):
        for match in re.finditer(r"\.claude/hooks/([A-Za-z0-9_]+\.py)", command):
            referenced.append(match.group(1))
            assert (HOOKS_DIR / match.group(1)).is_file(), (
                f"settings.json wires .claude/hooks/{match.group(1)} which does not exist"
            )
    assert referenced, "no hook script is referenced by settings.json"


@pytest.mark.parametrize("needle", REQUIRED_DENY_SUBSTRINGS)
def test_hard_boundary_present_in_deny_list(settings: dict, needle: str) -> None:
    deny = settings["permissions"]["deny"]
    assert any(needle in rule for rule in deny), f"deny list does not cover {needle!r}"


def test_deny_list_uses_edit_not_write_for_file_rules(settings: dict) -> None:
    """`Write(path)` deny rules are silently ineffective; only `Edit(path)` covers writes.

    The client emits a startup warning for these. Regression guard: a `Write(...)` rule
    reads as protection and provides none.
    """
    offenders = [rule for rule in settings["permissions"]["deny"] if rule.startswith("Write(")]
    assert not offenders, (
        "Write(path) deny rules do not match file permission checks; use Edit(path). "
        f"Offending rules: {offenders}"
    )


def test_shell_guards_cover_every_shell_tool(settings: dict) -> None:
    """On Windows the session exposes BOTH a Bash and a PowerShell tool.

    A matcher of only "Bash" leaves `git push --force` reachable through PowerShell, which
    would defeat every command guard on this platform.
    """
    shell_matchers = [
        matcher.get("matcher", "")
        for matcher in settings["hooks"]["PreToolUse"]
        if "Bash" in matcher.get("matcher", "")
    ]
    assert shell_matchers, "no PreToolUse matcher covers the Bash tool"
    for matcher in shell_matchers:
        assert "PowerShell" in matcher, (
            f"matcher {matcher!r} covers Bash but not PowerShell; command guards would be "
            "bypassable through the PowerShell tool on Windows"
        )

    post_matchers = [
        matcher.get("matcher", "")
        for matcher in settings["hooks"]["PostToolUse"]
        if "Bash" in matcher.get("matcher", "")
    ]
    for matcher in post_matchers:
        assert "PowerShell" in matcher, (
            f"evidence recording matcher {matcher!r} misses PowerShell-run validation"
        )


def test_every_hook_declares_a_timeout_above_its_subprocess_budget(settings: dict) -> None:
    """A hook TIMEOUT exits non-zero with empty stdout, which the client treats as
    non-blocking -- so a slow guard silently ALLOWS. The configured timeout must exceed the
    worst-case subprocess budget of the slowest guard.

    guard_migration_unlock makes up to four git calls; `_common.git` bounds each at 5s.
    """
    worst_case_seconds = 4 * 5
    for matchers in settings["hooks"].values():
        for matcher in matchers:
            for hook in matcher.get("hooks", []):
                timeout = hook.get("timeout")
                assert isinstance(timeout, int), f"hook {hook.get('command')} declares no timeout"
                assert timeout > worst_case_seconds, (
                    f"timeout {timeout}s does not exceed the {worst_case_seconds}s worst-case "
                    "git budget; a timeout fails OPEN, not closed"
                )

    common = (CLAUDE_DIR / "hooks" / "_common.py").read_text(encoding="utf-8")
    assert common.count("timeout: float = 5.0") == 2, (
        "git helpers must keep a 5s bound so the worst case stays inside the hook timeout"
    )


def test_no_ask_rules_that_would_stall_an_unattended_session(settings: dict) -> None:
    """The standing Program Lead runs unattended; an `ask` rule has no approver."""
    assert "ask" not in settings["permissions"] or not settings["permissions"]["ask"], (
        "permissions.ask would block an unattended bypassPermissions session with no approver"
    )


def _committed_claude_files() -> list[Path]:
    files = [SETTINGS_PATH]
    files.extend(sorted(HOOKS_DIR.glob("*.py")))
    files.extend(sorted((CLAUDE_DIR / "rules").glob("*.md")))
    return files


SECRET_PATTERNS = (
    re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"][^'\"]{6,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._-]{20,}"),
)

# Absolute, user- or machine-specific paths must never be committed.
MACHINE_PATH_PATTERNS = (
    re.compile(r"(?i)[A-Z]:\\\\?Users\\\\?"),
    re.compile(r"(?i)[A-Z]:/Users/"),
    re.compile(r"/home/[a-z0-9._-]+/"),
    re.compile(r"/Users/[a-z0-9._-]+/"),
)


@pytest.mark.parametrize("path", _committed_claude_files(), ids=lambda p: p.name)
def test_committed_claude_file_has_no_secret(path: Path) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    for pattern in SECRET_PATTERNS:
        assert not pattern.search(text), f"{path} appears to contain secret material"


@pytest.mark.parametrize("path", _committed_claude_files(), ids=lambda p: p.name)
def test_committed_claude_file_has_no_machine_specific_path(path: Path) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    for pattern in MACHINE_PATH_PATTERNS:
        match = pattern.search(text)
        assert match is None, f"{path} contains a machine-specific path: {match.group(0)!r}"


def test_settings_local_is_ignored_by_tracked_gitignore() -> None:
    """It was previously ignored only via .git/info/exclude, which no other clone sees."""
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    entries = {line.strip() for line in gitignore.splitlines()}
    assert ".claude/settings.local.json" in entries, (
        ".claude/settings.local.json must be ignored by the tracked .gitignore, not only by "
        ".git/info/exclude which does not travel to other clones"
    )
