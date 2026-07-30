"""The standing Program Lead launcher must hold its declared posture and fail closed.

The launcher is the one place the model, permission, teammate and session-name posture is
established. A silent drift here (a stray --effort pin, a cleared subagent-model override, a
hardcoded machine path) changes what every downstream agent runs on, and nothing else would
catch it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts" / "program"
LAUNCHER = SCRIPTS / "Start-ProgramLead.ps1"
UNLOCK_MINTER = SCRIPTS / "New-MigrationUnlock.ps1"


@pytest.fixture(scope="module")
def launcher_text() -> str:
    assert LAUNCHER.is_file(), f"{LAUNCHER} is missing"
    return LAUNCHER.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def minter_text() -> str:
    assert UNLOCK_MINTER.is_file(), f"{UNLOCK_MINTER} is missing"
    return UNLOCK_MINTER.read_text(encoding="utf-8")


REQUIRED_POSTURE = (
    ("opus[1m]", "the Opus 1M model selector"),
    ("bypassPermissions", "unattended permission mode"),
    ("in-process", "in-process teammate mode"),
    ("secp-program-lead", "the Program Lead agent name"),
    ("SECP Program Lead", "the stable session name"),
)


@pytest.mark.parametrize("needle,description", REQUIRED_POSTURE)
def test_launcher_declares_posture(launcher_text: str, needle: str, description: str) -> None:
    assert needle in launcher_text, f"launcher does not establish {description}"


def _executable_body(text: str) -> str:
    """Strip the comment-based help block so prose about --effort is not mistaken for code."""
    return re.sub(r"<#.*?#>", "", text, flags=re.DOTALL)


def test_launcher_passes_no_effort_flag(launcher_text: str) -> None:
    """A launch-effort pin would interfere with interactive Ultracode activation."""
    body = _executable_body(launcher_text)
    assert "--effort" not in body, (
        "the launcher must not pass --effort; Ultracode is activated interactively"
    )
    assert "/effort ultracode" in launcher_text, (
        "the launcher must tell the operator how to activate Ultracode"
    )


def test_launcher_sets_subagent_model_rather_than_clearing_it(launcher_text: str) -> None:
    """CLAUDE_CODE_SUBAGENT_MODEL silently overrides every per-agent model frontmatter.

    Clearing it would make child model selection ambient; it must be set explicitly.
    """
    assert "CLAUDE_CODE_SUBAGENT_MODEL" in launcher_text
    assert re.search(r"\$env:CLAUDE_CODE_SUBAGENT_MODEL\s*=", launcher_text), (
        "the launcher must SET CLAUDE_CODE_SUBAGENT_MODEL, not merely reference it"
    )
    assert not re.search(r"Remove-Item\s+Env:CLAUDE_CODE_SUBAGENT_MODEL", launcher_text), (
        "clearing CLAUDE_CODE_SUBAGENT_MODEL would make child model selection ambient"
    )


FAIL_CLOSED_CONDITIONS = (
    ("settings.json", "missing hook configuration"),
    ("guard_bash.py", "missing required hook file"),
    ("PROJECT_CHARTER", "checkout is not the SECP repository"),
    ("disableBypassPermissionsMode", "bypassPermissions disabled by managed configuration"),
    ("issue with the selected model", "requested model unavailable"),
)


@pytest.mark.parametrize("needle,condition", FAIL_CLOSED_CONDITIONS)
def test_launcher_fails_closed_on(launcher_text: str, needle: str, condition: str) -> None:
    assert needle in launcher_text, f"launcher does not fail closed on: {condition}"


def test_launcher_has_a_single_refusal_path(launcher_text: str) -> None:
    assert "function Stop-FailClosed" in launcher_text
    assert launcher_text.count("Stop-FailClosed ") >= 6, (
        "expected every fail-closed condition to route through the refusal helper"
    )


def test_launcher_documents_the_authority_model_honestly(launcher_text: str) -> None:
    """bypassPermissions grants full host authority; hooks are not an OS boundary."""
    lowered = launcher_text.lower()
    assert "full host authority" in lowered
    assert "not an operating-system security boundary" in lowered
    assert "accidental" in lowered, "must state that hooks reduce ACCIDENTAL violations"


def test_launcher_only_passes_agent_when_the_definition_exists(launcher_text: str) -> None:
    """.claude/agents/ arrives in PR 2; passing --agent before then cannot resolve."""
    body = _executable_body(launcher_text)
    assert re.search(r"agents[\\/]\$AgentName\.md|agents[\\/]secp-program-lead\.md", body), (
        "the launcher must resolve the agent definition path before passing --agent"
    )
    guarded = re.search(
        r"Test-Path[^\n]*agentDefinition|agentDefinition[^\n]*\n[^\n]*Test-Path", body
    )
    assert guarded, "--agent must be gated on the definition existing"


MACHINE_PATH_PATTERNS = (
    re.compile(r"(?i)[A-Z]:\\Users\\"),
    re.compile(r"(?i)[A-Z]:/Users/"),
    re.compile(r"/home/[a-z0-9._-]+/"),
)

SECRET_PATTERNS = (
    re.compile(r"(?i)\b(password|api[_-]?key|secret)\s*=\s*['\"][^'\"]{6,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


@pytest.mark.parametrize("script", [LAUNCHER, UNLOCK_MINTER], ids=lambda p: p.name)
def test_script_has_no_machine_specific_path(script: Path) -> None:
    text = script.read_text(encoding="utf-8")
    for pattern in MACHINE_PATH_PATTERNS:
        match = pattern.search(text)
        assert match is None, f"{script.name} hardcodes a machine path: {match.group(0)!r}"


@pytest.mark.parametrize("script", [LAUNCHER, UNLOCK_MINTER], ids=lambda p: p.name)
def test_script_has_no_secret(script: Path) -> None:
    text = script.read_text(encoding="utf-8")
    for pattern in SECRET_PATTERNS:
        assert not pattern.search(text), f"{script.name} appears to contain secret material"


@pytest.mark.parametrize("script", [LAUNCHER, UNLOCK_MINTER], ids=lambda p: p.name)
def test_script_derives_repo_root_from_its_own_location(script: Path) -> None:
    assert "$PSScriptRoot" in script.read_text(encoding="utf-8"), (
        f"{script.name} must locate the repository relative to itself, not by absolute path"
    )


# ---------------------------------------------------------------------------------------
# Unlock minter
# ---------------------------------------------------------------------------------------

MINTER_REQUIREMENTS = (
    ("MaxTtlMinutes = 60", "60-minute maximum TTL"),
    ("migration_filename", "binds the exact migration filename"),
    ("base_sha", "binds the exact base SHA"),
    ("branch", "binds the exact branch"),
    ("repository", "binds the exact repository"),
    ("issuer", "records the issuer"),
    ("expires_at", "records expiry"),
    ("nonce", "carries a nonce"),
)


@pytest.mark.parametrize("needle,description", MINTER_REQUIREMENTS)
def test_minter_binds_required_fields(minter_text: str, needle: str, description: str) -> None:
    assert needle in minter_text, f"unlock minter does not implement: {description}"


def test_minter_refuses_a_second_outstanding_token(minter_text: str) -> None:
    """CI cannot detect branching Alembic heads, so migration work is serialised."""
    assert "unconsumed unlock token" in minter_text
    assert "only one live migration contract is permitted" in minter_text


def test_minter_keeps_tokens_outside_the_repository(minter_text: str) -> None:
    assert "is inside the repository" in minter_text, (
        "the minter must refuse an unlock directory located inside the repo"
    )


def test_minter_refuses_to_authorise_a_migration_on_main(minter_text: str) -> None:
    assert "never on main" in minter_text


def test_minter_states_what_approval_does_not_grant(minter_text: str) -> None:
    lowered = minter_text.lower()
    assert "does not authorise" in lowered or "does not authorize" in lowered
    for scope in ("head", "database", "deploy", "merg"):
        assert scope in lowered, f"minter must state that approval does not cover: {scope}"


def test_minter_field_set_matches_the_hook_contract(minter_text: str) -> None:
    """A field the hook does not expect is rejected, which is what keeps secrets out."""
    hook = (REPO_ROOT / ".claude" / "hooks" / "guard_migration_unlock.py").read_text(
        encoding="utf-8"
    )
    required = re.search(r"REQUIRED_FIELDS\s*=\s*\{(.*?)\}", hook, re.DOTALL)
    assert required, "guard_migration_unlock.py must declare REQUIRED_FIELDS"
    for field in re.findall(r'"([a-z_]+)"', required.group(1)):
        assert field in minter_text, f"minter does not emit required token field {field!r}"
