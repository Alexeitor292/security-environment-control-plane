"""Behavioural tests for the committed guard hooks.

The hooks are the deterministic enforcement layer of the multi-agent operating model, so
they are tested the way the client invokes them: as subprocesses fed a synthetic hook
payload on stdin, asserting on the emitted decision.

Two properties matter equally and both are tested:
  * every hard boundary is denied (a guard that under-denies is unsafe);
  * ordinary work is untouched (a guard that over-denies is unusable, and under
    bypassPermissions there is no human to appeal to).

Branch-dependent behaviour is unit-tested against the pure predicate instead of the
subprocess, so the suite is deterministic on a feature branch and on CI's detached HEAD.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HOOKS_DIR = REPO_ROOT / ".claude" / "hooks"


def run_hook(hook: str, payload: dict, env: dict[str, str] | None = None) -> dict | None:
    """Invoke a hook as the client does. Returns the parsed decision, or None if silent."""
    merged = dict(os.environ)
    merged["CLAUDE_PROJECT_DIR"] = str(REPO_ROOT)
    if env:
        merged.update(env)
    completed = subprocess.run(
        [sys.executable, str(HOOKS_DIR / hook)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(REPO_ROOT),
        env=merged,
        check=False,
    )
    assert completed.returncode == 0, f"{hook} exited {completed.returncode}: {completed.stderr}"
    out = completed.stdout.strip()
    if not out:
        return None
    return json.loads(out)


def decision_of(result: dict | None) -> str:
    if result is None:
        return "allow"
    hook_output = result.get("hookSpecificOutput")
    if isinstance(hook_output, dict) and "permissionDecision" in hook_output:
        return str(hook_output["permissionDecision"])
    if result.get("decision") == "block":
        return "block"
    return "allow"


def bash(command: str) -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }


def write(path: str, content: str = "x") -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": path, "content": content},
    }


def load_hook_module(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"secp_hook_{name}", HOOKS_DIR / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------------------
# guard_bash: hard boundaries
# ---------------------------------------------------------------------------------------

DENIED_COMMANDS = [
    "git push --force origin feature/x",
    "git push --force-with-lease origin feature/x",
    "git push -f origin feature/x",
    "git push --mirror origin",
    "git push --delete origin feature/x",
    "git push origin +feature/x:feature/x",
    "git push origin main",
    "git push origin HEAD:main",
    "git push upstream master",
    "git rebase -i main",
    "git rebase --onto main",
    "git reset --hard HEAD~1",
    "git commit --amend -m 'x'",
    "git filter-branch --tree-filter true HEAD",
    "git filter-repo --path x",
    "git update-ref refs/heads/main abc123",
    "git reflog delete HEAD@{0}",
    "git branch -D main",
    "git worktree remove --force ../wt",
    "gh pr merge 12 --squash",
    "gh pr ready 12",
    "gh pr create --title x --body y",
    "gh api --method DELETE /repos/o/r",
    "gh api -X PATCH /repos/o/r",
    "tofu apply -auto-approve",
    "tofu destroy",
    "terraform apply",
    "terraform destroy -auto-approve",
    "opentofu apply",
    "alembic upgrade head",
    "alembic downgrade -1",
    "ssh operator@10.0.0.5",
    "scp file operator@host:/tmp",
    "secpctl bootstrap --write --confirm",
    "secp-discovery-activation install --write --confirm",
    # Chaining and substitution must not smuggle a denied verb past the guard.
    "echo hello && git push --force",
    "true; git push origin main",
    "echo a | git push -f",
    "$(git push --force)",
    "cp t.json $LOCALAPPDATA/secp-migration-unlock/t.json",
    "rm -rf ~/.local/state/secp-migration-unlock",
    # A denied verb must not be reachable by dressing it up in a wrapper or a nested shell.
    "GIT_DIR=/x git push --force",
    "env GIT_DIR=/x git push --force",
    "sudo git push --force",
    "xargs git push --force",
    "echo x | xargs -n1 git push -f",
    'sh -c "git push --force"',
    'bash -lc "git push origin main"',
    'sh -c "tofu apply"',
    'bash -c "gh pr merge 12"',
    "git -C /repo push --force",
    "git -c user.name=x push --force",
    "git push --force-with-lease=refs/heads/main",
]


@pytest.mark.parametrize("command", DENIED_COMMANDS)
def test_guard_bash_denies_hard_boundary(command: str) -> None:
    result = run_hook("guard_bash.py", bash(command))
    assert decision_of(result) == "deny", f"expected deny for: {command}"
    reason = result["hookSpecificOutput"]["permissionDecisionReason"]
    assert reason.startswith("BLOCKED:"), "denial must explain itself to the agent"


ALLOWED_COMMANDS = [
    "git status --porcelain",
    "git log --oneline -5",
    "git diff HEAD",
    "git add -A",
    "git commit -m 'SECP: add guardrails'",
    "git push -u origin feature/secp-program-orchestration-foundation",
    "git push origin feature/x",
    "git checkout -b feature/y",
    "git worktree add ../wt feature/y",
    "gh pr create --draft --title x --body y",
    "gh pr view 12",
    "gh run list --branch main",
    "gh api /repos/o/r",
    "uv run pytest tests/program -q",
    "uv run ruff check tests scripts",
    "tofu plan",
    "terraform validate",
    "docker compose config",
    # Quoted text that merely MENTIONS a denied verb must not be denied. Splitting inside a
    # quoted string would block ordinary commits and searches, and under bypassPermissions
    # there is no human to appeal a wrong denial to.
    'git commit -m "docs: never git push --force"',
    'git commit -m "handle a && b correctly"',
    "git commit -m 'add guard for gh pr merge'",
    'grep -rn "git push --force" .claude',
    'echo "tofu apply is denied"',
    # Unwrapping must not turn benign wrapped commands into denials.
    "timeout 60 docker info",
    'sh -c "echo hello"',
    "env FOO=bar uv run pytest tests/program -q",
]


@pytest.mark.parametrize("command", ALLOWED_COMMANDS)
def test_guard_bash_allows_ordinary_work(command: str) -> None:
    result = run_hook("guard_bash.py", bash(command))
    assert decision_of(result) == "allow", f"guard over-denied ordinary work: {command}"


def test_guard_bash_ignores_non_bash_payload() -> None:
    assert run_hook("guard_bash.py", {"tool_name": "Read", "tool_input": {}}) is None


# ---------------------------------------------------------------------------------------
# guard_writes: unconditional protected paths (branch-independent)
# ---------------------------------------------------------------------------------------

ALWAYS_DENIED_PATHS = [
    ".github/workflows/ci.yml",
    ".github/dependabot.yml",
    "infra/ci/attest_trusted_ancestry.py",
    "apps/management/secp_management/production.py",
    "apps/management/secp_management/signing.py",
    ".env",
    "certs/server.pem",
    "certs/server.key",
]


@pytest.mark.parametrize("path", ALWAYS_DENIED_PATHS)
def test_guard_writes_denies_protected_path(path: str) -> None:
    result = run_hook("guard_writes.py", write(path))
    assert decision_of(result) == "deny", f"expected deny for: {path}"


ALWAYS_ALLOWED_PATHS = [
    "tests/program/test_program_hooks.py",
    "CLAUDE.md",
    ".claude/settings.json",
    ".claude/rules/00-core.md",
    "docs/program/FILE_OWNERSHIP.md",
    "scripts/program/Start-ProgramLead.ps1",
]


@pytest.mark.parametrize("path", ALWAYS_ALLOWED_PATHS)
def test_guard_writes_allows_program_spine_paths(path: str) -> None:
    result = run_hook("guard_writes.py", write(path))
    assert decision_of(result) == "allow", f"guard over-denied: {path}"


EQUIVALENT_PROTECTED_SPELLINGS = [
    "apps/api/../../.github/workflows/ci.yml",
    "./.github/workflows/ci.yml",
    str(REPO_ROOT / ".github" / "workflows" / "ci.yml"),
]


@pytest.mark.parametrize("path", EQUIVALENT_PROTECTED_SPELLINGS)
def test_guard_writes_normalises_before_matching(path: str) -> None:
    """Traversal, `./` prefixes and absolute forms must all resolve to the same rule."""
    assert decision_of(run_hook("guard_writes.py", write(path))) == "deny", (
        f"path normalisation failed for: {path}"
    )


def test_guard_writes_denies_unlock_directory_manipulation() -> None:
    result = run_hook("guard_writes.py", write("/tmp/secp-migration-unlock/forged.json"))
    assert decision_of(result) == "deny"


def test_program_branch_predicate_recognises_foundation_branches() -> None:
    module = load_hook_module("guard_writes")
    for branch in (
        "feature/secp-program-orchestration-foundation",
        "feature/secp-program-spine",
        "chore/program-orchestration-tidy",
    ):
        assert module._is_program_branch(branch) is True, branch
    for branch in ("main", "feature/secp-pr6-provisioning", "fix/oidc-clock-skew"):
        assert module._is_program_branch(branch) is False, branch


def test_seal_literals_are_scoped_to_product_source() -> None:
    """Doctrine documents must be able to NAME a seal without tripping the guard."""
    module = load_hook_module("guard_writes")
    assert module.matches_any("apps/worker/secp_worker/x.py", module.SEAL_SCOPE_GLOBS) is not None
    assert module.matches_any("docs/program/SAFETY_INVARIANTS.md", module.SEAL_SCOPE_GLOBS) is None
    assert module.matches_any(".claude/rules/11-worker-plane.md", module.SEAL_SCOPE_GLOBS) is None


def test_append_only_record_rejects_line_removal(tmp_path: Path) -> None:
    module = load_hook_module("guard_writes")
    assert "docs/program/SAFETY_INVARIANTS.md" in module.APPEND_ONLY
    invariants = REPO_ROOT / "docs" / "program" / "SAFETY_INVARIANTS.md"
    assert invariants.is_file()
    first_real_line = next(
        line for line in invariants.read_text(encoding="utf-8").splitlines() if line.strip()
    )
    result = run_hook(
        "guard_writes.py",
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "docs/program/SAFETY_INVARIANTS.md",
                "old_string": first_real_line,
                "new_string": "",
            },
        },
    )
    assert decision_of(result) == "deny"
    assert "append-only" in result["hookSpecificOutput"]["permissionDecisionReason"]


# ---------------------------------------------------------------------------------------
# guard_migration_unlock: every failure mode
# ---------------------------------------------------------------------------------------

MIGRATION_TARGET = "apps/api/migrations/versions/zz99_program_spine_probe.py"


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(REPO_ROOT), capture_output=True, text=True, check=False
    ).stdout.strip()


def _valid_token(**overrides: object) -> dict:
    now = datetime.now(UTC)
    token = {
        "version": 1,
        "repository": str(REPO_ROOT),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "base_sha": _git("rev-parse", "HEAD"),
        "migration_filename": Path(MIGRATION_TARGET).name,
        "purpose": "program spine hook test",
        "issuer": "test",
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce": "0123456789abcdef",
    }
    token.update(overrides)
    return token


def _run_unlock(tmp_path: Path, tokens: list[dict] | None, target: str = MIGRATION_TARGET):
    unlock_dir = tmp_path / "unlock"
    if tokens is not None:
        unlock_dir.mkdir(parents=True, exist_ok=True)
        for index, token in enumerate(tokens):
            (unlock_dir / f"unlock-{index}.json").write_text(json.dumps(token), encoding="utf-8")
    return run_hook(
        "guard_migration_unlock.py",
        write(target),
        env={"SECP_MIGRATION_UNLOCK_DIR": str(unlock_dir)},
    )


def test_unlock_missing_directory_denies(tmp_path: Path) -> None:
    assert decision_of(_run_unlock(tmp_path, None)) == "deny"


def test_unlock_no_token_denies(tmp_path: Path) -> None:
    (tmp_path / "unlock").mkdir()
    assert decision_of(_run_unlock(tmp_path, [])) == "deny"


def test_unlock_duplicate_tokens_deny(tmp_path: Path) -> None:
    result = _run_unlock(tmp_path, [_valid_token(), _valid_token(nonce="ff")])
    assert decision_of(result) == "deny"
    assert "ambiguous" in result["hookSpecificOutput"]["permissionDecisionReason"]


def test_unlock_malformed_token_denies(tmp_path: Path) -> None:
    unlock_dir = tmp_path / "unlock"
    unlock_dir.mkdir()
    (unlock_dir / "unlock-0.json").write_text("{not json", encoding="utf-8")
    result = run_hook(
        "guard_migration_unlock.py",
        write(MIGRATION_TARGET),
        env={"SECP_MIGRATION_UNLOCK_DIR": str(unlock_dir)},
    )
    assert decision_of(result) == "deny"


def test_unlock_missing_field_denies(tmp_path: Path) -> None:
    token = _valid_token()
    del token["base_sha"]
    assert decision_of(_run_unlock(tmp_path, [token])) == "deny"


def test_unlock_extra_field_denies_because_tokens_carry_no_secrets(tmp_path: Path) -> None:
    token = _valid_token()
    token["database_url"] = "postgresql://user:pw@host/db"
    result = _run_unlock(tmp_path, [token])
    assert decision_of(result) == "deny"
    assert "secret" in result["hookSpecificOutput"]["permissionDecisionReason"]


def test_unlock_expired_token_denies(tmp_path: Path) -> None:
    past = datetime.now(UTC) - timedelta(minutes=90)
    token = _valid_token(
        issued_at=past.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=(past + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    result = _run_unlock(tmp_path, [token])
    assert decision_of(result) == "deny"
    assert "expired" in result["hookSpecificOutput"]["permissionDecisionReason"]


def test_unlock_ttl_over_sixty_minutes_denies(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    token = _valid_token(
        issued_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=(now + timedelta(minutes=61)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    assert decision_of(_run_unlock(tmp_path, [token])) == "deny"


def test_unlock_wrong_branch_denies(tmp_path: Path) -> None:
    result = _run_unlock(tmp_path, [_valid_token(branch="some/other-branch")])
    assert decision_of(result) == "deny"
    assert "branch" in result["hookSpecificOutput"]["permissionDecisionReason"]


def test_unlock_wrong_repository_denies(tmp_path: Path) -> None:
    result = _run_unlock(tmp_path, [_valid_token(repository=str(tmp_path))])
    assert decision_of(result) == "deny"


def test_unlock_wrong_migration_filename_denies(tmp_path: Path) -> None:
    result = _run_unlock(tmp_path, [_valid_token(migration_filename="other_migration.py")])
    assert decision_of(result) == "deny"
    assert "another" in result["hookSpecificOutput"]["permissionDecisionReason"]


def test_unlock_unknown_base_sha_denies(tmp_path: Path) -> None:
    result = _run_unlock(tmp_path, [_valid_token(base_sha="0" * 40)])
    assert decision_of(result) == "deny"


def test_unlock_accepts_an_ancestor_base_sha(tmp_path: Path) -> None:
    """HEAD advances as the agent commits, so an ancestor base must stay valid."""
    ancestor = _git("rev-parse", "HEAD~1")
    if not ancestor:
        pytest.skip("no parent commit available")
    result = _run_unlock(tmp_path, [_valid_token(base_sha=ancestor)])
    assert decision_of(result) == "allow"


def test_unlock_rejects_a_base_sha_that_is_not_an_ancestor(tmp_path: Path) -> None:
    """`merge-base --is-ancestor` signals via exit code and prints nothing.

    Regression guard: reading its stdout made this check vacuous, so a token bound to an
    unrelated commit was accepted as though it pinned the real base.
    """
    candidates = _git("rev-list", "--all", "--max-count=400").splitlines()
    foreign = next(
        (
            sha
            for sha in candidates
            if sha
            and subprocess.run(
                ["git", "merge-base", "--is-ancestor", sha, "HEAD"],
                cwd=str(REPO_ROOT),
                capture_output=True,
                check=False,
            ).returncode
            != 0
        ),
        None,
    )
    if foreign is None:
        pytest.skip("no non-ancestor commit reachable in this checkout")
    result = _run_unlock(tmp_path, [_valid_token(base_sha=foreign)])
    assert decision_of(result) == "deny", (
        f"a token bound to non-ancestor {foreign[:12]} must not authorise a write"
    )


def test_unlock_valid_token_is_consumed_exactly_once(tmp_path: Path) -> None:
    unlock_dir = tmp_path / "unlock"
    unlock_dir.mkdir()
    (unlock_dir / "unlock-0.json").write_text(json.dumps(_valid_token()), encoding="utf-8")

    first = run_hook(
        "guard_migration_unlock.py",
        write(MIGRATION_TARGET),
        env={"SECP_MIGRATION_UNLOCK_DIR": str(unlock_dir)},
    )
    assert decision_of(first) == "allow", "a valid token must authorise the write"
    assert not (unlock_dir / "unlock-0.json").exists()
    assert (unlock_dir / "unlock-0.json.consumed").exists()

    second = run_hook(
        "guard_migration_unlock.py",
        write(MIGRATION_TARGET),
        env={"SECP_MIGRATION_UNLOCK_DIR": str(unlock_dir)},
    )
    assert decision_of(second) == "deny", "a consumed token must never authorise a second write"


def test_unlock_accepts_a_bom_prefixed_token(tmp_path: Path) -> None:
    """Windows PowerShell writes UTF-8 with a BOM; a strict UTF-8 read would reject it.

    Regression guard for a real minter/hook incompatibility found by an end-to-end run.
    """
    unlock_dir = tmp_path / "unlock"
    unlock_dir.mkdir()
    (unlock_dir / "unlock-0.json").write_text(json.dumps(_valid_token()), encoding="utf-8-sig")
    result = run_hook(
        "guard_migration_unlock.py",
        write(MIGRATION_TARGET),
        env={"SECP_MIGRATION_UNLOCK_DIR": str(unlock_dir)},
    )
    assert decision_of(result) == "allow", (
        "a BOM-prefixed token minted by Windows PowerShell must still be readable"
    )


def test_unlock_ignores_non_migration_paths(tmp_path: Path) -> None:
    assert _run_unlock(tmp_path, None, target="tests/program/test_program_hooks.py") is None


# ---------------------------------------------------------------------------------------
# Orientation and idle/completion guards
# ---------------------------------------------------------------------------------------


def test_session_start_reports_observed_state_and_head() -> None:
    result = run_hook("session_start_orient.py", {"hook_event_name": "SessionStart"})
    context = result["hookSpecificOutput"]["additionalContext"]
    assert "SECP observed state" in context
    assert "HEAD:" in context
    assert "authoritative" in context


def test_session_start_computes_alembic_head_from_files_not_from_docs() -> None:
    module = load_hook_module("session_start_orient")
    heads = module.alembic_heads(REPO_ROOT)
    assert len(heads) == 1, f"expected exactly one Alembic head, found {heads}"
    # The head is computed, never quoted from a document.
    status_text = (REPO_ROOT / "docs" / "STATUS.md").read_text(encoding="utf-8", errors="replace")
    if heads[0] not in status_text:
        pytest.skip(f"docs/STATUS.md is behind the real head {heads[0]} (known drift)")


def test_teammate_idle_blocks_when_work_is_uncommitted() -> None:
    dirty = _git("status", "--porcelain")
    result = run_hook("guard_teammate_idle.py", {"hook_event_name": "TeammateIdle"})
    if dirty.strip():
        assert decision_of(result) == "block"
        assert "uncommitted" in result["reason"]
    else:
        assert decision_of(result) == "allow"


def test_task_completion_requires_evidence_when_tree_is_dirty(tmp_path: Path) -> None:
    dirty = _git("status", "--porcelain")
    if not dirty.strip():
        pytest.skip("working tree is clean; the evidence gate does not apply")
    result = run_hook(
        "guard_task_completion.py",
        {"hook_event_name": "TaskCompleted", "session_id": "program-spine-test-no-evidence"},
    )
    assert decision_of(result) == "block"
    assert "validation" in result["reason"]
