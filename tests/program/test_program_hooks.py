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
    # Control flow and grouping leave a keyword or bracket as the head token.
    "if true; then git push --force origin feat; fi",
    "for r in origin; do git push --force $r feat; done",
    "while read x; do git push --force origin feat; done",
    "(git push --force origin feat)",
    "{ git push --force origin feat; }",
    # A leading '+' forces the push with or without an explicit source:destination.
    "git push origin +main",
    "git push origin +feature/x",
    "git push origin +refs/heads/main",
    # gh global flags must not shift the subcommand index.
    "gh -R owner/repo pr merge 123 --squash",
    "gh --repo owner/repo pr ready 123",
    # gh api sends POST implicitly when a field flag is present.
    "gh api graphql -f query='mutation { m }'",
    "gh api repos/o/r/pulls -f title=x -f head=y -f base=main",
    "gh api --input body.json repos/o/r/pulls",
    # Alembic is reachable through uv, poetry, docker compose run, or an explicit -c.
    "alembic -c alembic.ini upgrade head",
    "uv run alembic upgrade head",
    "poetry run alembic downgrade -1",
    "docker compose run --rm api alembic upgrade head",
    # PowerShell indirection.
    "Invoke-Expression 'git push --force origin feat'",
    "Start-Process git -ArgumentList 'push','--force'",
    # Shell write channels reach protected paths without any editing tool.
    "echo 'on: push' > .github/workflows/ci.yml",
    "printf 'x' >> infra/ci/attest_trusted_ancestry.py",
    "sed -i 's/a/b/' .github/workflows/ci.yml",
    "cp /tmp/ci.yml .github/workflows/ci.yml",
    "rm .github/workflows/ci.yml",
    "git checkout main -- .github/workflows/ci.yml",
    "git restore --source=main .github/workflows/ci.yml",
    "cat > apps/management/secp_management/production.py",
    "tee .github/workflows/ci.yml",
    "python -c \"open('.github/workflows/ci.yml','w').write('x')\"",
    "Set-Content .github/workflows/ci.yml 'x'",
    "Remove-Item .github/workflows/ci.yml",
    # A shell write cannot present an unlock token.
    "echo x > apps/api/migrations/versions/zz_new.py",
    # The append-only record has no shell exemption: a shell write cannot be shown to be
    # an append, so every form is refused.
    "echo '' > docs/program/SAFETY_INVARIANTS.md",
    "sed -i '1,50d' docs/program/SAFETY_INVARIANTS.md",
    "truncate -s 0 docs/program/SAFETY_INVARIANTS.md",
    "rm docs/program/SAFETY_INVARIANTS.md",
    "cp /tmp/short.md docs/program/SAFETY_INVARIANTS.md",
    # Write verbs and redirection forms that no target-extraction heuristic would catch.
    # The mention scan covers them without needing to model each one.
    "dd of=.github/workflows/ci.yml if=/dev/zero",
    "tar -xf payload.tar -C .github",
    "unzip -o payload.zip -d .github",
    "find .github -name ci.yml -delete",
    "echo x >| .github/workflows/ci.yml",
    "exec 3> .github/workflows/ci.yml",
    'echo x > "$(pwd)/.github/workflows/ci.yml"',
    "echo .github/workflows/ci.yml | xargs rm",
    "busybox rm .github/workflows/ci.yml",
    "vim -es -c 'wq' .github/workflows/ci.yml",
    "rsync -a /tmp/x .github/workflows/ci.yml",
    "python scripts/validate_ci.py .github/workflows/ci.yml",
    # Content-bearing writes whose target is not on the command line at all.
    "git apply /tmp/ci.diff",
    "patch -p1 < /tmp/ci.diff",
    # Writers that a naive reader-classification waves through.
    "sed --in-place 's/a/b/' .github/workflows/ci.yml",
    "sed --in-place=.bak 's/a/b/' .github/workflows/ci.yml",
    "python -m pip install --target .github/workflows somepkg",
    "python -m venv .github/venv",
    "find . -name x -fprint .github/workflows/ci.yml",
    # A wildcard target that could match a protected path.
    "echo x > .git*/workflows/ci.yml",
    "echo x > .gi*hub/workflows/ci.yml",
    "cp /tmp/x .git?ub/workflows/ci.yml",
    # A protected directory named as a destination, not as a file.
    "rm -rf .github",
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
    # Branch-specific push shapes are covered by the C1 matrix below, which resolves the
    # current branch at runtime; a hardcoded name here would be wrong on CI's detached HEAD.
    "git push",
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
    # Writes to ordinary paths must stay untouched by the shell write-channel guard.
    "echo x > notes.txt",
    "cp a.txt b.txt",
    "rm build/artifact.tar",
    "python -c \"open('notes.txt','w').write('x')\"",
    "python scripts/ci/pytest_shards.py verify --collect",
    "git checkout -- tests/program/test_program_hooks.py",
    # --draft=true is valid pflag syntax and must not be treated as a missing --draft.
    "gh pr create --draft=true --title x --body y",
    # Read-only gh api calls, including an explicit GET with fields.
    "gh api repos/o/r --method GET",
    # Merely MENTIONING the unlock directory is not touching it.
    "git log --grep=secp-migration-unlock",
    'grep -rn "secp-migration-unlock" docs/program',
    # rsync is only a host-contact risk when it actually targets a remote.
    "rsync -a build/ dist/",
    # The project's OWN validation loop must not be blocked. Interpreter positionals are
    # not evidence of a write; treating them as such denied every direct pytest/mypy run
    # on a program branch, where apps/** is fenced.
    "python -m pytest apps/api/tests -q",
    "python -m pytest apps/api/tests/test_migrations.py -q",
    "python -m mypy apps/api",
    "python -m ruff check apps/api",
    # A quoted dotted string in inline code is not key material.
    "python -c \"print(cfg['db.key'])\"",
    # Reading an operator-owned path is ordinary work; only writing it is denied.
    "cat .github/workflows/ci.yml",
    "grep -rn jobs .github/workflows",
    "git log --oneline -- .github",
    "git diff HEAD -- .github/workflows/ci.yml",
    "ls .github/workflows",
    "git log -1 -- docs/program/SAFETY_INVARIANTS.md",
    # The mention scan is PER SEGMENT. A command-global rule let one unrelated writer
    # poison every other segment -- including the exact workflow for landing a
    # safety-invariant entry (append, stage, commit, push).
    "git add docs/program/SAFETY_INVARIANTS.md && git commit -m 'docs: x' && git push",
    "git commit -m 'ci: note .github/workflows/ci.yml change' && git push",
    "cd .github/workflows && ls",
    "cd apps/api/migrations/versions && ls -la",
    "ls apps/api/migrations/versions/ && python -m alembic heads",
    # A writer whose own targets are all unprotected may name a protected path.
    "grep -c runs-on .github/workflows/ci.yml > /tmp/count.txt",
    "cat .github/workflows/ci.yml | head -40 > /tmp/ci-head.yml",
    # find -exec running a reader is still a read.
    "find .github -name '*.yml' -exec grep -l runs-on {} ;",
    # git read subcommands beyond the obvious ones.
    "git check-ignore .github/workflows/ci.yml",
    "git show-ref --verify refs/heads/main && cat .github/workflows/ci.yml",
    # `->` in a quoted pattern is not a redirection.
    'grep -n "a->b" .github/workflows/ci.yml',
    'rg -n "->" .github/',
]


@pytest.mark.parametrize("command", ALLOWED_COMMANDS)
def test_guard_bash_allows_ordinary_work(command: str) -> None:
    result = run_hook("guard_bash.py", bash(command))
    assert decision_of(result) == "allow", f"guard over-denied ordinary work: {command}"


HOOK_SCRIPTS = sorted(p.name for p in HOOKS_DIR.glob("*.py") if p.name != "_common.py")


@pytest.mark.parametrize("hook", HOOK_SCRIPTS)
def test_hook_module_imports_cleanly(hook: str) -> None:
    """An import-time error silently DISABLES a guard, and `guard()` cannot catch it.

    A module-level failure happens before the fail-closed wrapper exists, so the process
    exits non-zero with empty stdout -- which the client treats as non-blocking rather than
    as a denial. This is the one failure mode where a broken guard looks exactly like an
    absent one, so it is asserted directly.
    """
    completed = subprocess.run(
        [sys.executable, "-c", f"import runpy; runpy.run_path(r'{HOOKS_DIR / hook}')"],
        input="{}",
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(REPO_ROOT),
        check=False,
    )
    assert "NameError" not in completed.stderr, f"{hook} has an import-time NameError"
    assert "ImportError" not in completed.stderr, f"{hook} has an import-time ImportError"
    assert "SyntaxError" not in completed.stderr, f"{hook} has a SyntaxError"
    assert completed.returncode == 0, (
        f"{hook} exited {completed.returncode}; a non-zero exit with empty stdout is treated "
        f"as non-blocking, so the guard would be silently disabled. stderr: {completed.stderr}"
    )


# ---------------------------------------------------------------------------------------
# C1: an agent may push ONLY the branch it is working on.
#
# Denying force and protected destinations is not sufficient: `git push --all origin` and
# `git push origin some-other-feature` are ordinary fast-forwards to non-protected refs,
# and both push work the agent was never assigned.
# ---------------------------------------------------------------------------------------


def _current_branch() -> str:
    return _git("rev-parse", "--abbrev-ref", "HEAD")


def test_push_of_the_current_branch_is_permitted() -> None:
    branch = _current_branch()
    if branch.lower() in {"main", "master", "head"}:
        pytest.skip(f"checkout is on {branch!r}; every push is denied by design")
    for command in (
        "git push",
        "git push origin",
        f"git push origin {branch}",
        f"git push -u origin {branch}",
        f"git push --set-upstream origin {branch}",
        f"git push origin HEAD:{branch}",
        f"git push origin {branch}:{branch}",
        f"git push origin refs/heads/{branch}",
    ):
        assert decision_of(run_hook("guard_bash.py", bash(command))) == "allow", command


def test_push_outside_the_current_branch_is_denied() -> None:
    branch = _current_branch()
    if branch.lower() in {"main", "master", "head"}:
        pytest.skip(f"checkout is on {branch!r}; every push is denied by design")
    denied = [
        "git push --all origin",
        "git push --mirror origin",
        "git push --prune origin",
        "git push --tags origin",
        "git push --delete origin feature/x",
        "git push origin some-other-feature",
        "git push origin feature/unrelated-work",
        f"git push origin {branch}:some-other-feature",
        "git push origin main",
        "git push origin master",
        f"git push origin {branch}:main",
        "git push origin refs/heads/main",
        "git push origin HEAD",
        "git push origin @",
        "git push --force origin " + branch,
        "git push -f origin " + branch,
        f"git push origin +{branch}",
    ]
    for command in denied:
        result = run_hook("guard_bash.py", bash(command))
        assert decision_of(result) == "deny", f"expected deny for: {command}"


def test_guard_bash_ignores_non_shell_payload() -> None:
    assert run_hook("guard_bash.py", {"tool_name": "Read", "tool_input": {}}) is None


UNREADABLE_SHELL_PAYLOADS = [
    {},
    {"tool_name": "Bash"},
    {"tool_name": "Bash", "tool_input": "git push --force"},
    {"tool_name": "Bash", "tool_input": {"cmd": "git push --force"}},
    {"tool_name": "PowerShell", "tool_input": {"command": "   "}},
]


@pytest.mark.parametrize("payload", UNREADABLE_SHELL_PAYLOADS)
def test_guard_bash_fails_closed_on_unreadable_shell_payload(payload: dict) -> None:
    """`guard()` only fails closed on exceptions; an early return would ALLOW.

    A shell call this guard cannot read is a shell call it cannot clear.
    """
    assert decision_of(run_hook("guard_bash.py", payload)) == "deny", (
        f"unreadable shell payload must not be allowed: {payload}"
    )


def test_data_heredoc_content_is_not_treated_as_a_command() -> None:
    """Writing a file whose CONTENT names a protected path is ordinary work.

    A commit message describing these guards, or a doc quoting a workflow path, must not be
    refused as though the command targeted that path.
    """
    command = (
        "cat > /tmp/msg.txt <<'EOF'\n"
        "see .github/workflows/ci.yml for details\n"
        "grep -c runs-on .github/workflows/ci.yml > /tmp/n\n"
        "EOF"
    )
    assert decision_of(run_hook("guard_bash.py", bash(command))) == "allow"


def test_heredoc_does_not_disarm_a_real_write() -> None:
    command = "cat > .github/workflows/ci.yml <<'EOF'\nhello\nEOF"
    assert decision_of(run_hook("guard_bash.py", bash(command))) == "deny"


def test_interpreter_heredoc_body_is_still_code() -> None:
    """A body fed to an interpreter is code, not data, and stays in scope."""
    command = "python - <<'PY'\nopen('.github/workflows/ci.yml','w').write('x')\nPY"
    assert decision_of(run_hook("guard_bash.py", bash(command))) == "deny"


def test_guard_bash_covers_powershell_tool_payloads() -> None:
    """The matcher covers PowerShell; the guard must evaluate its payloads identically."""
    result = run_hook(
        "guard_bash.py",
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "PowerShell",
            "tool_input": {"command": "git push --force origin feat"},
        },
    )
    assert decision_of(result) == "deny"


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
    # fnmatch has no `**` semantics, so `**/*.pem` never matched a repo-root file.
    # Secrets are matched on basename instead, at every depth.
    "server.pem",
    "signing.key",
    ".env.production",
    ".env.local",
    "apps/api/.env",
    "nested/deep/private.key",
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
    module = load_hook_module("_common")
    for branch in (
        "feature/secp-program-orchestration-foundation",
        "feature/secp-program-spine",
        "chore/program-orchestration-tidy",
    ):
        assert module.is_program_branch(branch) is True, branch
    for branch in ("main", "feature/secp-pr6-provisioning", "fix/oidc-clock-skew"):
        assert module.is_program_branch(branch) is False, branch


# ---------------------------------------------------------------------------------------
# Non-program-branch policy.
#
# Every subprocess test above runs on whatever branch the checkout is on, which today is a
# program-foundation branch. That is NOT the state this guard spends most of its life in:
# the moment PR 1 merges, ordinary work happens on feature branches where the broad
# product-source fence is absent. These exercise the policy functions directly so both
# branch states are covered regardless of the checkout.
# ---------------------------------------------------------------------------------------

FEATURE_BRANCH = "feature/secp-pr6-provisioning"
PROGRAM_BRANCH = "feature/secp-program-orchestration-foundation"

ABSOLUTE_ON_EVERY_BRANCH = [
    ".github/workflows/ci.yml",
    "infra/ci/attest_trusted_ancestry.py",
    "apps/management/secp_management/production.py",
    "apps/management/secp_management/signing.py",
    ".env",
    ".env.production",
    "server.pem",
    "apps/api/signing.key",
]


@pytest.mark.parametrize("rel_path", ABSOLUTE_ON_EVERY_BRANCH)
@pytest.mark.parametrize("branch", [FEATURE_BRANCH, PROGRAM_BRANCH])
def test_absolute_protections_hold_on_every_branch(rel_path: str, branch: str) -> None:
    module = load_hook_module("_common")
    assert module.protected_write_reason(rel_path, branch) is not None, (
        f"{rel_path} must be protected on {branch}"
    )


ORDINARY_PRODUCT_WORK = [
    "apps/api/secp_api/routers/scoring.py",
    "apps/worker/secp_worker/main.py",
    "apps/web/src/api/client.ts",
    "plugins/proxmox/secp_plugin_proxmox/plugin.py",
    "contracts/plugin-api/secp_plugin_api/v1/__init__.py",
    "docs/STATUS.md",
    "docs/adr/ADR-029-scoring.md",
    "infra/dev/docker-compose.yml",
]


@pytest.mark.parametrize("rel_path", ORDINARY_PRODUCT_WORK)
def test_product_work_is_permitted_on_a_feature_branch(rel_path: str) -> None:
    """After this PR merges, product work is the normal case and must not be fenced."""
    module = load_hook_module("_common")
    assert module.protected_write_reason(rel_path, FEATURE_BRANCH) is None, (
        f"{rel_path} must be writable on an ordinary feature branch"
    )


@pytest.mark.parametrize("rel_path", ORDINARY_PRODUCT_WORK)
def test_product_work_is_fenced_on_a_program_branch(rel_path: str) -> None:
    module = load_hook_module("_common")
    assert module.protected_write_reason(rel_path, PROGRAM_BRANCH) is not None, (
        f"{rel_path} must be fenced on a program-foundation branch"
    )


def test_append_only_and_migrations_are_shell_only_protections() -> None:
    """The editing tools must still be able to append; only the shell is refused outright."""
    module = load_hook_module("_common")
    for rel_path in (
        "docs/program/SAFETY_INVARIANTS.md",
        "apps/api/migrations/versions/zz_new.py",
    ):
        assert module.absolute_protection_reason(rel_path, shell=True) is not None
        assert module.absolute_protection_reason(rel_path, shell=False) is None, (
            f"{rel_path} must remain reachable by the editing tools, which can verify the edit"
        )


READER_SEGMENTS = [
    "cat README.md",
    "grep -rn secp docs",
    "ls apps/api",
    "git log --oneline -5",
    "git diff HEAD",
    "git show HEAD",
    "git status --porcelain",
    "git rev-parse HEAD",
    "git ls-files apps",
    "python -m pytest tests -q",
    "python -m mypy apps/api",
    "find docs -name '*.md'",
    "sed -n '1,10p' README.md",
]

WRITER_SEGMENTS = [
    "echo x > file.txt",
    "cp a b",
    "rm file.txt",
    "sed -i s/a/b/ file.txt",
    "find docs -name '*.md' -delete",
    "git checkout main -- file.txt",
    "python script.py",
    "tar -xf p.tar -C dir",
    "dd of=file.txt",
]


@pytest.mark.parametrize("segment", READER_SEGMENTS)
def test_reader_classification_recognises_read_only_work(segment: str) -> None:
    module = load_hook_module("guard_bash")
    assert module._is_reader(module._unwrap(module.tokenize(segment))) is True, segment


@pytest.mark.parametrize("segment", WRITER_SEGMENTS)
def test_reader_classification_recognises_writers(segment: str) -> None:
    module = load_hook_module("guard_bash")
    assert module._is_reader(module._unwrap(module.tokenize(segment))) is False, segment


def test_multiedit_cannot_bypass_the_append_only_record() -> None:
    """MultiEdit carries its pairs in `edits`; reading only top-level keys let it through."""
    invariants = REPO_ROOT / "docs" / "program" / "SAFETY_INVARIANTS.md"
    first_real_line = next(
        line for line in invariants.read_text(encoding="utf-8").splitlines() if line.strip()
    )
    result = run_hook(
        "guard_writes.py",
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "MultiEdit",
            "tool_input": {
                "file_path": "docs/program/SAFETY_INVARIANTS.md",
                "edits": [{"old_string": first_real_line, "new_string": ""}],
            },
        },
    )
    assert decision_of(result) == "deny"
    assert "append-only" in result["hookSpecificOutput"]["permissionDecisionReason"]


def test_seal_check_denies_a_change_but_permits_a_mention() -> None:
    """Denying on PRESENCE refused pure appends that merely quote a seal name.

    `_B1A_SUBPROCESS_SEALED` alone appears in dozens of files, so that false-deny was
    broad enough to push agents into routing around the guards entirely.
    """
    module = load_hook_module("guard_writes")
    unchanged = {
        "file_path": "apps/api/tests/t.py",
        "old_string": "assert x._B1A_SUBPROCESS_SEALED is True\n",
        "new_string": "assert x._B1A_SUBPROCESS_SEALED is True\nassert y\n",
    }
    module._check_seal_literals("apps/api/tests/t.py", REPO_ROOT, unchanged)  # must not raise

    for changing in (
        {
            "file_path": "apps/api/tests/t.py",
            "old_string": "assert x._B1A_SUBPROCESS_SEALED is True\n",
            "new_string": "pass\n",
        },
        {
            "file_path": "apps/worker/secp_worker/x.py",
            "edits": [
                {"old_string": "_B1A_SUBPROCESS_SEALED = True", "new_string": "OTHER = True"}
            ],
        },
    ):
        with pytest.raises(SystemExit):
            module._check_seal_literals("apps/api/tests/t.py", REPO_ROOT, changing)


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


# ---------------------------------------------------------------------------------------
# Ancestry binding, proven HERMETICALLY.
#
# These previously derived an ancestor from HEAD~1 in the checkout under test, which made
# them depend on ancestry across a shallow PR merge boundary. GitHub Actions checks out with
# fetch-depth 1, where `git rev-parse HEAD~1` returns the literal string "HEAD~1" -- not a
# SHA and not empty -- so the token carried an unresolvable base and the hook correctly
# refused it. The guard was right; the test was not hermetic.
#
# A purpose-built temporary repository with real commits removes the dependency entirely.
# The real `git` and `git_succeeds` helpers run against it -- `merge-base --is-ancestor` is
# never mocked, because the defect these tests exist to catch was precisely that its exit
# code was being ignored.
# ---------------------------------------------------------------------------------------


class _HermeticRepo:
    """A throwaway git repository with a base commit, a child commit and an unrelated root."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._git("init", "--quiet")
        self._git("config", "user.email", "hermetic@secp.test")
        self._git("config", "user.name", "SECP Hermetic Test")
        self._git("config", "commit.gpgsign", "false")

        self._commit("base.txt", "base revision\n", "base revision")
        self.base_sha = self._git("rev-parse", "HEAD")

        self._commit("child.txt", "child revision\n", "child revision")
        self.head_sha = self._git("rev-parse", "HEAD")
        self.branch = self._git("rev-parse", "--abbrev-ref", "HEAD")

        # A second root commit: a real, complete object that is genuinely NOT an ancestor.
        self._git("checkout", "--quiet", "--orphan", "unrelated-line")
        self._commit("unrelated.txt", "unrelated\n", "unrelated root")
        self.unrelated_sha = self._git("rev-parse", "HEAD")
        self._git("checkout", "--quiet", self.branch)

    def _git(self, *args: str) -> str:
        completed = subprocess.run(
            ["git", *args], cwd=str(self.root), capture_output=True, text=True, check=False
        )
        assert completed.returncode == 0, f"git {' '.join(args)} failed: {completed.stderr}"
        return completed.stdout.strip()

    def _commit(self, name: str, body: str, message: str) -> None:
        (self.root / name).write_text(body, encoding="utf-8")
        self._git("add", "-A")
        self._git("commit", "--quiet", "-m", message)

    def token(self, base_sha: str, filename: str = "zz99_probe.py") -> dict:
        return {
            "version": 1,
            "repository": str(self.root),
            "branch": self.branch,
            "base_sha": base_sha,
            "migration_filename": filename,
            "purpose": "hermetic ancestry proof",
            "issuer": "test",
            "issued_at": "2026-07-30T12:00:00Z",
            "expires_at": "2026-07-30T12:30:00Z",
            "nonce": "0123456789abcdef",
        }


@pytest.fixture
def hermetic_repo(tmp_path: Path) -> _HermeticRepo:
    return _HermeticRepo(tmp_path / "hermetic-ancestry")


def _binding_verdict(repo: _HermeticRepo, base_sha: str) -> str:
    module = load_hook_module("guard_migration_unlock")
    try:
        module._validate_binding(repo.token(base_sha), repo.root, "zz99_probe.py")
    except SystemExit:
        return "deny"
    return "allow"


def test_hermetic_fixture_has_real_distinct_commits(hermetic_repo: _HermeticRepo) -> None:
    """The fixture must be sound before anything is concluded from it."""
    shas = {hermetic_repo.base_sha, hermetic_repo.head_sha, hermetic_repo.unrelated_sha}
    assert len(shas) == 3, f"expected three distinct commits, got {shas}"
    for sha in shas:
        assert len(sha) == 40, sha

    common = load_hook_module("_common")
    # Proves the real helper is being exercised, in both directions, against real git.
    assert (
        common.git_succeeds(
            hermetic_repo.root,
            "merge-base",
            "--is-ancestor",
            hermetic_repo.base_sha,
            hermetic_repo.head_sha,
        )
        is True
    )
    assert (
        common.git_succeeds(
            hermetic_repo.root,
            "merge-base",
            "--is-ancestor",
            hermetic_repo.unrelated_sha,
            hermetic_repo.head_sha,
        )
        is False
    )
    assert common.git(hermetic_repo.root, "cat-file", "-t", hermetic_repo.unrelated_sha) == "commit"


def test_unlock_accepts_an_ancestor_base_sha(hermetic_repo: _HermeticRepo) -> None:
    """HEAD advances as the agent commits, so an ancestor base must stay valid."""
    assert _binding_verdict(hermetic_repo, hermetic_repo.base_sha) == "allow"


def test_unlock_accepts_a_base_sha_equal_to_head(hermetic_repo: _HermeticRepo) -> None:
    assert _binding_verdict(hermetic_repo, hermetic_repo.head_sha) == "allow"


def test_unlock_rejects_a_base_sha_that_is_not_an_ancestor(hermetic_repo: _HermeticRepo) -> None:
    """`merge-base --is-ancestor` signals via exit code and prints nothing.

    Regression guard: reading its stdout made this check vacuous, so a token bound to an
    unrelated commit was accepted as though it pinned the real base. The unrelated commit
    here is a real, readable object -- so passing requires the ancestry check, not merely
    an object-existence check.
    """
    assert _binding_verdict(hermetic_repo, hermetic_repo.unrelated_sha) == "deny"


def test_unlock_rejects_a_base_sha_with_no_object(hermetic_repo: _HermeticRepo) -> None:
    assert _binding_verdict(hermetic_repo, "0" * 40) == "deny"


def test_unlock_valid_token_allows_and_burns_only_when_the_write_can_proceed(
    tmp_path: Path,
) -> None:
    """A valid token authorises the write; it is consumed only if the write can proceed.

    Both PreToolUse guards fire for the same call. On a program-foundation branch
    guard_writes denies migrations outright, so consuming here would burn a single-use
    operator approval on a call that wrote nothing.
    """
    module = load_hook_module("_common")
    on_program_branch = module.is_program_branch(_git("rev-parse", "--abbrev-ref", "HEAD"))

    unlock_dir = tmp_path / "unlock"
    unlock_dir.mkdir()
    (unlock_dir / "unlock-0.json").write_text(json.dumps(_valid_token()), encoding="utf-8")

    first = run_hook(
        "guard_migration_unlock.py",
        write(MIGRATION_TARGET),
        env={"SECP_MIGRATION_UNLOCK_DIR": str(unlock_dir)},
    )
    assert decision_of(first) == "allow", "a valid token must not be refused"

    if on_program_branch:
        assert (unlock_dir / "unlock-0.json").exists(), (
            "the token must NOT be burned when a sibling guard will deny the write anyway"
        )
        return

    assert not (unlock_dir / "unlock-0.json").exists()
    assert (unlock_dir / "unlock-0.json.consumed").exists()
    second = run_hook(
        "guard_migration_unlock.py",
        write(MIGRATION_TARGET),
        env={"SECP_MIGRATION_UNLOCK_DIR": str(unlock_dir)},
    )
    assert decision_of(second) == "deny", "a consumed token must never authorise a second write"


def test_unlock_consume_is_single_use(tmp_path: Path) -> None:
    """Direct test of the consumption primitive, independent of branch policy."""
    module = load_hook_module("guard_migration_unlock")
    token_path = tmp_path / "unlock-0.json"
    token_path.write_text(json.dumps(_valid_token()), encoding="utf-8")

    module._consume(token_path)
    assert not token_path.exists()
    assert token_path.with_suffix(token_path.suffix + ".consumed").exists()

    token_path.write_text(json.dumps(_valid_token()), encoding="utf-8")
    with pytest.raises(SystemExit):
        module._consume(token_path)


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


# ---------------------------------------------------------------------------------------
# C2: closed token freshness window, issued_at <= now < expires_at.
# `now` is injected so the boundaries are exact rather than timing-sensitive.
# ---------------------------------------------------------------------------------------


def _expiry_verdict(payload: dict, now: datetime) -> str:
    module = load_hook_module("guard_migration_unlock")
    try:
        module._validate_expiry(payload, now)
    except SystemExit:
        return "deny"
    return "allow"


ISSUED = datetime(2026, 7, 30, 12, 0, 0, tzinfo=UTC)
EXPIRES = ISSUED + timedelta(minutes=30)


def _timed_token(**overrides) -> dict:
    return _valid_token(
        issued_at=ISSUED.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=EXPIRES.strftime("%Y-%m-%dT%H:%M:%SZ"),
        **overrides,
    )


FRESHNESS_BOUNDARIES = [
    (ISSUED - timedelta(seconds=1), "deny", "a token stamped in the future is refused"),
    (ISSUED, "allow", "now == issued_at is inside the window"),
    (ISSUED + timedelta(minutes=15), "allow", "mid-window is inside the window"),
    (EXPIRES - timedelta(seconds=1), "allow", "just before expiry is inside the window"),
    (EXPIRES, "deny", "now == expires_at is outside the window"),
    (EXPIRES + timedelta(seconds=1), "deny", "after expiry is outside the window"),
]


@pytest.mark.parametrize("moment,expected,why", FRESHNESS_BOUNDARIES)
def test_token_freshness_window_is_closed(moment: datetime, expected: str, why: str) -> None:
    assert _expiry_verdict(_timed_token(), moment) == expected, why


def test_token_ttl_over_sixty_minutes_denies_at_any_moment() -> None:
    long_token = _valid_token(
        issued_at=ISSUED.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=(ISSUED + timedelta(minutes=61)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    assert _expiry_verdict(long_token, ISSUED + timedelta(minutes=1)) == "deny"


def test_future_issued_token_denies_end_to_end(tmp_path: Path) -> None:
    """The forward-dated case through the real hook, not only the helper."""
    future = datetime.now(UTC) + timedelta(minutes=20)
    token = _valid_token(
        issued_at=future.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=(future + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    result = _run_unlock(tmp_path, [token])
    assert decision_of(result) == "deny"
    assert "future" in result["hookSpecificOutput"]["permissionDecisionReason"]


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


def test_teammate_idle_does_not_infer_ownership_from_a_dirty_tree() -> None:
    """C3: a read-only teammate must be able to go idle while OTHERS' work is uncommitted.

    Inferring ownership from shared working-tree state is wrong in a shared checkout, and
    blocked read-only reviewers over the lead's changes twice during this PR's own review.
    """
    active_work = REPO_ROOT / "docs" / "program" / "ACTIVE_WORK.md"
    if active_work.is_file():
        pytest.skip("ACTIVE_WORK.md exists; contract-based enforcement is active (PR 2)")

    dirty = _git("status", "--porcelain")
    result = run_hook("guard_teammate_idle.py", {"hook_event_name": "TeammateIdle"})
    assert decision_of(result) == "allow", (
        "TeammateIdle must be inert without recorded contracts, even with a dirty tree "
        f"(tree dirty: {bool(dirty.strip())})"
    )


def test_teammate_idle_is_inert_without_recorded_contracts() -> None:
    """PR 1 ships this hook deliberately inert; PR 2 binds contracts to an exact agent."""
    module = load_hook_module("guard_teammate_idle")
    assert module._open_contracts(REPO_ROOT) == []
    source = (HOOKS_DIR / "guard_teammate_idle.py").read_text(encoding="utf-8")
    assert "status --porcelain" not in source, "the dirty-tree ownership inference must not return"


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
