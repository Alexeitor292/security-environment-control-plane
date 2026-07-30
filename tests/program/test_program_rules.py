"""Path-scoped rule files must be well-formed and must actually cover the repository.

`.claude/rules/*.md` load automatically alongside CLAUDE.md, scoped by a `paths:` frontmatter
glob. A rule with a malformed or stale glob loads for nothing and provides no guidance, which
is indistinguishable from having no rule at all until an agent gets something wrong.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / ".claude" / "rules"

UNSCOPED = "00-core.md"

# Every top-level source tree an agent may edit must be reachable by at least one rule.
COVERED_TREES = (
    "apps/api",
    "apps/worker",
    "apps/management",
    "apps/commissioning",
    "apps/deployment",
    "apps/web",
    "contracts",
    "plugins",
    "infra",
    "docs",
    "tests",
)


def rule_files() -> list[Path]:
    return sorted(RULES_DIR.glob("*.md"))


def parse_frontmatter(path: Path) -> dict[str, list[str]]:
    """Minimal YAML frontmatter reader for the `paths:` list form used by rules."""
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}
    _, _, rest = text.partition("---\n")
    block, _, _ = rest.partition("\n---")
    result: dict[str, list[str]] = {}
    key: str | None = None
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- ") and key:
            result[key].append(stripped[2:].strip().strip("\"'"))
        elif stripped.endswith(":"):
            key = stripped[:-1].strip()
            result[key] = []
    return result


def test_rules_directory_is_populated() -> None:
    assert len(rule_files()) >= 10, "expected the full set of path-scoped rules"


def test_core_rule_exists_and_is_unscoped() -> None:
    core = RULES_DIR / UNSCOPED
    assert core.is_file(), f"{UNSCOPED} must exist and always load"
    assert not core.read_text(encoding="utf-8").startswith("---"), (
        f"{UNSCOPED} must be unscoped so it loads in every session"
    )


@pytest.mark.parametrize(
    "path", [p for p in rule_files() if p.name != UNSCOPED], ids=lambda p: p.name
)
def test_scoped_rule_declares_paths(path: Path) -> None:
    frontmatter = parse_frontmatter(path)
    assert "paths" in frontmatter, f"{path.name} has no `paths:` frontmatter, so it never loads"
    assert frontmatter["paths"], f"{path.name} declares an empty `paths:` list"


@pytest.mark.parametrize(
    "path", [p for p in rule_files() if p.name != UNSCOPED], ids=lambda p: p.name
)
def test_scoped_rule_globs_resolve_to_something_real(path: Path) -> None:
    """A glob that matches nothing is a stale rule -- it silently stops applying."""
    for pattern in parse_frontmatter(path)["paths"]:
        anchor = pattern.split("*")[0].rstrip("/")
        if not anchor:
            continue  # A leading-wildcard pattern such as **/docker-compose*.yml.
        target = REPO_ROOT / anchor
        matched = target.exists() or any(REPO_ROOT.glob(pattern))
        assert matched, f"{path.name} scopes {pattern!r} which matches nothing in the repo"


@pytest.mark.parametrize("tree", COVERED_TREES)
def test_every_source_tree_is_covered_by_some_rule(tree: str) -> None:
    for path in rule_files():
        if path.name == UNSCOPED:
            continue
        for pattern in parse_frontmatter(path).get("paths", []):
            anchor = pattern.split("*")[0].rstrip("/")
            if anchor and (tree.startswith(anchor) or anchor.startswith(tree)):
                return
    pytest.fail(f"no .claude/rules file scopes {tree!r}")


@pytest.mark.parametrize("path", rule_files(), ids=lambda p: p.name)
def test_rule_has_content_beyond_frontmatter(path: Path) -> None:
    body = path.read_text(encoding="utf-8")
    if body.startswith("---"):
        _, _, rest = body.partition("---\n")
        _, _, body = rest.partition("\n---")
    assert len(body.strip()) > 200, f"{path.name} carries no substantive guidance"
