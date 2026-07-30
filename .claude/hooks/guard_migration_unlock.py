"""PreToolUse guard for Alembic migration authoring: operator-issued single-use unlock.

Writing under ``apps/api/migrations/versions/`` is denied unless exactly one valid,
unexpired, operator-issued unlock token authorises this exact migration on this exact
branch. The token is minted only by ``scripts/program/New-MigrationUnlock.ps1``, lives
outside the repository, and is consumed atomically on first use.

A token binds repository, branch, base SHA, migration filename, purpose, issuer and
expiry. Missing, malformed, expired, mismatched, duplicated or already-consumed tokens
all hard-deny. A token for one migration can never authorise another migration or
another branch.

Approving a migration does NOT authorise changing the sole Alembic head, merging,
deploying, or running migrations against a real database -- those remain independently
denied.

Honest boundary: this is an agent-error guardrail. It is not a security boundary against
a malicious process running under the operator's own identity.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import (  # noqa: E402
    MIGRATION_GLOBS,
    deny,
    edited_paths,
    git,
    git_succeeds,
    guard,
    matches_any,
    protected_write_reason,
    read_event,
    relative_posix,
    repo_root,
)

UNLOCK_DIR_NAME = "secp-migration-unlock"

REQUIRED_FIELDS = {
    "version",
    "repository",
    "branch",
    "base_sha",
    "migration_filename",
    "purpose",
    "issuer",
    "issued_at",
    "expires_at",
    "nonce",
}

MAX_TTL_SECONDS = 60 * 60


def unlock_dir() -> Path:
    """The operator-owned unlock directory, always OUTSIDE the repository."""
    override = os.environ.get("SECP_MIGRATION_UNLOCK_DIR")
    if override:
        return Path(override)
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / UNLOCK_DIR_NAME
    xdg_state = os.environ.get("XDG_STATE_HOME")
    if xdg_state:
        return Path(xdg_state) / UNLOCK_DIR_NAME
    return Path.home() / ".local" / "state" / UNLOCK_DIR_NAME


def _parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_single_token(directory: Path) -> tuple[Path, dict]:
    if not directory.is_dir():
        deny(
            "BLOCKED: migration authoring requires an operator-issued unlock token and no "
            f"unlock directory exists ({directory}). Ask Juan to run "
            "scripts/program/New-MigrationUnlock.ps1."
        )
    tokens = sorted(p for p in directory.glob("*.json") if p.is_file())
    if not tokens:
        deny(
            "BLOCKED: migration authoring requires an operator-issued unlock token and none "
            "is present. Ask Juan to run scripts/program/New-MigrationUnlock.ps1."
        )
    if len(tokens) > 1:
        deny(
            f"BLOCKED: {len(tokens)} unlock tokens are present, which is ambiguous. "
            "Exactly one live migration contract is permitted at a time. "
            "Ask Juan to remove the stale tokens."
        )
    token_path = tokens[0]
    try:
        # utf-8-sig: Windows PowerShell writes UTF-8 with a BOM, which strict utf-8 rejects.
        # Reading BOM-tolerantly keeps the minter and this hook interoperable on both
        # platforms; utf-8-sig decodes plain UTF-8 unchanged.
        raw = token_path.read_text(encoding="utf-8-sig")
        payload = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        deny(f"BLOCKED: the unlock token is malformed and cannot be read ({exc!r}).")
    if not isinstance(payload, dict):
        deny("BLOCKED: the unlock token is malformed (expected a JSON object).")
    return token_path, payload


def _validate_schema(payload: dict) -> None:
    keys = set(payload)
    missing = REQUIRED_FIELDS - keys
    if missing:
        deny(
            "BLOCKED: the unlock token is malformed; missing required field(s): "
            f"{', '.join(sorted(missing))}."
        )
    unexpected = keys - REQUIRED_FIELDS
    if unexpected:
        deny(
            "BLOCKED: the unlock token carries unexpected field(s): "
            f"{', '.join(sorted(unexpected))}. Tokens must never carry credentials, "
            "connection strings or any other secret material."
        )
    if payload.get("version") != 1:
        deny(f"BLOCKED: unsupported unlock token version {payload.get('version')!r}.")
    for field in ("repository", "branch", "base_sha", "migration_filename", "issuer", "nonce"):
        if not isinstance(payload.get(field), str) or not payload[field].strip():
            deny(f"BLOCKED: the unlock token field '{field}' is malformed or empty.")


def _validate_binding(payload: dict, root: Path, target_filename: str) -> None:
    token_repo = Path(payload["repository"])
    try:
        same_repo = token_repo.resolve() == root.resolve()
    except OSError:
        same_repo = False
    if not same_repo:
        deny(
            "BLOCKED: the unlock token was issued for a different repository "
            f"({payload['repository']!r}); this checkout is {str(root)!r}."
        )

    branch = git(root, "rev-parse", "--abbrev-ref", "HEAD")
    if payload["branch"] != branch:
        deny(
            f"BLOCKED: the unlock token authorises branch {payload['branch']!r} but the "
            f"current branch is {branch!r}. A token for one branch can never authorise another."
        )

    base_sha = payload["base_sha"]
    head = git(root, "rev-parse", "HEAD")
    if not head:
        deny("BLOCKED: unable to resolve HEAD to validate the unlock token; denied fail-closed.")
    if base_sha != head:
        # `merge-base --is-ancestor` reports through the exit code and prints nothing, so
        # it must be evaluated with git_succeeds -- reading stdout would accept any commit.
        is_commit = git(root, "cat-file", "-t", base_sha) == "commit"
        is_ancestor = git_succeeds(root, "merge-base", "--is-ancestor", base_sha, head)
        if not (is_commit and is_ancestor):
            deny(
                f"BLOCKED: the unlock token is bound to base SHA {base_sha[:12]} which is not "
                f"HEAD ({head[:12]}) nor an ancestor of it. Re-issue the token for this base."
            )

    if payload["migration_filename"] != target_filename:
        deny(
            f"BLOCKED: the unlock token authorises migration {payload['migration_filename']!r} "
            f"but this write targets {target_filename!r}. A token for one migration can never "
            "authorise another."
        )


def _validate_expiry(payload: dict, now: datetime | None = None) -> None:
    """Enforce a CLOSED freshness window: ``issued_at <= now < expires_at``.

    Checking only the upper bound accepted a token stamped in the future, which would let a
    forward-dated approval sit valid indefinitely. ``now`` is injectable so the boundaries
    can be tested exactly rather than with timing-sensitive sleeps.
    """
    try:
        issued_at = _parse_timestamp(payload["issued_at"])
        expires_at = _parse_timestamp(payload["expires_at"])
    except (TypeError, ValueError) as exc:
        deny(f"BLOCKED: the unlock token timestamps are malformed ({exc!r}).")

    ttl = (expires_at - issued_at).total_seconds()
    if ttl <= 0 or ttl > MAX_TTL_SECONDS:
        deny(
            f"BLOCKED: the unlock token declares a {int(ttl)}s lifetime; the permitted maximum "
            f"is {MAX_TTL_SECONDS}s (60 minutes)."
        )

    moment = now or datetime.now(timezone.utc)
    if moment < issued_at:
        deny(
            f"BLOCKED: the unlock token is stamped in the future "
            f"(issued_at {issued_at.isoformat()}, now {moment.isoformat()}). "
            "A forward-dated token is refused."
        )
    if moment >= expires_at:
        deny(
            f"BLOCKED: the unlock token expired at {expires_at.isoformat()} "
            f"(now {moment.isoformat()}). Ask Juan to issue a fresh token."
        )


def _consume(token_path: Path) -> None:
    """Atomically consume the token. Failure to consume denies the write."""
    consumed = token_path.with_suffix(token_path.suffix + ".consumed")
    if consumed.exists():
        deny("BLOCKED: this unlock token has already been consumed. Tokens are single-use.")
    try:
        os.rename(token_path, consumed)
    except OSError as exc:
        deny(
            f"BLOCKED: the unlock token could not be consumed atomically ({exc!r}); "
            "denied fail-closed so it cannot be replayed."
        )


def main() -> None:
    event = read_event()
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return

    root = repo_root()
    targets: list[str] = []
    for raw_path in edited_paths(tool_input):
        rel_path = relative_posix(raw_path, root)
        if rel_path and matches_any(rel_path, MIGRATION_GLOBS) is not None:
            targets.append(rel_path)
    if not targets:
        return
    if len(set(targets)) > 1:
        deny(
            "BLOCKED: this call writes more than one migration file. An unlock token "
            "authorises exactly one migration filename."
        )

    target_filename = Path(targets[0]).name
    token_path, payload = _load_single_token(unlock_dir())
    _validate_schema(payload)
    _validate_binding(payload, root, target_filename)
    _validate_expiry(payload)

    # Both PreToolUse guards fire for the same call. Validation above still runs so an
    # invalid token is always refused, but the token is only CONSUMED when the write can
    # actually proceed -- otherwise a sibling guard's denial would burn a single-use
    # operator approval on a call that never wrote anything, forcing a needless re-mint.
    branch = git(root, "rev-parse", "--abbrev-ref", "HEAD")
    if protected_write_reason(targets[0], branch) is not None:
        return
    _consume(token_path)


if __name__ == "__main__":
    guard(main)
