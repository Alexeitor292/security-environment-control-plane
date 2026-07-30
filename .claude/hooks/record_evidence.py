"""PostToolUse(Bash) recorder: append validation outcomes to the session evidence ledger.

``guard_task_completion.py`` reads this ledger, so "done" has to be earned by a command
that actually ran rather than asserted in prose.

The ledger lives outside the repository (OS temp dir, keyed by session id) so it never
pollutes the working tree or a diff.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import evidence_path, guard, normalized, read_event  # noqa: E402

VALIDATION_MARKERS = (
    "pytest",
    "ruff",
    "mypy",
    "npm run test",
    "npm run lint",
    "npm run build",
    "npm test",
    "gh run view",
    "gh pr checks",
    "py_compile",
)

FAILURE_MARKERS = (
    "failed",
    "error:",
    "errors:",
    "traceback",
    "assertionerror",
    "no tests ran",
    "exit code 1",
    "fatal:",
)

SUCCESS_MARKERS = ("passed", "ok", "success", "all checks passed", "would reformat: 0")


def _looks_like_validation(command: str) -> bool:
    lowered = normalized(command)
    return any(marker in lowered for marker in VALIDATION_MARKERS)


def _response_text(response: object) -> str:
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        chunks = []
        for key in ("stdout", "stderr", "output", "content", "result"):
            value = response.get(key)
            if isinstance(value, str):
                chunks.append(value)
        return "\n".join(chunks)
    return ""


def _classify(response: object) -> str:
    """Return 'passed' | 'failed' | 'unknown' for a tool response."""
    if isinstance(response, dict):
        if response.get("interrupted") is True:
            return "failed"
        for key in ("isError", "is_error", "error"):
            if response.get(key):
                return "failed"
        for key in ("exitCode", "exit_code", "returncode"):
            value = response.get(key)
            if isinstance(value, int):
                return "passed" if value == 0 else "failed"

    text = _response_text(response).lower()
    if not text.strip():
        return "unknown"
    if any(marker in text for marker in FAILURE_MARKERS):
        return "failed"
    if any(marker in text for marker in SUCCESS_MARKERS):
        return "passed"
    return "unknown"


def main() -> None:
    event = read_event()
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return
    command = tool_input.get("command")
    if not isinstance(command, str) or not _looks_like_validation(command):
        return

    record = {
        "at": datetime.now(timezone.utc).isoformat(),
        "command": command[:2000],
        "status": _classify(event.get("tool_response")),
    }
    path = evidence_path(str(event.get("session_id") or ""))
    try:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
    except OSError:
        return  # Recording is best-effort; never block the agent's work.


if __name__ == "__main__":
    guard(main)
