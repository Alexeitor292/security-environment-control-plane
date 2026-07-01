"""Sealed worker-only process executor (SECP-002B-1A, ADR-013).

The ``OpenTofuRunner`` runs OpenTofu ONLY through this seam. Two implementations:

* ``FakeProcessExecutor`` — used by EVERY test and by in-process verification. It runs
  **nothing**: it records the exact ``argv`` / ``cwd`` / ``timeout`` / (redacted) ``env``
  it was handed and returns scripted, secret-free output. This is how the whole real
  path is proven without any binary, provider, network, or endpoint.

* ``SubprocessProcessExecutor`` — the ONLY code that would ever run a real process. It
  uses **argv arrays only** (never a shell string, never ``shell=True``), a fixed
  restrictive-permission working directory, an explicit **timeout**, an **output-size
  cap**, an **environment allowlist**, and mandatory **output redaction**. It is
  **inert unless explicitly armed** and is **not constructed or invoked anywhere in
  B1-A**. Arming it is deferred to a reviewed disposable lab (B1-B).

``apps/api`` never imports this module (architecture tests enforce it).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

# Environment allowlist for a would-be OpenTofu invocation. Only these exact keys and
# these prefixes are ever passed to the child process; everything else is dropped.
ALLOWED_ENV_KEYS = frozenset(
    {
        "PATH",
        "HOME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "TF_IN_AUTOMATION",
        "TF_DATA_DIR",
        "TF_PLUGIN_CACHE_DIR",
        "TF_CLI_CONFIG_FILE",
        "CHECKPOINT_DISABLE",
    }
)
ALLOWED_ENV_PREFIXES = ("TF_VAR_", "TF_LOG")

# Keys whose *values* are masked in any redacted view / record / log.
_SECRET_KEY_RE = re.compile(
    r"(pass|passwd|password|secret|token|api[_-]?key|apikey|priv|credential|cred)",
    re.IGNORECASE,
)
_REDACTION = "***REDACTED***"

# Default output cap: OpenTofu output is bounded so a runaway process cannot fill logs
# or exfiltrate large blobs into records.
DEFAULT_MAX_OUTPUT_BYTES = 256 * 1024
DEFAULT_TIMEOUT_S = 600.0


class ProcessExecutionError(Exception):
    """A process seam failure. Messages are redacted (never include secrets/output)."""


@dataclass(frozen=True)
class ProcessSpec:
    """A fully-specified, shell-free process invocation."""

    argv: list[str]
    cwd: str
    timeout_s: float = DEFAULT_TIMEOUT_S
    env: dict[str, str] = field(default_factory=dict)
    label: str = ""

    def redacted_env(self) -> dict[str, str]:
        return redact_env(self.env)


@dataclass(frozen=True)
class ProcessResult:
    """Result of a process invocation. ``stdout`` is capped; never persist raw output."""

    returncode: int
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False
    duration_s: float = 0.0

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def redact_env(env: dict[str, str]) -> dict[str, str]:
    """Return a copy of ``env`` with secret-like values masked (for logs/records)."""
    out: dict[str, str] = {}
    for k, v in env.items():
        out[k] = _REDACTION if _SECRET_KEY_RE.search(k) else v
    return out


def build_process_env(
    injected: dict[str, str], base: dict[str, str] | None = None
) -> dict[str, str]:
    """Filter ``base`` + ``injected`` down to the allowlist. Nothing else passes.

    ``injected`` (e.g. ``TF_VAR_*`` produced from just-in-time secret resolution in the
    worker) is applied on top of the allowlisted ``base``. Non-allowlisted keys are
    dropped rather than forwarded.
    """
    merged: dict[str, str] = {}
    for source in (base or {}, injected):
        for k, v in source.items():
            if k in ALLOWED_ENV_KEYS or k.startswith(ALLOWED_ENV_PREFIXES):
                merged[k] = v
    return merged


class ProcessExecutor:
    """Structural type for a process executor. See the two implementations."""

    def run(self, spec: ProcessSpec) -> ProcessResult:  # pragma: no cover - interface
        raise NotImplementedError


class FakeProcessExecutor(ProcessExecutor):
    """Runs nothing. Records every ``ProcessSpec`` and returns scripted, safe output.

    * ``show_json`` — a realistic, safe ``tofu show -json`` fixture returned for the
      ``show`` step (default: an empty-plan fixture). The runner canonicalizes and
      redacts it; different fixtures produce different change-set hashes (proof #10).
    * ``script`` — optional per-call ``ProcessResult`` overrides (consumed in order).
    """

    def __init__(
        self,
        *,
        show_json: dict | None = None,
        returncode: int = 0,
        script: list[ProcessResult] | None = None,
    ) -> None:
        self.calls: list[ProcessSpec] = []
        self._show_json = show_json
        self._returncode = returncode
        self._script = list(script or [])

    def run(self, spec: ProcessSpec) -> ProcessResult:
        # Record the spec so tests can assert safe argv / cwd / timeout / redacted env.
        self.calls.append(spec)
        if self._script:
            return self._script.pop(0)
        if spec.label == "show":
            import json

            payload = (
                self._show_json
                if self._show_json is not None
                else {"format_version": "1.2", "resource_changes": []}
            )
            return ProcessResult(
                returncode=self._returncode, stdout=json.dumps(payload), duration_s=0.0
            )
        # init / plan / apply / destroy produce no parsed stdout in the fake.
        return ProcessResult(returncode=self._returncode, stdout="", duration_s=0.0)


class SubprocessProcessExecutor(ProcessExecutor):
    """The ONLY real-process executor. Inert unless explicitly armed (B1-B).

    Not constructed or invoked anywhere in B1-A. When armed it runs argv arrays with
    ``shell=False`` in a fixed cwd, an explicit timeout, an output cap, and an
    allowlisted, redacted environment.
    """

    def __init__(self, *, armed: bool = False, max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES):
        if not armed:
            raise ProcessExecutionError(
                "SubprocessProcessExecutor is disarmed; real OpenTofu execution is not "
                "enabled in SECP-002B-1A. Arming is deferred to a reviewed disposable "
                "lab (B1-B) behind the isolated-lab activation gate."
            )
        self._armed = armed
        self._max_output_bytes = max_output_bytes

    def run(self, spec: ProcessSpec) -> ProcessResult:  # pragma: no cover - never run in B1-A
        if not self._armed:
            raise ProcessExecutionError("SubprocessProcessExecutor is disarmed")
        # Defensive: argv must be a non-empty list of strings; never a shell string.
        if (
            not isinstance(spec.argv, list)
            or not spec.argv
            or not all(isinstance(a, str) for a in spec.argv)
        ):
            raise ProcessExecutionError("argv must be a non-empty list of strings")
        import subprocess  # imported lazily; worker-only, never reached in B1-A

        started = time.monotonic()
        completed = subprocess.run(  # noqa: S603 - argv list, shell=False, allowlisted env
            spec.argv,
            cwd=spec.cwd,
            env=spec.env,
            timeout=spec.timeout_s,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )
        duration = time.monotonic() - started
        stdout = completed.stdout or ""
        truncated = len(stdout.encode("utf-8", "ignore")) > self._max_output_bytes
        if truncated:
            stdout = stdout.encode("utf-8", "ignore")[: self._max_output_bytes].decode(
                "utf-8", "ignore"
            )
        return ProcessResult(
            returncode=completed.returncode,
            stdout=stdout,
            stderr="(redacted)",
            truncated=truncated,
            duration_s=duration,
        )
