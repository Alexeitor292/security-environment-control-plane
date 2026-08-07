"""The worker-only process seam (ADR-013, reopened by ADR-030).

The ``OpenTofuRunner`` runs OpenTofu ONLY through here. Two implementations:

* ``FakeProcessExecutor`` — used by every test and by in-process verification. It runs
  **nothing**: it records the exact ``argv`` / ``cwd`` / ``timeout`` / (redacted) ``env`` it was
  handed and returns scripted, secret-free output. This is how the real path is proven without a
  binary, a provider, a network or an endpoint.

* ``SubprocessProcessExecutor`` — the only code that runs a real process. It previously carried
  `_B1A_SUBPROCESS_SEALED` and an ``armed=`` flag, which together made real execution
  *unconstructible* because no authorization model existed to make it *unauthorized*. ADR-030 built
  that model, so both are gone: the executor is now production-capable and is closed by requiring
  the exact durable operation authority and by rebuilding every command from
  :mod:`command_grammar`. No constant, settings field, environment variable or constructor flag
  here widens what may execute.

``apps/api`` never imports this module (architecture tests enforce it).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from secp_worker.provisioning.command_grammar import build_argv, step_for_label

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


#: The widest a workspace directory may sit. A worker owns its workspaces; a settable root is a
#: settable ``-chdir``, which is a settable apply.
WORKSPACE_ROOT = "/var/lib/secp/workspaces"

#: A ceiling on the timeout a spec may ask for, applied independently of the spec. An unbounded
#: timeout is a worker that never returns and an operation that never fails.
MAX_TIMEOUT_S = 3600.0


class ProcessExecutor:
    """Structural type for a process executor. See the two implementations."""

    # Only executors that run NOTHING (fakes) set this True. ``run_real_provisioning``
    # refuses any executor that is not B1-A fake-only, defense-in-depth against an
    # injected real executor bypassing the factory.
    b1a_fake_only: bool = False

    def run(self, spec: ProcessSpec) -> ProcessResult:  # pragma: no cover - interface
        raise NotImplementedError


class FakeProcessExecutor(ProcessExecutor):
    """Runs nothing. Records every ``ProcessSpec`` and returns scripted, safe output.

    * ``show_json`` — a realistic, safe ``tofu show -json`` fixture returned for the
      ``show`` step (default: an empty-plan fixture). The runner canonicalizes and
      redacts it; different fixtures produce different change-set hashes (proof #10).
    * ``script`` — optional per-call ``ProcessResult`` overrides (consumed in order).
    """

    b1a_fake_only = True

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
    """The ONLY real-process executor. Production-capable, and closed by authority + derivation.

    `_B1A_SUBPROCESS_SEALED` and `armed=` are gone (ADR-030). Neither is replaced by another
    boolean, because **a boolean is not the replacement for a boolean**: setting a seal to
    ``False`` converts an unconditional refusal into an unconditional permission, which is worse
    than either. Two things close this executor instead, and they are independent:

    **1. It cannot be constructed without the exact durable operation authority.** ``authority``
    must be a real :class:`~secp_api.provisioning_execution_authority.AuthorizedExecution` — the
    value ``authorize_provisioning_execution`` returns after all of its conditions hold against
    durable rows. The check is ``isinstance``, so a duck-typed object carrying the right attribute
    names is refused; there is no settings field, environment variable or constructor flag that
    substitutes for it, and no way to build one except by satisfying the derivation.

    **2. It cannot run a command the reviewed engine could not have produced.** The pinned
    executable and provider-mirror identity come from that authority — never from the spec being
    run — and every spec is rebuilt from :mod:`command_grammar`, the same function the engine
    builds with, and must match byte for byte. The working directory must be a workspace under
    :data:`WORKSPACE_ROOT`, and the plan path is derived from it rather than supplied.

    Because the argv is *rebuilt* rather than inspected, ``shell=True``, a shell string, a
    ``/bin/sh -c`` payload, argv from an API request, a caller-supplied environment or working
    directory and a caller-selected executable are structurally impossible rather than checked for.
    The environment is re-filtered to the allowlist and the timeout is capped independently of the
    spec.
    """

    def __init__(
        self,
        *,
        authority: object,
        workspace_root: str = WORKSPACE_ROOT,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ):
        # Imported here rather than at module scope: the API plane must never import this module,
        # and a top-level import in the other direction is the kind of edge that makes an
        # architecture guard hard to reason about.
        from secp_api.provisioning_execution_authority import AuthorizedExecution

        if not isinstance(authority, AuthorizedExecution):
            raise ProcessExecutionError(
                "a real process executor requires the AuthorizedExecution returned by "
                "authorize_provisioning_execution for THIS operation; no flag, setting, grant or "
                "look-alike object substitutes for it"
            )
        from secp_worker.provisioning.identifiers import IdentifierError, validate_executable

        try:
            self._executable = validate_executable(authority.opentofu_executable)
        except IdentifierError as exc:
            raise ProcessExecutionError(
                f"the authorized toolchain names an executable that is not an approved "
                f"worker-managed identity: {type(exc).__name__}"
            ) from None
        mirror = str(authority.provider_mirror_identity or "").strip()
        if not mirror:
            raise ProcessExecutionError("the authorized toolchain names no provider mirror")
        self.authority = authority
        self._mirror_identity = mirror
        self._workspace_root = workspace_root.rstrip("/")
        self._max_output_bytes = max_output_bytes

    def _assert_within_workspace_root(self, cwd: str) -> None:
        """``-chdir`` may only name a workspace this worker owns."""
        import posixpath

        if not cwd or not cwd.startswith("/") or ".." in cwd.split("/"):
            raise ProcessExecutionError("working directory must be an absolute path with no '..'")
        normalized = posixpath.normpath(cwd)
        if normalized != self._workspace_root and not normalized.startswith(
            self._workspace_root + "/"
        ):
            raise ProcessExecutionError("working directory is outside the worker's workspace root")

    def authorize(self, spec: ProcessSpec) -> ProcessSpec:
        """Re-derive what this command must be, or refuse. Returns the spec actually run.

        The RETURNED spec is rebuilt rather than the argument passed through, so every value that
        reaches :func:`subprocess.run` is this executor's — including the environment, which is
        filtered again here even though the engine already filtered it. That last part is not
        redundant: this is the final point before a real process, and a spec arriving with an extra
        key would otherwise carry it straight through.
        """
        self._assert_within_workspace_root(spec.cwd)

        step = step_for_label(spec.label)
        expected = build_argv(
            step,
            executable=self._executable,
            workdir=spec.cwd,
            mirror_identity=self._mirror_identity,
        )
        if list(spec.argv) != expected:
            # Names the STEP, never the argv: a refusal that echoes the rejected command into a log
            # is a way to write arbitrary attacker text into an operator's records.
            raise ProcessExecutionError(
                f"command is not the reviewed form of step {step.value!r}; refusing"
            )

        timeout = float(spec.timeout_s)
        if timeout <= 0 or timeout > MAX_TIMEOUT_S:
            raise ProcessExecutionError("timeout must be positive and within the executor's cap")

        return ProcessSpec(
            argv=expected,
            cwd=spec.cwd,
            timeout_s=timeout,
            env=build_process_env(dict(spec.env), base={"TF_IN_AUTOMATION": "1"}),
            label=step.value,
        )

    def run(self, spec: ProcessSpec) -> ProcessResult:
        spec = self.authorize(spec)
        import subprocess  # lazy: worker-only, and never imported into the API plane

        started = time.monotonic()
        completed = subprocess.run(  # noqa: S603 - rebuilt argv list, shell=False, allowlisted env
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
