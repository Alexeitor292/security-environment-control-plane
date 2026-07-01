"""Worker-only OpenTofuRunner (SECP-002B-1A, ADR-013).

Implements the ``ProvisioningRunner`` protocol (ADR-012) for the real path and adds an
exact-artifact ``prepare`` / ``apply_prepared`` / ``destroy_prepared`` flow that eliminates
the approval-to-apply TOCTOU: the *same* generated plan whose canonical change set was
approved is the one applied — no second render or plan.

The runner:

- uses the **pinned executable** from the toolchain profile (validated safe identifier),
  never a hard-coded name;
- validates every pinned identifier before interpolation into ``argv`` / paths / files;
- requires a ``ToolchainVerifier`` attestation of executable/version/binary-digest/
  module-bundle/lockfile/mirror/renderer before init/plan/apply/destroy;
- runs OpenTofu only through the injected ``ProcessExecutor`` (a ``FakeProcessExecutor``
  in B1-A) using **argv arrays**, offline flags, an env allowlist, redaction, an output
  cap, and a bounded timeout;
- canonicalizes the ``show -json`` plan into a redacted change set (no raw JSON, no
  before/after/sensitive/state) and never persists a raw binary plan.

**No real binary, provider, network, or endpoint is used in B1-A.** ``apps/api`` never
imports this module (architecture tests enforce it).
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field

from secp_worker.provisioning.change_set import planned_resources, summarize
from secp_worker.provisioning.identifiers import (
    IdentifierError,
    validate_executable,
    validate_toolchain_identifiers,
)
from secp_worker.provisioning.plan_json import (
    PlanCanonicalizationError,
    canonicalize_plan_json,
    change_set_hash,
)
from secp_worker.provisioning.process_executor import (
    DEFAULT_TIMEOUT_S,
    ProcessExecutor,
    ProcessSpec,
)
from secp_worker.provisioning.rendering import RenderedWorkspace, RenderingError, WorkspaceRenderer
from secp_worker.provisioning.runner import (
    RunnerApplyResult,
    RunnerChangeSet,
    RunnerDestroyResult,
    RunnerError,
    RunnerStatus,
    RunnerValidationResult,
)
from secp_worker.provisioning.toolchain_verify import FakeToolchainVerifier, ToolchainVerifier

_REQUIRED_KEYS = ("manifest_version", "topology", "reservations", "resource_limits")


@dataclass(frozen=True)
class PreparedOpenTofuPlan:
    """A transient, worker-only prepared plan bound to an ephemeral workspace.

    Holds only in-memory + ephemeral-workspace data: the canonical redacted change set,
    its hash, the workspace hash, the operation kind, and handles to the ephemeral
    workspace directory and the exact generated plan file. It **must never** be
    serialized into an API response, database record, audit event, workflow detail, log,
    or durable artifact — hence the redacted ``__repr__`` and the ``cleanup`` contract.
    """

    change_set: dict
    change_set_hash: str
    workspace_hash: str
    kind: str
    _workdir: str = field(repr=False)
    _plan_file: str = field(repr=False)

    def __repr__(self) -> str:  # never leak filesystem handles
        return (
            f"PreparedOpenTofuPlan(kind={self.kind!r}, "
            f"change_set_hash={self.change_set_hash!r}, workspace=<redacted>)"
        )


class OpenTofuRunner:
    """Real OpenTofu runner behind a sealed process executor. Worker-only."""

    name = "opentofu"

    def __init__(
        self,
        executor: ProcessExecutor,
        *,
        profile: dict,
        verifier: ToolchainVerifier | None = None,
        renderer: WorkspaceRenderer | None = None,
        workspace_root: str | None = None,
        secret_env: dict[str, str] | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        self._executor = executor
        self._profile = dict(profile or {})
        self._verifier = verifier or FakeToolchainVerifier()
        self._renderer = renderer or WorkspaceRenderer()
        self._workspace_root = workspace_root
        self._secret_env = dict(secret_env or {})
        self._timeout_s = timeout_s
        self._assert_safe_profile()
        self._executable = validate_executable(self._profile.get("executable"))

    # -- safety guards ---------------------------------------------------------

    def _assert_safe_profile(self) -> None:
        """Refuse unpinned / runtime-download / local-state / unsafe-identifier config."""
        from secp_api.toolchain_profile import validate_toolchain_profile

        spec = validate_toolchain_profile(self._profile)  # raises on any unsafe field
        mirror = spec.provider_mirror
        if mirror.allow_runtime_download or mirror.network_access not in {
            "offline",
            "none",
            "air-gapped",
            "airgapped",
            "mirror-only",
        }:
            raise RunnerError("provider mirror is not offline; runtime download is refused")
        try:
            validate_toolchain_identifiers(self._profile)
        except IdentifierError as exc:
            raise RunnerError(
                f"unsafe toolchain identifier (redacted): {type(exc).__name__}"
            ) from None

    def _verify_toolchain(self) -> None:
        """Require attested proof of the pinned provenance before executing."""
        verification = self._verifier.verify(self._profile)
        if not verification.ok:
            raise RunnerError(
                f"toolchain provenance not verified (missing: {verification.missing()})"
            )

    def _provenance(self, workspace: RenderedWorkspace) -> dict:
        p = self._profile
        return {
            "renderer_version": workspace.renderer_version,
            "module_bundle_hash": str(p.get("module_bundle_hash", "")),
            "opentofu_version": str(p.get("opentofu_version", "")),
            "provider_lockfile_hash": str(p.get("provider_lockfile_hash", "")),
            "provider_mirror": str((p.get("provider_mirror") or {}).get("identity", "")),
        }

    # -- argv builders (pinned executable, offline, no local state) ------------

    def _offline_init_argv(self, workdir: str) -> list[str]:
        mirror = self._profile["provider_mirror"]["identity"]
        return [
            self._executable,
            f"-chdir={workdir}",
            "init",
            "-input=false",
            "-no-color",
            "-get=false",
            "-upgrade=false",
            "-lockfile=readonly",
            f"-plugin-dir=/opt/secp/provider-mirror/{mirror}",
        ]

    def _plan_argv(self, workdir: str, plan_file: str, *, destroy: bool) -> list[str]:
        argv = [
            self._executable,
            f"-chdir={workdir}",
            "plan",
            "-input=false",
            "-no-color",
            "-lock=true",
            f"-out={plan_file}",
        ]
        if destroy:
            argv.append("-destroy")
        return argv

    def _show_argv(self, workdir: str, plan_file: str) -> list[str]:
        return [self._executable, f"-chdir={workdir}", "show", "-json", plan_file]

    def _apply_argv(self, workdir: str, plan_file: str) -> list[str]:
        return [
            self._executable,
            f"-chdir={workdir}",
            "apply",
            "-input=false",
            "-no-color",
            "-lock=true",
            plan_file,
        ]

    def _spec(self, argv: list[str], workdir: str, label: str) -> ProcessSpec:
        from secp_worker.provisioning.process_executor import build_process_env

        env = build_process_env(self._secret_env, base={"TF_IN_AUTOMATION": "1"})
        return ProcessSpec(argv=argv, cwd=workdir, timeout_s=self._timeout_s, env=env, label=label)

    # -- rendering + prepared plan --------------------------------------------

    def _render(self, manifest: dict) -> RenderedWorkspace:
        try:
            return self._renderer.render(manifest, self._profile)
        except RenderingError as exc:
            raise RunnerError(f"workspace rendering refused: {exc}") from exc

    def prepare(self, manifest: dict, *, operation_id: str, destroy: bool) -> PreparedOpenTofuPlan:
        """Render, offline-init, generate ONE plan, and canonicalize it.

        Returns a transient prepared plan bound to the exact generated plan file, ready
        for ``apply_prepared`` / ``destroy_prepared`` without any further render or plan.
        The caller owns the lifecycle and MUST call ``cleanup`` (in a finally block).
        """
        if not self.validate(manifest).ok:
            raise RunnerError("manifest is not runnable (redacted)")
        self._verify_toolchain()
        workspace = self._render(manifest)
        workdir = self._renderer.materialize(workspace, root=self._workspace_root)
        plan_file = f"{workdir}/plan.tfplan"
        if not self._executor.run(self._spec(self._offline_init_argv(workdir), workdir, "init")).ok:
            raise RunnerError("opentofu init failed (redacted)")
        label = "destroy-plan" if destroy else "plan"
        if not self._executor.run(
            self._spec(self._plan_argv(workdir, plan_file, destroy=destroy), workdir, label)
        ).ok:
            raise RunnerError("opentofu plan failed (redacted)")
        show = self._executor.run(self._spec(self._show_argv(workdir, plan_file), workdir, "show"))
        if not show.ok:
            raise RunnerError("opentofu show failed (redacted)")
        try:
            show_json = json.loads(show.stdout or "{}")
        except (ValueError, TypeError) as exc:
            raise RunnerError("opentofu show output was not valid JSON (redacted)") from exc
        try:
            cs = canonicalize_plan_json(
                show_json,
                kind="destroy" if destroy else "apply",
                workspace_hash=workspace.content_hash,
                provenance=self._provenance(workspace),
            )
        except PlanCanonicalizationError as exc:
            raise RunnerError("opentofu plan could not be canonicalized (redacted)") from exc
        return PreparedOpenTofuPlan(
            change_set=cs,
            change_set_hash=change_set_hash(cs),
            workspace_hash=workspace.content_hash,
            kind=cs["kind"],
            _workdir=workdir,
            _plan_file=plan_file,
        )

    def apply_prepared(
        self, prepared: PreparedOpenTofuPlan, *, operation_id: str
    ) -> RunnerApplyResult:
        """Apply the EXACT prepared plan file — no render, no re-plan (TOCTOU-free)."""
        if prepared.kind != "apply":
            raise RunnerError("prepared plan is not an apply plan")
        self._verify_toolchain()
        result = self._executor.run(
            self._spec(
                self._apply_argv(prepared._workdir, prepared._plan_file), prepared._workdir, "apply"
            )
        )
        if not result.ok:
            raise RunnerError("opentofu apply failed (redacted)")
        resources = list(prepared.change_set.get("resources", []))
        return RunnerApplyResult(
            operation_id=operation_id,
            ok=True,
            resources=resources,
            summary=prepared.change_set.get("summary", {}),
            idempotent_noop=False,
        )

    def destroy_prepared(
        self, prepared: PreparedOpenTofuPlan, *, operation_id: str
    ) -> RunnerDestroyResult:
        """Apply the EXACT prepared destroy plan file — no render, no re-plan."""
        if prepared.kind != "destroy":
            raise RunnerError("prepared plan is not a destroy plan")
        self._verify_toolchain()
        result = self._executor.run(
            self._spec(
                self._apply_argv(prepared._workdir, prepared._plan_file),
                prepared._workdir,
                "destroy",
            )
        )
        if not result.ok:
            raise RunnerError("opentofu destroy failed (redacted)")
        destroyed = [r["address"] for r in prepared.change_set.get("resources", [])]
        return RunnerDestroyResult(
            operation_id=operation_id, ok=True, destroyed=destroyed, idempotent_noop=False
        )

    def cleanup(self, prepared: PreparedOpenTofuPlan | None) -> None:
        """Remove the ephemeral workspace + binary plan artifact. Safe to call twice."""
        if prepared is None:
            return
        shutil.rmtree(prepared._workdir, ignore_errors=True)

    # -- ProvisioningRunner protocol ------------------------------------------

    def validate(self, manifest: dict) -> RunnerValidationResult:
        errors = [f"manifest missing '{k}'" for k in _REQUIRED_KEYS if k not in manifest]
        if not manifest.get("topology"):
            errors.append("manifest topology is empty")
        if not manifest.get("toolchain_profile_hash"):
            errors.append("manifest has no toolchain profile binding")
        return RunnerValidationResult(ok=not errors, errors=errors)

    def _dry_run(self, manifest: dict, *, operation_id: str, destroy: bool) -> RunnerChangeSet:
        prepared = self.prepare(manifest, operation_id=operation_id, destroy=destroy)
        try:
            return RunnerChangeSet(
                operation_id=operation_id,
                creates=list(prepared.change_set.get("resources", [])),
                summary=prepared.change_set.get("summary", {}),
                change_set_hash=prepared.change_set_hash,
                workspace_hash=prepared.workspace_hash,
                kind=prepared.kind,
            )
        finally:
            self.cleanup(prepared)

    def dry_run(self, manifest: dict, *, operation_id: str) -> RunnerChangeSet:
        return self._dry_run(manifest, operation_id=operation_id, destroy=False)

    def dry_run_destroy(self, manifest: dict, *, operation_id: str) -> RunnerChangeSet:
        return self._dry_run(manifest, operation_id=operation_id, destroy=True)

    def apply(self, manifest: dict, *, operation_id: str) -> RunnerApplyResult:
        """Protocol apply: single render+plan, apply that same plan (TOCTOU-free)."""
        prepared = self.prepare(manifest, operation_id=operation_id, destroy=False)
        try:
            return self.apply_prepared(prepared, operation_id=operation_id)
        finally:
            self.cleanup(prepared)

    def destroy(self, manifest: dict, *, operation_id: str) -> RunnerDestroyResult:
        prepared = self.prepare(manifest, operation_id=operation_id, destroy=True)
        try:
            return self.destroy_prepared(prepared, operation_id=operation_id)
        finally:
            self.cleanup(prepared)

    def status(self, operation_id: str) -> RunnerStatus:
        # The durable ProvisioningOperation record is authoritative for real-path status
        # (execution.py reads it before ever calling the runner). Report unknown here.
        return RunnerStatus(operation_id=operation_id, state="unknown", exists=False)


# Kept importable for result summaries used by callers/tests.
__all__ = ["OpenTofuRunner", "PreparedOpenTofuPlan", "planned_resources", "summarize"]
