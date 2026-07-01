"""Worker-only OpenTofuRunner (SECP-002B-1A, ADR-013).

Implements the ``ProvisioningRunner`` protocol (ADR-012) for the real path. It renders a
secret-free workspace, materializes it into an ephemeral restrictive-permission dir, and
executes OpenTofu ONLY through the injected ``ProcessExecutor`` seam using **argv arrays**
with offline, pinned, no-local-state flags.

In SECP-002B-1A the executor is always a ``FakeProcessExecutor`` — **no real binary,
provider, network, or endpoint is ever used**. The runner refuses any unpinned,
downloaded-at-runtime, or local-state configuration. ``apps/api`` never imports this
module (architecture tests enforce it).
"""

from __future__ import annotations

import json

from secp_worker.provisioning.change_set import (
    canonical_change_set,
    change_set_hash,
    planned_resources,
    summarize,
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

_EXECUTABLE = "tofu"
_REQUIRED_KEYS = ("manifest_version", "topology", "reservations", "resource_limits")


class OpenTofuRunner:
    """Real OpenTofu runner behind a sealed process executor. Worker-only."""

    name = "opentofu"

    def __init__(
        self,
        executor: ProcessExecutor,
        *,
        profile: dict,
        renderer: WorkspaceRenderer | None = None,
        workspace_root: str | None = None,
        secret_env: dict[str, str] | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        self._executor = executor
        self._profile = dict(profile or {})
        self._renderer = renderer or WorkspaceRenderer()
        self._workspace_root = workspace_root
        # TF_VAR_* env (JIT-resolved in the worker). Empty in B1-A tests unless a fake
        # resolver injects fake values. Never persisted, hashed, or logged un-redacted.
        self._secret_env = dict(secret_env or {})
        self._timeout_s = timeout_s
        self._assert_safe_profile()

    # -- safety guards ---------------------------------------------------------

    def _assert_safe_profile(self) -> None:
        """Refuse unpinned / runtime-download / local-state configuration."""
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

    def _offline_init_argv(self, workdir: str) -> list[str]:
        mirror = self._profile["provider_mirror"]["identity"]
        # Offline, pinned init: no network, no module fetch, read-only lockfile, and a
        # pinned local plugin mirror. These are the "offline-only flags" (proof #8).
        return [
            _EXECUTABLE,
            f"-chdir={workdir}",
            "init",
            "-input=false",
            "-no-color",
            "-get=false",
            "-upgrade=false",
            "-lockfile=readonly",
            f"-plugin-dir=/opt/secp/provider-mirror/{mirror}",
        ]

    def _plan_argv(self, workdir: str, *, destroy: bool) -> list[str]:
        argv = [
            _EXECUTABLE,
            f"-chdir={workdir}",
            "plan",
            "-input=false",
            "-no-color",
            "-lock=true",
            f"-out={workdir}/plan.tfplan",
        ]
        if destroy:
            argv.append("-destroy")
        return argv

    def _show_argv(self, workdir: str) -> list[str]:
        return [_EXECUTABLE, f"-chdir={workdir}", "show", "-json", f"{workdir}/plan.tfplan"]

    def _apply_argv(self, workdir: str) -> list[str]:
        return [
            _EXECUTABLE,
            f"-chdir={workdir}",
            "apply",
            "-input=false",
            "-no-color",
            "-lock=true",
            f"{workdir}/plan.tfplan",
        ]

    def _destroy_argv(self, workdir: str) -> list[str]:
        return [
            _EXECUTABLE,
            f"-chdir={workdir}",
            "apply",
            "-input=false",
            "-no-color",
            "-lock=true",
            f"{workdir}/plan.tfplan",  # a saved destroy plan
        ]

    def _spec(self, argv: list[str], workdir: str, label: str) -> ProcessSpec:
        from secp_worker.provisioning.process_executor import build_process_env

        env = build_process_env(self._secret_env, base={"TF_IN_AUTOMATION": "1"})
        return ProcessSpec(argv=argv, cwd=workdir, timeout_s=self._timeout_s, env=env, label=label)

    # -- rendering + plan ------------------------------------------------------

    def _render(self, manifest: dict) -> RenderedWorkspace:
        try:
            return self._renderer.render(manifest, self._profile)
        except RenderingError as exc:
            raise RunnerError(f"workspace rendering refused: {exc}") from exc

    def _run_plan(self, manifest: dict, *, destroy: bool) -> tuple[RenderedWorkspace, str]:
        """Render, materialize, init (offline), plan, and show. Returns (ws, plan_digest)."""
        workspace = self._render(manifest)
        workdir = self._renderer.materialize(workspace, root=self._workspace_root)
        init = self._executor.run(self._spec(self._offline_init_argv(workdir), workdir, "init"))
        if not init.ok:
            raise RunnerError("opentofu init failed (redacted)")
        label = "destroy-plan" if destroy else "plan"
        plan = self._executor.run(
            self._spec(self._plan_argv(workdir, destroy=destroy), workdir, label)
        )
        if not plan.ok:
            raise RunnerError("opentofu plan failed (redacted)")
        show = self._executor.run(self._spec(self._show_argv(workdir), workdir, "show"))
        if not show.ok:
            raise RunnerError("opentofu show failed (redacted)")
        plan_digest = self._extract_plan_digest(show.stdout)
        return workspace, plan_digest

    @staticmethod
    def _extract_plan_digest(stdout: str) -> str:
        """Extract the non-secret plan_digest marker from show -json output."""
        try:
            data = json.loads(stdout or "{}")
        except (ValueError, TypeError):
            return ""
        digest = data.get("plan_digest")
        return str(digest) if digest is not None else ""

    def _change_set(self, manifest: dict, *, destroy: bool) -> tuple[dict, RenderedWorkspace, str]:
        workspace, plan_digest = self._run_plan(manifest, destroy=destroy)
        resources = planned_resources(manifest)
        cs = canonical_change_set(
            kind="destroy" if destroy else "apply",
            workspace_hash=workspace.content_hash,
            resources=resources,
            plan_digest=plan_digest,
        )
        return cs, workspace, plan_digest

    # -- ProvisioningRunner protocol ------------------------------------------

    def validate(self, manifest: dict) -> RunnerValidationResult:
        errors = [f"manifest missing '{k}'" for k in _REQUIRED_KEYS if k not in manifest]
        if not manifest.get("topology"):
            errors.append("manifest topology is empty")
        if not manifest.get("toolchain_profile_hash"):
            errors.append("manifest has no toolchain profile binding")
        return RunnerValidationResult(ok=not errors, errors=errors)

    def dry_run(self, manifest: dict, *, operation_id: str) -> RunnerChangeSet:
        return self._dry_run(manifest, operation_id=operation_id, destroy=False)

    def dry_run_destroy(self, manifest: dict, *, operation_id: str) -> RunnerChangeSet:
        return self._dry_run(manifest, operation_id=operation_id, destroy=True)

    def _dry_run(self, manifest: dict, *, operation_id: str, destroy: bool) -> RunnerChangeSet:
        if not self.validate(manifest).ok:
            raise RunnerError("manifest is not runnable (redacted)")
        cs, workspace, plan_digest = self._change_set(manifest, destroy=destroy)
        return RunnerChangeSet(
            operation_id=operation_id,
            creates=cs["resources"],
            summary=cs["summary"],
            change_set_hash=change_set_hash(cs),
            workspace_hash=workspace.content_hash,
            plan_digest=plan_digest,
            kind=cs["kind"],
        )

    def apply(self, manifest: dict, *, operation_id: str) -> RunnerApplyResult:
        if not self.validate(manifest).ok:
            raise RunnerError("manifest is not runnable (redacted)")
        workspace, _plan_digest = self._run_plan(manifest, destroy=False)
        workdir = self._renderer.materialize(workspace, root=self._workspace_root)
        result = self._executor.run(self._spec(self._apply_argv(workdir), workdir, "apply"))
        if not result.ok:
            raise RunnerError("opentofu apply failed (redacted)")
        resources = planned_resources(manifest)
        return RunnerApplyResult(
            operation_id=operation_id,
            ok=True,
            resources=resources,
            summary=summarize(resources),
            idempotent_noop=False,
        )

    def destroy(self, manifest: dict, *, operation_id: str) -> RunnerDestroyResult:
        if not self.validate(manifest).ok:
            raise RunnerError("manifest is not runnable (redacted)")
        workspace, _plan_digest = self._run_plan(manifest, destroy=True)
        workdir = self._renderer.materialize(workspace, root=self._workspace_root)
        result = self._executor.run(self._spec(self._destroy_argv(workdir), workdir, "destroy"))
        if not result.ok:
            raise RunnerError("opentofu destroy failed (redacted)")
        resources = planned_resources(manifest)
        return RunnerDestroyResult(
            operation_id=operation_id,
            ok=True,
            destroyed=[r["resource_id"] for r in resources],
            idempotent_noop=False,
        )

    def status(self, operation_id: str) -> RunnerStatus:
        # The durable ProvisioningOperation record is authoritative for real-path status
        # (execution.py reads it before ever calling the runner). The runner itself keeps
        # no cross-instance state; report unknown.
        return RunnerStatus(operation_id=operation_id, state="unknown", exists=False)
