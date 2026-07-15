"""The plan-only OpenTofu runner (B1B-PR5B, ADR-022 §5/§6) — worker-only.

:class:`PlanOnlyOpenTofuRunner` drives the ONE reviewed plan-only sequence and STOPS at a durable,
redacted canonical change set awaiting human approval. The ordering materializes the secret-free
workspace BEFORE any secret-manager contact:

    secret-free render output → safe ephemeral workspace (materialize) → resolve the two credentials
    (the injected ``resolve_child_env`` callback, called only AFTER materialization) → build the
    typed :class:`PlanOnlyExecutionContext` → offline ``init`` (plugin-dir bound to the attested
    mirror) → non-destroy ``plan`` → re-validate the transient binary plan file → ``show -json`` →
    in-memory canonicalize + redact → manifest-EXACT change policy → ``(canonical change set,
    change_set_hash)`` → workspace + plan discarded.

It has NO ``apply``/``destroy``/``apply_prepared``/``destroy_prepared``/``refresh``/``import``
method.
The subprocess is created ONLY by the injected executor factory (the sealed production issuer on the
shipped path). Every failure raises :class:`PlanOnlyRunError` with a bounded reason code — never an
argv, path, endpoint, secret, environment value, or process output.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from secp_scenario_schema import content_hash

from secp_worker.plan_gen.change_policy import (
    PLAN_CHANGE_POLICY_VERSION,
    ExpectedPlanContext,
    PlanChangePolicyError,
    PlanChangePolicyEvaluator,
)
from secp_worker.plan_gen.ephemeral_workspace import (
    EphemeralWorkspaceError,
    plan_only_workspace,
    validate_transient_plan_file,
)
from secp_worker.plan_gen.process_boundary import (
    PlanOnlyExecutionContext,
    PlanOnlyProcessError,
    PlanOnlyProcessExecutor,
    build_init_command,
    build_plan_command,
    build_show_command,
    issue_plan_only_executor,
)
from secp_worker.plan_gen.reattest import AttestedToolchain
from secp_worker.provisioning.plan_json import (
    PlanCanonicalizationError,
    canonicalize_plan_json,
    change_set_hash,
)

PLAN_ONLY_RUNNER_VERSION = "secp-002b-1b-pr5b/plan-only-runner/v1"

ExecutorFactory = Callable[..., PlanOnlyProcessExecutor]
# The injected callback that resolves the two credentials + builds the exact child env — called ONLY
# after the workspace is materialized, so no secret manager is contacted before materialization.
ResolveChildEnv = Callable[[], Mapping[str, str]]


class PlanOnlyRunError(Exception):
    """A plan-only run failed at a bounded, secret-free step (carries a reason code only)."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class PlanOnlyPlanResult:
    """In-memory outcome of a plan-only run: a redacted change set + its exact hash (no plan)."""

    change_set: dict
    change_set_hash: str
    workspace_hash: str
    created: int
    resource_types: tuple[str, ...]
    change_policy_version: str = PLAN_CHANGE_POLICY_VERSION
    runner_version: str = PLAN_ONLY_RUNNER_VERSION


def _workspace_hash(files: Mapping[str, str]) -> str:
    return content_hash({"files": {name: files[name] for name in sorted(files)}})


class PlanOnlyOpenTofuRunner:
    """Drive the plan-only ``init``/``plan``/``show`` sequence; STOP at a redacted change set."""

    def __init__(self, *, executor_factory: ExecutorFactory = issue_plan_only_executor) -> None:
        self._executor_factory = executor_factory

    def generate_plan(  # noqa: PLR0913
        self,
        *,
        files: Mapping[str, str],
        trusted_root: str,
        resolve_child_env: ResolveChildEnv,
        attested: AttestedToolchain,
        capability: object,
        expected_lease_id: object,
        expected_attempt_id: object,
        expected_attempt_number: int,
        operation_fingerprint: str,
        env_contract_version: str,
        expected_plan_context: ExpectedPlanContext,
        provenance: Mapping[str, object],
        timeout: int,
        max_output_bytes: int,
        now: object,
    ) -> PlanOnlyPlanResult:
        """Run the reviewed plan-only sequence once; return a redacted change set or fail closed."""
        try:
            with plan_only_workspace(files, trusted_root=trusted_root) as ws:
                # Secret-manager contact happens ONLY here, after the workspace is materialized.
                child_env = dict(resolve_child_env())
                context = PlanOnlyExecutionContext(
                    executable_handle=attested.executable,
                    provider_mirror_handle=attested.provider_mirror,
                    cli_config_handle=attested.cli_config,
                    module_bundle_handle=attested.module_bundle,
                    workspace=ws.workspace_dir,
                    plan_file=ws.plan_file,
                    env=child_env,
                    env_contract_version=env_contract_version,
                    capability=capability,
                    timeout=timeout,
                    max_output_bytes=max_output_bytes,
                    expected_lease_id=expected_lease_id,
                    expected_attempt_id=expected_attempt_id,
                    expected_attempt_number=expected_attempt_number,
                    expected_operation_fingerprint=operation_fingerprint,
                    now=now,
                )
                executor = self._executor_factory(context=context)
                exe = attested.executable.path
                self._run_step(
                    executor,
                    build_init_command(
                        executable=exe,
                        workspace=ws.workspace_dir,
                        plugin_dir=attested.provider_mirror.path,
                    ),
                    fail="init_failed",
                )
                self._run_step(
                    executor,
                    build_plan_command(
                        executable=exe, workspace=ws.workspace_dir, plan_file=ws.plan_file
                    ),
                    fail="plan_failed",
                )
                # Re-validate the transient binary plan BEFORE reading it back with ``show``.
                validate_transient_plan_file(ws.plan_file, workspace_dir=ws.workspace_dir)
                show = self._run_step(
                    executor,
                    build_show_command(
                        executable=exe, workspace=ws.workspace_dir, plan_file=ws.plan_file
                    ),
                    fail="show_failed",
                )
                return self._canonicalize(
                    show.stdout,
                    files=files,
                    provenance=provenance,
                    expected_plan_context=expected_plan_context,
                )
        except EphemeralWorkspaceError as exc:
            reason = (
                "recovery_required" if exc.reason_code == "workspace_residue" else exc.reason_code
            )
            raise PlanOnlyRunError(reason) from exc
        except PlanOnlyProcessError as exc:
            reason = (
                "recovery_required"
                if exc.reason_code == "process_uncertain_termination"
                else (exc.reason_code or "internal")
            )
            raise PlanOnlyRunError(reason) from exc

    def _run_step(self, executor, command, *, fail: str):  # noqa: ANN001
        result = executor.run(command)
        if result.returncode != 0:
            raise PlanOnlyRunError(fail)
        return result

    def _canonicalize(
        self,
        show_stdout: str,
        *,
        files: Mapping[str, str],
        provenance: Mapping[str, object],
        expected_plan_context: ExpectedPlanContext,
    ) -> PlanOnlyPlanResult:
        try:
            show_json = json.loads(show_stdout)
        except (ValueError, TypeError) as exc:
            raise PlanOnlyRunError("plan_json_malformed") from exc
        workspace_hash = _workspace_hash(files)
        try:
            change_set = canonicalize_plan_json(
                show_json, kind="plan", workspace_hash=workspace_hash, provenance=dict(provenance)
            )
        except PlanCanonicalizationError as exc:
            raise PlanOnlyRunError("plan_json_malformed") from exc
        try:
            decision = PlanChangePolicyEvaluator(expected=expected_plan_context).evaluate(
                change_set
            )
        except PlanChangePolicyError as exc:
            raise PlanOnlyRunError(exc.reason_code) from exc
        return PlanOnlyPlanResult(
            change_set=change_set,
            change_set_hash=change_set_hash(change_set),
            workspace_hash=workspace_hash,
            created=decision.created,
            resource_types=decision.resource_types,
            change_policy_version=decision.policy_version,
        )
