"""Isolated-lab activation helpers (SECP-002B-1A, ADR-013, ADR-030) — worker-only.

The full activation gate is enforced in ``execution.run_real_provisioning``; this module provides:

- ``build_process_executor`` — returns a ``FakeProcessExecutor``, always. It is the DEVELOPMENT and
  simulator path, and it is severed from real execution rather than gated.
- ``authorized_executor_for_operation`` — the production composition: measure this worker's real
  toolchain, ask the control plane whether THIS operation may execute right now, and construct the
  real executor from the answer. It is the only place in the worker where a real process executor
  comes into existence on the shipped path.
- ``issue_authorized_executor`` — the low-level door, taking the durable operation authority rather
  than any form of permission a caller can assert.
- just-in-time secret env building for a would-be lab apply.

WHAT WAS REMOVED, AND WHY IT COULD NOT STAY
--------------------------------------------
``RealLabActivationGrant`` and ``grant_real_lab_activation(gate_passed=...)`` are gone. The grant
was minted by the caller attesting its own gate had passed — ``gate_passed=True`` written at the
one call site — which is the ambient bypass CLAUDE.md §2 forbids, in its purest form: a value that
widens what may execute, supplied by the code being permitted. While `_B1A_SUBPROCESS_SEALED` held
the subprocess shut it was dormant rather than dangerous. ADR-030 retired that seal, and the grant
became the most permissive thing left on the path.

It is not replaced by another token. A caller cannot attest anything here; it supplies identifiers
and what its own filesystem measures, and the answer is computed from durable rows.
"""

from __future__ import annotations

import uuid

from secp_api.config import Settings

from secp_worker.provisioning.process_executor import (
    FakeProcessExecutor,
    ProcessExecutionError,
    ProcessExecutor,
    SubprocessProcessExecutor,
)


def build_process_executor(settings: Settings) -> ProcessExecutor:
    """The development/simulator factory. Returns the fake, and structurally cannot return anything
    else.

    This used to read ``settings.enable_opentofu_subprocess`` together with a grant, held shut by
    `_B1A_SUBPROCESS_SEALED`. ADR-030 retired that seal, and retiring it is what made the rest
    unacceptable rather than merely dormant: a configuration field or a caller-attested
    ``gate_passed`` boolean that widens what may execute would have gone live the moment the seal
    went.

    So the branch is deleted rather than re-gated, and ``settings`` is now **severed** from real
    execution: it is accepted for call-site compatibility and cannot influence the result. A real
    executor requires the durable operation authority, which this function is never handed and must
    never synthesize — see :func:`authorized_executor_for_operation`.

    This function remaining is deliberate. The simulator must keep working without a live worker,
    and the way to guarantee "the simulator can run headless" never implies "real execution can run
    headless" is for the two to be produced by different functions with different inputs, rather
    than by one function with a mode.
    """
    del settings
    return FakeProcessExecutor()


def authorized_executor_for_operation(
    session,
    *,
    operation_id: uuid.UUID,
    organization_id: uuid.UUID,
    worker_installation_id: str,
    toolchain_layout,
    rendered_workspace_hash: str,
) -> SubprocessProcessExecutor:
    """Measure, ask, and construct. The production route to a real process executor.

    Three steps, in this order, and the order is the point:

    1. **Measure.** ``RealToolchainVerifier.measure`` reads this worker's actual executable digest,
       lockfile digest, provider address/version/dirhash and mirror tree hash off disk. It is given
       no expected value, so what it returns is a fact about the machine rather than an echo of the
       profile.
    2. **Ask.** ``authorize_provisioning_execution`` compares that measurement to the pins on the
       operation's toolchain profile, and to twelve other things it reads for itself — the selected
       worker, the target, the freshness of the observation the plan rests on, the approved change
       set, the operation's generation and status. The caller supplies four identifiers and cannot
       choose any expected value.
    3. **Construct.** Only the object returned by step 2 can build the executor, and the executor
       checks that by type rather than by shape.

    ``rendered_workspace_hash`` is the digest of the workspace that will ACTUALLY be applied,
    rendered once by the caller and passed here. Re-rendering to obtain it would authorize a hash
    computed from a second render; rendering is deterministic, so the two would normally agree, and
    "normally agree" is the whole problem — the authorized artifact and the executed artifact must
    be the same object, not two objects that ought to match.

    Raises ``ToolchainMeasurementError`` if the toolchain cannot be read and
    ``ExecutionAuthorityRefused`` if it can be read and is not authorized. Those are deliberately
    different exceptions: one sends an operator to the worker's filesystem, the other to a row.
    """
    from secp_api.provisioning_execution_authority import authorize_provisioning_execution

    from secp_worker.provisioning.toolchain_verify import RealToolchainVerifier

    observed = RealToolchainVerifier(toolchain_layout).measure(
        rendered_workspace_hash=rendered_workspace_hash
    )
    authority = authorize_provisioning_execution(
        session,
        operation_id=operation_id,
        organization_id=organization_id,
        worker_installation_id=worker_installation_id,
        observed_toolchain=observed,
    )
    return issue_authorized_executor(authority)


def issue_authorized_executor(authority: object) -> SubprocessProcessExecutor:
    """The ONLY way to obtain a real process executor.

    Takes the ``AuthorizedExecution`` that ``authorize_provisioning_execution`` returns after every
    ADR-030 condition has held against durable rows. There is deliberately no ``settings``
    parameter, no grant, and no flag: the argument list is the whole authorization surface, and
    nothing in it is a value a caller can assert about itself.

    The refusal for a missing or forged authority comes from the executor's own constructor rather
    than from a check here, so a caller that bypasses this function and constructs the executor
    directly is refused identically. This function exists to give the worker one obvious door, not
    to be the lock.
    """
    if authority is None:
        raise ProcessExecutionError(
            "a real process executor requires the durable operation authority; none was supplied"
        )
    return SubprocessProcessExecutor(authority=authority)


def build_lab_secret_env(config: dict, token_value: str) -> dict[str, str]:
    """Build TF_VAR_* env for a lab apply from JIT-resolved material (worker-only).

    ``token_value`` is resolved just-in-time in the worker (never in the API, never
    persisted). Only the endpoint (non-secret config) and the token are exposed, and both
    flow through the environment allowlist + redaction in the process executor.
    """
    endpoint = str(config.get("base_url", ""))
    env: dict[str, str] = {}
    if endpoint:
        env["TF_VAR_pm_endpoint"] = endpoint
    if token_value:
        env["TF_VAR_pm_api_token"] = token_value
    return env
