"""Worker-only provisioning runner seam (ADR-012, ADR-013).

NEVER imported by ``apps/api``. Implements a ``FakeOpenTofuRunner`` (SECP-002B-0) and a
sealed real ``OpenTofuRunner`` (SECP-002B-1A) behind the same ``ProvisioningRunner``
protocol. The real runner executes OpenTofu only through a worker-only ``ProcessExecutor``
seam; in B1-A that is always a ``FakeProcessExecutor`` (no subprocess, network, provider
client, or OpenTofu/Terraform binary). The ``SubprocessProcessExecutor`` exists but is
inert and never invoked in B1-A.
"""

from secp_worker.provisioning.change_set import planned_resources, summarize
from secp_worker.provisioning.fake_opentofu import FakeOpenTofuRunner
from secp_worker.provisioning.opentofu import OpenTofuRunner, PreparedOpenTofuPlan
from secp_worker.provisioning.plan_json import (
    PlanCanonicalizationError,
    build_fixture_show_json,
    canonicalize_plan_json,
    change_set_hash,
)
from secp_worker.provisioning.process_executor import (
    FakeProcessExecutor,
    ProcessExecutor,
    ProcessResult,
    ProcessSpec,
    SubprocessProcessExecutor,
)
from secp_worker.provisioning.rendering import RenderedWorkspace, WorkspaceRenderer
from secp_worker.provisioning.runner import (
    ProvisioningRunner,
    RunnerApplyResult,
    RunnerChangeSet,
    RunnerDestroyResult,
    RunnerError,
    RunnerStatus,
    RunnerValidationResult,
)
from secp_worker.provisioning.state_store import DbRunnerStateStore, RunnerStateStore
from secp_worker.provisioning.toolchain_verify import (
    ATTESTATION_POLICY_VERSION,
    FakeToolchainVerifier,
    RealToolchainVerifier,
    ToolchainAttestationEvidence,
    ToolchainFilesystemLayout,
    ToolchainVerification,
    ToolchainVerifier,
    render_offline_cli_config,
)

__all__ = [
    "ATTESTATION_POLICY_VERSION",
    "DbRunnerStateStore",
    "FakeOpenTofuRunner",
    "FakeProcessExecutor",
    "FakeToolchainVerifier",
    "OpenTofuRunner",
    "PlanCanonicalizationError",
    "PreparedOpenTofuPlan",
    "ProcessExecutor",
    "ProcessResult",
    "ProcessSpec",
    "ProvisioningRunner",
    "RealToolchainVerifier",
    "RenderedWorkspace",
    "RunnerApplyResult",
    "RunnerChangeSet",
    "RunnerDestroyResult",
    "RunnerError",
    "RunnerStatus",
    "RunnerStateStore",
    "RunnerValidationResult",
    "SubprocessProcessExecutor",
    "ToolchainAttestationEvidence",
    "ToolchainFilesystemLayout",
    "ToolchainVerification",
    "ToolchainVerifier",
    "WorkspaceRenderer",
    "build_fixture_show_json",
    "canonicalize_plan_json",
    "change_set_hash",
    "render_offline_cli_config",
    "planned_resources",
    "summarize",
]
