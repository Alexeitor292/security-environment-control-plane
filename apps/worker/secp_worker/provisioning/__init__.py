"""Worker-only provisioning runner seam (ADR-012).

NEVER imported by ``apps/api``. Implements only a FakeOpenTofuRunner in
SECP-002B-0 — no subprocess, network, provider client, or OpenTofu/Terraform
binary. A future real ``OpenTofuRunner`` will implement the same protocol behind
the same gate.
"""

from secp_worker.provisioning.fake_opentofu import FakeOpenTofuRunner
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

__all__ = [
    "DbRunnerStateStore",
    "FakeOpenTofuRunner",
    "ProvisioningRunner",
    "RunnerApplyResult",
    "RunnerChangeSet",
    "RunnerDestroyResult",
    "RunnerError",
    "RunnerStatus",
    "RunnerStateStore",
    "RunnerValidationResult",
]
