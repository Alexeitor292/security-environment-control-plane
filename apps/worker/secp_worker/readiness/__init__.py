"""Worker-owned readiness package (SECP-002B-1B, B1B-PR4 / ADR-021).

Every external readiness contact — the remote-state backend and the secret manager — happens ONLY
here, in the worker, behind a sealed-by-default composition. ``apps/api`` never imports this package
(the architecture-boundary lock enforces it).

This package NEVER:

* runs OpenTofu or Terraform, or any of ``init``/``plan``/``show``/``apply``/``destroy``/``import``/
  ``refresh``/``output``/``state``/``force-unlock``/``workspace``/``providers``/``console``/
  ``validate``;
* executes a subprocess, ``os.system``, or ``os.popen``;
* imports ``OpenTofuRunner``, a process executor, a renderer, a provider mutation client, or the
  provisioning activation module;
* constructs a ``RealLabActivationGrant``;
* renders an OpenTofu workspace;
* creates, reads, writes, uploads, downloads, copies, restores, migrates, deletes, or exposes an
  OpenTofu state payload;
* reads or mutates ``os.environ``;
* persists, logs, audits, returns, serializes, or hashes a provisioning secret or a secret
  reference;
* advances to a plan, an apply, or a destroy.

Readiness is a validation posture. It STOPS.
"""

from __future__ import annotations

from secp_worker.readiness.composition import (
    ReadinessComposition,
    build_readiness_composition,
    sealed_readiness_composition,
)
from secp_worker.readiness.plan_env import (
    PlanSecretEnvContract,
    PlanSecretEnvViolation,
    build_plan_secret_env,
)
from secp_worker.readiness.plan_secret_readiness import (
    PlanSecretReadinessResult,
    run_plan_secret_readiness,
)
from secp_worker.readiness.self_test import (
    PlanSecretSelfTest,
    PlanSecretSelfTestResult,
    SealedPlanSecretSelfTest,
)
from secp_worker.readiness.state_adapter import (
    LockCapabilityProof,
    RemoteStateAdapterReport,
    RemoteStateReadinessAdapter,
    RemoteStateReadinessBinding,
    RemoteStateReadinessUnavailable,
    SealedRemoteStateReadinessAdapter,
    StateProof,
)
from secp_worker.readiness.state_readiness import (
    RemoteStateReadinessResult,
    run_remote_state_readiness,
)

__all__ = [
    "LockCapabilityProof",
    "PlanSecretEnvContract",
    "PlanSecretEnvViolation",
    "PlanSecretReadinessResult",
    "PlanSecretSelfTest",
    "PlanSecretSelfTestResult",
    "SealedPlanSecretSelfTest",
    "ReadinessComposition",
    "RemoteStateAdapterReport",
    "RemoteStateReadinessAdapter",
    "RemoteStateReadinessBinding",
    "RemoteStateReadinessResult",
    "RemoteStateReadinessUnavailable",
    "SealedRemoteStateReadinessAdapter",
    "StateProof",
    "build_plan_secret_env",
    "build_readiness_composition",
    "run_plan_secret_readiness",
    "run_remote_state_readiness",
    "sealed_readiness_composition",
]
