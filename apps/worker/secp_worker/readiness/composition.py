"""Default-disabled readiness composition (B1B-PR4 / ADR-021 §5).

The SHIPPED composition is fully **sealed**: the gate is disabled and it carries **no** toolchain
filesystem layout, **no** remote-state adapter, **no** resolver self-test, **no** adapter
activation,
and **no** capability. The durable Temporal path therefore runs end to end — records loaded, binding
derived, seam invoked — and REFUSES at the seal **before any disk read, state backend, or secret
manager is touched**.

**The seal is the out-of-band reviewed composition, never an environment flag.** No environment
variable, backend kind, URL string, installed SDK, ``PATH`` entry, database row, or API request can
activate it. A separately reviewed deployment-local composition must supply:

* the explicit, immutable :class:`ToolchainFilesystemLayout` (for real on-disk attestation);
* the remote-state adapter **and** its reviewed :class:`AdapterActivation`;
* the secret-backend self-test **and** its reviewed :class:`AdapterActivation`.

An adapter WITHOUT a matching reviewed activation obtains no capability and is refused before any
contact — a self-declared ``contract_version`` is never sufficient (B1B-PR4 §3).

``settings`` is accepted for parity with the discovery / eligibility precedent and to make a future
two-factor gate explicit; in B1B-PR4 it wires nothing.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_worker.provisioning.toolchain_verify import ToolchainFilesystemLayout
from secp_worker.readiness.capability import AdapterActivation
from secp_worker.readiness.self_test import PlanSecretSelfTest
from secp_worker.readiness.state_adapter import RemoteStateReadinessAdapter


@dataclass(frozen=True)
class ReadinessGate:
    """Default-**disabled** activation gate.

    A disabled gate refuses BEFORE any layout read, adapter, resolver, self-test, lease, capability,
    or external contact.
    """

    enabled: bool = False


@dataclass(frozen=True)
class ReadinessComposition:
    """The reviewed set of injected seams. The shipped default is fully sealed."""

    gate: ReadinessGate = ReadinessGate()

    # --- real toolchain attestation (B1B-PR4 §1) — worker filesystem only, no execution ----------
    # The EXPLICIT, immutable deployment-local layout. Nothing is inferred from PATH/cwd/HOME/env.
    toolchain_layout: ToolchainFilesystemLayout | None = None

    # --- remote-state readiness: the ONLY thing that may contact a state backend ------------------
    state_adapter: RemoteStateReadinessAdapter | None = None
    # The REVIEWED activation authorizing that exact adapter implementation for that exact
    # operation.
    state_adapter_activation: AdapterActivation | None = None

    # --- plan-secret readiness: the ONLY thing that may contact a secret manager ------------------
    # It is a SELF-TEST — it proves the worker can AUTHENTICATE and returns no target credential.
    resolver_self_test: PlanSecretSelfTest | None = None
    plan_secret_adapter_activation: AdapterActivation | None = None
    # The resolver whose CONTRACT VERSION is bound. PR4 never calls ``resolve()``: the actual target
    # provisioning credential is NOT resolved as project evidence.
    resolver_contract_version: str = ""

    # --- test-only escape hatch (explicitly named; NEVER controlled-live) ------------------------
    # When True, capabilities are issued through ``issue_test_only_capability`` and every record
    # produced is permanently marked ``test_only``. Such evidence can NEVER make combined
    # provisioning readiness current.
    test_only_capability: bool = False


def sealed_readiness_composition() -> ReadinessComposition:
    """The shipped, sealed composition: gate off; no layout, adapter, self-test, or activation."""
    return ReadinessComposition()


def build_readiness_composition(settings=None) -> ReadinessComposition:  # noqa: ANN001
    """Deployment-local composition factory used by the durable Temporal activities.

    SHIPPED DEFAULT: fully **sealed**. The durable path completes, but every seam refuses at the
    seal
    before any disk read, state backend, or secret manager is contacted. A future, separately
    reviewed activation injects the real, gated composition HERE — behind out-of-band reviewed
    material — so no single configuration flag can enable it.
    """
    return sealed_readiness_composition()
