"""Sealed, fail-closed composition seams for the deployment engine (SECP-B4 corrective).

Each seam here is the boundary to a piece of real infrastructure whose implementation is
INTEGRATION-
BLOCKED until it can be validated against the disposable isolated staging target: provider/host
discovery of exact locators, the OpenBao handoff, and observed post-deploy verification evidence.
The shipped default of every seam REFUSES (or reports "unverifiable"), so the engine fails closed
and
performs no real action until a reviewed real composition is supplied out of band on the worker.

Nothing here contacts a host, reads a secret, or performs I/O. The engine's decision logic that
consumes these seams is fully unit-testable with injected fakes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from secp_api.enums import DeploymentResourceKind

from secp_worker.deployment.locators import ResourceLocator


class DiscoveryUnavailable(Exception):
    """The provider discovery backend is sealed — no exact locator can be supplied. Fail closed."""

    def __init__(self, reason_code: str = "discovery_required") -> None:
        super().__init__(f"discovery unavailable: {reason_code}")
        self.reason_code = reason_code


class OpenBaoHandoffUnavailable(Exception):
    """The OpenBao handoff backend is sealed — no scoped credential can be stored. Fail closed."""

    def __init__(self, reason_code: str = "openbao_handoff_failed") -> None:
        super().__init__(f"openbao handoff unavailable: {reason_code}")
        self.reason_code = reason_code


@runtime_checkable
class DeploymentLocatorSource(Protocol):
    """Supplies the EXACT discovered provider locator for each planned resource kind. A real source
    derives locators from the approved plan's discovered inventory (enrolled node, selected storage,
    allocated VMIDs, generated owned names). The shipped default refuses (discovery sealed)."""

    def locator_for(self, kind: DeploymentResourceKind) -> ResourceLocator: ...


class SealedDeploymentLocatorSource:
    """The shipped default: NO discovered locators. Refuses — the plan is not executable until real
    read-only discovery supplies exact locators (integration-blocked)."""

    def locator_for(self, kind: DeploymentResourceKind) -> ResourceLocator:
        raise DiscoveryUnavailable()


@runtime_checkable
class OpenBaoHandoff(Protocol):
    """Boots/uses OpenBao in the control-plane VM and stores the scoped Proxmox credential after
    verified readiness. The shipped default refuses (not ready; stores nothing)."""

    def is_ready(self) -> bool: ...

    def store_scoped_credential(self, *, credential_ref: str, owner_marker: str) -> None: ...


class SealedOpenBaoHandoff:
    """The shipped default: OpenBao is not booted/ready; storing a credential refuses."""

    def is_ready(self) -> bool:
        return False

    def store_scoped_credential(self, *, credential_ref: str, owner_marker: str) -> None:
        raise OpenBaoHandoffUnavailable()


# Observed post-deploy verification evidence. Each value is True (positively observed), False
# (observed to fail), or None (not observed → unverifiable). There is NO static "passed" anywhere.
VerificationEvidence = dict[str, bool | None]


@runtime_checkable
class VerificationEvidenceCollector(Protocol):
    """Collects observed post-deploy evidence for the closed verification checks (isolation, routes,
    control-plane health, OpenBao readiness/resolution, canary GET). The shipped default observes
    NOTHING, so every externally-observed check is ``unverifiable``."""

    def collect(self) -> VerificationEvidence: ...


class SealedVerificationEvidenceCollector:
    """The shipped default: observes nothing. Every check it would supply is unverifiable."""

    def collect(self) -> VerificationEvidence:
        return {}


@dataclass(frozen=True)
class RemotePoPOutcome:
    ok: bool
    reason_code: str


@runtime_checkable
class RemotePoPAuthority(Protocol):
    """Runs the full verifier-issued-challenge → deployment-local Ed25519 sign → verify cycle for
    one
    operation, bound to the exact deployment/operation/org/registration/identity-version/plan-hash,
    with a durable single-use nonce store. The shipped default refuses (no signer)."""

    def prove(
        self,
        *,
        deployment_id: object,
        operation_fingerprint: str,
        organization_id: object,
        worker_registration_id: object,
        worker_identity_version: int,
        plan_hash: str,
    ) -> RemotePoPOutcome: ...


class SealedRemotePoPAuthority:
    """The shipped default: NO deployment-local signer. Proof refuses — never asserts success."""

    def prove(self, **_kwargs: object) -> RemotePoPOutcome:
        return RemotePoPOutcome(False, "remote_pop_unavailable")
