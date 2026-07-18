"""SECP-PR5D — Controlled-live operator deployment package (sealed, NOT activated).

This is the separately-reviewed, root-controlled, deployment-local package the PR5C operator
entrypoint imports (``from secp_operator_deployment import compositions, runner``). It supplies the
typed controlled-live compositions + the worker run hook — but operator activation is HARD-SEALED
here (:data:`secp_operator_deployment.runner._OPERATOR_ACTIVATION_SEALED` is ``True``), so nothing
in
this milestone starts an operator worker, constructs a Temporal ``Worker``, submits a workflow, runs
OpenTofu, resolves a credential, or contacts Proxmox / OpenBao / remote state / Temporal /
PostgreSQL.

It is DECOUPLED from the commissioning engine: ``secp_commissioning`` must never import this package
(it stays a pure, injected-seam engine). This package MAY import ``secp_commissioning`` (for the
injected ``ContainerRuntime`` / ``ServiceStateAdapter`` / ``inspect_host`` seams) and
``secp_worker``
(for the EXACT authoritative composition types + reviewed implementation digests) — it never creates
parallel or weaker composition types.

The shipped/default package state fails closed:
:func:`compositions.build_controlled_live_compositions`
refuses unless a complete, secret-free, root-controlled deployment PROFILE and every reviewed
controlled-live RUNTIME prerequisite are present (both absent by default). Package installation is
NOT
activation.
"""

from __future__ import annotations

# The deployment-package CONTRACT version (distinct from the tool/package version and from the
# commissioning descriptor contract). A profile whose contract_version is not EXACTLY this is
# refused.
PACKAGE_CONTRACT_VERSION = "secp.operator-deployment/v1alpha1"

# The package's own version, recorded in verification evidence.
PACKAGE_VERSION = "0.1.0"

# The reviewed package IMPLEMENTATION identity (bound into provenance + verification evidence). A
# self-declared package identity that differs from this is refused.
PACKAGE_IMPLEMENTATION_ID = "secp-pr5d/operator-deployment/v1"

__all__ = [
    "PACKAGE_CONTRACT_VERSION",
    "PACKAGE_VERSION",
    "PACKAGE_IMPLEMENTATION_ID",
    "package_implementation_digest",
    "DeploymentPackageError",
]


class DeploymentPackageError(Exception):
    """A deployment-package operation failed closed. Carries a BOUNDED reason code; never a value,
    path, endpoint, credential, or raw upstream message."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)

    def __repr__(self) -> str:  # never echo anything but the bounded code
        return f"DeploymentPackageError({self.reason_code!r})"


def package_implementation_digest() -> str:
    """The deterministic aggregate ``sha256:`` digest of the reviewed package IMPLEMENTATION — a
    real
    manifest over the covered package modules (NOT a hash of the identity label). See
    :mod:`secp_operator_deployment.manifest`."""
    from secp_operator_deployment.manifest import implementation_manifest_digest

    return implementation_manifest_digest()
