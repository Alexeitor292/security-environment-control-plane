"""Offline, secret-free preflight-wiring self-test (SECP-B2-4.2).

A worker-owned liveness check that proves the shipped read-only-preflight chain is wired
fail-closed WITHOUT resolving a reference, creating credentials, contacting OpenBao/Proxmox/any
backend, constructing a transport, acquiring a lease, or reading the environment/config. It only
constructs the SHIPPED default seals in memory, confirms each denies/disables/seals, and confirms
the mandatory durable activation-capability verifier is present. It returns ONLY a closed status
code and a small map of safe boolean facts — never a reference, secret, endpoint, or record value.

This module performs no I/O and depends on no database, network, environment variable, feature
flag, or activation configuration. It cannot enable anything.
"""

from __future__ import annotations

from dataclasses import dataclass

# Closed status codes (never free text).
SELF_TEST_SEALED_OK = "sealed_ok"
SELF_TEST_MISCONFIGURED = "misconfigured"


@dataclass(frozen=True)
class PreflightSelfTestResult:
    """The closed result of the offline wiring self-test: a closed status + safe boolean facts."""

    status: str
    facts: dict[str, bool]


def _identity_denies_by_default() -> bool:
    """The shipped worker identity verifier denies fail-closed (constructs no identity)."""
    from secp_worker.preflight.identity import (
        DenyingWorkerIdentityVerifier,
        WorkerIdentityUnavailable,
    )

    try:
        DenyingWorkerIdentityVerifier().verify()
    except WorkerIdentityUnavailable:
        return True
    return False


def _activation_gate_disabled_by_default() -> bool:
    """The shipped activation gate is disabled fail-closed (cannot be enabled by config/env/DB)."""
    from secp_worker.preflight.activation_gate import (
        ResolutionActivationDisabled,
        SealedActivationGate,
    )

    try:
        SealedActivationGate().check()
    except ResolutionActivationDisabled:
        return True
    return False


def _shipped_resolver_is_sealed() -> bool:
    """The shipped/default preflight resolver is the sealed (never-resolving) resolver type."""
    from secp_worker.preflight.sealed_secret_resolver import SealedSecretResolver
    from secp_worker.preflight.secret_resolution import SealedUnavailableResolver

    return issubclass(SealedSecretResolver, SealedUnavailableResolver)


def _activation_capability_required() -> bool:
    """The mandatory durable activation-capability verifier is wired into the orchestration."""
    from secp_worker.preflight import orchestration

    verifier = getattr(orchestration, "load_and_verify_activation_capability", None)
    return callable(verifier)


def run_preflight_wiring_self_test() -> PreflightSelfTestResult:
    """Run the offline, secret-free preflight-wiring self-test.

    Constructs only the shipped default seals in memory and confirms the chain is fail-closed and
    the mandatory activation-capability verifier is present. Resolves nothing, contacts nothing,
    reads no environment/config, and returns only a closed status + safe boolean facts.
    """
    facts = {
        "identity_denies_by_default": _identity_denies_by_default(),
        "activation_gate_disabled_by_default": _activation_gate_disabled_by_default(),
        "shipped_resolver_is_sealed": _shipped_resolver_is_sealed(),
        "activation_capability_required": _activation_capability_required(),
    }
    status = SELF_TEST_SEALED_OK if all(facts.values()) else SELF_TEST_MISCONFIGURED
    return PreflightSelfTestResult(status=status, facts=facts)
