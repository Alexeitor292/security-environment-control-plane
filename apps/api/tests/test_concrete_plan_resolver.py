"""B1B-PR5B — the concrete OpenBao plan-execution secret resolver + client (ADR-022 §10).

The reviewed, in-repository CONCRETE ``WorkerPlanSecretResolver`` is sealed by default (no injected
client → fail closed), enforces the full plan-execution contract BEFORE any client is touched,
resolves ONLY the authoritative ``openbao``/``vault`` reference, and never logs / returns / leaks a
secret or reference. No OpenBao endpoint, token, or credential is present anywhere. These tests
inject a fake client / transport only; nothing contacts a network.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from secp_worker.plan_gen.openbao_plan_resolver import (
    ConcreteOpenBaoPlanSecretClient,
    OpenBaoPlanSecretResolver,
    PlanSecretBackendError,
    SealedPlanSecretBackendTransport,
)
from secp_worker.plan_gen.plan_secret_resolution import (
    PlanCredentialReference,
    PlanResolutionContractViolation,
    PlanSecretResolutionUnavailable,
    build_trusted_plan_resolution_request,
)
from secp_worker.preflight.secret_resolution import SecretMaterial
from tests.test_plan_execution_components import NOW, _contract, _resolver_capability


class _FakeClient:
    """Records the exact reference/scheme it was asked to resolve and returns a fixed secret."""

    def __init__(self, secret: str = "PROVIDER-TOKEN-VALUE") -> None:
        self.secret = secret
        self.calls: list[tuple[str, str]] = []

    def read_plan_secret(self, *, reference: str, scheme: str, now: datetime) -> str:
        self.calls.append((reference, scheme))
        return self.secret


class _RaisingClient:
    def read_plan_secret(self, *, reference: str, scheme: str, now: datetime) -> str:
        raise PlanSecretBackendError("reference_unknown")


def _request_expectation_capability(contract=None):
    contract = contract if contract is not None else _contract()
    request = build_trusted_plan_resolution_request(contract)
    capability = _resolver_capability(contract)
    return request, contract, capability


# --- the resolver: sealed by default; contract enforced BEFORE the client ------------------------


def test_sealed_by_default_enforces_contract_then_fails_closed():
    request, expectation, capability = _request_expectation_capability()
    resolver = OpenBaoPlanSecretResolver()  # no client injected
    with pytest.raises(PlanSecretResolutionUnavailable):
        resolver.resolve(request, expectation=expectation, capability=capability, now=NOW)


def test_contract_drift_is_refused_before_any_client_is_touched():
    _, expectation, capability = _request_expectation_capability()
    # A candidate request whose fingerprint drifts from the expectation is refused per-fact — the
    # client (which would resolve) is never even constructed.
    drifted = _contract(operation_fingerprint="sha256:" + "9" * 64)
    request = build_trusted_plan_resolution_request(drifted)
    client = _FakeClient()
    resolver = OpenBaoPlanSecretResolver(client=client)
    with pytest.raises(PlanResolutionContractViolation, match="operation_fingerprint_mismatch"):
        resolver.resolve(request, expectation=expectation, capability=capability, now=NOW)
    assert client.calls == []


def test_non_capability_object_is_refused():
    request, expectation, _ = _request_expectation_capability()
    resolver = OpenBaoPlanSecretResolver(client=_FakeClient())
    with pytest.raises(PlanResolutionContractViolation, match="resolver_capability_invalid"):
        resolver.resolve(request, expectation=expectation, capability=object(), now=NOW)


def test_secretref_scheme_is_refused_by_the_openbao_adapter():
    # ``secretref`` is valid for the plan-execution contract but is NOT an OpenBao reference; this
    # adapter refuses it (a different reviewed adapter would resolve it) BEFORE the client boundary.
    contract = _contract(
        credential_reference=PlanCredentialReference("secretref://x", scheme="secretref")
    )
    request, expectation, capability = _request_expectation_capability(contract)
    client = _FakeClient()
    resolver = OpenBaoPlanSecretResolver(client=client)
    with pytest.raises(PlanResolutionContractViolation, match="reference_scheme_unsupported"):
        resolver.resolve(request, expectation=expectation, capability=capability, now=NOW)
    assert client.calls == []


def test_happy_path_resolves_the_authoritative_reference_into_secret_material():
    contract = _contract(
        credential_reference=PlanCredentialReference("openbao://kv/data/proxmox", scheme="openbao")
    )
    request, expectation, capability = _request_expectation_capability(contract)
    client = _FakeClient(secret="TOP-SECRET-TOKEN")
    resolver = OpenBaoPlanSecretResolver(client=client)

    material = resolver.resolve(request, expectation=expectation, capability=capability, now=NOW)
    assert isinstance(material, SecretMaterial)
    assert material.reveal_secret() == "TOP-SECRET-TOKEN"
    # The AUTHORITATIVE reference (from the expectation) + its scheme were resolved — exactly once.
    assert client.calls == [("openbao://kv/data/proxmox", "openbao")]
    # The material is redacted in every string form (never leaks the secret).
    assert "TOP-SECRET-TOKEN" not in repr(material)


def test_backend_failure_maps_to_a_closed_reason_without_leaking():
    contract = _contract(
        credential_reference=PlanCredentialReference("openbao://kv/data/x", scheme="openbao")
    )
    request, expectation, capability = _request_expectation_capability(contract)
    resolver = OpenBaoPlanSecretResolver(client=_RaisingClient())
    with pytest.raises(PlanSecretResolutionUnavailable) as exc:
        resolver.resolve(request, expectation=expectation, capability=capability, now=NOW)
    # The closed reason code surfaces; the reference/secret never does.
    assert "reference_unknown" in str(exc.value)
    assert "kv/data/x" not in str(exc.value)


# --- the concrete client over an injected transport ----------------------------------------------


class _FakeTransport:
    def __init__(self, payload) -> None:  # noqa: ANN001
        self.payload = payload
        self.locators: list[str] = []

    def read(self, *, locator: str, now: datetime):  # noqa: ANN201
        self.locators.append(locator)
        return self.payload


def test_concrete_client_extracts_the_opaque_locator_and_secret():
    transport = _FakeTransport({"value": "SECRET-XYZ"})
    client = ConcreteOpenBaoPlanSecretClient(transport=transport)
    secret = client.read_plan_secret(
        reference="openbao://kv/data/proxmox", scheme="openbao", now=NOW
    )
    assert secret == "SECRET-XYZ"
    # Only the opaque locator (never the scheme prefix / endpoint) reaches the transport.
    assert transport.locators == ["kv/data/proxmox"]
    # A vault reference resolves the same way (both schemes supported).
    assert client.read_plan_secret(reference="vault:kv/data/x", scheme="vault", now=NOW)


@pytest.mark.parametrize(
    ("reference", "scheme"),
    [
        ("openbao://../escape", "openbao"),  # dot-segment traversal
        ("openbao:///leading", "openbao"),  # empty first segment
        ("openbao://kv/data/proxmox", "vault"),  # scheme prefix mismatch
        ("", "openbao"),  # blank
        ("openbao://has space", "openbao"),  # whitespace
    ],
)
def test_concrete_client_refuses_malformed_or_mismatched_references(reference, scheme):
    client = ConcreteOpenBaoPlanSecretClient(transport=_FakeTransport({"value": "x"}))
    with pytest.raises(PlanSecretBackendError):
        client.read_plan_secret(reference=reference, scheme=scheme, now=NOW)


def test_concrete_client_maps_a_missing_value_to_reference_unknown():
    client = ConcreteOpenBaoPlanSecretClient(transport=_FakeTransport({"not_value": "x"}))
    with pytest.raises(PlanSecretBackendError, match="reference_unknown"):
        client.read_plan_secret(reference="openbao://kv/data/x", scheme="openbao", now=NOW)


def test_sealed_transport_refuses_with_a_closed_reason():
    client = ConcreteOpenBaoPlanSecretClient(transport=SealedPlanSecretBackendTransport())
    with pytest.raises(PlanSecretBackendError, match="plan_secret_transport_sealed"):
        client.read_plan_secret(reference="openbao://kv/data/x", scheme="openbao", now=NOW)
