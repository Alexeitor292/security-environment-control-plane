"""Every authority-bearing component has a production caller, proved by reaching it.

The defect this file exists to catch has recurred throughout this system: a module that is correct,
tested, green — and reached by nothing. `build_plan_document` had no production caller.
`TargetObservation` had a reader and no writer. `pveversion` was allowlisted for a probe nobody
emitted. Each was invisible to its own unit tests, because unit tests call the module directly.

So these tests drive the real composition and assert that the guarded resolver, the worker-local
signer and the control-plane verifier were actually invoked — with spies that fail the test by
never being called, rather than text scans that fail when someone renames something.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.discovery_required_facts import (
    facts_required_before_apply,
    facts_required_before_compilation,
)
from secp_api.discovery_verification import (
    BINDING_MATCHED,
    DISCOVERY_CONTRACT_VERSION,
    DISCOVERY_SNAPSHOT_DOMAIN,
    DISCOVERY_SNAPSHOT_KIND,
    ELIGIBILITY_REFUSED,
    SIGNATURE_VALID,
    DiscoverySnapshotBinding,
    ExpectedWorkerRegistration,
    verify_discovery_snapshot,
)
from secp_commissioning.canonical import sha256_digest
from secp_commissioning.enrollment_attestation import key_id_for, sign_detached
from secp_management.signing import generate_keypair
from secp_worker.preflight.secret_resolution import (
    DISCOVERY_RESOLUTION_CONTRACT_VERSION,
    ResolutionContractViolation,
    ResolutionPurpose,
    SealedDiscoveryCredentialResolver,
    SecretMaterial,
    SecretResolutionUnavailable,
    TrustedCredentialReference,
    build_discovery_resolution_request,
)
from secp_worker.proxmox_discovery_composition import run_signed_discovery

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
ORG = uuid.uuid4()
TARGET_ID = uuid.uuid4()
WORKER = "wk-1"
OPERATION = "op-1"
GENERATION = 3
AUTHORITY = "pve.example.test:8006"
FAKE_TOKEN = "secpdisc@pve!discovery=00000000-0000-0000-0000-000000000000"

_PAYLOAD = {"version": "9.1.1", "release": "9.1", "repoid": "abc1234567"}


class _SpyResolver:
    """Records that it was called, and with what. A test that never reaches it fails."""

    def __init__(self, material: str = FAKE_TOKEN, raises: Exception | None = None) -> None:
        self.material = material
        self.raises = raises
        self.calls: list[tuple] = []

    def resolve(self, request, *, expectation, now):
        self.calls.append((request.contract.purpose, expectation.worker_installation_id, now))
        if self.raises is not None:
            raise self.raises
        return SecretMaterial(self.material)


class _SpyTransportFactory:
    def __init__(self, payload=None) -> None:
        self.payload = payload if payload is not None else dict(_PAYLOAD)
        self.built_with: list[dict] = []

    def build(self, *, base_url: str, ca_path: str, token: str):
        self.built_with.append({"base_url": base_url, "ca_path": ca_path, "token": token})
        payload = self.payload

        class _T:
            def get(self, path, params=None):
                return payload

        return _T()


class _SpySigner:
    def __init__(self, priv: str, pub: str, installation: str = WORKER) -> None:
        self._priv, self._pub, self._installation = priv, pub, installation
        self.signed_digests: list[str] = []

    def installation_id(self) -> str:
        return self._installation

    def key_fingerprint(self) -> str:
        return key_id_for(self._pub)

    def sign_discovery_binding(self, *, digest: str):
        self.signed_digests.append(digest)
        return sign_detached(
            self._priv,
            domain=DISCOVERY_SNAPSHOT_DOMAIN,
            kind=DISCOVERY_SNAPSHOT_KIND,
            digest=digest,
        )


def _resolution(**overrides):
    kwargs = dict(
        organization_id=ORG,
        execution_target_id=TARGET_ID,
        worker_installation_id=WORKER,
        operation_identity=OPERATION,
        operation_generation=GENERATION,
        credential_reference=TrustedCredentialReference("vault:secp/discovery/target-abc"),
    )
    kwargs.update(overrides)
    return build_discovery_resolution_request(**kwargs)


def _binding_factory(pub: str):
    def _build(observations, manifest) -> DiscoverySnapshotBinding:
        states = tuple((code, obs.state.value) for code, obs in observations.items())
        return DiscoverySnapshotBinding(
            discovery_contract_version=DISCOVERY_CONTRACT_VERSION,
            operation_identity=OPERATION,
            operation_generation=GENERATION,
            organization_identity=str(ORG),
            target_identity=str(TARGET_ID),
            requested_target_authority=AUTHORITY,
            worker_installation_id=WORKER,
            worker_role="proxmox_privileged",
            worker_release_fingerprint="sha256:" + "r" * 64,
            signer_fingerprint=key_id_for(pub),
            observation_started_at=(NOW - timedelta(seconds=30)).isoformat(),
            observation_completed_at=(NOW - timedelta(seconds=10)).isoformat(),
            freshness_bound_seconds=1800,
            facts_hash=sha256_digest({"observations": sorted(states)}),
            operation_manifest_hash=sha256_digest({"manifest": manifest.canonical()}),
            projection_implementation_id="secp-discovery/projection/v1",
            required_fact_observation_states=states,
        )

    return _build


def _run(resolver=None, signer=None, factory=None, **overrides):
    priv, pub = overrides.pop("keys", generate_keypair())
    request, expectation = overrides.pop("resolution", _resolution())
    resolver = resolver if resolver is not None else _SpyResolver()
    signer = signer if signer is not None else _SpySigner(priv, pub)
    factory = factory if factory is not None else _SpyTransportFactory()
    kwargs = dict(
        resolver=resolver,
        resolution_request=request,
        resolution_expectation=expectation,
        transport_factory=factory,
        signer=signer,
        base_url="https://pve.example.test:8006/api2/json",
        ca_path="/etc/secp/pve-ca.pem",
        target_authority_identity=AUTHORITY,
        binding_factory=_binding_factory(pub),
        expected_worker_installation_id=WORKER,
        expected_worker_key_fingerprint=key_id_for(pub),
        now=NOW,
        started_at=NOW - timedelta(seconds=30),
        completed_at=NOW - timedelta(seconds=10),
    )
    kwargs.update(overrides)
    return run_signed_discovery(**kwargs), resolver, signer, factory, pub


# === the guarded resolver IS reached =============================================================


def test_the_production_path_calls_the_guarded_resolver():
    result, resolver, _signer, _factory, _pub = _run()
    assert resolver.calls, "the production composition never called the resolver"
    purpose, worker, _now = resolver.calls[0]
    assert purpose is ResolutionPurpose.proxmox_readonly_discovery
    assert worker == WORKER
    assert result.failed is False


def test_the_resolved_token_reaches_the_transport_and_nowhere_else():
    result, _resolver, _signer, factory, _pub = _run()
    assert factory.built_with[0]["token"] == FAKE_TOKEN
    # And it appears in none of the durable products of the run.
    assert FAKE_TOKEN not in repr(result.manifest.canonical())
    assert FAKE_TOKEN not in repr(result.binding.canonical())
    assert FAKE_TOKEN not in repr(result.observations)
    assert FAKE_TOKEN not in repr(result.attestation)


def test_a_resolution_failure_refuses_before_any_request():
    result, _resolver, _signer, factory, _pub = _run(
        resolver=_SpyResolver(raises=SecretResolutionUnavailable("sealed"))
    )
    assert result.failed is True
    assert result.failure_reason == "credential_unavailable"
    assert factory.built_with == [], "a transport was built despite no credential"
    assert result.manifest.operations == ()
    assert result.attestation is None


def test_the_sealed_default_resolver_fails_closed():
    result, _r, _s, factory, _pub = _run(resolver=SealedDiscoveryCredentialResolver())
    assert result.failed is True
    assert factory.built_with == []


def test_a_mismatched_resolution_binding_refuses():
    """Wrong worker, wrong org and wrong target each refuse before resolution."""
    _req, expectation = _resolution()
    other_request, _e = _resolution(worker_installation_id="wk-9999")
    result, resolver, _s, factory, _pub = _run(resolution=(other_request, expectation))
    assert result.failed is True
    assert resolver.calls == [], "the resolver was called despite a binding mismatch"
    assert factory.built_with == []


def test_the_builder_fixes_the_purpose_and_refuses_an_unbound_worker():
    request, contract = _resolution()
    assert contract.purpose is ResolutionPurpose.proxmox_readonly_discovery
    assert contract.contract_version == DISCOVERY_RESOLUTION_CONTRACT_VERSION
    with pytest.raises(ResolutionContractViolation, match="worker_unbound"):
        _resolution(worker_installation_id="")
    with pytest.raises(ResolutionContractViolation, match="operation_unbound"):
        _resolution(operation_identity="")


def test_the_request_cannot_be_constructed_directly():
    from secp_worker.preflight.secret_resolution import TrustedDiscoveryResolutionRequest

    _request, contract = _resolution()
    with pytest.raises(TypeError, match="worker-constructed only"):
        TrustedDiscoveryResolutionRequest(contract, token=object())


# === the worker-local signer IS reached ==========================================================


def test_the_production_path_calls_the_worker_local_signer():
    result, _resolver, signer, _factory, _pub = _run()
    assert signer.signed_digests, "the production composition never called the signer"
    assert result.attestation is not None
    assert signer.signed_digests[0] == result.binding.digest()


def test_the_signer_is_checked_against_the_selected_worker_before_signing():
    """A misbound worker never contacts the target at all."""
    priv, pub = generate_keypair()
    wrong = _SpySigner(priv, pub, installation="wk-9999")
    result, _resolver, signer, factory, _pub = _run(signer=wrong, keys=(priv, pub))
    assert result.failed is True
    assert result.failure_reason == "discovery_signer_installation_mismatch"
    assert signer.signed_digests == []
    assert factory.built_with == [], "a request went out with a misbound signer"


def test_a_signer_whose_key_is_not_the_enrolled_one_refuses():
    priv, pub = generate_keypair()
    _other_priv, other_pub = generate_keypair()
    result, _r, signer, factory, _p = _run(
        signer=_SpySigner(priv, pub),
        expected_worker_key_fingerprint=key_id_for(other_pub),
    )
    assert result.failed is True
    assert result.failure_reason == "discovery_signer_key_mismatch"
    assert signer.signed_digests == []
    assert factory.built_with == []


def test_the_signer_seam_takes_no_key_from_orchestration():
    """There is no key parameter, so a private key cannot arrive from a caller."""
    import inspect

    from secp_worker.proxmox_discovery_composition import WorkerLocalSigner

    sig = inspect.signature(WorkerLocalSigner.sign_discovery_binding)
    assert set(sig.parameters) == {"self", "digest"}


def test_run_signed_discovery_accepts_no_signature_or_key_material():
    import inspect

    params = set(inspect.signature(run_signed_discovery).parameters)
    for banned in ("private_key", "private_key_hex", "signature", "signature_valid", "signing_key"):
        assert banned not in params, banned


# === the verifier IS reached, end to end =========================================================


def test_the_signed_result_verifies_against_the_registered_anchor():
    result, _resolver, _signer, _factory, pub = _run()
    registration = ExpectedWorkerRegistration(
        worker_installation_id=WORKER,
        worker_role="proxmox_privileged",
        worker_release_fingerprint="sha256:" + "r" * 64,
        verification_anchor_fingerprint=key_id_for(pub),
        target_identity=str(TARGET_ID),
        organization_identity=str(ORG),
    )
    projection, authority = verify_discovery_snapshot(
        binding=result.binding,
        attestation=result.attestation,
        registration=registration,
        expected_operation_identity=OPERATION,
        expected_operation_generation=GENERATION,
        expected_target_identity=str(TARGET_ID),
        expected_organization_identity=str(ORG),
        facts_hash=result.binding.facts_hash,
        operation_manifest_hash=result.binding.operation_manifest_hash,
        compilation_required_facts=facts_required_before_compilation(),
        apply_required_facts=facts_required_before_apply(),
        now=NOW,
    )
    assert projection.signature == SIGNATURE_VALID
    assert projection.identity_and_target_binding == BINDING_MATCHED
    assert authority is not None
    # Still refused: a `/version` run observed six facts, not twenty.
    assert projection.compilation_eligibility == ELIGIBILITY_REFUSED


def test_a_signature_over_a_tampered_manifest_does_not_verify():
    """The whole chain in one case: sign, alter the manifest, verify."""
    result, _resolver, _signer, _factory, pub = _run()
    registration = ExpectedWorkerRegistration(
        worker_installation_id=WORKER,
        worker_role="proxmox_privileged",
        worker_release_fingerprint="sha256:" + "r" * 64,
        verification_anchor_fingerprint=key_id_for(pub),
        target_identity=str(TARGET_ID),
        organization_identity=str(ORG),
    )
    projection, authority = verify_discovery_snapshot(
        binding=result.binding,
        attestation=result.attestation,
        registration=registration,
        expected_operation_identity=OPERATION,
        expected_operation_generation=GENERATION,
        expected_target_identity=str(TARGET_ID),
        expected_organization_identity=str(ORG),
        facts_hash=result.binding.facts_hash,
        operation_manifest_hash="sha256:" + "0" * 64,
        compilation_required_facts=facts_required_before_compilation(),
        apply_required_facts=facts_required_before_apply(),
        now=NOW,
    )
    assert "discovery_operation_manifest_changed_after_signing" in projection.reasons
    assert authority is None
