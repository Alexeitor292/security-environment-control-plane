"""The credential path, proved by reaching it — and by refusing before reaching anything else.

Companion to ``test_discovery_full_run_reachability``: that file proves the happy path wires every
component together, this one proves the refusals happen in the right ORDER. Order is the whole
property here. A credential resolved for the wrong target, or a signer that is not the selected
worker, must stop the run BEFORE a request goes out — refusing afterwards would mean the target was
already contacted with a credential nobody authorised for it.

The spies fail the test by never being called, rather than by a text scan that breaks when somebody
renames something.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.discovery_observation import Observation
from secp_api.discovery_verification import DISCOVERY_SNAPSHOT_DOMAIN, DISCOVERY_SNAPSHOT_KIND
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
from secp_worker.proxmox_discovery_composition import run_full_discovery

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
ORG = uuid.uuid4()
TARGET_ID = uuid.uuid4()
WORKER = "wk-1"
OPERATION = "op-1"
GENERATION = 3
AUTHORITY = "pve.example.test:8006"
FAKE_TOKEN = "secpdisc@pve!discovery=00000000-0000-0000-0000-000000000000"
ROLE = "proxmox_privileged"
RELEASE = "sha256:" + "r" * 64


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
    def __init__(self) -> None:
        self.built_with: list[dict] = []
        self.requested: list[str] = []

    def build(self, *, base_url: str, ca_path: str, token: str):
        self.built_with.append({"base_url": base_url, "ca_path": ca_path, "token": token})
        requested = self.requested

        class _T:
            def execute(self, operation):
                path = operation.rendered_path()
                requested.append(path)
                if path == "/version":
                    return {"version": "9.1.1", "release": "9.1", "repoid": "abc1234567"}
                raise RuntimeError("proxmox_discovery_endpoint_absent")

        return _T()


class _SpySigner:
    def __init__(self, priv: str, pub: str, installation: str = WORKER) -> None:
        self._priv, self._pub, self._installation = priv, pub, installation
        self.signed_digests: list[str] = []

    def installation_id(self) -> str:
        return self._installation

    def key_fingerprint(self) -> str:
        return key_id_for(self._pub)

    def role(self) -> str:
        return ROLE

    def release_fingerprint(self) -> str:
        return RELEASE

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


def _control_plane_facts() -> dict[str, Observation]:
    return {
        "target_identity": Observation.observed(str(TARGET_ID)),
        "observation_timestamp": Observation.observed(NOW.isoformat()),
        "worker_identity": Observation.observed(WORKER),
        "evidence_signature": Observation.observed("pending"),
        "worker_release_fingerprint": Observation.observed(RELEASE),
        "target_tls_identity": Observation.observed("sha256:" + "t" * 64),
    }


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
        expected_worker_installation_id=WORKER,
        expected_worker_key_fingerprint=key_id_for(pub),
        control_plane_facts=_control_plane_facts(),
        freshness_bound_seconds=1800,
        now=NOW,
        started_at=NOW - timedelta(seconds=30),
        completed_at=NOW - timedelta(seconds=10),
    )
    kwargs.update(overrides)
    return run_full_discovery(**kwargs), resolver, signer, factory, pub


# === the guarded resolver IS reached ==============================================================


def test_the_production_path_calls_the_guarded_resolver():
    result, resolver, _signer, _factory, _pub = _run()
    assert resolver.calls, "the production composition never called the resolver"
    purpose, worker, _now = resolver.calls[0]
    assert purpose is ResolutionPurpose.proxmox_readonly_discovery
    assert worker == WORKER
    assert result.binding is not None


def test_the_resolved_token_reaches_the_transport_and_nowhere_else():
    result, _resolver, _signer, factory, _pub = _run()
    assert factory.built_with[0]["token"] == FAKE_TOKEN
    # And it appears in none of the durable products of the run.
    assert FAKE_TOKEN not in repr(result.manifest.canonical())
    assert FAKE_TOKEN not in repr(result.binding.canonical())
    assert FAKE_TOKEN not in repr(result.observations)
    assert FAKE_TOKEN not in repr(result.required_facts)
    assert FAKE_TOKEN not in repr(result.attestation)


# === refusals happen BEFORE anything is contacted =================================================


def test_a_resolution_failure_refuses_before_any_request():
    result, _resolver, _signer, factory, _pub = _run(
        resolver=_SpyResolver(raises=SecretResolutionUnavailable("sealed"))
    )
    assert result.failed is True
    assert result.failure_reason == "credential_unavailable"
    assert factory.built_with == [], "a transport was built despite no credential"
    assert factory.requested == []
    assert result.manifest.operations == ()
    assert result.attestation is None


def test_the_sealed_default_resolver_fails_closed():
    result, _r, _s, factory, _pub = _run(resolver=SealedDiscoveryCredentialResolver())
    assert result.failed is True
    assert factory.built_with == []
    assert factory.requested == []


def test_a_mismatched_resolution_binding_refuses_before_resolution():
    """Wrong worker, org or target refuses before the credential is even fetched."""
    _req, expectation = _resolution()
    other_request, _e = _resolution(worker_installation_id="wk-9999")
    result, resolver, _s, factory, _pub = _run(resolution=(other_request, expectation))
    assert result.failed is True
    assert resolver.calls == [], "the resolver was called despite a binding mismatch"
    assert factory.built_with == []


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


# === the resolution contract itself ===============================================================


def test_the_builder_fixes_the_purpose_and_refuses_an_unbound_worker():
    request, contract = _resolution()
    assert contract.purpose is ResolutionPurpose.proxmox_readonly_discovery
    assert contract.contract_version == DISCOVERY_RESOLUTION_CONTRACT_VERSION
    assert request is not None
    with pytest.raises(ResolutionContractViolation, match="worker_unbound"):
        _resolution(worker_installation_id="")
    with pytest.raises(ResolutionContractViolation, match="operation_unbound"):
        _resolution(operation_identity="")


def test_the_request_cannot_be_constructed_directly():
    from secp_worker.preflight.secret_resolution import TrustedDiscoveryResolutionRequest

    _request, contract = _resolution()
    assert contract is not None
    with pytest.raises(TypeError, match="worker-constructed only"):
        TrustedDiscoveryResolutionRequest(contract, token=object())


# === no key or signature may arrive from orchestration ============================================


def test_the_signer_seam_takes_no_key_from_orchestration():
    """There is no key parameter, so a private key cannot arrive from a caller."""
    import inspect

    from secp_worker.proxmox_discovery_composition import WorkerLocalSigner

    sig = inspect.signature(WorkerLocalSigner.sign_discovery_binding)
    assert set(sig.parameters) == {"self", "digest"}


def test_the_production_run_accepts_no_signature_or_key_material():
    import inspect

    params = set(inspect.signature(run_full_discovery).parameters)
    for banned in ("private_key", "private_key_hex", "signature", "signature_valid", "signing_key"):
        assert banned not in params, banned


def test_the_worker_local_signer_is_reached_and_signs_the_binding_it_built():
    result, _resolver, signer, _factory, _pub = _run()
    assert signer.signed_digests == [result.binding.digest()]
