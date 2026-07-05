"""SECP-B2-5-pre — behavioral tests for the sealed staging-live composition + canaries.

Everything here is fake-only: no real socket, host, endpoint, credential, certificate, CA, DNS,
OpenBao, or Proxmox is ever contacted. The tests prove:

* the composition factory fails closed on any missing or shipped sealed/deny dependency;
* the OpenBao readiness canary drives the FULL durable authorization chain and proves OpenBao
  authentication WITHOUT resolving a Proxmox credential or contacting Proxmox;
* the Proxmox transport canary runs the single allowlisted GET ONLY after a valid identity,
  activation, and a RESOLVED staging credential, then persists ONLY safe facts through the immutable
  live-evidence boundary (no raw response);
* each broken link in the chain fails the canary closed BEFORE the next privileged boundary;
* the concrete mTLS attestation source and OpenBao client obey proof-of-possession, TLS/redaction,
  and closed-error contracts;
* the first real contact is structurally OpenBao (the Proxmox credential is resolved THROUGH it).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from secp_api.enums import (
    IsolationModel,
    LivePreflightEvidenceStatus,
    OnboardingMode,
    OnboardingStatus,
    ReadonlyPreflightOutcome,
    ResolverActivationEvidenceKind,
    ResolverActivationEvidenceStatus,
    TargetStatus,
)
from secp_api.models import ExecutionTarget, LivePreflightEvidence, TargetOnboarding
from secp_api.services import readonly_preflight, resolver_activation, staging_labs
from secp_worker.preflight.activation_gate import SealedActivationGate
from secp_worker.preflight.backends.openbao_resolver import OpenBaoWorkerSecretResolver
from secp_worker.preflight.identity import DenyingWorkerIdentityVerifier
from secp_worker.preflight.live_evidence_writer import (
    DurableLivePreflightEvidenceWriter,
    SealedLivePreflightEvidenceWriter,
)
from secp_worker.preflight.reverify import DbAuthoritativeReverifier
from secp_worker.preflight.sealed_secret_resolver import SealedSecretResolver
from secp_worker.staging_live.canaries import (
    run_openbao_readiness_canary,
    run_proxmox_transport_canary,
)
from secp_worker.staging_live.composition import (
    StagingLiveCompositionError,
    build_staging_live_composition,
)
from secp_worker.staging_live.mtls_attestation import (
    MtlsIdentityDescriptor,
    MtlsWorkloadIdentitySource,
    SealedMtlsWorkloadMaterial,
    build_operation_challenge,
)
from secp_worker.staging_live.openbao_client import (
    ConcreteOpenBaoClient,
    OpenBaoClientError,
    OpenBaoResolverSelfTest,
    SealedOpenBaoBackendTransport,
    validate_openbao_base_url,
)

VAULT_REF = "vault:secp/proxmox/target-1"
_OBSERVED = {"nodes": ["a", "b"], "storage": ["s1"], "network_segments": ["vmbr0", "vmbr1"]}


# --- Fakes (injected only; never contact anything) -----------------------------------------------


class _ApprovedGate:
    def check(self) -> None:
        return None


class _FakeOpenBaoBackend:
    """A fake OpenBao backend transport. Auth may pass/fail; read returns an opaque secret. Records
    every access so tests can assert ordering + that no read happens in the readiness canary."""

    def __init__(self, *, auth_ok: bool = True, secret: str = "opaque-staging-cred") -> None:
        self._auth_ok = auth_ok
        self._secret = secret
        self.authenticated = 0
        self.reads: list[str] = []

    def authenticate(self, *, now: datetime) -> None:
        self.authenticated += 1
        if not self._auth_ok:
            raise OpenBaoClientError("authentication_failed")

    def read(self, *, locator: str, now: datetime) -> dict:
        self.reads.append(locator)
        return {"value": self._secret}


class _FakeCollector:
    def __init__(self, observed: dict) -> None:
        self._observed = observed
        self.transports: list[object] = []

    def collect(self, transport: object, *, declared_boundary: dict) -> dict:
        self.transports.append(transport)
        return self._observed


def _transport_factory(verified: object, secret: str) -> object:
    # A real factory builds a hardened HttpxReadOnlyTransport; here we return an opaque marker and
    # deliberately never touch the secret beyond receiving it.
    return object()


# --- Durable substrate builders (approved preflight with a vault: reference) ----------------------


def _queued(session, principal, *, secret_ref: str = VAULT_REF):
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref=secret_ref,
        status=TargetStatus.active,
        scope_policy={},
        created_by=principal.user_id,
    )
    session.add(target)
    session.flush()
    session.add(
        TargetOnboarding(
            organization_id=principal.organization_id,
            execution_target_id=target.id,
            onboarding_mode=OnboardingMode.existing_environment,
            isolation_model=IsolationModel.logical,
            status=OnboardingStatus.active,
            declared_boundary={},
            boundary_hash="sha256:" + "cd" * 32,
            created_by=principal.user_id,
        )
    )
    session.flush()
    staging_labs.grant_substrate_eligibility(session, principal, execution_target_id=target.id)
    auth = readonly_preflight.create_preflight_authorization(
        session, principal, execution_target_id=target.id
    )
    readonly_preflight.approve_preflight_authorization(session, principal, auth.id)
    return readonly_preflight.queue_preflight(
        session, principal, live_read_authorization_id=auth.id
    )


def _approve_activation(session, principal, pf) -> None:
    row = resolver_activation.create_activation_authorization(
        session, principal, preflight_id=pf.id
    )
    for kind in ResolverActivationEvidenceKind:
        resolver_activation.record_evidence(
            session,
            principal,
            row.id,
            kind=kind,
            status=ResolverActivationEvidenceStatus.verified,
            proof_id="TKT-1",
            issuer="reviewer",
        )
    resolver_activation.approve_activation_authorization(session, principal, row.id)


def _build_resolver(session, backend: _FakeOpenBaoBackend) -> OpenBaoWorkerSecretResolver:
    client = ConcreteOpenBaoClient(transport=backend)
    return OpenBaoWorkerSecretResolver(
        reverifier=DbAuthoritativeReverifier(session),
        http_client=client,
        self_test=OpenBaoResolverSelfTest(client=client),
    )


def _composition(session, principal, worker_identity_verifier, backend, collector):
    return build_staging_live_composition(
        identity_verifier=worker_identity_verifier(),
        activation_gate=_ApprovedGate(),
        secret_resolver=_build_resolver(session, backend),
        transport_factory=_transport_factory,
        collector=collector,
        evidence_writer=DurableLivePreflightEvidenceWriter(),
    )


# --- 1. Composition factory fails closed ---------------------------------------------------------


def test_composition_rejects_sealed_and_deny_defaults(session, principal, worker_identity_verifier):
    backend = _FakeOpenBaoBackend()
    good = dict(
        identity_verifier=worker_identity_verifier(),
        activation_gate=_ApprovedGate(),
        secret_resolver=_build_resolver(session, backend),
        transport_factory=_transport_factory,
        collector=_FakeCollector(_OBSERVED),
        evidence_writer=DurableLivePreflightEvidenceWriter(),
    )
    # A fully-injected composition builds.
    build_staging_live_composition(**good)

    # Each shipped sealed/deny default is rejected with a closed reason.
    for field, bad in [
        ("identity_verifier", DenyingWorkerIdentityVerifier()),
        ("activation_gate", SealedActivationGate()),
        ("secret_resolver", SealedSecretResolver()),
        ("evidence_writer", SealedLivePreflightEvidenceWriter()),
    ]:
        with pytest.raises(StagingLiveCompositionError):
            build_staging_live_composition(**{**good, field: bad})


def test_composition_rejects_missing_dependency(session, principal, worker_identity_verifier):
    backend = _FakeOpenBaoBackend()
    good = dict(
        identity_verifier=worker_identity_verifier(),
        activation_gate=_ApprovedGate(),
        secret_resolver=_build_resolver(session, backend),
        transport_factory=_transport_factory,
        collector=_FakeCollector(_OBSERVED),
        evidence_writer=DurableLivePreflightEvidenceWriter(),
    )
    with pytest.raises(StagingLiveCompositionError):
        build_staging_live_composition(**{**good, "collector": None})


# --- 2. OpenBao readiness canary: full chain + auth, NO secret, NO Proxmox ------------------------


def test_openbao_readiness_canary_authenticates_without_resolving_or_contacting_proxmox(
    session, principal, worker_identity_verifier
):
    pf = _queued(session, principal)
    _approve_activation(session, principal, pf)
    backend = _FakeOpenBaoBackend(auth_ok=True)
    collector = _FakeCollector(_OBSERVED)
    comp = _composition(session, principal, worker_identity_verifier, backend, collector)

    result = run_openbao_readiness_canary(session, preflight_id=pf.id, composition=comp)

    assert result.ok is True
    assert result.reason_code == "authenticated"
    assert backend.authenticated == 1  # OpenBao auth WAS exercised (full chain reached resolver)
    assert backend.reads == []  # no secret resolved
    assert collector.transports == []  # Proxmox never contacted
    assert session.query(LivePreflightEvidence).count() == 0  # readiness writes no evidence


def test_openbao_readiness_canary_reports_backend_auth_failure_closed(
    session, principal, worker_identity_verifier
):
    pf = _queued(session, principal)
    _approve_activation(session, principal, pf)
    backend = _FakeOpenBaoBackend(auth_ok=False)
    comp = _composition(session, principal, worker_identity_verifier, backend, _FakeCollector({}))

    result = run_openbao_readiness_canary(session, preflight_id=pf.id, composition=comp)

    assert result.ok is False
    assert result.reason_code == "authentication_failed"
    assert backend.reads == []


def test_readiness_canary_fails_closed_before_openbao_when_activation_missing(
    session, principal, worker_identity_verifier
):
    # No approved activation: the chain fails closed BEFORE the resolver boundary, so OpenBao is
    # never contacted and the canary reports a closed preflight outcome (not an auth result).
    pf = _queued(session, principal)
    backend = _FakeOpenBaoBackend()
    comp = _composition(session, principal, worker_identity_verifier, backend, _FakeCollector({}))

    result = run_openbao_readiness_canary(session, preflight_id=pf.id, composition=comp)

    assert result.ok is False
    assert result.reason_code == ReadonlyPreflightOutcome.credential_unavailable.value
    assert backend.authenticated == 0  # never reached OpenBao


# --- 3. Proxmox transport canary: ordered after resolved credential + safe evidence ---------------


def test_proxmox_transport_canary_single_get_and_safe_evidence(
    session, principal, worker_identity_verifier
):
    pf = _queued(session, principal)
    _approve_activation(session, principal, pf)
    backend = _FakeOpenBaoBackend()
    collector = _FakeCollector(_OBSERVED)
    comp = _composition(session, principal, worker_identity_verifier, backend, collector)

    result = run_proxmox_transport_canary(
        session, preflight_id=pf.id, composition=comp, declared_boundary={}
    )

    assert result.ok is True
    assert result.reason_code == "collected"
    # OpenBao was contacted (credential resolved) BEFORE the single Proxmox GET. The backend sees
    # only the OPAQUE locator (the `vault:` scheme is stripped and never forwarded).
    assert backend.reads == ["secp/proxmox/target-1"]
    assert len(collector.transports) == 1  # exactly ONE governed collection
    # Exactly one immutable evidence row, secret-free, with only safe bounded facts.
    row = session.query(LivePreflightEvidence).one()
    assert row.status == LivePreflightEvidenceStatus.passed
    assert row.payload["facts"]["node_count"] == 2
    assert row.payload["facts"]["storage_count"] == 1
    assert row.payload["facts"]["network_segment_count"] == 2
    blob = str(row.payload)
    for leak in ("opaque-staging-cred", VAULT_REF, "vmbr0", "nodes"):
        assert leak not in blob


def test_proxmox_transport_canary_fails_closed_when_chain_broken(
    session, principal, worker_identity_verifier
):
    # A broken authorization chain (revoked live-read auth) fails closed up front: no credential
    # resolved, no GET, no evidence — proving the Proxmox GET is gated behind the full chain.
    pf = _queued(session, principal)
    _approve_activation(session, principal, pf)
    backend = _FakeOpenBaoBackend()
    collector = _FakeCollector(_OBSERVED)
    comp = _composition(session, principal, worker_identity_verifier, backend, collector)

    readonly_preflight.revoke_preflight_authorization(
        session, principal, pf.live_read_authorization_id, "operator"
    )
    result = run_proxmox_transport_canary(
        session, preflight_id=pf.id, composition=comp, declared_boundary={}
    )
    assert result.ok is False
    assert backend.reads == []
    assert collector.transports == []
    assert session.query(LivePreflightEvidence).count() == 0


def test_proxmox_transport_canary_idempotent_evidence(session, principal, worker_identity_verifier):
    pf = _queued(session, principal)
    _approve_activation(session, principal, pf)
    backend = _FakeOpenBaoBackend()
    comp = _composition(
        session, principal, worker_identity_verifier, backend, _FakeCollector(_OBSERVED)
    )

    first = run_proxmox_transport_canary(
        session, preflight_id=pf.id, composition=comp, declared_boundary={}
    )
    # Re-running the same durable operation writes NO second evidence row (exact-once idempotency),
    # regardless of whether the lease grants another attempt or replay-refuses.
    run_proxmox_transport_canary(
        session, preflight_id=pf.id, composition=comp, declared_boundary={}
    )
    assert first.ok is True
    assert session.query(LivePreflightEvidence).count() == 1


# --- 4. Shipped-default composition never resolves ------------------------------------------------


def test_readiness_canary_with_sealed_resolver_composition_never_authenticates(
    session, principal, worker_identity_verifier
):
    # A composition cannot even be built with a sealed resolver; prove the guard holds here too.
    with pytest.raises(StagingLiveCompositionError):
        build_staging_live_composition(
            identity_verifier=worker_identity_verifier(),
            activation_gate=_ApprovedGate(),
            secret_resolver=SealedSecretResolver(),
            transport_factory=_transport_factory,
            collector=_FakeCollector({}),
            evidence_writer=DurableLivePreflightEvidenceWriter(),
        )


# --- 5. mTLS proof-of-possession attestation source ----------------------------------------------


class _FakeMaterial:
    """A fake mTLS material with an in-memory keypair-substitute. Never a real key."""

    def __init__(self, *, anchor: str = "test-public-anchor-v1", honest: bool = True) -> None:
        self._anchor = anchor
        self._honest = honest

    def public_anchor(self) -> str:
        return self._anchor

    def sign_challenge(self, challenge: bytes) -> bytes:
        return b"sig:" + challenge if self._honest else b"forged"

    def verify_signature(self, challenge: bytes, signature: bytes) -> bool:
        return signature == b"sig:" + challenge


def _descriptor(principal):
    return MtlsIdentityDescriptor(
        organization_id=principal.organization_id,
        mechanism="mtls_workload_identity",
        identity_label="staging-worker-a",
        deployment_binding="deploy-01",
        identity_version=1,
    )


def test_mtls_source_emits_claim_on_valid_proof_of_possession(session, principal):
    pf = _queued(session, principal)
    source = MtlsWorkloadIdentitySource(material=_FakeMaterial(), descriptor=_descriptor(principal))
    claim = source.attest(preflight=pf, now=datetime.now(UTC))
    assert claim.organization_id == principal.organization_id
    assert claim.public_anchor == "test-public-anchor-v1"


def test_mtls_source_fails_closed_on_bad_proof(session, principal):
    from secp_worker.preflight.worker_identity_attestation import (
        WorkerIdentityAttestationUnavailable,
    )

    pf = _queued(session, principal)
    source = MtlsWorkloadIdentitySource(
        material=_FakeMaterial(honest=False), descriptor=_descriptor(principal)
    )
    with pytest.raises(WorkerIdentityAttestationUnavailable):
        source.attest(preflight=pf, now=datetime.now(UTC))


def test_sealed_mtls_material_refuses(session, principal):
    from secp_worker.preflight.worker_identity_attestation import (
        WorkerIdentityAttestationUnavailable,
    )

    pf = _queued(session, principal)
    source = MtlsWorkloadIdentitySource(
        material=SealedMtlsWorkloadMaterial(), descriptor=_descriptor(principal)
    )
    with pytest.raises(WorkerIdentityAttestationUnavailable):
        source.attest(preflight=pf, now=datetime.now(UTC))


def test_operation_challenge_is_fresh_and_bound(session, principal):
    pf = _queued(session, principal)
    now = datetime.now(UTC)
    a = build_operation_challenge(pf, now)
    b = build_operation_challenge(pf, now)
    assert a != b  # fresh nonce each time → non-replayable
    assert len(a) == 32  # fixed-length sha256 digest, carries no secret


# --- 6. Concrete OpenBao client: TLS + redaction + closed errors ----------------------------------


def test_openbao_client_reads_only_valid_vault_reference(session):
    backend = _FakeOpenBaoBackend()
    client = ConcreteOpenBaoClient(transport=backend)
    secret = client.read_secret(reference=VAULT_REF, now=datetime.now(UTC))
    assert secret == "opaque-staging-cred"
    assert backend.reads == ["secp/proxmox/target-1"]  # opaque locator, not the full reference


def test_openbao_client_rejects_non_vault_reference(session):
    client = ConcreteOpenBaoClient(transport=_FakeOpenBaoBackend())
    with pytest.raises(OpenBaoClientError) as exc:
        # A well-formed but non-vault (dev env:) reference is refused at the scheme boundary.
        client.read_secret(reference="env:SECP_PROVIDER_SECRET__X", now=datetime.now(UTC))
    assert exc.value.reason_code == "unsupported_reference_scheme"


def test_sealed_openbao_transport_refuses():
    t = SealedOpenBaoBackendTransport()
    with pytest.raises(OpenBaoClientError):
        t.authenticate(now=datetime.now(UTC))
    with pytest.raises(OpenBaoClientError):
        t.read(locator="x", now=datetime.now(UTC))


@pytest.mark.parametrize(
    "base_url",
    [
        "http://vault.example/v1",  # not https
        "https://user:pass@vault.example/v1",  # userinfo
        "https://vault.example/v1?x=1",  # query
        "https://vault.example/v1#frag",  # fragment
        "https://vault.example/../v1",  # unsafe path
    ],
)
def test_openbao_base_url_validation_rejects_unsafe(base_url):
    with pytest.raises(OpenBaoClientError):
        validate_openbao_base_url(base_url)


def test_openbao_base_url_validation_accepts_https():
    validate_openbao_base_url("https://vault.example:8200/v1")
