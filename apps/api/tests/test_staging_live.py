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
* the dedicated single-GET canary collector issues exactly one allowlisted GET, and transport-policy
  evidence is recorded as passed ONLY after proving an approved hardened transport was built;
* the OpenBao client obeys TLS/redaction/closed-error contracts;
* the first real contact is structurally OpenBao (the Proxmox credential is resolved THROUGH it).

Independent mTLS proof-of-possession is covered in test_staging_live_mtls_pop.py.
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
from secp_worker.staging_live.hardened_transport import (
    ApprovedHardenedTransport,
    ApprovedHardenedTransportFactory,
    HardeningManifest,
)
from secp_worker.staging_live.openbao_client import (
    ConcreteOpenBaoClient,
    OpenBaoClientError,
    OpenBaoResolverSelfTest,
    SealedOpenBaoBackendTransport,
    validate_openbao_base_url,
)
from secp_worker.staging_live.single_get_canary import (
    SingleGetCanaryCollector,
    SingleGetCanaryCollectorFactory,
)

VAULT_REF = "vault:secp/proxmox/target-1"
_CANARY_NODES = [{"node": "node-alpha"}, {"node": "node-bravo"}]


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


class _FakeApprovedTransport(ApprovedHardenedTransport):
    """A fake APPROVED hardened transport: reports a fully-enforced manifest and returns the canned
    node list from a single GET. Never touches a network."""

    def __init__(self, *, nodes: list[dict], enforced: bool = True) -> None:
        self._nodes = nodes
        self._enforced = enforced
        self.gets: list[str] = []

    def get(self, path: str) -> object:
        self.gets.append(path)
        return self._nodes

    def hardening_manifest(self) -> HardeningManifest:
        e = self._enforced
        return HardeningManifest(
            tls_verified=e,
            redirects_disabled=e,
            trust_env_disabled=e,
            get_only=e,
            timeout_bounded=e,
        )


class _FakeApprovedFactory(ApprovedHardenedTransportFactory):
    def __init__(self, *, nodes: list[dict] | None = None, enforced: bool = True) -> None:
        self._nodes = _CANARY_NODES if nodes is None else nodes
        self._enforced = enforced

    def __call__(self, verified: object, secret: str) -> ApprovedHardenedTransport:
        return _FakeApprovedTransport(nodes=self._nodes, enforced=self._enforced)


class _LooseTransport:
    """A foreign transport that is NOT an ApprovedHardenedTransport (duck-typed only)."""

    def get(self, path: str) -> object:
        return []

    def hardening_manifest(self) -> HardeningManifest:
        return HardeningManifest(True, True, True, True, True)


class _LooseFactory(ApprovedHardenedTransportFactory):
    """An approved factory that (wrongly) returns a non-approved transport."""

    def __call__(self, verified: object, secret: str) -> ApprovedHardenedTransport:
        return _LooseTransport()  # type: ignore[return-value]


class _RecordingCollectorFactory(SingleGetCanaryCollectorFactory):
    """A single-GET collector factory that RETAINS each fresh collector it produces, so a test can
    assert a fresh collector is built per canary run and count that run's requests independently."""

    def __init__(self) -> None:
        self.created: list[SingleGetCanaryCollector] = []

    def __call__(self) -> SingleGetCanaryCollector:
        collector = SingleGetCanaryCollector()
        self.created.append(collector)
        return collector


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


def _composition(
    session,
    principal,
    worker_identity_verifier,
    backend,
    collector_factory=None,
    *,
    transport_factory=None,
):
    return build_staging_live_composition(
        identity_verifier=worker_identity_verifier(),
        activation_gate=_ApprovedGate(),
        secret_resolver=_build_resolver(session, backend),
        transport_factory=transport_factory or _FakeApprovedFactory(),
        collector_factory=collector_factory or SingleGetCanaryCollectorFactory(),
        evidence_writer=DurableLivePreflightEvidenceWriter(),
    )


# --- 1. Composition factory fails closed ---------------------------------------------------------


def test_composition_rejects_sealed_and_deny_defaults(session, principal, worker_identity_verifier):
    backend = _FakeOpenBaoBackend()
    good = dict(
        identity_verifier=worker_identity_verifier(),
        activation_gate=_ApprovedGate(),
        secret_resolver=_build_resolver(session, backend),
        transport_factory=_FakeApprovedFactory(),
        collector_factory=SingleGetCanaryCollectorFactory(),
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
        transport_factory=_FakeApprovedFactory(),
        collector_factory=SingleGetCanaryCollectorFactory(),
        evidence_writer=DurableLivePreflightEvidenceWriter(),
    )
    with pytest.raises(StagingLiveCompositionError):
        build_staging_live_composition(**{**good, "collector_factory": None})


# --- 2. OpenBao readiness canary: full chain + auth, NO secret, NO Proxmox ------------------------


def test_openbao_readiness_canary_authenticates_without_resolving_or_contacting_proxmox(
    session, principal, worker_identity_verifier
):
    pf = _queued(session, principal)
    _approve_activation(session, principal, pf)
    backend = _FakeOpenBaoBackend(auth_ok=True)
    factory = _RecordingCollectorFactory()
    comp = _composition(session, principal, worker_identity_verifier, backend, factory)

    result = run_openbao_readiness_canary(session, preflight_id=pf.id, composition=comp)

    assert result.ok is True
    assert result.reason_code == "authenticated"
    assert backend.authenticated == 1  # OpenBao auth WAS exercised (full chain reached resolver)
    assert backend.reads == []  # no secret resolved
    assert factory.created == []  # no collector built → Proxmox never contacted
    assert session.query(LivePreflightEvidence).count() == 0  # readiness writes no evidence


def test_openbao_readiness_canary_reports_backend_auth_failure_closed(
    session, principal, worker_identity_verifier
):
    pf = _queued(session, principal)
    _approve_activation(session, principal, pf)
    backend = _FakeOpenBaoBackend(auth_ok=False)
    comp = _composition(session, principal, worker_identity_verifier, backend)

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
    comp = _composition(session, principal, worker_identity_verifier, backend)

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
    factory = _RecordingCollectorFactory()
    comp = _composition(session, principal, worker_identity_verifier, backend, factory)

    result = run_proxmox_transport_canary(
        session, preflight_id=pf.id, composition=comp, declared_boundary={}
    )

    assert result.ok is True
    assert result.reason_code == "collected"
    # OpenBao was contacted (credential resolved) BEFORE the single Proxmox GET. The backend sees
    # only the OPAQUE locator (the `vault:` scheme is stripped and never forwarded).
    assert backend.reads == ["secp/proxmox/target-1"]
    # A fresh collector was built for this run and observed EXACTLY one allowlisted GET.
    assert len(factory.created) == 1
    assert factory.created[0].get_count == 1
    # Exactly one immutable evidence row, secret-free, with only safe bounded facts.
    row = session.query(LivePreflightEvidence).one()
    assert row.status == LivePreflightEvidenceStatus.passed
    assert row.payload["facts"]["node_count"] == 2
    # A single GET observes nodes only; storage/segment counts are not claimed.
    assert row.payload["facts"]["storage_count"] == 0
    assert row.payload["facts"]["network_segment_count"] == 0
    blob = str(row.payload)
    for leak in ("opaque-staging-cred", VAULT_REF, "node-alpha", "node-bravo"):
        assert leak not in blob


def test_proxmox_transport_canary_fails_closed_when_chain_broken(
    session, principal, worker_identity_verifier
):
    # A broken authorization chain (revoked live-read auth) fails closed up front: no credential
    # resolved, no GET, no evidence — proving the Proxmox GET is gated behind the full chain.
    pf = _queued(session, principal)
    _approve_activation(session, principal, pf)
    backend = _FakeOpenBaoBackend()
    factory = _RecordingCollectorFactory()
    comp = _composition(session, principal, worker_identity_verifier, backend, factory)

    readonly_preflight.revoke_preflight_authorization(
        session, principal, pf.live_read_authorization_id, "operator"
    )
    result = run_proxmox_transport_canary(
        session, preflight_id=pf.id, composition=comp, declared_boundary={}
    )
    assert result.ok is False
    assert backend.reads == []
    assert factory.created == []  # collection never reached → no collector built, no GET
    assert session.query(LivePreflightEvidence).count() == 0


def test_proxmox_transport_canary_exact_once_evidence_via_durable_lease(
    session, principal, worker_identity_verifier
):
    # First run writes exactly one evidence row. A second run for the SAME operation is refused by
    # the durable lease (exactly-once at the operation boundary) BEFORE any collection; no second
    # collector is even built, and the outcome is asserted explicitly (a lease refusal, NOT a masked
    # transport-verification failure). Exactly one evidence row persists.
    pf = _queued(session, principal)
    _approve_activation(session, principal, pf)
    backend = _FakeOpenBaoBackend()
    factory = _RecordingCollectorFactory()
    comp = _composition(session, principal, worker_identity_verifier, backend, factory)

    first = run_proxmox_transport_canary(
        session, preflight_id=pf.id, composition=comp, declared_boundary={}
    )
    second = run_proxmox_transport_canary(
        session, preflight_id=pf.id, composition=comp, declared_boundary={}
    )
    assert first.ok is True
    assert first.evidence_id is not None
    assert len(factory.created) == 1 and factory.created[0].get_count == 1
    assert second.ok is False
    assert second.reason_code == ReadonlyPreflightOutcome.credential_unavailable.value
    assert len(factory.created) == 1  # no second collector built (refused before collection)
    assert session.query(LivePreflightEvidence).count() == 1


def test_durable_evidence_writer_dedups_same_operation(
    session, principal, worker_identity_verifier
):
    # Reach the durable writer's EXACT-ONCE dedup path directly: after the canary writes the row, a
    # second write with the SAME operation context returns the SAME row (no new insert),
    # proving exact-once persistence at the writer/dedup layer.
    from secp_worker.staging_live import canaries

    pf = _queued(session, principal)
    _approve_activation(session, principal, pf)
    backend = _FakeOpenBaoBackend()
    comp = _composition(
        session, principal, worker_identity_verifier, backend, _RecordingCollectorFactory()
    )
    first = run_proxmox_transport_canary(
        session, preflight_id=pf.id, composition=comp, declared_boundary={}
    )
    assert first.ok is True

    context = canaries._build_evidence_context(session, pf.id, comp, datetime.now(UTC))
    assert context is not None
    row_again = comp.evidence_writer.write(
        session,
        context=context,
        status=LivePreflightEvidenceStatus.passed,
        facts={
            "api_reachable": True,
            "readonly_policy_enforced": True,
            "node_count": 2,
            "storage_count": 0,
            "network_segment_count": 0,
        },
        checks=[],
        now=datetime.now(UTC),
    )
    assert str(row_again.id) == str(first.evidence_id)  # dedup returned the SAME durable row
    assert session.query(LivePreflightEvidence).count() == 1


# --- 3b. Single-GET collector (8A) + hardened-transport proof (8B) --------------------------------


def test_single_get_collector_issues_exactly_one_get():
    collector = SingleGetCanaryCollector()
    transport = _FakeApprovedTransport(nodes=_CANARY_NODES)
    observed = collector.collect(transport, declared_boundary={})
    assert collector.get_count == 1  # EXACTLY one GET (not the multi-GET inventory collector)
    assert collector.methods == {"GET"}
    assert collector.requests == [("GET", "/nodes")]
    assert transport.gets == ["/nodes"]
    assert observed == {"observed": {"nodes": _CANARY_NODES}}


def test_composition_rejects_loose_transport_factory_and_foreign_collector(
    session, principal, worker_identity_verifier
):
    backend = _FakeOpenBaoBackend()
    good = dict(
        identity_verifier=worker_identity_verifier(),
        activation_gate=_ApprovedGate(),
        secret_resolver=_build_resolver(session, backend),
        transport_factory=_FakeApprovedFactory(),
        collector_factory=SingleGetCanaryCollectorFactory(),
        evidence_writer=DurableLivePreflightEvidenceWriter(),
    )
    build_staging_live_composition(**good)

    # A non-approved factory (a plain callable) is rejected — approval is nominal, not duck-typed.
    with pytest.raises(StagingLiveCompositionError):
        build_staging_live_composition(**{**good, "transport_factory": lambda v, s: object()})

    # A foreign collector factory is rejected: only the dedicated single-GET collector factory
    # (nominal) is admitted, so a duck-typed factory returning any collector cannot masquerade.
    class _ForeignCollectorFactory:
        def __call__(self):
            return SingleGetCanaryCollector()

    with pytest.raises(StagingLiveCompositionError):
        build_staging_live_composition(**{**good, "collector_factory": _ForeignCollectorFactory()})


def test_transport_canary_fails_closed_when_transport_not_hardened(
    session, principal, worker_identity_verifier
):
    # The factory is an approved factory but returns a NON-approved transport: the runner refuses to
    # record transport-policy evidence as passed and writes NO evidence.
    pf = _queued(session, principal)
    _approve_activation(session, principal, pf)
    backend = _FakeOpenBaoBackend()
    comp = _composition(
        session,
        principal,
        worker_identity_verifier,
        backend,
        transport_factory=_LooseFactory(),
    )
    result = run_proxmox_transport_canary(
        session, preflight_id=pf.id, composition=comp, declared_boundary={}
    )
    assert result.ok is False
    assert result.reason_code == "transport_policy_unverified"
    assert session.query(LivePreflightEvidence).count() == 0


def test_transport_canary_fails_closed_when_hardening_not_enforced(
    session, principal, worker_identity_verifier
):
    # An approved transport whose manifest is not enforced fails the proof: no passed evidence.
    pf = _queued(session, principal)
    _approve_activation(session, principal, pf)
    backend = _FakeOpenBaoBackend()
    comp = _composition(
        session,
        principal,
        worker_identity_verifier,
        backend,
        transport_factory=_FakeApprovedFactory(enforced=False),
    )
    result = run_proxmox_transport_canary(
        session, preflight_id=pf.id, composition=comp, declared_boundary={}
    )
    assert result.ok is False
    assert result.reason_code == "transport_policy_unverified"
    assert session.query(LivePreflightEvidence).count() == 0


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
            transport_factory=_FakeApprovedFactory(),
            collector_factory=SingleGetCanaryCollectorFactory(),
            evidence_writer=DurableLivePreflightEvidenceWriter(),
        )


# --- 5. Concrete OpenBao client: TLS + redaction + closed errors ----------------------------------
# (Independent mTLS proof-of-possession is covered in test_staging_live_mtls_pop.py.)


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
