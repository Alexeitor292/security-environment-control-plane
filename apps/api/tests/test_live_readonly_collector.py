"""SECP-002B-1B-4/1B-5 — dormant, default-disabled live read-only Proxmox collector.

Fakes only. Proves the collector is unreachable unless an explicitly-enabled gate + a valid
immutable binding + authoritative ``ExecutionTarget`` / ``TargetOnboarding`` records + injected
fake resolver + injected fake transport are all supplied; that a disabled gate, invalid binding,
or an untrusted/mismatched target/onboarding record fails BEFORE secret resolution or transport
construction; that the runner derives the target config, declared boundary, and opaque credential
reference EXCLUSIVELY from the trusted records (a caller cannot supply them independently); that
the collector issues only canonical allowlisted GETs, never infers isolation, and returns an
in-memory observed dict; that the hardened HttpxReadOnlyTransport applies the closed policy before
any client activity and cannot be misused; and that no API/persistence/live-activation path was
introduced, legacy discovery stays separate, and the sealed collector stays sealed. Nothing real
is contacted.
"""

from __future__ import annotations

import inspect
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from secp_api.enums import EvidenceStatus, VerificationLevel
from secp_api.models import ExecutionTarget, TargetOnboarding
from secp_api.target_evidence import (
    CHECK_ISOLATION,
    SIMULATED_EVIDENCE_SOURCE,
    TARGET_EVIDENCE_SCHEMA_VERSION,
    compare_boundary_to_evidence,
    findings_pass,
    summarize_findings,
)
from secp_plugin_api.v1 import ProviderCredential
from secp_plugin_proxmox import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    LIVE_READ_EVIDENCE_SOURCE,
    PROXMOX_READONLY_POLICY_VERSION,
    HttpxReadOnlyTransport,
    LiveReadOnlyProxmoxCollector,
    MutatingRequestRefused,
    ProxmoxTargetConfigError,
    QueryParametersRefused,
    RedirectRefused,
    UnknownPathRefused,
    ValidatedProxmoxTargetConfig,
    parse_proxmox_target_config,
    path_is_allowed,
)
from secp_plugin_proxmox.readonly_policy import assert_no_params
from secp_plugin_proxmox.readonly_transport import FakeProxmoxReadOnlyTransport
from secp_worker.onboarding.live_readonly import (
    InvalidLiveReadBinding,
    LiveReadAuthorizationDenied,
    LiveReadCollectionBinding,
    LiveReadCollectionDisabled,
    LiveReadCollectionGate,
    UntrustedRecordBinding,
    canonical_sha256,
    run_live_readonly_collection,
)
from tests.conftest import VALID_ONBOARDING_BOUNDARY  # type: ignore

NOW = datetime(2026, 7, 2, tzinfo=UTC)
BOUNDARY = VALID_ONBOARDING_BOUNDARY
SECRET_REF = "env:SECP_PROVIDER_SECRET__FAKE"

# Authoritative record identities (worker-memory only; no DB session is used).
ORG_ID = uuid.uuid4()
TARGET_ID = uuid.uuid4()
ONBOARDING_ID = uuid.uuid4()

# Secret-free STORED connection config on ExecutionTarget.config: connection identity ONLY
# (base_url + verify_tls). It carries no credential reference and no secret — the credential
# reference is derived by the runner from ExecutionTarget.secret_ref.
STORED_CONFIG = {
    "base_url": "https://proxmox.example.test:8006/api2/json",
    "verify_tls": True,
}

# Plugin-parser-shaped config (connection identity + opaque credential reference). Used for
# DIRECT parser-level assertions only — the runner never receives this from a caller.
TARGET_CONFIG = {**STORED_CONFIG, "credential_ref": SECRET_REF}

FAKE_INV = {
    "/nodes": [
        {"node": "pve-node-1", "status": "online", "description": "lab", "password": "hunter2"},
        {"node": "pve-node-2", "status": "online", "tags": "t"},
    ],
    "/cluster/sdn/vnets": [{"vnet": "vmbr0", "cidr": "10.60.0.0/16", "notes": "n"}],
    "/nodes/pve-node-1/storage": [{"storage": "local-lvm", "type": "lvmthin"}],
    "/nodes/pve-node-2/storage": [{"storage": "local-lvm"}],
}


def _execution_target(**over) -> ExecutionTarget:
    """An authoritative, secret-free ExecutionTarget (in-memory only; never flushed)."""
    fields = dict(
        id=TARGET_ID,
        organization_id=ORG_ID,
        display_name="lab-proxmox",
        plugin_name="proxmox",
        config=dict(STORED_CONFIG),
        config_hash="sha256:" + "0" * 64,
        secret_ref=SECRET_REF,
    )
    fields.update(over)
    return ExecutionTarget(**fields)


def _onboarding(**over) -> TargetOnboarding:
    """An authoritative TargetOnboarding bound to the ExecutionTarget (in-memory only)."""
    fields = dict(
        id=ONBOARDING_ID,
        organization_id=ORG_ID,
        execution_target_id=TARGET_ID,
        declared_boundary=dict(BOUNDARY),
        boundary_hash="sha256:" + "0" * 64,
    )
    fields.update(over)
    return TargetOnboarding(**fields)


class RecordingResolver:
    """Fake worker SecretResolver that records every resolve() call."""

    def __init__(self, token: str = "fake-token") -> None:
        self.calls: list[str] = []
        self._token = token

    def resolve(self, secret_ref: str) -> ProviderCredential:
        self.calls.append(secret_ref)
        return ProviderCredential.from_secret(self._token)


class RecordingVerifier:
    """Fake authorization verifier that records calls and returns a fixed decision."""

    def __init__(self, approve: bool = True) -> None:
        self.approve = approve
        self.calls: list[tuple] = []

    def verify(self, binding, *, now) -> bool:
        self.calls.append((binding, now))
        return self.approve


class RecordingCollector:
    """Fake collector wrapper that records calls and delegates to the offline collector."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self._delegate = LiveReadOnlyProxmoxCollector()

    def collect(self, transport, *, declared_boundary: dict) -> dict:
        self.calls.append((transport, declared_boundary))
        return self._delegate.collect(transport, declared_boundary=declared_boundary)


def _recording_factory(responses):
    # Records (validated_config, token, transport) so tests can prove the transport is built
    # from the VALIDATED config supplied to construction, not a separate factory choice.
    created: list[tuple] = []

    def factory(validated_config, token: str) -> FakeProxmoxReadOnlyTransport:
        t = FakeProxmoxReadOnlyTransport(responses)
        created.append((validated_config, token, t))
        return t

    return factory, created


def _binding(**over) -> LiveReadCollectionBinding:
    base = dict(
        execution_target_id=str(TARGET_ID),
        target_config_hash=canonical_sha256(
            parse_proxmox_target_config(
                {**STORED_CONFIG, "credential_ref": SECRET_REF}
            ).connection_representation()
        ),
        onboarding_id=str(ONBOARDING_ID),
        boundary_hash=canonical_sha256(BOUNDARY),
        authorization_id="auth-1",
        authorization_version=1,
        authorization_expiry="2999-01-01T00:00:00Z",
        credential_ref=SECRET_REF,
        evidence_source=LIVE_READ_EVIDENCE_SOURCE,
        verification_level=VerificationLevel.live_verified.value,
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
    )
    base.update(over)
    return LiveReadCollectionBinding(**base)


def _run(
    *,
    gate,
    resolver,
    factory,
    verifier,
    binding=None,
    execution_target=None,
    onboarding=None,
    collector=None,
    now=NOW,
):
    return run_live_readonly_collection(
        gate=gate,
        binding=_binding() if binding is None else binding,
        execution_target=_execution_target() if execution_target is None else execution_target,
        onboarding=_onboarding() if onboarding is None else onboarding,
        secret_resolver=resolver,
        transport_factory=factory,
        collector=RecordingCollector() if collector is None else collector,
        authorization_verifier=verifier,
        now=now,
    )


def _sim_payload(observed: dict) -> dict:
    """TEST-ONLY: wrap observed data in the simulated evidence schema to exercise comparison.
    This is not a runtime collection path and creates no evidence record."""
    return {
        "schema_version": TARGET_EVIDENCE_SCHEMA_VERSION,
        "evidence_source": SIMULATED_EVIDENCE_SOURCE,
        "verification_level": VerificationLevel.simulated.value,
        "observed": observed,
    }


# --- default-disabled gate --------------------------------------------------------


def test_gate_default_is_disabled():
    assert LiveReadCollectionGate().enabled is False


def test_disabled_gate_refuses_before_verifier_resolver_transport():
    resolver = RecordingResolver()
    factory, created = _recording_factory(FAKE_INV)
    verifier = RecordingVerifier()
    collector = RecordingCollector()
    with pytest.raises(LiveReadCollectionDisabled):
        _run(
            gate=LiveReadCollectionGate(),
            resolver=resolver,
            factory=factory,
            verifier=verifier,
            collector=collector,
        )
    assert verifier.calls == []  # no authorization verification
    assert resolver.calls == []  # no secret resolution
    assert created == []  # no transport construction
    assert collector.calls == []  # no collection


# --- immutable binding validation (before verifier / resolver / transport) --------


@pytest.mark.parametrize(
    "over",
    [
        {"execution_target_id": ""},  # missing field
        {"onboarding_id": "  "},  # blank field
        {"authorization_version": 0},  # non-positive
        {"authorization_version": "1"},  # wrong type
        {"authorization_expiry": "2000-01-01T00:00:00Z"},  # expired
        {"authorization_expiry": "2999-01-01 00:00:00"},  # malformed (no 'Z')
        {"authorization_expiry": "not-a-time"},  # malformed
        {"verification_level": "simulated"},  # inconsistent (not live)
        {"evidence_source": "simulated_target_evidence"},  # wrong source
        {"collector_contract_version": "bogus/v0"},  # contract mismatch
        {"endpoint_allowlist_version": "bogus/v0"},  # allowlist mismatch
    ],
)
def test_invalid_binding_refuses_before_verifier_resolver_transport(over):
    resolver = RecordingResolver()
    factory, created = _recording_factory(FAKE_INV)
    verifier = RecordingVerifier()
    collector = RecordingCollector()
    with pytest.raises(InvalidLiveReadBinding):
        _run(
            gate=LiveReadCollectionGate(enabled=True),
            binding=_binding(**over),
            resolver=resolver,
            factory=factory,
            verifier=verifier,
            collector=collector,
        )
    assert verifier.calls == []
    assert resolver.calls == []
    assert created == []
    assert collector.calls == []


# --- recomputed binding hashes + credential-ref binding (before verifier/resolver) --


@pytest.mark.parametrize(
    "kwargs",
    [
        {"binding": None, "mutate_hash": "target_config_hash"},  # config hash mismatch
        {"binding": None, "mutate_hash": "boundary_hash"},  # boundary hash mismatch
        {"binding": None, "malformed": "target_config_hash"},  # malformed digest
    ],
)
def test_hash_mismatch_or_malformed_refused_before_verifier(kwargs):
    over = {}
    if kwargs.get("mutate_hash"):
        over[kwargs["mutate_hash"]] = canonical_sha256({"tampered": True})
    if kwargs.get("malformed"):
        over[kwargs["malformed"]] = "not-a-sha256-digest"
    resolver = RecordingResolver()
    factory, created = _recording_factory(FAKE_INV)
    verifier = RecordingVerifier()
    collector = RecordingCollector()
    with pytest.raises(InvalidLiveReadBinding):
        _run(
            gate=LiveReadCollectionGate(enabled=True),
            binding=_binding(**over),
            resolver=resolver,
            factory=factory,
            verifier=verifier,
            collector=collector,
        )
    assert verifier.calls == [] and resolver.calls == [] and created == []
    assert collector.calls == []


def test_boundary_canonicalization_failure_refused_before_verifier():
    # An onboarding declared boundary carrying a non-finite float cannot be canonicalized.
    resolver = RecordingResolver()
    factory, created = _recording_factory(FAKE_INV)
    verifier = RecordingVerifier()
    collector = RecordingCollector()
    with pytest.raises(InvalidLiveReadBinding):
        _run(
            gate=LiveReadCollectionGate(enabled=True),
            onboarding=_onboarding(declared_boundary={**BOUNDARY, "nan": float("nan")}),
            resolver=resolver,
            factory=factory,
            verifier=verifier,
            collector=collector,
        )
    assert verifier.calls == [] and resolver.calls == [] and created == []
    assert collector.calls == []


# --- malformed authoritative target config: rejected at parse (before hash/verifier/resolver) ---


@pytest.mark.parametrize(
    "bad_config",
    [
        {**STORED_CONFIG, "token": "raw-secret-value"},  # secret-like unknown key
        {**STORED_CONFIG, "password": "raw-secret-value"},  # secret-like unknown key
        {**STORED_CONFIG, "headers": {"Authorization": "Bearer x"}},  # headers / nested
        {**STORED_CONFIG, "extra": 1},  # unknown key
        {"verify_tls": True},  # missing base_url
        {"base_url": {"nested": "x"}, "verify_tls": True},  # nested base_url
        {**STORED_CONFIG, "verify_tls": False},  # not exactly True
        {**STORED_CONFIG, "verify_tls": "true"},  # non-boolean
        {**STORED_CONFIG, "base_url": "https://proxmox.example.test:8006"},  # not the API root
        {**STORED_CONFIG, "base_url": "http://proxmox.example.test:8006/api2/json"},  # not https
        {**STORED_CONFIG, "credential_ref": "env:INLINE"},  # config must not carry a cred ref
    ],
)
def test_malformed_authoritative_config_refused_before_hash_verifier_resolver_transport(bad_config):
    # The config is taken from the authoritative ExecutionTarget.config; a malformed record is
    # refused before hashing/verifier/resolver/transport.
    resolver = RecordingResolver()
    factory, created = _recording_factory(FAKE_INV)
    verifier = RecordingVerifier()
    collector = RecordingCollector()
    with pytest.raises(InvalidLiveReadBinding):
        _run(
            gate=LiveReadCollectionGate(enabled=True),
            execution_target=_execution_target(config=bad_config),
            resolver=resolver,
            factory=factory,
            verifier=verifier,
            collector=collector,
        )
    assert verifier.calls == [] and resolver.calls == [] and created == []
    assert collector.calls == []


def test_secret_value_is_never_echoed_by_config_rejection():
    # A rejected raw config must not leak the secret-like VALUE into the error.
    try:
        parse_proxmox_target_config({**TARGET_CONFIG, "token": "TOP-SECRET-VALUE"})
    except ProxmoxTargetConfigError as exc:
        assert "TOP-SECRET-VALUE" not in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected rejection")


# --- plugin-owned target-config model ---------------------------------------------


def test_connection_representation_excludes_credential_ref():
    cfg = parse_proxmox_target_config(dict(TARGET_CONFIG))
    assert isinstance(cfg, ValidatedProxmoxTargetConfig)
    rep = cfg.connection_representation()
    # ONLY base_url + verify_tls are hashed; the opaque credential_ref is never in the hash.
    assert set(rep) == {"base_url", "verify_tls"}
    assert "credential_ref" not in rep
    assert rep["verify_tls"] is True
    # The credential reference value must not appear in the canonical (hashed) representation.
    assert SECRET_REF not in canonical_sha256(rep)
    from secp_worker.onboarding.live_readonly import canonical_json

    assert SECRET_REF not in canonical_json(rep)


def test_live_read_repr_redacts_credential_references():
    cfg = parse_proxmox_target_config(dict(TARGET_CONFIG))
    binding = _binding()

    assert cfg.credential_ref == SECRET_REF
    assert binding.credential_ref == SECRET_REF
    assert SECRET_REF not in repr(cfg)
    assert SECRET_REF not in repr(binding)
    assert "credential_ref=<redacted>" in repr(cfg)
    assert "credential_ref=<redacted>" in repr(binding)


def test_binding_default_config_hash_matches_connection_representation():
    cfg = parse_proxmox_target_config(dict(TARGET_CONFIG))
    assert _binding().target_config_hash == canonical_sha256(cfg.connection_representation())


def test_changing_only_target_secret_ref_fails_before_verifier_even_though_hash_matches():
    # The connection hash covers only base_url + verify_tls, so changing only the target's
    # secret_ref leaves the connection hash identical — the three-way credential equality (not
    # the hash) catches it, before verifier / resolver / transport.
    resolver = RecordingResolver()
    factory, created = _recording_factory(FAKE_INV)
    verifier = RecordingVerifier()
    et = _execution_target(secret_ref="env:SECP_PROVIDER_SECRET__OTHER")
    collector = RecordingCollector()
    # Sanity: the connection hash is unchanged by a different derived credential reference.
    assert (
        canonical_sha256(
            parse_proxmox_target_config(
                {**STORED_CONFIG, "credential_ref": et.secret_ref}
            ).connection_representation()
        )
        == _binding().target_config_hash
    )
    with pytest.raises(InvalidLiveReadBinding):
        _run(
            gate=LiveReadCollectionGate(enabled=True),
            execution_target=et,  # binding.credential_ref (SECRET_REF) != target secret_ref
            resolver=resolver,
            factory=factory,
            verifier=verifier,
            collector=collector,
        )
    assert verifier.calls == [] and resolver.calls == [] and created == []
    assert collector.calls == []


def test_binding_credential_ref_mismatch_fails_before_verifier():
    # binding.credential_ref differs from the (matching) derived config ref + target secret_ref.
    resolver = RecordingResolver()
    factory, created = _recording_factory(FAKE_INV)
    verifier = RecordingVerifier()
    collector = RecordingCollector()
    with pytest.raises(InvalidLiveReadBinding):
        _run(
            gate=LiveReadCollectionGate(enabled=True),
            binding=_binding(credential_ref="env:SECP_PROVIDER_SECRET__BINDINGREF"),
            resolver=resolver,
            factory=factory,
            verifier=verifier,
            collector=collector,
        )
    assert verifier.calls == [] and resolver.calls == [] and created == []
    assert collector.calls == []


def test_credential_reference_never_echoed_in_mismatch_error():
    resolver = RecordingResolver()
    factory, _created = _recording_factory(FAKE_INV)
    verifier = RecordingVerifier()
    secret_like_ref = "env:SECP_PROVIDER_SECRET__TOPSECRET"
    try:
        _run(
            gate=LiveReadCollectionGate(enabled=True),
            # target secret_ref != binding.credential_ref -> three-way equality fails
            execution_target=_execution_target(secret_ref=secret_like_ref),
            resolver=resolver,
            factory=factory,
            verifier=verifier,
        )
    except InvalidLiveReadBinding as exc:
        assert secret_like_ref not in str(exc)
        assert SECRET_REF not in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected credential reference mismatch")


# --- trusted-record identity + relationship (before all sensitive steps) ----------


@pytest.mark.parametrize(
    "case",
    [
        "binding_execution_target_id_mismatch",
        "binding_onboarding_id_mismatch",
        "onboarding_execution_target_id_mismatch",
        "organization_mismatch",
        "wrong_plugin_name",
        "missing_target_secret_ref_none",
        "missing_target_secret_ref_blank",
    ],
)
def test_untrusted_records_refused_before_verifier_resolver_transport(case):
    other = uuid.uuid4()
    binding = None
    execution_target = None
    onboarding = None
    if case == "binding_execution_target_id_mismatch":
        binding = _binding(execution_target_id=str(other))
    elif case == "binding_onboarding_id_mismatch":
        binding = _binding(onboarding_id=str(other))
    elif case == "onboarding_execution_target_id_mismatch":
        onboarding = _onboarding(execution_target_id=other)
    elif case == "organization_mismatch":
        onboarding = _onboarding(organization_id=other)
    elif case == "wrong_plugin_name":
        execution_target = _execution_target(plugin_name="libvirt")
    elif case == "missing_target_secret_ref_none":
        execution_target = _execution_target(secret_ref=None)
    elif case == "missing_target_secret_ref_blank":
        execution_target = _execution_target(secret_ref="   ")

    resolver = RecordingResolver()
    factory, created = _recording_factory(FAKE_INV)
    verifier = RecordingVerifier()
    collector = RecordingCollector()
    with pytest.raises(UntrustedRecordBinding):  # subclass of InvalidLiveReadBinding
        _run(
            gate=LiveReadCollectionGate(enabled=True),
            binding=binding,
            execution_target=execution_target,
            onboarding=onboarding,
            resolver=resolver,
            factory=factory,
            verifier=verifier,
            collector=collector,
        )
    assert verifier.calls == [] and resolver.calls == [] and created == []
    assert collector.calls == []


def test_untrusted_record_error_never_echoes_secret_reference():
    # A wrong-plugin refusal (and any trusted-record refusal) must not leak the credential ref.
    resolver = RecordingResolver()
    factory, _created = _recording_factory(FAKE_INV)
    verifier = RecordingVerifier()
    try:
        _run(
            gate=LiveReadCollectionGate(enabled=True),
            execution_target=_execution_target(plugin_name="libvirt"),
            resolver=resolver,
            factory=factory,
            verifier=verifier,
        )
    except UntrustedRecordBinding as exc:
        assert SECRET_REF not in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected an untrusted-record refusal")


def test_boundary_hash_mismatch_against_onboarding_declared_boundary():
    # binding.boundary_hash is pinned to BOUNDARY; an onboarding with a different declared
    # boundary fails the recomputed hash comparison before verifier / resolver / transport.
    resolver = RecordingResolver()
    factory, created = _recording_factory(FAKE_INV)
    verifier = RecordingVerifier()
    collector = RecordingCollector()
    with pytest.raises(InvalidLiveReadBinding):
        _run(
            gate=LiveReadCollectionGate(enabled=True),
            onboarding=_onboarding(declared_boundary={**BOUNDARY, "extra_segment": ["x"]}),
            resolver=resolver,
            factory=factory,
            verifier=verifier,
            collector=collector,
        )
    assert verifier.calls == [] and resolver.calls == [] and created == []
    assert collector.calls == []


def test_runner_derives_inputs_only_from_trusted_records_signature():
    # The public signature accepts the authoritative records and NO raw target_config /
    # declared_boundary / secret_ref inputs a caller could supply independently.
    params = set(inspect.signature(run_live_readonly_collection).parameters)
    assert {"execution_target", "onboarding"} <= params
    for removed in ("target_config", "declared_boundary", "secret_ref"):
        assert removed not in params, f"runner must not accept raw {removed}"


def test_stored_target_config_is_secret_free():
    et = _execution_target()
    # Stored config is connection identity only — never a secret or a credential reference.
    assert set(et.config) == {"base_url", "verify_tls"}
    for forbidden in ("credential_ref", "token", "password", "secret", "cookie", "headers"):
        assert forbidden not in et.config
    # The opaque credential reference lives on secret_ref, separate from the hashed config.
    assert et.secret_ref == SECRET_REF


# --- authorization verifier (before secret resolution) ----------------------------


def test_authorization_denied_refuses_before_resolver_and_transport():
    resolver = RecordingResolver()
    factory, created = _recording_factory(FAKE_INV)
    verifier = RecordingVerifier(approve=False)  # verifier is reached, but denies
    collector = RecordingCollector()
    with pytest.raises(LiveReadAuthorizationDenied):
        _run(
            gate=LiveReadCollectionGate(enabled=True),
            resolver=resolver,
            factory=factory,
            verifier=verifier,
            collector=collector,
        )
    assert len(verifier.calls) == 1  # verifier consulted
    assert resolver.calls == []  # but no secret resolution
    assert created == []  # and no transport construction
    assert collector.calls == []


# --- explicitly enabled test-only path: derives everything from trusted records ----


def test_enabled_path_derives_config_boundary_ref_from_trusted_records():
    resolver = RecordingResolver()
    factory, created = _recording_factory(FAKE_INV)
    verifier = RecordingVerifier(approve=True)
    et = _execution_target()
    ob = _onboarding()
    observed = _run(
        gate=LiveReadCollectionGate(enabled=True),  # valid gate
        execution_target=et,  # authoritative target record
        onboarding=ob,  # authoritative onboarding record
        resolver=resolver,  # fake resolver
        factory=factory,  # fake transport
        verifier=verifier,  # verified authorization
    )
    assert len(verifier.calls) == 1  # authorization verified
    # The resolver is keyed by the TARGET's own secret_ref (derived), not a caller-supplied value.
    assert resolver.calls == [et.secret_ref]
    # The transport is built from the VALIDATED config derived from the trusted records: the
    # connection identity comes from ExecutionTarget.config and the credential reference from
    # ExecutionTarget.secret_ref — never from an independent caller input.
    cfg, token, _t = created[0]
    assert isinstance(cfg, ValidatedProxmoxTargetConfig)
    assert cfg.base_url == et.config["base_url"]
    assert cfg.verify_tls is True
    assert cfg.credential_ref == et.secret_ref
    assert token == "fake-token"  # transport built with the resolved transient token
    assert observed["nodes"] == ["pve-node-1", "pve-node-2"]
    assert observed["storage"] == ["local-lvm"]
    assert observed["network_segments"] == ["vmbr0"]
    assert "isolation" not in observed  # never inferred
    blob = str(observed).lower()
    for leak in ("description", "password", "hunter2", "tags", "notes"):
        assert leak not in blob


# --- collector: canonical allowlisted GETs, no isolation inference ----------------


def test_collector_issues_only_canonical_allowlisted_gets():
    t = FakeProxmoxReadOnlyTransport(FAKE_INV)
    LiveReadOnlyProxmoxCollector().collect(t, declared_boundary=BOUNDARY)
    assert t.calls, "collector should have issued GETs"
    assert {method for (method, _p) in t.calls} == {"GET"}
    for _method, path in t.calls:
        assert path_is_allowed(path), path


def test_generic_inventory_cannot_pass_fully_segregated():
    observed = LiveReadOnlyProxmoxCollector().collect(
        FakeProxmoxReadOnlyTransport(FAKE_INV), declared_boundary=BOUNDARY
    )
    findings = compare_boundary_to_evidence(BOUNDARY, _sim_payload(observed))
    by_check = {f["check"]: f["status"] for f in findings}
    assert by_check[CHECK_ISOLATION] == EvidenceStatus.unverifiable.value
    assert findings_pass(findings) is False


@pytest.mark.parametrize(
    "responses",
    [
        {},  # nothing observed
        {"/nodes": {"node": "pve-node-1"}},  # malformed (non-list) node response
    ],
)
def test_missing_or_malformed_observations_are_unverifiable(responses):
    observed = LiveReadOnlyProxmoxCollector().collect(
        FakeProxmoxReadOnlyTransport(responses), declared_boundary=BOUNDARY
    )
    findings = compare_boundary_to_evidence(BOUNDARY, _sim_payload(observed))
    assert summarize_findings(findings) == EvidenceStatus.unverifiable
    assert findings_pass(findings) is False


# --- hardened HttpxReadOnlyTransport ----------------------------------------------


class _FakeResp:
    def __init__(self, status_code=200, json_data=None, headers=None, is_redirect=False):
        self.status_code = status_code
        self._json = {"data": []} if json_data is None else json_data
        self.headers = headers or {}
        self.is_redirect = is_redirect

    def raise_for_status(self):
        if self.status_code >= 400:  # pragma: no cover - not exercised
            raise RuntimeError("http error")

    def json(self):
        return self._json


class _FakeClient:
    def __init__(self, resp: _FakeResp | None = None):
        self.resp = resp or _FakeResp()
        self.get_calls: list[tuple] = []

    def get(self, url, params=None, headers=None):
        self.get_calls.append((url, params, headers))
        return self.resp

    def close(self):
        pass


def test_httptransport_applies_policy_before_injected_client():
    client = _FakeClient()
    t = HttpxReadOnlyTransport("https://proxmox.example.test:8006/api2/json", "tok", client=client)
    with pytest.raises(MutatingRequestRefused):
        t.request("POST", "/nodes")
    with pytest.raises(UnknownPathRefused):
        t.request("GET", "/nodes/pve-node-1/qemu/9000/config")
    assert client.get_calls == []  # policy refused before any client activity


def test_httptransport_refuses_and_never_follows_redirect():
    redirect = _FakeResp(status_code=302, headers={"location": "https://elsewhere/nodes"})
    client = _FakeClient(redirect)
    t = HttpxReadOnlyTransport("https://proxmox.example.test:8006/api2/json", "tok", client=client)
    with pytest.raises(RedirectRefused):
        t.get("/nodes")
    assert len(client.get_calls) == 1  # issued once, redirect NOT followed


def test_httptransport_tls_cannot_be_disabled():
    with pytest.raises(ValueError, match="verify_tls"):
        HttpxReadOnlyTransport(
            "https://proxmox.example.test:8006/api2/json", "tok", verify_tls=False
        )


@pytest.mark.parametrize(
    "base_url",
    [
        "http://proxmox.example.test:8006/api2/json",  # not https
        "https://user:pass@proxmox.example.test:8006/api2/json",  # userinfo
        "https://proxmox.example.test:8006/api2/json?x=1",  # query
        "https://proxmox.example.test:8006/api2/json#frag",  # fragment
        "https://proxmox.example.test:8006/api2/%2e%2e",  # escape/traversal
        "https://proxmox.example.test:8006",  # empty root
        "https://proxmox.example.test:8006/",  # root only, not the API root
        "https://proxmox.example.test:8006/api2/json/nodes",  # arbitrary deeper path
    ],
)
def test_httptransport_base_url_validation(base_url):
    with pytest.raises(ValueError):
        HttpxReadOnlyTransport(base_url, "tok")


def test_httptransport_accepts_exact_api_root(monkeypatch):
    # Both /api2/json and /api2/json/ normalize to the same accepted root.
    class _CapturingClient(_FakeClient):
        def __init__(self, **kwargs):
            super().__init__(_FakeResp(200, {"data": []}))

    monkeypatch.setattr(httpx, "Client", _CapturingClient)
    for base_url in (
        "https://proxmox.example.test:8006/api2/json",
        "https://proxmox.example.test:8006/api2/json/",
    ):
        HttpxReadOnlyTransport(base_url, "tok").get("/nodes")  # no ValueError


# --- Part 1: query parameters are refused before client / lookup activity ---------


def test_httptransport_refuses_nonempty_params_before_client():
    client = _FakeClient()
    t = HttpxReadOnlyTransport("https://proxmox.example.test:8006/api2/json", "tok", client=client)
    with pytest.raises(QueryParametersRefused):
        t.get("/nodes", params={"full": "1"})
    with pytest.raises(QueryParametersRefused):
        t.request("GET", "/nodes", {"x": "y"})
    assert client.get_calls == []  # refused before any client activity


def test_fake_transport_refuses_nonempty_params_before_lookup():
    t = FakeProxmoxReadOnlyTransport({"/nodes": [{"node": "pve-node-1"}]})
    with pytest.raises(QueryParametersRefused):
        t.get("/nodes", params={"full": "1"})
    assert t.calls == []  # refused before canned-response lookup


def test_params_none_and_empty_preserve_valid_get():
    # Fake transport: None and {} both yield the canned data.
    fake = FakeProxmoxReadOnlyTransport({"/nodes": [{"node": "pve-node-1"}]})
    assert fake.get("/nodes") == [{"node": "pve-node-1"}]
    assert fake.get("/nodes", params={}) == [{"node": "pve-node-1"}]
    assert fake.get("/nodes", params=None) == [{"node": "pve-node-1"}]
    # Httpx transport: None and {} both reach the injected client and return data.
    client = _FakeClient(_FakeResp(200, {"data": [{"node": "pve-node-1"}]}))
    t = HttpxReadOnlyTransport("https://proxmox.example.test:8006/api2/json", "tok", client=client)
    assert t.get("/nodes") == [{"node": "pve-node-1"}]
    assert t.get("/nodes", params={}) == [{"node": "pve-node-1"}]
    assert len(client.get_calls) == 2


def test_assert_no_params_accepts_only_none_or_empty_dict():
    assert_no_params(None)  # no raise
    assert_no_params({})  # no raise


@pytest.mark.parametrize("bad", [[], (), "", "abc", 0, False, True, [1], ("x",), {"full": "1"}])
def test_assert_no_params_rejects_all_other_values(bad):
    with pytest.raises(QueryParametersRefused):
        assert_no_params(bad)


@pytest.mark.parametrize("bad", [[], (), "", 0, False, {"full": "1"}])
def test_both_transports_refuse_strict_params_before_activity(bad):
    fake = FakeProxmoxReadOnlyTransport({"/nodes": [{"node": "pve-node-1"}]})
    with pytest.raises(QueryParametersRefused):
        fake.get("/nodes", params=bad)
    assert fake.calls == []  # refused before canned-response lookup
    client = _FakeClient()
    t = HttpxReadOnlyTransport("https://proxmox.example.test:8006/api2/json", "tok", client=client)
    with pytest.raises(QueryParametersRefused):
        t.get("/nodes", params=bad)
    assert client.get_calls == []  # refused before injected-client activity


def test_httptransport_own_client_uses_verify_trustenv_noredirect(monkeypatch):
    captured: dict = {}

    class _CapturingClient(_FakeClient):
        def __init__(self, **kwargs):
            super().__init__(_FakeResp(200, {"data": [{"node": "pve-node-1"}]}))
            captured.update(kwargs)

    monkeypatch.setattr(httpx, "Client", _CapturingClient)
    t = HttpxReadOnlyTransport("https://proxmox.example.test:8006/api2/json", "tok")
    data = t.get("/nodes")  # no injected client -> constructs its own (captured)
    assert captured.get("verify") is True
    assert captured.get("trust_env") is False
    assert captured.get("follow_redirects") is False
    assert data == [{"node": "pve-node-1"}]


# --- boundary / no-network-imports / sealed / no-persistence ----------------------


def test_api_package_does_not_import_live_readonly_paths():
    api_pkg = Path(__file__).resolve().parents[1] / "secp_api"
    needles = (
        "live_readonly",
        "LiveReadOnlyProxmoxCollector",
        "run_live_readonly_collection",
        "LiveReadCollection",
        "secp_plugin_proxmox",
    )
    for py in api_pkg.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        # live_read_contract.py is the deliberate PLUGIN-FREE mirror of the live-read contract
        # labels (SECP-B2-0). It imports no collector/transport/policy code (asserted by
        # test_readonly_preflight_contract) but must hold the matching evidence-source value
        # ("live_readonly_proxmox"); exclude only this file.
        if py.name == "live_read_contract.py":
            continue
        text = py.read_text(encoding="utf-8")
        for needle in needles:
            assert needle not in text, f"{py.name} references {needle!r}"


def test_new_code_has_no_network_capable_imports():
    import secp_plugin_proxmox.live_collector as lc
    import secp_worker.onboarding.live_authorization as la
    import secp_worker.onboarding.live_readonly as lr

    forbidden = (
        "import httpx",
        "from httpx",
        "import requests",
        "from requests",
        "import aiohttp",
        "import socket",
        "from socket",
        "import ssl",
        "import subprocess",
        "from subprocess",
        "import http.client",
        "import urllib.request",
        "import paramiko",
    )
    for module in (lc, lr, la):
        src = inspect.getsource(module)
        for token in forbidden:
            assert token not in src, f"{module.__name__} must not use `{token}`"


def test_live_read_path_has_no_production_direct_instantiation_or_runner_call():
    """The dormant live-read worker modules use injected seams, not direct activation calls."""
    worker_onboarding = (
        Path(__file__).resolve().parents[2] / "worker" / "secp_worker" / "onboarding"
    )
    forbidden_call_names = {
        "LiveReadOnlyProxmoxCollector",
        "HttpxReadOnlyTransport",
        "run_live_readonly_collection",
    }

    def call_name(node):
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return ""

    import ast

    for path in worker_onboarding.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = call_name(node)
                assert name not in forbidden_call_names, f"{path.name} directly calls {name}"


def test_no_evidence_persistence_in_live_run():
    import secp_worker.onboarding.live_readonly as lr

    src = inspect.getsource(lr)
    # Scan for code-shaped persistence tokens (call/attribute forms), so prose in docstrings
    # that merely names TargetEvidenceRecord is not mistaken for a persistence call.
    for token in (
        "TargetEvidenceRecord(",
        "import TargetEvidenceRecord",
        "record_target_evidence",
        "session.add(",
        "session.commit(",
        "sessionmaker",
        "session_scope",
    ):
        assert token not in src, f"live run must not persist evidence ({token})"


def test_sealed_provider_collector_remains_sealed():
    from secp_api.errors import LiveEvidenceSealedError
    from secp_api.onboarding import B1B0_LIVE_EVIDENCE_SEALED
    from secp_worker.onboarding.target_evidence import SealedProviderTargetEvidenceCollector

    assert B1B0_LIVE_EVIDENCE_SEALED is True
    with pytest.raises(LiveEvidenceSealedError):
        SealedProviderTargetEvidenceCollector().collect(declared_boundary={})


def test_simulated_collector_unchanged():
    from secp_worker.onboarding.target_evidence import SimulatedTargetEvidenceCollector

    assert (
        SimulatedTargetEvidenceCollector().verification_level == VerificationLevel.simulated.value
    )


def test_legacy_discovery_is_separate_from_target_evidence_collection():
    # SECP-002B-1B-5 §7: legacy provider discovery is a distinct code path that produces an
    # immutable ProviderInventorySnapshot (inventory) — it does NOT collect, satisfy, persist,
    # or authorize live *target evidence*, and it never touches the live read-only collector.
    import secp_worker.discovery as disc

    src = inspect.getsource(disc)
    assert "ProviderInventorySnapshot" in src  # discovery persists inventory, not evidence
    for evidence_token in (
        "TargetEvidenceRecord",
        "record_target_evidence",
        "run_live_readonly_collection",
        "LiveReadOnlyProxmoxCollector",
        "LIVE_READ_EVIDENCE_SOURCE",
        "live_readonly",
    ):
        assert evidence_token not in src, (
            f"legacy discovery must stay separate from target evidence ({evidence_token})"
        )
