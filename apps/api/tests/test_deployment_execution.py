"""SECP-B4 §3/§4/§7 — execution primitives, fake-backed (no real host/ssh/http/crypto I/O).

Covers the hardened SSH bootstrap executor (fixed argv, host-key binding enforced, no shell, fail-
closed + credential disposal on every path, redacted result), the concrete hardened Proxmox mutation
transport (real locally-constructed httpx client satisfies hardening; closed typed route allowlist),
the observed-ownership-gated typed mutation executor (fresh-read proof;
foreign/absent/mismatch/sealed
fail closed; no caller tag), and the REAL Ed25519 remote PoP with a DURABLE nonce store that refuses
replay across a verifier restart. No real ssh binary, Proxmox host, or network is contacted.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.ownership_contract import compute_resource_marker
from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint
from secp_plugin_proxmox.mutation_transport import (
    HardenedProxmoxMutationTransport,
    HardeningManifest,
    MutationRequestRefused,
    assert_mutation_allowed,
)
from secp_worker.deployment.durable_pop import DurableChallengeStore, LocalRemotePoPAuthority
from secp_worker.deployment.locators import BridgeLocator, GuestLocator
from secp_worker.deployment.mutation_executor import ProxmoxMutationExecutor
from secp_worker.deployment.mutations import (
    CreateIsolatedBridge,
    DestroyOwnedVM,
    RemoveOwnedBridge,
)
from secp_worker.deployment.ownership_evidence import (
    ObservedOwnership,
    SealedOwnershipObserver,
)
from secp_worker.deployment.remote_pop import RemotePoPVerifier
from secp_worker.deployment.ssh_bootstrap import (
    CommandResult,
    SealedKnownHostsBindingVerifier,
    SealedWorkerBootstrapBundleSource,
    SshBootstrapBundle,
    SshBootstrapExecutor,
)
from secp_worker.staging_live.bootstrap.host_operations import (
    CreateIsolatedBridge as BootstrapBridge,
)
from secp_worker.staging_live.bootstrap.ownership import ownership_namespace
from secp_worker.staging_live.mtls_pop import (
    Ed25519DeploymentSigner,
    Ed25519PoPScheme,
    SealedDeploymentLocalSigner,
)

_LABEL = "secp-deploy-abc123def456"
_NS = ownership_namespace(_LABEL)


# --- §3 SSH bootstrap executor -------------------------------------------------------------------


class _FakeRunner:
    def __init__(self, result: CommandResult) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    def run(self, argv, *, timeout):
        self.calls.append(list(argv))
        return self.result


class _FakeBundleSource:
    def __init__(self, *, port: int = 22, raise_unexpected: bool = False) -> None:
        self.disposed = 0
        self._port = port
        self._raise_unexpected = raise_unexpected

    def acquire(self) -> SshBootstrapBundle:
        if self._raise_unexpected:
            raise RuntimeError("mount failure mid-acquire")
        return SshBootstrapBundle(
            "host.example", self._port, "secpops", "/mnt/key", "/mnt/known_hosts", "SHA256:abc"
        )

    def dispose(self) -> None:
        self.disposed += 1


class _PassVerifier:
    def verify(self, bundle) -> bool:
        return True


def _executor(runner, source, *, verifier=None):
    return SshBootstrapExecutor(
        bundle_source=source, runner=runner, host_key_verifier=verifier or _PassVerifier()
    )


def test_ssh_executor_issues_fixed_hardened_argv_no_shell():
    runner = _FakeRunner(CommandResult(exit_code=0))
    source = _FakeBundleSource()
    ex = _executor(runner, source)
    result = ex.execute(BootstrapBridge(bridge_index=0), _NS)
    assert result.ok is True and result.reason_code == "completed"
    argv = runner.calls[0]
    assert argv[0] == "/usr/bin/ssh"
    assert "BatchMode=yes" in argv and "StrictHostKeyChecking=yes" in argv
    assert "PasswordAuthentication=no" in argv and "ProxyCommand=none" in argv
    assert "--" in argv  # options terminated before the remote argv
    assert not any(tok.startswith("sh -c") or " " in tok and ";" in tok for tok in argv)
    assert source.disposed == 1  # disposed on success


def test_ssh_result_leaks_no_deployment_metadata():
    runner = _FakeRunner(CommandResult(exit_code=0))
    ex = _executor(runner, _FakeBundleSource())
    result = ex.execute(BootstrapBridge(bridge_index=0), _NS)
    # The result object carries ONLY closed status/codes — never
    # host/account/port/paths/fingerprint.
    fields = set(vars(result))
    assert fields == {"ok", "operation_code", "reason_code"}
    blob = repr(result) + repr(vars(result))
    for secret in ("host.example", "secpops", "/mnt/key", "/mnt/known_hosts", "SHA256:abc", "22"):
        assert secret not in blob


def test_ssh_host_key_binding_must_verify_before_ssh():
    runner = _FakeRunner(CommandResult(exit_code=0))
    source = _FakeBundleSource()
    # Sealed verifier cannot prove the fingerprint/known_hosts binding -> refuse before any ssh
    # call.
    ex = SshBootstrapExecutor(
        bundle_source=source, runner=runner, host_key_verifier=SealedKnownHostsBindingVerifier()
    )
    result = ex.execute(BootstrapBridge(bridge_index=0), _NS)
    assert result.ok is False and result.reason_code == "host_key_binding_unverified"
    assert runner.calls == []  # ssh was never invoked
    assert source.disposed == 1


def test_ssh_host_key_mismatch_fails_closed():
    runner = _FakeRunner(CommandResult(exit_code=255, stderr=b"Host key verification failed."))
    ex = _executor(runner, _FakeBundleSource())
    result = ex.execute(BootstrapBridge(bridge_index=0), _NS)
    assert result.ok is False and result.reason_code == "bootstrap_host_key_mismatch"


def test_ssh_sealed_bundle_and_disposal_on_unexpected_acquire_failure():
    ex = _executor(_FakeRunner(CommandResult(0)), SealedWorkerBootstrapBundleSource())
    assert ex.execute(BootstrapBridge(0), _NS).reason_code == "bootstrap_unavailable"
    # An unexpected error during acquire still disposes the bundle source.
    source = _FakeBundleSource(raise_unexpected=True)
    with pytest.raises(RuntimeError):
        _executor(_FakeRunner(CommandResult(0)), source).execute(BootstrapBridge(0), _NS)
    assert source.disposed == 1


# --- §4 hardened transport + typed route allowlist -----------------------------------------------


def _self_signed_ca(path) -> str:
    from datetime import datetime as _dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "secp-test-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt(2020, 1, 1))
        .not_valid_after(_dt(2035, 1, 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    pem = str(path)
    with open(pem, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    return pem


def test_real_httpx_client_satisfies_hardening(tmp_path):
    # Construct against a REAL, locally-built httpx.Client (no injected/attribute-shaped fake) with
    # a
    # real loadable CA; the manifest must report every control enforced.
    ca = _self_signed_ca(tmp_path / "ca.pem")
    transport = HardenedProxmoxMutationTransport(
        "https://host.example:8006/api2/json", "SCOPED-TOKEN", ca_bundle_path=ca
    )
    manifest = transport.hardening_manifest()
    assert isinstance(manifest, HardeningManifest)
    assert manifest.all_enforced() is True
    assert manifest.tls_verified and manifest.ca_pinned
    assert manifest.trust_env_disabled and manifest.redirects_disabled and manifest.timeouts_bounded
    transport.close()


def test_transport_rejects_non_https_and_missing_ca():
    with pytest.raises(MutationRequestRefused):
        HardenedProxmoxMutationTransport("http://h/api2/json", "t", ca_bundle_path="/x")
    with pytest.raises(MutationRequestRefused):
        HardenedProxmoxMutationTransport("https://h:8006/api2/json", "t", ca_bundle_path="")


def test_typed_routes_allowed_arbitrary_paths_refused():
    for method, path in [
        ("POST", "/access/users"),
        ("DELETE", "/access/users/secp-x@pve"),
        ("POST", "/access/users/secp-x@pve/token/scoped"),
        ("POST", "/nodes/pve-a/network"),
        ("DELETE", "/nodes/pve-a/network/secpbr7"),
        ("POST", "/cluster/firewall/groups"),
        ("DELETE", "/cluster/firewall/groups/secpfw1"),
        ("POST", "/nodes/pve-a/qemu"),
        ("DELETE", "/nodes/pve-a/qemu/9123"),
    ]:
        assert_mutation_allowed(method, path)  # does not raise
    for method, path in [
        ("GET", "/nodes/pve/qemu"),
        ("DELETE", "/nodes/pve/../etc"),
        ("POST", "/nodes/pve/qemu/9000/config"),
        ("PATCH", "/access/users"),
    ]:
        with pytest.raises(MutationRequestRefused):
            assert_mutation_allowed(method, path)


# --- §4 observed-ownership-gated executor --------------------------------------------------------


class _FakeTransport:
    def __init__(self, *, hardened: bool = True) -> None:
        self._hardened = hardened
        self.calls: list[tuple] = []

    def hardening_manifest(self):
        v = self._hardened
        return HardeningManifest(v, v, v, v, v, v, v)

    def apply(self, method, path, *, body=None):
        self.calls.append((method, path, body))
        return {"ok": True}


class _FlipObserver:
    """Models a provider: first observe of a seeded key -> absent; after that -> present + marker.
    Unseeded keys are always absent; a key seeded 'foreign' is present with a NON-matching
    marker."""

    def __init__(self) -> None:
        self._markers: dict[str, str] = {}
        self._seen: set[str] = set()

    def seed_create(self, locator, marker: str) -> None:
        self._markers[locator.observe_key()] = marker

    def seed_present(self, locator, marker: str) -> None:
        self._markers[locator.observe_key()] = marker
        self._seen.add(locator.observe_key())

    def observe(self, locator):
        k = locator.observe_key()
        if k not in self._markers:
            return ObservedOwnership(False, None)
        if k not in self._seen:
            self._seen.add(k)
            return ObservedOwnership(False, None)
        return ObservedOwnership(True, self._markers[k])


def _bridge_marker():
    return compute_resource_marker(_LABEL, "isolated_bridge", 0)


def test_create_owned_proves_absent_then_confirms_marker():
    transport = _FakeTransport()
    obs = _FlipObserver()
    loc = BridgeLocator(node="pve-a", iface="secpbr0")
    marker = _bridge_marker()
    obs.seed_create(loc, marker)
    ex = ProxmoxMutationExecutor(transport=transport, observer=obs)
    result = ex.create_owned(CreateIsolatedBridge(loc, marker), expected_marker=marker)
    assert result.ok is True and result.reason_code == "created"
    assert transport.calls and transport.calls[0][0] == "POST"


def test_create_refuses_when_locator_occupied_by_foreign():
    transport = _FakeTransport()
    obs = _FlipObserver()
    loc = BridgeLocator(node="pve-a", iface="secpbr0")
    marker = _bridge_marker()
    obs.seed_present(loc, "secp-owned:deadbeef#foreign")  # present, foreign marker
    ex = ProxmoxMutationExecutor(transport=transport, observer=obs)
    result = ex.create_owned(CreateIsolatedBridge(loc, marker), expected_marker=marker)
    assert result.ok is False and result.reason_code == "locator_occupied"
    assert transport.calls == []  # never issued a create against a foreign occupant


def test_delete_refuses_foreign_and_absent_targets():
    transport = _FakeTransport()
    obs = _FlipObserver()
    loc = BridgeLocator(node="pve-a", iface="secpbr0")
    marker = _bridge_marker()
    ex = ProxmoxMutationExecutor(transport=transport, observer=obs)
    # Absent -> refuse, no request.
    absent = ex.delete_owned(RemoveOwnedBridge(loc, marker), expected_marker=marker)
    assert absent.reason_code == "resource_absent" and transport.calls == []
    # Present but FOREIGN marker -> refuse, no request.
    obs.seed_present(loc, "secp-owned:deadbeef#foreign")
    foreign = ex.delete_owned(RemoveOwnedBridge(loc, marker), expected_marker=marker)
    assert foreign.reason_code == "resource_not_secp_owned" and transport.calls == []


def test_delete_owned_succeeds_only_on_fresh_proof():
    transport = _FakeTransport()
    obs = _FlipObserver()
    loc = GuestLocator(node="pve-a", vmid=9123)
    marker = compute_resource_marker(_LABEL, "nested_target_vm", 0)
    obs.seed_present(loc, marker)  # observed present + ours
    ex = ProxmoxMutationExecutor(transport=transport, observer=obs)
    result = ex.delete_owned(DestroyOwnedVM(loc, marker), expected_marker=marker)
    assert result.ok is True and transport.calls[0][0] == "DELETE"


def test_executor_fails_closed_on_sealed_observer_and_unhardened_transport():
    marker = _bridge_marker()
    loc = BridgeLocator(node="pve-a", iface="secpbr0")
    op = CreateIsolatedBridge(loc, marker)
    sealed = ProxmoxMutationExecutor(transport=_FakeTransport(), observer=SealedOwnershipObserver())
    r = sealed.create_owned(op, expected_marker=marker)
    assert r.reason_code == "ownership_observation_unavailable"
    weak = ProxmoxMutationExecutor(
        transport=_FakeTransport(hardened=False), observer=_FlipObserver()
    )
    assert weak.create_owned(op, expected_marker=marker).reason_code == "transport_not_hardened"
    # A bare caller tag can never satisfy the gate — the default observer is sealed and refuses.
    default = ProxmoxMutationExecutor(transport=_FakeTransport())
    assert default.create_owned(op, expected_marker=marker).ok is False


# --- §7 real Ed25519 remote PoP with a DURABLE nonce store ----------------------------------------


def _pop_ctx():
    return dict(
        deployment_id=uuid.uuid4(),
        operation_fingerprint="op-1",
        organization_id=uuid.uuid4(),
        worker_registration_id=uuid.uuid4(),
        worker_identity_version=3,
        plan_hash="sha256:plan",
    )


def _durable_store(session, ctx):
    return DurableChallengeStore(
        session,
        deployment_id=ctx["deployment_id"],
        organization_id=ctx["organization_id"],
        operation_fingerprint=ctx["operation_fingerprint"],
        worker_registration_id=ctx["worker_registration_id"],
        worker_identity_version=ctx["worker_identity_version"],
        plan_hash=ctx["plan_hash"],
    )


def _signer():
    priv, pub = Ed25519PoPScheme().generate_keypair()
    return Ed25519DeploymentSigner(private_key_hex=priv, public_anchor_hex=pub), pub


def test_remote_pop_verifies_then_refuses_replay_across_restart(session):
    ctx = _pop_ctx()
    signer, pub = _signer()
    anchor_fp = compute_verification_anchor_fingerprint(pub)
    now = datetime.now(UTC)

    authority = LocalRemotePoPAuthority(
        signer=signer,
        store=_durable_store(session, ctx),
        registered_anchor_fingerprint=anchor_fp,
        now=now,
    )
    ok = authority.prove(**ctx)
    assert ok.ok is True and ok.reason_code == "verified"
    session.commit()

    # Simulate a verifier restart: a BRAND-NEW store over the same durable DB. The nonce was
    # persisted + consumed, so a replay of the same challenge is refused after restart.
    from secp_api.models import StagingDeploymentPoPChallenge
    from sqlalchemy import select as _select

    replay_store = _durable_store(session, ctx)
    issued = session.execute(_select(StagingDeploymentPoPChallenge)).scalars().all()
    assert issued and issued[0].consumed is True
    assert replay_store.consume(issued[0].nonce) is False  # already consumed -> replay refused


def test_remote_pop_sealed_signer_fails_closed(session):
    ctx = _pop_ctx()
    authority = LocalRemotePoPAuthority(
        signer=SealedDeploymentLocalSigner(),
        store=_durable_store(session, ctx),
        registered_anchor_fingerprint="sha256:whatever",
        now=datetime.now(UTC),
    )
    result = authority.prove(**ctx)
    assert result.ok is False and result.reason_code == "remote_pop_unavailable"


def test_remote_pop_wrong_key_and_cross_org_and_stale_fail_closed(session):
    ctx = _pop_ctx()
    signer, pub = _signer()
    anchor_fp = compute_verification_anchor_fingerprint(pub)
    verifier = RemotePoPVerifier(scheme=Ed25519PoPScheme(), store=_durable_store(session, ctx))
    now = datetime.now(UTC)
    challenge = verifier.issue_challenge(
        deployment_id=ctx["deployment_id"],
        operation_fingerprint=ctx["operation_fingerprint"],
        organization_id=ctx["organization_id"],
        worker_registration_id=ctx["worker_registration_id"],
        worker_identity_version=ctx["worker_identity_version"],
        plan_hash=ctx["plan_hash"],
        now=now,
    )
    sig = signer.sign(challenge.signing_message())
    common = dict(
        challenge=challenge,
        presented_anchor=pub,
        registered_anchor_fingerprint=anchor_fp,
        expected_deployment_id=ctx["deployment_id"],
        expected_operation_fingerprint=ctx["operation_fingerprint"],
        expected_organization_id=ctx["organization_id"],
        expected_worker_registration_id=ctx["worker_registration_id"],
        expected_worker_identity_version=ctx["worker_identity_version"],
        expected_plan_hash=ctx["plan_hash"],
    )
    # Cross-org (altered expected) -> binding mismatch, before consuming the nonce.
    cross = verifier.verify(
        **{**common, "expected_organization_id": uuid.uuid4()}, signature=sig, now=now
    )
    assert cross.reason_code == "challenge_binding_mismatch"
    # Stale -> refused.
    stale = verifier.verify(**common, signature=sig, now=now + timedelta(seconds=600))
    assert stale.reason_code == "stale_challenge"
    # Wrong key -> Ed25519 verification fails.
    _, other_pub = Ed25519PoPScheme().generate_keypair()
    wrong = verifier.verify(
        **{
            **common,
            "presented_anchor": other_pub,
            "registered_anchor_fingerprint": compute_verification_anchor_fingerprint(other_pub),
        },
        signature=sig,
        now=now,
    )
    assert wrong.reason_code == "remote_pop_failed"
