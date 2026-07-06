"""SECP-B4 §3/§4/§7 — real execution primitives, fake-backed (no real host/ssh/http/crypto I/O).

Covers the hardened SSH bootstrap executor (fixed argv, host-key pinning, no shell, fail-closed +
credential disposal), the concrete hardened Proxmox mutation transport (closed method/path allowlist
+ hardening derived from actual client config + ownership-gated mutation executor), and the REAL
Ed25519 remote proof-of-possession (verifier-issued challenge; replay / wrong-key / cross-org /
stale / altered-payload all fail closed). No real ssh binary, Proxmox host, or network is contacted.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint
from secp_plugin_proxmox.mutation_transport import (
    HardenedProxmoxMutationTransport,
    HardeningManifest,
    MutationRequestRefused,
    assert_mutation_allowed,
)
from secp_worker.deployment.mutation_executor import ProxmoxMutationExecutor
from secp_worker.deployment.remote_pop import (
    InMemoryChallengeStore,
    RemotePoPVerifier,
)
from secp_worker.deployment.ssh_bootstrap import (
    BootstrapBundleUnavailable,
    CommandResult,
    SealedWorkerBootstrapBundleSource,
    SshBootstrapBundle,
    SshBootstrapExecutor,
)
from secp_worker.staging_live.bootstrap.host_operations import CreateIsolatedBridge
from secp_worker.staging_live.bootstrap.ownership import ownership_namespace
from secp_worker.staging_live.live_proxmox_provider import (
    CapacityProfile,
    LiveProxmoxProvider,
    TargetInventory,
)
from secp_worker.staging_live.mtls_pop import (
    Ed25519PoPScheme,
    LocalHashBasedPoPScheme,
    RemoteAuthenticationIneligible,
    assert_remote_authentication_eligible,
)

_NS = ownership_namespace("secp-deploy-abc123def456")


# --- §3 SSH bootstrap executor -------------------------------------------------------------------


class _FakeRunner:
    def __init__(self, result: CommandResult) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    def run(self, argv, *, timeout):
        self.calls.append(list(argv))
        return self.result


class _FakeBundleSource:
    def __init__(self, *, port: int = 22) -> None:
        self.disposed = 0
        self._port = port

    def acquire(self) -> SshBootstrapBundle:
        return SshBootstrapBundle(
            "host.example", self._port, "secpops", "/mnt/key", "/mnt/known_hosts", "SHA256:abc"
        )

    def dispose(self) -> None:
        self.disposed += 1


def test_ssh_executor_issues_fixed_hardened_argv_no_shell():
    runner = _FakeRunner(CommandResult(exit_code=0))
    source = _FakeBundleSource()
    ex = SshBootstrapExecutor(bundle_source=source, runner=runner)
    result = ex.execute(CreateIsolatedBridge(bridge_index=0), _NS)
    assert result.ok is True
    argv = runner.calls[0]
    assert argv[0] == "/usr/bin/ssh"  # fixed executable path (not PATH-discovered)
    for flag in (
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=/dev/null",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "ForwardAgent=no",
        "ProxyCommand=none",
        "UserKnownHostsFile=/mnt/known_hosts",
        "secpops@host.example",
    ):
        assert flag in argv
    # No shell wrapper anywhere in the argv.
    assert "sh" not in argv and "bash" not in argv
    assert source.disposed == 1  # credential disposed after success


def test_ssh_executor_fails_closed_on_host_key_mismatch_and_disposes():
    source = _FakeBundleSource()
    ex = SshBootstrapExecutor(
        bundle_source=source,
        runner=_FakeRunner(CommandResult(exit_code=255, stderr=b"Host key verification failed.")),
    )
    result = ex.execute(CreateIsolatedBridge(bridge_index=0), _NS)
    assert result.ok is False
    assert result.reason_code == "bootstrap_host_key_mismatch"
    assert source.disposed == 1


def test_ssh_executor_fails_closed_on_timeout():
    ex = SshBootstrapExecutor(
        bundle_source=_FakeBundleSource(),
        runner=_FakeRunner(CommandResult(exit_code=124, timed_out=True)),
    )
    result = ex.execute(CreateIsolatedBridge(bridge_index=0), _NS)
    assert result.reason_code == "bootstrap_timeout"


def test_ssh_executor_fails_closed_on_invalid_bundle_port():
    ex = SshBootstrapExecutor(
        bundle_source=_FakeBundleSource(port=999999),
        runner=_FakeRunner(CommandResult(exit_code=0)),
    )
    result = ex.execute(CreateIsolatedBridge(bridge_index=0), _NS)
    assert result.reason_code == "bootstrap_operation_refused"


def test_sealed_bootstrap_bundle_source_refuses():
    with pytest.raises(BootstrapBundleUnavailable):
        SealedWorkerBootstrapBundleSource().acquire()


def test_ssh_bundle_is_redacted_and_not_serializable():
    import pickle

    bundle = SshBootstrapBundle("h", 22, "u", "/k", "/kh", "fp")
    assert repr(bundle) == "SshBootstrapBundle(<redacted>)"
    with pytest.raises(TypeError):
        pickle.dumps(bundle)


# --- §4 hardened mutation transport + ownership-gated executor ------------------------------------


@pytest.mark.parametrize(
    "method, path, allowed",
    [
        ("POST", "/nodes/pve1/network", True),
        ("DELETE", "/access/token/secp/t1", True),
        ("POST", "/nodes/pve1/qemu", True),
        ("GET", "/nodes/pve1/network", False),
        ("POST", "/nodes/pve1/../network", False),
        ("POST", "/arbitrary/path", False),
        ("PATCH", "/nodes/pve1/network", False),
    ],
)
def test_mutation_allowlist_is_closed(method, path, allowed):
    if allowed:
        assert_mutation_allowed(method, path)
    else:
        with pytest.raises(MutationRequestRefused):
            assert_mutation_allowed(method, path)


class _FakeResp:
    status_code = 200
    is_redirect = False
    headers: dict = {}

    def raise_for_status(self):
        return None

    def json(self):
        return {"data": {"ok": True}}


class _FakeHttpxClient:
    trust_env = False
    follow_redirects = False
    timeout = object()
    _verify = "/mnt/ca.pem"

    def __init__(self):
        self.requests: list[tuple] = []

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs.get("data")))
        return _FakeResp()

    def close(self):
        return None


def _transport(client=None):
    return HardenedProxmoxMutationTransport(
        "https://host.example:8006/api2/json",
        "SCOPED-TOKEN",
        ca_bundle_path="/mnt/ca.pem",
        client=client or _FakeHttpxClient(),
    )


def test_mutation_transport_manifest_derived_from_actual_config():
    manifest = _transport().hardening_manifest()
    assert isinstance(manifest, HardeningManifest)
    assert manifest.all_enforced() is True
    assert manifest.ca_pinned and manifest.trust_env_disabled and manifest.redirects_disabled


def test_mutation_transport_rejects_non_https_and_missing_ca():
    with pytest.raises(MutationRequestRefused):
        HardenedProxmoxMutationTransport(
            "http://host.example/api2/json",
            "t",
            ca_bundle_path="/mnt/ca.pem",
            client=_FakeHttpxClient(),
        )
    with pytest.raises(MutationRequestRefused):
        HardenedProxmoxMutationTransport(
            "https://host.example:8006/api2/json", "t", ca_bundle_path="", client=_FakeHttpxClient()
        )


def _provider():
    reader = type(
        "R",
        (),
        {
            "read_inventory": lambda self: TargetInventory(
                True, False, 1, True, "available", 100, 32, 65536, 2048
            )
        },
    )()
    return LiveProxmoxProvider(
        namespace=_NS, inventory_reader=reader, capacity_profile=CapacityProfile(10, 8, 8192, 200)
    )


def test_mutation_executor_gates_on_hardening_and_ownership():
    client = _FakeHttpxClient()
    ex = ProxmoxMutationExecutor(transport=_transport(client), provider=_provider())
    assert ex.transport_is_hardened() is True
    ok = ex.apply_owned(
        method="POST", path="/nodes/pve1/network", owner_tag=_NS.ownership_tag, body={"iface": "x"}
    )
    assert ok.ok is True and ok.reason_code == "applied"
    assert client.requests and client.requests[0][0] == "POST"
    # A foreign / non-SECP-owned tag is refused BEFORE any request would be issued.
    foreign = ex.apply_owned(
        method="POST",
        path="/nodes/pve1/network",
        owner_tag="secp-owned:deadbeef",
        body={"iface": "x"},
    )
    assert foreign.ok is False and foreign.reason_code == "resource_not_secp_owned"


def test_mutation_executor_refuses_non_hardened_transport():
    class _WeakClient(_FakeHttpxClient):
        follow_redirects = True  # not hardened

    ex = ProxmoxMutationExecutor(transport=_transport(_WeakClient()), provider=_provider())
    assert ex.transport_is_hardened() is False
    result = ex.apply_owned(
        method="POST", path="/nodes/pve1/network", owner_tag=_NS.ownership_tag, body={"iface": "x"}
    )
    assert result.ok is False and result.reason_code == "transport_not_hardened"


# --- §7 real Ed25519 remote proof-of-possession --------------------------------------------------


def test_ed25519_scheme_is_remote_eligible_and_real():
    scheme = Ed25519PoPScheme()
    assert scheme.remote_authentication_eligible is True
    assert_remote_authentication_eligible(scheme)  # does not raise
    priv, pub = scheme.generate_keypair()
    sig = scheme.sign(private_key_hex=priv, message=b"m")
    assert scheme.verify(public_anchor=pub, message=b"m", signature=sig) is True
    assert scheme.verify(public_anchor=pub, message=b"tampered", signature=sig) is False
    _, other_pub = scheme.generate_keypair()
    assert scheme.verify(public_anchor=other_pub, message=b"m", signature=sig) is False


def test_remote_pop_verifier_refuses_the_local_hash_scheme():
    with pytest.raises(RemoteAuthenticationIneligible):
        RemotePoPVerifier(scheme=LocalHashBasedPoPScheme())


def _remote_ctx():
    return dict(
        deployment_id=uuid.uuid4(),
        operation_fingerprint="op-1",
        organization_id=uuid.uuid4(),
        worker_registration_id=uuid.uuid4(),
        worker_identity_version=3,
        plan_hash="sha256:plan",
    )


def _sign_and_verify(scheme, verifier, priv, pub, ctx, challenge, now, **overrides):
    verify_now = overrides.pop("now", now)
    sig = scheme.sign(private_key_hex=priv, message=challenge.signing_message())
    kwargs = dict(
        challenge=challenge,
        presented_anchor=pub,
        registered_anchor_fingerprint=compute_verification_anchor_fingerprint(pub),
        signature=sig,
        now=verify_now,
        expected_deployment_id=ctx["deployment_id"],
        expected_operation_fingerprint=ctx["operation_fingerprint"],
        expected_organization_id=ctx["organization_id"],
        expected_worker_registration_id=ctx["worker_registration_id"],
        expected_worker_identity_version=ctx["worker_identity_version"],
        expected_plan_hash=ctx["plan_hash"],
    )
    kwargs.update(overrides)
    return verifier.verify(**kwargs)


def test_remote_pop_verifier_issued_challenge_succeeds_and_binds_context():
    scheme = Ed25519PoPScheme()
    priv, pub = scheme.generate_keypair()
    verifier = RemotePoPVerifier(scheme=scheme, store=InMemoryChallengeStore())
    ctx = _remote_ctx()
    now = datetime.now(UTC)
    challenge = verifier.issue_challenge(now=now, **ctx)
    result = _sign_and_verify(scheme, verifier, priv, pub, ctx, challenge, now)
    assert result.ok is True and result.reason_code == "verified"


def test_remote_pop_replay_is_refused():
    scheme = Ed25519PoPScheme()
    priv, pub = scheme.generate_keypair()
    verifier = RemotePoPVerifier(scheme=scheme, store=InMemoryChallengeStore())
    ctx = _remote_ctx()
    now = datetime.now(UTC)
    challenge = verifier.issue_challenge(now=now, **ctx)
    assert _sign_and_verify(scheme, verifier, priv, pub, ctx, challenge, now).ok is True
    replayed = _sign_and_verify(scheme, verifier, priv, pub, ctx, challenge, now)
    assert replayed.ok is False and replayed.reason_code == "challenge_replayed"


def test_remote_pop_wrong_key_and_cross_org_and_stale_fail_closed():
    scheme = Ed25519PoPScheme()
    priv, pub = scheme.generate_keypair()
    verifier = RemotePoPVerifier(scheme=scheme, store=InMemoryChallengeStore())
    ctx = _remote_ctx()
    now = datetime.now(UTC)

    # Wrong key: sign the challenge with an impostor key but present the registered anchor.
    challenge = verifier.issue_challenge(now=now, **ctx)
    impostor_priv, _ = scheme.generate_keypair()
    forged = scheme.sign(private_key_hex=impostor_priv, message=challenge.signing_message())
    wrong_key = _sign_and_verify(scheme, verifier, priv, pub, ctx, challenge, now, signature=forged)
    assert wrong_key.reason_code == "remote_pop_failed"

    # Cross-org / altered payload: verify against a different expected org.
    challenge = verifier.issue_challenge(now=now, **ctx)
    cross = _sign_and_verify(
        scheme, verifier, priv, pub, ctx, challenge, now, expected_organization_id=uuid.uuid4()
    )
    assert cross.reason_code == "challenge_binding_mismatch"

    # Stale challenge: verify well after expiry (verify-time now is the 7th positional arg).
    challenge = verifier.issue_challenge(now=now, **ctx)
    stale = _sign_and_verify(
        scheme, verifier, priv, pub, ctx, challenge, now + timedelta(seconds=600)
    )
    assert stale.reason_code == "stale_challenge"


def test_remote_pop_wrong_registration_anchor_pin_mismatch():
    scheme = Ed25519PoPScheme()
    priv, pub = scheme.generate_keypair()
    verifier = RemotePoPVerifier(scheme=scheme, store=InMemoryChallengeStore())
    ctx = _remote_ctx()
    now = datetime.now(UTC)
    challenge = verifier.issue_challenge(now=now, **ctx)
    _, other_pub = scheme.generate_keypair()
    result = _sign_and_verify(
        scheme,
        verifier,
        priv,
        pub,
        ctx,
        challenge,
        now,
        registered_anchor_fingerprint=compute_verification_anchor_fingerprint(other_pub),
    )
    assert result.reason_code == "anchor_pin_mismatch"
