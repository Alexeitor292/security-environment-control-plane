"""``run_full_discovery`` has a production caller, and this is what proves it.

The engine was complete and reachable from nothing: twenty-four typed operations, a derived
transport grammar, a canonical fact commitment and a worker-local signature, all invoked only by
fixtures. This file drives ``run_authorized_discovery`` — the real entry point — against real
durable rows, and asserts the composition was actually entered rather than that it could be.

**No socket is opened.** The transport factory is spied on, the credential resolver is the sealed
shipped default in most tests, and the two tests that reach the transport hand it a bounded fake.
The one test that uses the REAL ``HardenedDiscoveryTransportFactory`` never gets past the
credential step, which is the shipped posture.
"""

from __future__ import annotations

import pytest
from secp_api.discovery_authority_loader import DiscoveryAuthorityRefused
from secp_api.discovery_verification import REQUIRED_WORKER_ROLE
from secp_commissioning.enrollment_attestation import key_id_for
from secp_management.signing import generate_keypair
from secp_worker.proxmox_discovery_runtime import (
    DISCOVERY_FRESHNESS_BOUND_SECONDS,
    AuthorizedDiscoveryOutcome,
    DiscoveryRuntimeError,
    LocalWorkerDiscoverySigner,
    run_authorized_discovery,
)
from test_discovery_authority_loader import NOW, RELEASE, WORKER, _build

CA_PATH = "/etc/secp/pve-ca.pem"


class _FakeInstalledRecord:
    """What ``read_installed_worker_record`` returns: the worker's own view of itself."""

    def __init__(self, installation_id: str = WORKER, release_digest: str = RELEASE) -> None:
        self.installation_id = installation_id
        self.release_digest = release_digest


class _FakeKeySeam:
    """Holds a real Ed25519 pair and signs with it. Reads no filesystem."""

    def __init__(self, priv: str, pub: str) -> None:
        self._priv, self._pub = priv, pub
        self.loads = 0

    def load_or_create(self):
        self.loads += 1
        seam = self

        class _Signer:
            worker_key_id = key_id_for(seam._pub)

            def sign_discovery_snapshot(self, digest: str):
                from secp_api.discovery_verification import (
                    DISCOVERY_SNAPSHOT_DOMAIN,
                    DISCOVERY_SNAPSHOT_KIND,
                )
                from secp_commissioning.enrollment_attestation import sign_detached

                return sign_detached(
                    seam._priv,
                    domain=DISCOVERY_SNAPSHOT_DOMAIN,
                    kind=DISCOVERY_SNAPSHOT_KIND,
                    digest=digest,
                )

        return _Signer()


@pytest.fixture
def installed_worker(monkeypatch):
    """Patch the worker's host-local self-observation. Every test needs one."""
    import secp_worker.enrollment_health_probes as probes

    record = _FakeInstalledRecord()
    monkeypatch.setattr(probes, "read_installed_worker_record", lambda fs: record)
    return record


def _keys_for_anchor(session, principal, **overrides):
    """Build the durable chain with the registration's anchor matching a real key pair."""
    priv, pub = generate_keypair()
    admission, target, registration, authorization = _build(
        session, principal, anchor=key_id_for(pub), **overrides
    )
    return priv, pub, admission, target, registration, authorization


def _run(session, principal, admission, **kw):
    return run_authorized_discovery(
        session,
        admission_id=admission.id,
        organization_id=principal.organization_id,
        ca_path=kw.pop("ca_path", CA_PATH),
        now=kw.pop("now", NOW),
        **kw,
    )


# === the production caller is entered ============================================================


def test_the_production_caller_reaches_the_signed_composition(
    session, principal, installed_worker, monkeypatch
):
    """The whole point. A real admission id drives the real composition, and the transport factory
    is BUILT — which only happens after the credential resolved and every binding check passed."""
    priv, pub, admission, target, _reg, _auth = _keys_for_anchor(session, principal)

    built: list[dict] = []
    requested: list[str] = []

    class _Factory:
        def build(self, *, base_url, ca_path, token):
            built.append({"base_url": base_url, "ca_path": ca_path, "token": token})

            class _T:
                def execute(self, operation):
                    requested.append(operation.rendered_path())
                    raise RuntimeError("proxmox_discovery_endpoint_absent")

            return _T()

    class _Resolver:
        def __init__(self):
            self.calls = []

        def resolve(self, request, *, expectation, now):
            from secp_worker.preflight.secret_resolution import SecretMaterial

            self.calls.append(expectation.worker_installation_id)
            return SecretMaterial("secpdisc@pve!discovery=" + "0" * 8)

    resolver = _Resolver()
    monkeypatch.setattr(
        "secp_worker.proxmox_discovery_transport.HardenedDiscoveryTransportFactory", _Factory
    )

    outcome = _run(
        session,
        principal,
        admission,
        resolver=resolver,
        key_seam=_FakeKeySeam(priv, pub),
        filesystem=object(),
    )

    assert isinstance(outcome, AuthorizedDiscoveryOutcome)
    assert resolver.calls == [WORKER], "the guarded resolver was never reached"
    assert built, "the transport factory was never built — the composition was not entered"
    assert requested, "no typed operation was executed"
    assert built[0]["ca_path"] == CA_PATH


def test_every_expected_value_comes_from_a_row_and_not_from_the_caller(
    session, principal, installed_worker
):
    """The caller supplies an admission id, an organization, a CA path and a clock. Nothing else."""
    import inspect

    params = set(inspect.signature(run_authorized_discovery).parameters)
    assert params == {
        "session",
        "admission_id",
        "organization_id",
        "ca_path",
        "resolver",
        "key_seam",
        "filesystem",
        "now",
    }
    for banned in (
        "target_identity",
        "worker_installation_id",
        "worker_role",
        "expected_key",
        "release",
        "operation_generation",
        "credential",
        "signature",
        "base_url",
    ):
        assert banned not in params, banned


def test_the_target_and_generation_reported_back_are_the_durable_ones(
    session, principal, installed_worker
):
    priv, pub, admission, target, _reg, authorization = _keys_for_anchor(session, principal)
    outcome = _run(
        session, principal, admission, key_seam=_FakeKeySeam(priv, pub), filesystem=object()
    )
    assert outcome.expected_target_identity == str(target.id)
    assert outcome.expected_organization_identity == str(principal.organization_id)
    assert outcome.expected_operation_generation == authorization.authorization_version


# === it fails closed, in the right order =========================================================


def test_the_shipped_default_resolver_refuses_before_a_socket(
    session, principal, installed_worker, monkeypatch
):
    """The shipped posture: real authority, real transport FACTORY, and a refusal at the credential
    step. Proved by sealing the client opener rather than by reading the code."""
    import secp_worker.proxmox_discovery_transport as transport

    opened: list[str] = []

    def _forbidden(*a, **k):
        opened.append("open")
        raise AssertionError("a client was opened on the sealed-resolver path")

    monkeypatch.setattr(transport, "open_hardened_client", _forbidden)

    priv, pub, admission, _t, _r, _a = _keys_for_anchor(session, principal)
    outcome = _run(
        session, principal, admission, key_seam=_FakeKeySeam(priv, pub), filesystem=object()
    )
    assert outcome.failed is True
    assert outcome.failure_reason == "credential_unavailable"
    assert opened == []


def test_the_shipped_default_is_the_SEALED_resolver_and_not_merely_a_failing_one():
    """A mutation that DELETED the sealed default survived the behavioural tests, and the reason is
    worth recording rather than papering over: ``run_full_discovery`` maps any resolution failure —
    including passing it ``None`` — to ``credential_unavailable``, so "no resolver at all" and "the
    sealed resolver" are behaviourally identical from outside.

    They are not identical in intent. The sealed default is what makes the shipped posture a
    DELIBERATE refusal rather than an accident of a missing argument, and it is what a future edit
    supplying a permissive default would have to remove. So this pins the identity structurally.
    """
    import ast
    import inspect
    import pathlib

    from secp_worker.preflight.secret_resolution import SealedDiscoveryCredentialResolver

    source = pathlib.Path(inspect.getfile(run_authorized_discovery)).read_text(encoding="utf-8")
    tree = ast.parse(source)

    defaults: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "resolver":
            # ``resolver if resolver is not None else <X>()`` — record the else branch.
            value = node.value
            assert isinstance(value, ast.IfExp), ast.dump(value)
            orelse = value.orelse
            assert isinstance(orelse, ast.Call), ast.dump(orelse)
            assert isinstance(orelse.func, ast.Name), ast.dump(orelse.func)
            defaults.append(orelse.func.id)
    assert defaults == ["SealedDiscoveryCredentialResolver"], defaults

    # And the class it names is the one that always fails closed.
    with pytest.raises(Exception, match="sealed default"):
        SealedDiscoveryCredentialResolver().resolve(object(), expectation=object(), now=NOW)


def test_an_unauthorized_operation_never_reaches_the_composition(
    session, principal, installed_worker
):
    """Every loader refusal stops the run before a signer, a factory or a resolver is touched."""
    from secp_api.enums import WorkerDiscoveryAdmissionStatus

    priv, pub, admission, _t, _r, _a = _keys_for_anchor(
        session, principal, admission_status=WorkerDiscoveryAdmissionStatus.consumed
    )
    with pytest.raises(DiscoveryAuthorityRefused) as exc:
        _run(session, principal, admission, key_seam=_FakeKeySeam(priv, pub), filesystem=object())
    assert exc.value.reason == "discovery_admission_not_admitted"


def test_an_unconfigured_ca_bundle_refuses_by_its_own_name(session, principal, installed_worker):
    """Named separately so an operator sees the installation fact to supply, rather than a generic
    transport failure."""
    priv, pub, admission, _t, _r, _a = _keys_for_anchor(session, principal)
    for blank in ("", "   "):
        with pytest.raises(DiscoveryRuntimeError, match="discovery_ca_bundle_not_configured"):
            _run(
                session,
                principal,
                admission,
                ca_path=blank,
                key_seam=_FakeKeySeam(priv, pub),
                filesystem=object(),
            )


# === the signer says what the WORKER observes, never what the control plane expects ==============


def test_the_signer_reads_its_identity_from_the_host_not_from_the_authority(monkeypatch):
    """The non-tautology test. If the signer took its installation id and release from the loaded
    authority, the control plane's comparison would pass by construction — which is exactly the
    supplied-expectation hole the chain exists to close."""
    import secp_worker.enrollment_health_probes as probes

    monkeypatch.setattr(
        probes,
        "read_installed_worker_record",
        lambda fs: _FakeInstalledRecord("wk-from-the-host", "sha256:" + "9" * 64),
    )
    priv, pub = generate_keypair()
    signer = LocalWorkerDiscoverySigner(_FakeKeySeam(priv, pub), filesystem=object())

    assert signer.installation_id() == "wk-from-the-host"
    assert signer.release_fingerprint() == "sha256:" + "9" * 64
    assert signer.key_fingerprint() == key_id_for(pub)
    assert signer.role() == REQUIRED_WORKER_ROLE


def test_a_host_that_cannot_say_what_it_is_refuses_to_sign(monkeypatch):
    """Absent, drifted, mismatched or not-a-worker are one refusal: this host must not sign a claim
    about what it is."""
    import secp_worker.enrollment_health_probes as probes

    monkeypatch.setattr(probes, "read_installed_worker_record", lambda fs: None)
    priv, pub = generate_keypair()
    signer = LocalWorkerDiscoverySigner(_FakeKeySeam(priv, pub), filesystem=object())
    with pytest.raises(DiscoveryRuntimeError, match="discovery_worker_installation_unobservable"):
        signer.installation_id()
    with pytest.raises(DiscoveryRuntimeError, match="discovery_worker_installation_unobservable"):
        signer.release_fingerprint()


def test_the_signer_holds_no_key_and_caches_nothing(monkeypatch):
    """A key rotated between calls must be observed, not remembered — and the private key must not
    be reachable through the signer at all."""
    import secp_worker.enrollment_health_probes as probes

    monkeypatch.setattr(probes, "read_installed_worker_record", lambda fs: _FakeInstalledRecord())
    priv, pub = generate_keypair()
    seam = _FakeKeySeam(priv, pub)
    signer = LocalWorkerDiscoverySigner(seam, filesystem=object())

    signer.key_fingerprint()
    signer.key_fingerprint()
    assert seam.loads == 2, "the signer cached the key seam"

    assert signer.__slots__ == ("_seam", "_fs")
    assert not hasattr(signer, "__dict__")
    assert priv not in repr(signer)
    assert "redacted" in repr(signer)


def test_the_signer_signs_under_the_discovery_domain_not_the_enrollment_one():
    """Domain separation is what stops an enrollment proof-of-possession being replayed as a
    discovery snapshot signature."""
    from secp_api.discovery_verification import (
        DISCOVERY_SNAPSHOT_DOMAIN,
        DISCOVERY_SNAPSHOT_KIND,
    )
    from secp_commissioning.enrollment_attestation import (
        ENROLLMENT_ATTESTATION_DOMAIN,
        AttestationError,
        verify_detached,
    )

    priv, pub = generate_keypair()
    from secp_worker.enrollment_http_transport import WorkerEnrollmentSigner

    real = WorkerEnrollmentSigner(priv)
    digest = "sha256:" + "d" * 64
    attestation = real.sign_discovery_snapshot(digest)

    verify_detached(
        attestation,
        domain=DISCOVERY_SNAPSHOT_DOMAIN,
        kind=DISCOVERY_SNAPSHOT_KIND,
        digest=digest,
        expected_key_id=key_id_for(pub),
    )
    with pytest.raises(AttestationError):
        verify_detached(
            attestation,
            domain=ENROLLMENT_ATTESTATION_DOMAIN,
            kind=DISCOVERY_SNAPSHOT_KIND,
            digest=digest,
            expected_key_id=key_id_for(pub),
        )


def test_the_freshness_bound_is_a_contract_constant_not_a_parameter():
    """A run that could widen its own freshness window could present an arbitrarily old cluster
    view as current."""
    import inspect

    assert DISCOVERY_FRESHNESS_BOUND_SECONDS == 1800
    assert "freshness_bound_seconds" not in inspect.signature(run_authorized_discovery).parameters
