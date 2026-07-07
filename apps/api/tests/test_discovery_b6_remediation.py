"""SECP-B6 merge-blocker remediations — behavioral proofs (fake-backed; zero real host contact).

Covers, end to end through the REAL engine/consumer/composition gates:
  F-BIND     a bundle for target/org A cannot be used for a job for target/org B; the live-read
             authorization is re-verified (revoked/expired/version/connection-hash/inactive fail).
  F-IDENTITY an approved worker identity is mandatory before host contact; revocation/version drift
             mid-run blocks the plan; a version-0 plan is unapprovable; ambiguous identity refuses.
  F-AUDIT    the completion audit + snapshot carry the TRUTHFUL bundle_available / contact_state.
  F-BLAST    a privileged (root) SSH account is refused.
  cmd-safety assert_read_only rejects metacharacters; the ssh argv pins -F none / IdentitiesOnly.
  F-FS       (POSIX) the strict descriptor path rejects hardlinks / writable mounts and hands ssh a
             worker-private inode-pinned copy.

Every failed-precondition test asserts the probe source was NEVER engaged (zero ssh).
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime

import pytest
import secp_api.audit as audit_mod
from secp_api.enums import (
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    TargetStatus,
    WorkerIdentityEvidenceKind,
    WorkerIdentityEvidenceStatus,
    WorkerIdentityMechanism,
)
from secp_api.models import (
    DiscoveryCandidatePlan,
    DiscoveryJob,
    DiscoverySnapshot,
    ExecutionTarget,
    LiveReadAuthorization,
    TargetDiscoveryEnrollment,
    TargetOnboarding,
)
from secp_api.services import readonly_preflight, staging_labs
from secp_api.services import target_discovery as svc
from secp_api.services import worker_identity as wi
from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint
from secp_worker.mounted_bundle import MountedWorkerBootstrapBundleSource
from secp_worker.target_discovery.consumer import claim_and_process_one
from secp_worker.target_discovery.engine import DiscoveryComposition, run_discovery
from secp_worker.target_discovery.seams import (
    InventoryFacts,
    LocatorPresence,
    ProbeSourceUnavailable,
    StorageOption,
)

_POSIX = os.name == "posix"


# --- fakes -------------------------------------------------------------------


def _healthy_facts() -> InventoryFacts:
    return InventoryFacts(
        8,
        1,
        False,
        "pve-a",
        1,
        16,
        65536,
        32768,
        True,
        (StorageOption("local-lvm", 500_000, True),),
        frozenset(),
    )


class _FakeProbe:
    """A probe source that records whether it was engaged (i.e., whether 'ssh' would run)."""

    def __init__(self, facts: InventoryFacts | None = None, raises: str | None = None):
        self._facts = facts if facts is not None else _healthy_facts()
        self._raises = raises
        self.inventory_calls = 0
        self.presence_calls = 0

    @property
    def calls(self) -> int:
        return self.inventory_calls + self.presence_calls

    def read_inventory(self) -> InventoryFacts:
        self.inventory_calls += 1
        if self._raises is not None:
            raise ProbeSourceUnavailable(self._raises)
        return self._facts

    def probe_candidate_presence(self, locators):
        self.presence_calls += 1
        return {loc.observe_key(): LocatorPresence(False, None) for loc in locators}


# --- authoritative-record helpers -------------------------------------------


_BASE_URL = "https://pve-a.internal:8006"
_HOST = "pve-a.internal"
_FP = "SHA256:" + "A" * 43


def _endpoint_hash(*, ssh_host=_HOST, ssh_port=22, fingerprint=_FP) -> str:
    from secp_api.live_read_contract import normalize_target_host, ssh_endpoint_binding_hash

    return ssh_endpoint_binding_hash(
        normalized_target_host=normalize_target_host({"base_url": _BASE_URL}),
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        host_key_fingerprint=fingerprint,
    )


def _ed_worker(session, principal, *, label: str = "staging-worker-a") -> tuple[str, str]:
    """Register + approve a worker identity whose anchor is a real Ed25519 public key. Returns
    (private_key_hex, public_anchor_hex) so the HttpWorkerAdmissionClient can prove possession."""
    from secp_api.worker_admission_contract import generate_ed25519_keypair

    priv, pub = generate_ed25519_keypair()
    row = wi.register_worker_identity(
        session,
        principal,
        mechanism=WorkerIdentityMechanism.mtls_workload_identity,
        identity_label=label,
        deployment_binding=f"deploy-{label}",
        verification_anchor_fingerprint=compute_verification_anchor_fingerprint(pub),
    )
    for kind in WorkerIdentityEvidenceKind:
        wi.record_evidence(
            session,
            principal,
            row.id,
            kind=kind,
            status=WorkerIdentityEvidenceStatus.verified,
            proof_id="TKT-1",
            issuer="rev",
        )
    wi.approve_worker_identity(session, principal, row.id)
    return priv, pub


def _approve_worker_identity(session, principal, *, label: str = "staging-worker-a"):
    """A worker identity with a non-key anchor (for tests that never run the admission)."""
    fingerprint = compute_verification_anchor_fingerprint(f"anchor-{label}")
    row = wi.register_worker_identity(
        session,
        principal,
        mechanism=WorkerIdentityMechanism.mtls_workload_identity,
        identity_label=label,
        deployment_binding=f"deploy-{label}",
        verification_anchor_fingerprint=fingerprint,
    )
    for kind in WorkerIdentityEvidenceKind:
        wi.record_evidence(
            session,
            principal,
            row.id,
            kind=kind,
            status=WorkerIdentityEvidenceStatus.verified,
            proof_id="TKT-1",
            issuer="rev",
        )
    return wi.approve_worker_identity(session, principal, row.id)


def _target_with_auth(
    session, principal, *, endpoint_binding_hash=None
) -> tuple[ExecutionTarget, TargetOnboarding, LiveReadAuthorization]:
    ebh = endpoint_binding_hash if endpoint_binding_hash is not None else _endpoint_hash()
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={"base_url": _BASE_URL, "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref="vault:secp/proxmox/target-1",
        status=TargetStatus.active,
        scope_policy={},
        created_by=principal.user_id,
    )
    session.add(target)
    session.flush()
    onboarding = TargetOnboarding(
        organization_id=principal.organization_id,
        execution_target_id=target.id,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=IsolationModel.logical,
        status=OnboardingStatus.active,
        declared_boundary={},
        boundary_hash="sha256:" + "cd" * 32,
        created_by=principal.user_id,
    )
    session.add(onboarding)
    session.flush()
    staging_labs.grant_substrate_eligibility(session, principal, execution_target_id=target.id)
    auth = readonly_preflight.create_preflight_authorization(
        session, principal, execution_target_id=target.id, endpoint_binding_hash=ebh
    )
    auth = readonly_preflight.approve_preflight_authorization(session, principal, auth.id)
    return target, onboarding, auth


def _enroll(session, principal, target) -> tuple[object, DiscoveryJob]:
    enrollment = svc.request_discovery(session, principal, execution_target_id=target.id)
    job = session.query(DiscoveryJob).filter(DiscoveryJob.enrollment_id == enrollment.id).one()
    return enrollment, job


def _anchor(
    *, org, target, onboarding, enrollment, auth_id, auth_version, endpoint_binding_hash=None
) -> dict:
    return {
        "organization_id": str(org),
        "execution_target_id": str(target),
        "onboarding_id": str(onboarding),
        "enrollment_id": str(enrollment),
        "authorization_id": str(auth_id),
        "authorization_version": auth_version,
        "endpoint_binding_hash": endpoint_binding_hash or _endpoint_hash(),
    }


def _full_mount(tmp_path, anchor: dict, *, ssh_host=_HOST, account="secp", fingerprint=_FP) -> str:
    mount = tmp_path / "bundle"
    mount.mkdir()
    (mount / "manifest.json").write_text(
        json.dumps(
            {
                "ssh_host": ssh_host,
                "ssh_port": 22,
                "account": account,
                "host_key_fingerprint": fingerprint,
            }
        )
    )
    (mount / "id_key").write_bytes(b"PRIVATE-KEY-BYTES")
    (mount / "known_hosts").write_bytes(f"{ssh_host} ssh-ed25519 AAAA\n".encode())
    (mount / "binding.json").write_text(json.dumps(anchor))
    if _POSIX:
        os.chmod(mount, 0o700)
        for f in ("manifest.json", "id_key", "known_hosts", "binding.json"):
            os.chmod(mount / f, 0o600)
    return str(mount)


class _InProcAdmissionTransport:
    """A faithful in-process realization of the internal admission ROUTE for the engine gate tests.

    The engine crosses the SAME control-plane boundary as production — its
    :class:`HttpWorkerAdmissionClient` builds the begin/complete/assert/consume requests and signs
    the server-issued nonce with Ed25519 — but this transport dispatches them against the engine's
    OWN session (mirroring the FastAPI route: server clock, enrollment re-derived from the job,
    closed reason codes). That keeps the ~15 gating tests on ONE transaction (no SQLite cross-conn
    lock contention with a long-lived engine session). The dedicated ASGI tests in
    ``test_worker_admission_route.py`` prove the identical client over the REAL HTTP route.
    """

    _BASE = "/internal/worker-discovery-admission"

    def __init__(self, session):
        self._session = session

    def post(self, path: str, payload: dict) -> tuple[int, dict]:
        from secp_api.services import worker_admission as adm

        s = self._session
        rel = path[len(self._BASE) :] if path.startswith(self._BASE) else path
        now = datetime.now(UTC)  # the route always uses the SERVER clock, never a client value
        try:
            if rel == "/begin":
                a = adm.issue_discovery_admission_challenge(
                    s,
                    discovery_job_id=uuid.UUID(payload["discovery_job_id"]),
                    authorization_id=uuid.UUID(payload["authorization_id"]),
                    authorization_version=payload["authorization_version"],
                    endpoint_binding_hash=payload["endpoint_binding_hash"],
                    now=now,
                )
                return 200, {
                    "admission_id": str(a.id),
                    "nonce": a.nonce,
                    "organization_id": str(a.organization_id),
                    "discovery_job_id": str(a.discovery_job_id),
                    "worker_registration_id": str(a.worker_registration_id),
                    "identity_version": a.identity_version,
                    "endpoint_binding_hash": a.endpoint_binding_hash,
                    "expires_at": a.expires_at.isoformat(),
                }
            if rel == "/complete":
                adm.complete_discovery_admission(
                    s,
                    admission_id=uuid.UUID(payload["admission_id"]),
                    presented_anchor=payload["public_anchor"],
                    signature=payload["signature"],
                    now=now,
                )
                return 200, {"status": "admitted", "admission_id": payload["admission_id"]}
            if rel in ("/assert", "/consume"):
                job = s.get(DiscoveryJob, uuid.UUID(payload["discovery_job_id"]))
                if job is None:
                    return 403, {"reason_code": "job_not_found"}
                enrollment = s.get(TargetDiscoveryEnrollment, job.enrollment_id)
                if enrollment is None:
                    return 403, {"reason_code": "enrollment_not_found"}
                fn = (
                    adm.assert_discovery_admission_valid
                    if rel == "/assert"
                    else adm.consume_discovery_admission
                )
                result = fn(
                    s,
                    admission_id=uuid.UUID(payload["admission_id"]),
                    enrollment=enrollment,
                    discovery_job_id=uuid.UUID(payload["discovery_job_id"]),
                    endpoint_binding_hash=payload["endpoint_binding_hash"],
                    now=now,
                )
                return 200, {
                    "status": "valid" if rel == "/assert" else "consumed",
                    "admission_id": payload["admission_id"],
                    "registration_id": str(result.registration_id),
                    "identity_version": result.identity_version,
                }
        except adm.WorkerAdmissionRefused as exc:
            return 403, {"code": "worker_admission_refused", "reason_code": exc.reason_code}
        return 404, {"code": "not_found"}


def _live_comp(session, mount: str, probe: _FakeProbe, priv: str, pub: str) -> DiscoveryComposition:
    from secp_worker.target_discovery.admission_client import HttpWorkerAdmissionClient

    # bundle_binding + admission_client present => the engine crosses the control-plane admission
    # BOUNDARY (real HTTP client + Ed25519 signing) and enforces the bundle-to-job + endpoint bind
    # gates before probing. The worker imports no admission service and passes no Session to the
    # client (see test_discovery_admission_boundary.py).
    return DiscoveryComposition(
        probe_source=probe,
        bundle_binding=MountedWorkerBootstrapBundleSource(mount),
        admission_client=HttpWorkerAdmissionClient(
            transport=_InProcAdmissionTransport(session),
            private_key_hex=priv,
            public_anchor_hex=pub,
        ),
    )


def _run(session, comp, job) -> object:
    return run_discovery(session, job, composition=comp, now=datetime.now(UTC))


def _valid_anchor(principal, target, onb, enrollment, auth) -> dict:
    return _anchor(
        org=principal.organization_id,
        target=target.id,
        onboarding=onb.id,
        enrollment=enrollment.id,
        auth_id=auth.id,
        auth_version=auth.authorization_version,
    )


def _dummy_keypair() -> tuple[str, str]:
    from secp_api.worker_admission_contract import generate_ed25519_keypair

    return generate_ed25519_keypair()


# --- F-BIND: a bundle for org/target A cannot process a job for B (zero SSH) --


def test_bind_bundle_for_other_target_same_org_fails_closed(session, principal, tmp_path):
    # Admission passes (job B's real authorization), but the prepared-bundle anchor names target A.
    priv, pub = _ed_worker(session, principal)
    target_a, _onb_a, _auth_a = _target_with_auth(session, principal)
    target_b, onb_b, auth_b = _target_with_auth(session, principal)
    enroll_b, job_b = _enroll(session, principal, target_b)
    anchor = _valid_anchor(principal, target_b, onb_b, enroll_b, auth_b)
    anchor["execution_target_id"] = str(target_a.id)  # bundle claims a different target
    mount = _full_mount(tmp_path, anchor)
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(session, mount, probe, priv, pub), job_b)
    assert outcome.ok is False and outcome.reason_code == "bundle_target_mismatch"
    assert probe.calls == 0  # zero ssh
    assert session.query(DiscoverySnapshot).filter_by(enrollment_id=enroll_b.id).count() == 0
    assert session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=enroll_b.id).count() == 0


def test_bind_bundle_for_other_org_fails_closed(session, principal, tmp_path):
    priv, pub = _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    anchor = _valid_anchor(principal, target, onb, enrollment, auth)
    anchor["organization_id"] = str(uuid.uuid4())  # bundle claims a different organization
    mount = _full_mount(tmp_path, anchor)
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(session, mount, probe, priv, pub), job)
    assert outcome.ok is False and outcome.reason_code == "bundle_organization_mismatch"
    assert probe.calls == 0
    assert session.query(DiscoverySnapshot).filter_by(enrollment_id=enrollment.id).count() == 0


def test_bind_valid_matching_bundle_proceeds_to_probe(session, principal, tmp_path):
    priv, pub = _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(session, mount, probe, priv, pub), job)
    assert outcome.ok is True and outcome.reason_code == "plan_ready"
    assert probe.inventory_calls >= 1  # the read-only path ran after all gates passed
    assert session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=enrollment.id).count() == 1


def test_bind_disabled_target_fails_closed(session, principal, tmp_path):
    # SECP-B6 MB-1 §3: the control-plane admission re-verifies the live-read authorization at every
    # phase, so a target disabled AFTER approval is caught at ADMISSION (fail-closed, before the
    # bundle-binding gate would independently catch it — the other-target test proves that gate).
    priv, pub = _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    target.status = TargetStatus.disabled
    session.flush()
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(session, mount, probe, priv, pub), job)
    assert outcome.ok is False and outcome.reason_code == "worker_admission_unverified"
    assert probe.calls == 0


# --- MB-2: SSH endpoint bound to the authoritative target authorization -------


def test_endpoint_manifest_host_mismatch_fails_closed(session, principal, tmp_path):
    priv, pub = _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    # The bundle's ssh_host is NOT the authoritative target host.
    other_hash = _endpoint_hash(ssh_host="attacker.example")
    anchor = _valid_anchor(principal, target, onb, enrollment, auth)
    anchor["endpoint_binding_hash"] = other_hash
    mount = _full_mount(tmp_path, anchor, ssh_host="attacker.example")
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(session, mount, probe, priv, pub), job)
    assert outcome.ok is False
    # A non-target ssh_host yields a digest the approved authorization never stored, so the
    # admission (endpoint-hash bound) or the binding's host check rejects it — either way, zero SSH.
    assert outcome.reason_code in (
        "worker_admission_unverified",
        "bundle_target_endpoint_mismatch",
    )
    assert probe.calls == 0


def test_endpoint_changed_port_fails_closed(session, principal, tmp_path):
    priv, pub = _ed_worker(session, principal)
    # Authorization is bound to port 22; the mounted manifest uses port 22 but binding.json claims a
    # digest for a different port, so the recomputed digest cannot match both.
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    anchor = _valid_anchor(principal, target, onb, enrollment, auth)
    anchor["endpoint_binding_hash"] = _endpoint_hash(ssh_port=2222)  # digest for a different port
    mount = _full_mount(tmp_path, anchor)  # manifest still uses port 22
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(session, mount, probe, priv, pub), job)
    assert outcome.ok is False
    # The admission binds the (wrong) hash to the authorization (which stores the port-22 hash).
    assert outcome.reason_code in (
        "worker_admission_unverified",
        "endpoint_binding_manifest_mismatch",
    )
    assert probe.calls == 0


def test_endpoint_changed_fingerprint_fails_closed(session, principal, tmp_path):
    priv, pub = _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    other_fp = "SHA256:" + "B" * 43
    anchor = _valid_anchor(principal, target, onb, enrollment, auth)
    anchor["endpoint_binding_hash"] = _endpoint_hash(fingerprint=other_fp)
    mount = _full_mount(tmp_path, anchor, fingerprint=other_fp)  # manifest fp != authorized fp
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(session, mount, probe, priv, pub), job)
    assert outcome.ok is False
    assert outcome.reason_code in (
        "worker_admission_unverified",
        "endpoint_binding_unauthorized",
    )
    assert probe.calls == 0


# --- MB-1: control-plane-verified worker admission before SSH ----------------


def test_admission_required_no_client_material_fails_closed(session, principal, tmp_path):
    # A live composition whose admission client is SEALED (no key material) cannot obtain admission.
    from secp_worker.target_discovery.admission_client import SealedWorkerAdmissionClient

    _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    probe = _FakeProbe()
    comp = DiscoveryComposition(
        probe_source=probe,
        bundle_binding=MountedWorkerBootstrapBundleSource(mount),
        admission_client=SealedWorkerAdmissionClient(),
    )
    outcome = _run(session, comp, job)
    assert outcome.ok is False and outcome.reason_code == "worker_admission_unverified"
    assert probe.calls == 0
    assert session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=enrollment.id).count() == 0


def test_admission_wrong_worker_key_fails_closed(session, principal, tmp_path):
    # A registered worker exists, but the admission client signs with a different unregistered key.
    _ed_worker(session, principal)
    wrong_priv, wrong_pub = _dummy_keypair()
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(session, mount, probe, wrong_priv, wrong_pub), job)
    assert outcome.ok is False and outcome.reason_code == "worker_admission_unverified"
    assert probe.calls == 0


def test_admission_revoked_authorization_fails_closed(session, principal, tmp_path):
    priv, pub = _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    readonly_preflight.revoke_preflight_authorization(session, principal, auth.id)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(session, mount, probe, priv, pub), job)
    assert outcome.ok is False and outcome.reason_code == "worker_admission_unverified"
    assert probe.calls == 0


# --- F-IDENTITY --------------------------------------------------------------


def test_identity_no_approved_registration_fails_closed(session, principal, tmp_path):
    # No worker identity is approved: the pre-probe identity gate fails closed before admission.
    priv, pub = _dummy_keypair()
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(session, mount, probe, priv, pub), job)
    assert outcome.ok is False and outcome.reason_code == "worker_identity_unapproved"
    assert probe.calls == 0
    assert session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=enrollment.id).count() == 0


def test_identity_ambiguous_registration_fails_closed(session, principal, tmp_path):
    _approve_worker_identity(session, principal, label="worker-a")
    _approve_worker_identity(session, principal, label="worker-b")
    priv, pub = _dummy_keypair()
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(session, mount, probe, priv, pub), job)
    assert outcome.ok is False and outcome.reason_code == "worker_identity_ambiguous"
    assert probe.calls == 0


def test_identity_revoked_mid_run_blocks_plan(session, principal, tmp_path):
    from secp_api.models import WorkerIdentityRegistration

    priv, pub = _ed_worker(session, principal)
    reg = session.query(WorkerIdentityRegistration).one()
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))

    class _RevokingProbe(_FakeProbe):
        def read_inventory(self_inner):
            # Revoke the worker identity DURING probing; the post-probe consume must catch it.
            wi.revoke_worker_identity(session, principal, reg.id, reason_code="compromise")
            return super().read_inventory()

    outcome = _run(session, _live_comp(session, mount, _RevokingProbe(), priv, pub), job)
    assert outcome.ok is False and outcome.reason_code == "worker_identity_changed"
    assert session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=enrollment.id).count() == 0


def test_identity_version_zero_plan_is_unapprovable(session, principal):
    # A plan produced by a NON-live composition with no worker identity binds version 0.
    target, _onb, _auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    outcome = run_discovery(
        session,
        job,
        composition=DiscoveryComposition(probe_source=_FakeProbe()),
        now=datetime.now(UTC),
    )
    assert outcome.ok is True
    plan = session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=enrollment.id).one()
    assert plan.worker_identity_version == 0
    from secp_api.errors import DomainError

    with pytest.raises(DomainError):
        svc.approve_candidate_plan(
            session, principal, enrollment.id, expected_plan_hash=plan.plan_hash
        )


# --- end-to-end lifecycle ----------------------------------------------------


def test_e2e_live_discovery_through_consumer_then_approve(session, principal, tmp_path):
    """API request → queued job → claim → admission + bundle/endpoint binding → probe → plan →
    approve. The full control-plane-verified live path end to end (fake runner only)."""
    priv, pub = _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    jid = claim_and_process_one(
        session,
        composition=_live_comp(session, mount, _FakeProbe(), priv, pub),
        now=datetime.now(UTC),
    )
    assert jid == job.id
    session.refresh(enrollment)
    assert enrollment.status.value == "plan_ready"
    plan = session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=enrollment.id).one()
    assert plan.worker_identity_version >= 1  # a real approved identity is bound
    approved = svc.approve_candidate_plan(
        session, principal, enrollment.id, expected_plan_hash=plan.plan_hash
    )
    assert approved.status.value == "approved"


def test_identity_rotation_to_same_version_different_id_is_unapprovable(session, principal):
    # SECP-B6 F-IDENTITY: a plan is bound to the exact worker registration (id), not just its
    # per-label integer version — so rotating to a DIFFERENT same-versioned identity cannot approve
    # a plan minted against the old (now revoked) identity.
    reg_a = _approve_worker_identity(session, principal, label="worker-a")  # version 1
    target, _onb, _auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    run_discovery(
        session,
        job,
        composition=DiscoveryComposition(probe_source=_FakeProbe()),
        now=datetime.now(UTC),
    )
    plan = session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=enrollment.id).one()
    assert plan.plan_document["worker_registration_id"] == str(reg_a.id)
    # Rotate: revoke A, approve a different identity B which (different label) also gets version 1.
    wi.revoke_worker_identity(session, principal, reg_a.id, reason_code="compromise")
    reg_b = _approve_worker_identity(session, principal, label="worker-b")
    assert reg_b.identity_version == plan.worker_identity_version  # same integer version
    assert reg_b.id != reg_a.id
    from secp_api.errors import DomainError

    with pytest.raises(DomainError):
        svc.approve_candidate_plan(
            session, principal, enrollment.id, expected_plan_hash=plan.plan_hash
        )


# --- F-AUDIT -----------------------------------------------------------------


def test_audit_live_error_after_contact_is_not_recorded_sealed(
    session, principal, tmp_path, monkeypatch
):
    # A live run that contacts the host and then hits an UNCAUGHT error must not be audited as
    # sealed/no-contact (SECP-B6 F-AUDIT).
    priv, pub = _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))

    class _ContactThenCrashProbe(_FakeProbe):
        def probe_candidate_presence(self_inner, locators):
            raise RuntimeError("post-contact boom")  # not a ProbeSourceUnavailable

    data = _capture_completion_audit(
        session, monkeypatch, _live_comp(session, mount, _ContactThenCrashProbe(), priv, pub), job
    )
    assert data.get("reason_code") == "internal_error"
    assert data.get("contact_state") == "internal_error"  # NOT "sealed"
    assert data.get("bundle_available") is True  # a live composition may have contacted the host


def _capture_completion_audit(session, monkeypatch, comp, job) -> dict:
    orig = audit_mod.record
    captured: dict = {}

    def spy(sess, **kw):
        if str(kw.get("action")).endswith("completed") or str(kw.get("action")).endswith("failed"):
            captured.clear()
            captured.update(kw.get("data") or {})
        return orig(sess, **kw)

    monkeypatch.setattr(audit_mod, "record", spy)
    claim_and_process_one(session, composition=comp, now=datetime.now(UTC))
    return captured


def test_audit_live_success_is_truthful(session, principal, tmp_path, monkeypatch):
    priv, pub = _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    data = _capture_completion_audit(
        session, monkeypatch, _live_comp(session, mount, _FakeProbe(), priv, pub), job
    )
    assert data.get("bundle_available") is True
    assert data.get("contact_state") == "contacted"
    snap = session.query(DiscoverySnapshot).filter_by(enrollment_id=enrollment.id).one()
    assert snap.bundle_available is True
    # No raw bundle field leaks into the audit payload.
    blob = json.dumps(data)
    for forbidden in ("pve", "SHA256", "known_hosts", "id_key", "root@", "8006"):
        assert forbidden not in blob


def test_audit_sealed_run_reports_no_contact(session, principal, monkeypatch):
    target, _onb, _auth = _target_with_auth(session, principal)
    _enrollment, job = _enroll(session, principal, target)
    from secp_worker.target_discovery.engine import sealed_discovery_composition

    data = _capture_completion_audit(session, monkeypatch, sealed_discovery_composition(), job)
    assert data.get("bundle_available") is False
    assert data.get("contact_state") == "sealed"


def test_audit_host_key_refusal_is_truthful(session, principal, tmp_path, monkeypatch):
    priv, pub = _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    probe = _FakeProbe(raises="host_key_binding_unverified")
    data = _capture_completion_audit(
        session, monkeypatch, _live_comp(session, mount, probe, priv, pub), job
    )
    assert data.get("reason_code") == "host_key_binding_unverified"
    assert data.get("contact_state") == "host_key_refused"
    assert data.get("bundle_available") is True  # a bundle WAS acquired before the host-key check


# --- F-BLAST -----------------------------------------------------------------


def _valid_ssh_mount(tmp_path, *, account: str) -> str:
    mount = tmp_path / "sshbundle"
    mount.mkdir()
    (mount / "manifest.json").write_text(
        json.dumps(
            {
                "ssh_host": "pve-a",
                "ssh_port": 22,
                "account": account,
                "host_key_fingerprint": "SHA256:" + "A" * 43,
            }
        )
    )
    (mount / "id_key").write_bytes(b"KEY")
    (mount / "known_hosts").write_bytes(b"pve-a ssh-ed25519 AAAA\n")
    if _POSIX:
        os.chmod(mount, 0o700)
        for f in ("manifest.json", "id_key", "known_hosts"):
            os.chmod(mount / f, 0o600)
    return str(mount)


def test_blast_root_account_refused(tmp_path):
    from secp_worker.mounted_bundle import MountedBundleRejected

    src = MountedWorkerBootstrapBundleSource(_valid_ssh_mount(tmp_path, account="root"))
    with pytest.raises(MountedBundleRejected) as exc:
        src.acquire()
    assert exc.value.reason_code == "manifest_account_privileged"


def test_blast_scoped_account_accepted(tmp_path):
    src = MountedWorkerBootstrapBundleSource(_valid_ssh_mount(tmp_path, account="secp-discovery"))
    bundle = src.acquire()
    assert bundle.account == "secp-discovery"


# --- command safety ----------------------------------------------------------


def test_assert_read_only_rejects_metacharacters():
    from secp_worker.target_discovery.probes import ProbeError, assert_read_only

    for bad in (
        ("pvesh", "get", "/nodes/pve a/status"),  # whitespace
        ("pvesh", "get", "/nodes/$(whoami)/status"),  # shell metachar
        ("pvesh", "get", "/nodes/pve;rm/status"),  # semicolon
        ("cat", "/sys/module/kvm_intel/parameters/nested; id"),
    ):
        with pytest.raises(ProbeError):
            assert_read_only(bad)


def test_ssh_argv_pins_isolation_options():
    from secp_worker.ssh_channel import SshBootstrapBundle, build_ssh_argv

    bundle = SshBootstrapBundle("pve-a", 22, "secp", "/k", "/kh", "SHA256:" + "A" * 43)
    argv = build_ssh_argv(bundle, ("pveversion",))
    joined = " ".join(argv)
    for opt in (
        "-F",
        "none",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "StrictHostKeyChecking=yes",
    ):
        assert opt in argv, opt
    assert "--" in argv and argv[argv.index("--") + 1] == "secp@pve-a"
    assert joined.count(" -F none") == 0 or "-F" in argv  # -F none present as discrete tokens


# --- F-FS (POSIX only) -------------------------------------------------------


def test_fs_strict_non_posix_fails_closed():
    if _POSIX:
        pytest.skip("non-POSIX-only dispatch check")
    from secp_worker.mounted_bundle import MountedBundleRejected

    src = MountedWorkerBootstrapBundleSource("/whatever", strict=True)
    with pytest.raises(MountedBundleRejected) as exc:
        src.acquire()
    assert exc.value.reason_code == "mount_non_posix_unsupported"


@pytest.mark.skipif(not _POSIX, reason="POSIX descriptor semantics")
def test_fs_strict_writable_mount_refused(tmp_path):
    from secp_worker.mounted_bundle import MountedBundleRejected

    mount = _valid_ssh_mount(tmp_path, account="secp")  # a normal RW tmp filesystem
    src = MountedWorkerBootstrapBundleSource(mount, strict=True)
    with pytest.raises(MountedBundleRejected) as exc:
        src.acquire()
    assert exc.value.reason_code == "mount_not_read_only"


@pytest.mark.skipif(not _POSIX, reason="POSIX descriptor semantics")
def test_fs_strict_hardlink_refused(tmp_path, monkeypatch):
    import secp_worker.mounted_bundle as mb

    monkeypatch.setattr(mb, "_statvfs", lambda _fd: type("V", (), {"f_flag": mb._ST_RDONLY})())
    mount = _valid_ssh_mount(tmp_path, account="secp")
    # Replace id_key with a hardlink (st_nlink == 2).
    os.remove(os.path.join(mount, "id_key"))
    outside = tmp_path / "outside_key"
    outside.write_bytes(b"KEY")
    os.chmod(outside, 0o600)
    os.link(str(outside), os.path.join(mount, "id_key"))
    from secp_worker.mounted_bundle import MountedBundleRejected

    with pytest.raises(MountedBundleRejected) as exc:
        MountedWorkerBootstrapBundleSource(mount, strict=True).acquire()
    assert exc.value.reason_code == "key_hardlinked"


@pytest.mark.skipif(not _POSIX, reason="POSIX descriptor semantics")
def test_fs_strict_happy_path_pins_private_copy(tmp_path, monkeypatch):
    import secp_worker.mounted_bundle as mb

    monkeypatch.setattr(mb, "_statvfs", lambda _fd: type("V", (), {"f_flag": mb._ST_RDONLY})())
    mount = _valid_ssh_mount(tmp_path, account="secp")
    src = MountedWorkerBootstrapBundleSource(mount, strict=True)
    bundle = src.acquire()
    # ssh consumes worker-private copies OUTSIDE the mount (immune to a later mount swap).
    assert not bundle.private_key_path.startswith(mount)
    assert not bundle.known_hosts_path.startswith(mount)
    assert open(bundle.known_hosts_path, "rb").read() == b"pve-a ssh-ed25519 AAAA\n"
    src.dispose()
    assert not os.path.exists(bundle.private_key_path)  # disposed


# --- SECP-B6 item-4: private SSH key material is read ONLY after admission ----


class _FinalizeSpyBundle:
    """Wraps the real bundle source and counts finalize_key_material() — the ONLY place the private
    id_key/known_hosts bytes are read/copied (item-4). prepare_metadata reads NON-secret data."""

    def __init__(self, inner):
        self._inner = inner
        self.prepare_calls = 0
        self.finalize_calls = 0

    def prepare_metadata(self):
        self.prepare_calls += 1
        return self._inner.prepare_metadata()

    def finalize_key_material(self):
        self.finalize_calls += 1
        return self._inner.finalize_key_material()

    def dispose(self):
        return self._inner.dispose()


def test_item4_refused_admission_never_reads_key_material(session, principal, tmp_path):
    # A refused control-plane admission must leave the worker-private key material UNREAD (item-4)
    # and invoke zero SSH — no plan, no snapshot.
    from secp_worker.target_discovery.admission_client import SealedWorkerAdmissionClient

    _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    spy = _FinalizeSpyBundle(MountedWorkerBootstrapBundleSource(mount))
    probe = _FakeProbe()
    comp = DiscoveryComposition(
        probe_source=probe, bundle_binding=spy, admission_client=SealedWorkerAdmissionClient()
    )
    outcome = run_discovery(session, job, composition=comp, now=datetime.now(UTC))
    assert outcome.ok is False and outcome.reason_code == "worker_admission_unverified"
    assert spy.prepare_calls == 1  # non-secret manifest/binding WAS validated (endpoint digest)
    assert spy.finalize_calls == 0  # ... but the private key bytes were NEVER read
    assert probe.calls == 0  # and zero SSH
    assert session.query(DiscoverySnapshot).filter_by(enrollment_id=enrollment.id).count() == 0
    assert session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=enrollment.id).count() == 0


def test_item4_successful_admission_reads_key_material_after(session, principal, tmp_path):
    # The private key material is read EXACTLY once and only AFTER admission succeeds.
    from secp_worker.target_discovery.admission_client import HttpWorkerAdmissionClient

    priv, pub = _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    spy = _FinalizeSpyBundle(MountedWorkerBootstrapBundleSource(mount))
    comp = DiscoveryComposition(
        probe_source=_FakeProbe(),
        bundle_binding=spy,
        admission_client=HttpWorkerAdmissionClient(
            transport=_InProcAdmissionTransport(session),
            private_key_hex=priv,
            public_anchor_hex=pub,
        ),
    )
    outcome = run_discovery(session, job, composition=comp, now=datetime.now(UTC))
    assert outcome.ok is True and outcome.reason_code == "plan_ready"
    assert spy.prepare_calls == 1 and spy.finalize_calls == 1  # key read once, post-admission


# --- SECP-B6 item-1 hardening: a rogue admission server cannot cause SSH ------


def _write_identity_files(tmp_path, priv, pub):
    (tmp_path / "id.key").write_text(priv)
    (tmp_path / "id.anchor").write_text(pub)
    return str(tmp_path / "id.key"), str(tmp_path / "id.anchor")


def _admit_anything_responder():
    # A MALICIOUS control plane that would 'admit' any worker for any job. It must never be able to
    # push the worker to SSH: the transport rejects plain HTTP / an untrusted CA before trusting it.
    import secrets as _secrets
    from datetime import UTC, datetime, timedelta

    aid = str(uuid.uuid4())
    reg = str(uuid.uuid4())

    def responder(path, body):
        now = datetime.now(UTC)
        if path.endswith("/begin"):
            return 200, {
                "admission_id": aid,
                "nonce": _secrets.token_hex(16),
                "organization_id": str(uuid.uuid4()),
                "discovery_job_id": str(body.get("discovery_job_id")),
                "worker_registration_id": reg,
                "identity_version": 9,
                "endpoint_binding_hash": body.get("endpoint_binding_hash"),
                "expires_at": (now + timedelta(seconds=90)).isoformat(),
            }
        if path.endswith("/complete"):
            return 200, {"status": "admitted", "admission_id": body.get("admission_id")}
        if path.endswith(("/assert", "/consume")):
            return 200, {
                "status": "valid" if path.endswith("/assert") else "consumed",
                "admission_id": body.get("admission_id"),
                "registration_id": reg,
                "identity_version": 9,
            }
        return 404, {}

    return responder


def _live_http_comp(settings, probe, spy):
    from secp_worker.target_discovery.composition import _build_admission_client

    return DiscoveryComposition(
        probe_source=probe, bundle_binding=spy, admission_client=_build_admission_client(settings)
    )


def test_plain_http_rogue_server_cannot_cause_ssh(session, principal, tmp_path):
    # A rogue admission server served over PLAIN HTTP: the worker's transport refuses http:// before
    # any request, so the server is never contacted and no SSH/key-read occurs.
    from _admission_tls_util import FakeAdmissionServer, write_ca_only
    from secp_api.config import Settings

    priv, pub = _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    key_path, anchor_path = _write_identity_files(tmp_path, priv, pub)
    ca_path = write_ca_only(tmp_path)  # a valid CA — the endpoint SCHEME (http) is the disqualifier

    with FakeAdmissionServer(responder=_admit_anything_responder()) as server:  # plain HTTP
        settings = Settings(
            discovery_controlled_integration_enabled=True,
            discovery_admission_endpoint=server.base_url,  # http://localhost:PORT
            discovery_worker_identity_key=key_path,
            discovery_worker_identity_anchor=anchor_path,
            discovery_admission_ca=ca_path,
        )
        spy = _FinalizeSpyBundle(MountedWorkerBootstrapBundleSource(mount))
        probe = _FakeProbe()
        outcome = run_discovery(
            session, job, composition=_live_http_comp(settings, probe, spy), now=datetime.now(UTC)
        )
        assert server.request_count == 0  # the rogue HTTP server was NEVER contacted
    assert outcome.ok is False and outcome.reason_code == "worker_admission_unverified"
    assert spy.finalize_calls == 0  # no private key read
    assert probe.calls == 0  # zero SSH
    assert session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=enrollment.id).count() == 0


def test_wrong_ca_rogue_tls_server_cannot_cause_ssh(session, principal, tmp_path):
    # A rogue admission server over HTTPS with a cert the worker's configured CA does NOT trust: the
    # TLS handshake fails, the admission fails closed, and no SSH/key-read occurs.
    from _admission_tls_util import FakeAdmissionServer, IssuedTls, write_ca_only
    from secp_api.config import Settings

    priv, pub = _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    key_path, anchor_path = _write_identity_files(tmp_path, priv, pub)
    server_tls = IssuedTls(tmp_path, label="rogue")  # server cert signed by the rogue CA
    trusted_ca = write_ca_only(tmp_path, label="trusted")  # worker trusts a DIFFERENT CA

    with FakeAdmissionServer(
        responder=_admit_anything_responder(),
        certfile=server_tls.server_cert_path,
        keyfile=server_tls.server_key_path,
    ) as server:
        settings = Settings(
            discovery_controlled_integration_enabled=True,
            discovery_admission_endpoint=server.base_url,  # https://localhost:PORT
            discovery_worker_identity_key=key_path,
            discovery_worker_identity_anchor=anchor_path,
            discovery_admission_ca=trusted_ca,  # does NOT sign the rogue server cert
        )
        spy = _FinalizeSpyBundle(MountedWorkerBootstrapBundleSource(mount))
        probe = _FakeProbe()
        outcome = run_discovery(
            session, job, composition=_live_http_comp(settings, probe, spy), now=datetime.now(UTC)
        )
    assert outcome.ok is False and outcome.reason_code == "worker_admission_unverified"
    assert spy.finalize_calls == 0  # no private key read despite a would-admit server
    assert probe.calls == 0  # zero SSH
    assert session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=enrollment.id).count() == 0


def test_trusted_ca_but_malformed_admission_cannot_cause_ssh(session, principal, tmp_path):
    # A server the worker's CA DOES trust (TLS succeeds) but which returns a bogus admission body
    # (a generic 200 whose /complete is not exactly "admitted") must still fail closed: strict
    # response validation refuses it before any key read or SSH.
    from _admission_tls_util import FakeAdmissionServer, IssuedTls
    from secp_api.config import Settings

    priv, pub = _ed_worker(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _full_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    key_path, anchor_path = _write_identity_files(tmp_path, priv, pub)
    tls = IssuedTls(tmp_path, label="trusted")  # worker will trust THIS CA (TLS handshake succeeds)

    base = _admit_anything_responder()

    def malformed(path, body):
        status, resp = base(path, body)
        if path.endswith("/complete"):
            resp = {**resp, "status": "ok"}  # not the exact required "admitted"
        return status, resp

    with FakeAdmissionServer(
        responder=malformed, certfile=tls.server_cert_path, keyfile=tls.server_key_path
    ) as server:
        settings = Settings(
            discovery_controlled_integration_enabled=True,
            discovery_admission_endpoint=server.base_url,
            discovery_worker_identity_key=key_path,
            discovery_worker_identity_anchor=anchor_path,
            discovery_admission_ca=tls.ca_path,  # trusts the server cert → TLS ok, content is bogus
        )
        spy = _FinalizeSpyBundle(MountedWorkerBootstrapBundleSource(mount))
        probe = _FakeProbe()
        outcome = run_discovery(
            session, job, composition=_live_http_comp(settings, probe, spy), now=datetime.now(UTC)
        )
    assert outcome.ok is False and outcome.reason_code == "worker_admission_unverified"
    assert spy.finalize_calls == 0  # no private key read
    assert probe.calls == 0  # zero SSH
    assert session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=enrollment.id).count() == 0
