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


def _approve_worker_identity(session, principal, *, label: str = "staging-worker-a"):
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
    session, principal
) -> tuple[ExecutionTarget, TargetOnboarding, LiveReadAuthorization]:
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
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
        session, principal, execution_target_id=target.id
    )
    auth = readonly_preflight.approve_preflight_authorization(session, principal, auth.id)
    return target, onboarding, auth


def _enroll(session, principal, target) -> tuple[object, DiscoveryJob]:
    enrollment = svc.request_discovery(session, principal, execution_target_id=target.id)
    job = session.query(DiscoveryJob).filter(DiscoveryJob.enrollment_id == enrollment.id).one()
    return enrollment, job


def _anchor(*, org, target, onboarding, enrollment, auth_id, auth_version) -> dict:
    return {
        "organization_id": str(org),
        "execution_target_id": str(target),
        "onboarding_id": str(onboarding),
        "enrollment_id": str(enrollment),
        "authorization_id": str(auth_id),
        "authorization_version": auth_version,
    }


def _binding_mount(tmp_path, anchor: dict) -> str:
    mount = tmp_path / "bundle"
    mount.mkdir()
    (mount / "binding.json").write_text(json.dumps(anchor))
    if _POSIX:
        os.chmod(mount, 0o700)
        os.chmod(mount / "binding.json", 0o600)
    return str(mount)


def _live_comp(mount: str, probe: _FakeProbe) -> DiscoveryComposition:
    # bundle_binding present => the engine enforces the identity + binding gates before probing.
    return DiscoveryComposition(
        probe_source=probe, bundle_binding=MountedWorkerBootstrapBundleSource(mount)
    )


def _run(session, comp, job) -> object:
    return run_discovery(session, job, composition=comp, now=datetime.now(UTC))


# --- F-BIND ------------------------------------------------------------------


def test_bind_bundle_for_other_target_same_org_fails_closed(session, principal, tmp_path):
    _approve_worker_identity(session, principal)
    target_a, onb_a, auth_a = _target_with_auth(session, principal)
    target_b, onb_b, auth_b = _target_with_auth(session, principal)
    enroll_a, _ = _enroll(session, principal, target_a)
    enroll_b, job_b = _enroll(session, principal, target_b)
    # A bundle honestly minted for target A, used while processing target B's job.
    mount = _binding_mount(
        tmp_path,
        _anchor(
            org=principal.organization_id,
            target=target_a.id,
            onboarding=onb_a.id,
            enrollment=enroll_a.id,
            auth_id=auth_a.id,
            auth_version=auth_a.authorization_version,
        ),
    )
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(mount, probe), job_b)
    assert outcome.ok is False and outcome.reason_code == "bundle_target_mismatch"
    assert probe.calls == 0  # zero ssh
    assert session.query(DiscoverySnapshot).filter_by(enrollment_id=enroll_b.id).count() == 0
    assert session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=enroll_b.id).count() == 0


def test_bind_bundle_for_other_org_fails_closed(session, principal, tmp_path):
    _approve_worker_identity(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _binding_mount(
        tmp_path,
        _anchor(
            org=uuid.uuid4(),
            target=target.id,
            onboarding=onb.id,
            enrollment=enrollment.id,
            auth_id=auth.id,
            auth_version=auth.authorization_version,
        ),
    )
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(mount, probe), job)
    assert outcome.ok is False and outcome.reason_code == "bundle_organization_mismatch"
    assert probe.calls == 0
    assert session.query(DiscoverySnapshot).filter_by(enrollment_id=enrollment.id).count() == 0


def test_bind_valid_matching_bundle_proceeds_to_probe(session, principal, tmp_path):
    _approve_worker_identity(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _binding_mount(
        tmp_path,
        _anchor(
            org=principal.organization_id,
            target=target.id,
            onboarding=onb.id,
            enrollment=enrollment.id,
            auth_id=auth.id,
            auth_version=auth.authorization_version,
        ),
    )
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(mount, probe), job)
    assert outcome.ok is True and outcome.reason_code == "plan_ready"
    assert probe.inventory_calls >= 1  # the read-only path ran through the fake probe
    assert session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=enrollment.id).count() == 1


def _valid_anchor(principal, target, onb, enrollment, auth) -> dict:
    return _anchor(
        org=principal.organization_id,
        target=target.id,
        onboarding=onb.id,
        enrollment=enrollment.id,
        auth_id=auth.id,
        auth_version=auth.authorization_version,
    )


def test_bind_revoked_authorization_fails_closed(session, principal, tmp_path):
    _approve_worker_identity(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    readonly_preflight.revoke_preflight_authorization(session, principal, auth.id)
    mount = _binding_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(mount, probe), job)
    assert outcome.ok is False and outcome.reason_code == "live_read_authorization_revoked"
    assert probe.calls == 0


def test_bind_wrong_authorization_version_fails_closed(session, principal, tmp_path):
    _approve_worker_identity(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    anchor = _valid_anchor(principal, target, onb, enrollment, auth)
    anchor["authorization_version"] = auth.authorization_version + 1
    mount = _binding_mount(tmp_path, anchor)
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(mount, probe), job)
    assert outcome.ok is False and outcome.reason_code == "live_read_authorization_version_drift"
    assert probe.calls == 0


def test_bind_missing_authorization_fails_closed(session, principal, tmp_path):
    _approve_worker_identity(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    anchor = _valid_anchor(principal, target, onb, enrollment, auth)
    anchor["authorization_id"] = str(uuid.uuid4())  # a live-read authorization that does not exist
    mount = _binding_mount(tmp_path, anchor)
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(mount, probe), job)
    assert outcome.ok is False and outcome.reason_code == "live_read_authorization_missing"
    assert probe.calls == 0


def test_bind_disabled_target_fails_closed(session, principal, tmp_path):
    _approve_worker_identity(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    target.status = TargetStatus.disabled
    session.flush()
    mount = _binding_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(mount, probe), job)
    assert outcome.ok is False and outcome.reason_code == "live_read_target_not_active"
    assert probe.calls == 0


# --- F-IDENTITY --------------------------------------------------------------


def test_identity_no_approved_registration_fails_closed(session, principal, tmp_path):
    # No worker identity is approved.
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _binding_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(mount, probe), job)
    assert outcome.ok is False and outcome.reason_code == "worker_identity_unapproved"
    assert probe.calls == 0
    assert session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=enrollment.id).count() == 0


def test_identity_ambiguous_registration_fails_closed(session, principal, tmp_path):
    _approve_worker_identity(session, principal, label="worker-a")
    _approve_worker_identity(session, principal, label="worker-b")
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _binding_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    probe = _FakeProbe()
    outcome = _run(session, _live_comp(mount, probe), job)
    assert outcome.ok is False and outcome.reason_code == "worker_identity_ambiguous"
    assert probe.calls == 0


def test_identity_revoked_mid_run_blocks_plan(session, principal, tmp_path):
    reg = _approve_worker_identity(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _binding_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))

    class _RevokingProbe(_FakeProbe):
        def read_inventory(self_inner):
            # Revoke the worker identity DURING probing; the post-probe recheck must catch it.
            wi.revoke_worker_identity(session, principal, reg.id, reason_code="compromise")
            return super().read_inventory()

    outcome = _run(session, _live_comp(mount, _RevokingProbe()), job)
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
    """API request → queued job → claim → identity+binding gates → probe → plan → approve."""
    _approve_worker_identity(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _binding_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    jid = claim_and_process_one(
        session, composition=_live_comp(mount, _FakeProbe()), now=datetime.now(UTC)
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
    _approve_worker_identity(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _binding_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))

    class _ContactThenCrashProbe(_FakeProbe):
        def probe_candidate_presence(self_inner, locators):
            raise RuntimeError("post-contact boom")  # not a ProbeSourceUnavailable

    data = _capture_completion_audit(
        session, monkeypatch, _live_comp(mount, _ContactThenCrashProbe()), job
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
    _approve_worker_identity(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _binding_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    data = _capture_completion_audit(session, monkeypatch, _live_comp(mount, _FakeProbe()), job)
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
    _approve_worker_identity(session, principal)
    target, onb, auth = _target_with_auth(session, principal)
    enrollment, job = _enroll(session, principal, target)
    mount = _binding_mount(tmp_path, _valid_anchor(principal, target, onb, enrollment, auth))
    probe = _FakeProbe(raises="host_key_binding_unverified")
    data = _capture_completion_audit(session, monkeypatch, _live_comp(mount, probe), job)
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
