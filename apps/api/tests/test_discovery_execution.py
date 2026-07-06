"""SECP-B5 — read-only probe executor + durable discovery worker (fake-backed; no real host/ssh).

Proves the probe executor runs ONLY read-only argv over the hardened SSH channel, enforces the
pinned
host-key binding BEFORE any ssh invocation, disposes the bundle on every path, and never returns raw
output; and that the wired worker claim/lease consumer runs the read-only engine with the SEALED
composition (zero I/O), with exclusive CAS claiming and lease-based restart reclaim.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.enums import (
    DiscoveryJobStatus,
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    TargetDiscoveryStatus,
    TargetStatus,
)
from secp_api.models import (
    DiscoveryCandidatePlan,
    DiscoveryJob,
    DiscoverySnapshot,
    ExecutionTarget,
    TargetDiscoveryEnrollment,
    TargetOnboarding,
)
from secp_api.services import target_discovery as svc
from secp_worker.deployment.locators import BridgeLocator, GuestLocator, ServiceIdentityLocator
from secp_worker.ssh_channel import (
    CommandResult,
    SealedKnownHostsBindingVerifier,
    SealedWorkerBootstrapBundleSource,
    SshBootstrapBundle,
)
from secp_worker.target_discovery import consumer
from secp_worker.target_discovery.probe_executor import ReadOnlyProbeExecutor
from secp_worker.target_discovery.seams import ProbeSourceUnavailable

# --- probe executor ------------------------------------------------------------------------------


class _FakeBundleSource:
    def __init__(self, *, port=22, raise_unexpected=False):
        self.disposed = 0
        self._port = port
        self._raise = raise_unexpected

    def acquire(self):
        if self._raise:
            raise RuntimeError("mount failure")
        return SshBootstrapBundle("host.example", self._port, "secpops", "/k", "/kh", "SHA256:x")

    def dispose(self):
        self.disposed += 1


class _PassVerifier:
    def verify(self, bundle):
        return True


def _remote_of(argv):
    # argv = ssh + hardening + -- + account@host + remote...
    idx = argv.index("--")
    return list(argv[idx + 2 :])


class _ReadOnlyFakeRunner:
    """Returns canned read-only outputs keyed on the remote command; records every argv."""

    def __init__(self):
        self.calls = []

    def run(self, argv, *, timeout):
        self.calls.append(list(argv))
        remote = _remote_of(argv)
        cmd = " ".join(remote)
        if cmd == "pvesh get /version --output-format json":
            return CommandResult(0, json.dumps({"version": "8.1.4"}).encode())
        if cmd == "pvesh get /cluster/status --output-format json":
            return CommandResult(0, b"[]")
        if cmd == "pvesh get /nodes --output-format json":
            return CommandResult(0, json.dumps([{"node": "pve-a"}]).encode())
        if cmd == "pvesh get /nodes/pve-a/status --output-format json":
            body = {"cpuinfo": {"cpus": 16}, "memory": {"total": 68719476736, "free": 34359738368}}
            return CommandResult(0, json.dumps(body).encode())
        if cmd == "pvesh get /nodes/pve-a/storage --output-format json":
            body = [
                {"storage": "local-lvm", "avail": 536870912000, "active": 1, "content": "images"}
            ]
            return CommandResult(0, json.dumps(body).encode())
        if cmd == "pvesh get /cluster/resources --type vm --output-format json":
            return CommandResult(0, b"[]")
        if remote[0] == "cat":
            return CommandResult(0, b"Y\n")
        # candidate locator presence GET → absent (exit 1)
        return CommandResult(1, b"")


def _executor(runner, source, verifier=None):
    return ReadOnlyProbeExecutor(
        bundle_source=source, runner=runner, host_key_verifier=verifier or _PassVerifier()
    )


def test_executor_reads_inventory_with_read_only_argv_only():
    runner = _ReadOnlyFakeRunner()
    source = _FakeBundleSource()
    facts = _executor(runner, source).read_inventory()
    assert facts.node == "pve-a" and facts.nested_available is True
    assert facts.cpu_total == 16 and facts.mem_free_mb == 32768
    assert facts.storages and facts.storages[0].storage == "local-lvm"
    assert source.disposed == 1  # disposed after the session
    # Every issued argv is the fixed hardened ssh, and every remote command is read-only.
    for argv in runner.calls:
        assert argv[0] == "/usr/bin/ssh"
        assert "BatchMode=yes" in argv and "StrictHostKeyChecking=yes" in argv
        remote = _remote_of(argv)
        assert remote[0] in ("pvesh", "pveversion", "cat")
        if remote[0] == "pvesh":
            assert remote[1] == "get"


def test_executor_enforces_host_key_binding_before_ssh():
    runner = _ReadOnlyFakeRunner()
    source = _FakeBundleSource()
    ex = _executor(runner, source, verifier=SealedKnownHostsBindingVerifier())
    with pytest.raises(ProbeSourceUnavailable) as exc:
        ex.read_inventory()
    assert exc.value.reason_code == "host_key_binding_unverified"
    assert runner.calls == []  # ssh was NEVER invoked
    assert source.disposed == 1  # bundle disposed on the fail path


def test_executor_sealed_bundle_and_disposal_on_error():
    ex = _executor(_ReadOnlyFakeRunner(), SealedWorkerBootstrapBundleSource())
    with pytest.raises(ProbeSourceUnavailable) as exc:
        ex.read_inventory()
    assert exc.value.reason_code == "bootstrap_unavailable"
    # An unexpected acquire failure still disposes the bundle source.
    source = _FakeBundleSource(raise_unexpected=True)
    with pytest.raises(RuntimeError):
        _executor(_ReadOnlyFakeRunner(), source).read_inventory()
    assert source.disposed == 1


def test_executor_result_is_typed_and_leaks_no_raw_output():
    facts = _executor(_ReadOnlyFakeRunner(), _FakeBundleSource()).read_inventory()
    blob = repr(facts)
    for forbidden in ("host.example", "secpops", "/k", "/kh", "SHA256", "8.1.4", "68719476736"):
        assert forbidden not in blob  # only typed/bounded facts, no raw output or SSH metadata


def test_candidate_presence_absent_for_fresh_locators():
    presences = _executor(_ReadOnlyFakeRunner(), _FakeBundleSource()).probe_candidate_presence(
        (
            BridgeLocator("pve-a", "secpbr"),
            ServiceIdentityLocator("secpx@pam"),
            GuestLocator("pve-a", 9001),
        )
    )
    assert all(not p.present for p in presences.values())


# --- durable worker claim/lease ------------------------------------------------------------------


def _enroll(session, principal) -> TargetDiscoveryEnrollment:
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="s",
        plugin_name="proxmox",
        config={"base_url": "x", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref="vault:x",
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
    row = svc.request_discovery(session, principal, execution_target_id=target.id)
    session.commit()
    return row


def test_worker_runs_sealed_and_contacts_nothing(session, principal):
    enrollment = _enroll(session, principal)
    job_id = consumer.claim_and_process_one(session)  # default SEALED composition
    assert job_id is not None
    job = session.get(DiscoveryJob, job_id)
    assert job.status == DiscoveryJobStatus.failed
    assert job.failure_code == "probe_source_sealed"
    session.refresh(enrollment)
    assert enrollment.status == TargetDiscoveryStatus.failed
    # Fail-closed: an unverifiable snapshot, no candidate plan, nothing contacted.
    snap = session.query(DiscoverySnapshot).filter_by(enrollment_id=enrollment.id).one()
    assert snap.bundle_available is False
    assert session.query(DiscoveryCandidatePlan).count() == 0
    assert consumer.claim_and_process_one(session) is None  # queue drained


def test_claim_is_exclusive_and_stale_lease_reclaimed(session, principal):
    _enroll(session, principal)
    now = datetime.now(UTC)
    first = consumer._claim_candidate(session, now)
    assert first is not None and first.status == DiscoveryJobStatus.claimed
    assert consumer._claim_candidate(session, now) is None  # exclusive

    # Simulate a crashed worker: reclaim a stale in-flight job after the lease.
    first.status = DiscoveryJobStatus.running
    first.claimed_at = now - timedelta(seconds=consumer._LEASE_SECONDS + 60)
    session.flush()
    reclaimed = consumer._claim_candidate(session, datetime.now(UTC))
    assert reclaimed is not None and reclaimed.id == first.id
