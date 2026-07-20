"""Focused, hermetic tests for the worker-local SECP-PR5F activation probe."""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from secp_api.discovery_bootstrap_contract import validate_public_ssh_key
from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint
from secp_worker import activation_probe as probe

ORG_ID = uuid.UUID("6b6e6a43-4c47-4ca6-92a1-8b6fa10ee657")
NODE_ID = uuid.UUID("227fd1d2-cbfd-4e60-bc5b-c2cb424f42f2")
REGISTRATION_ID = uuid.UUID("7a698ce3-21c8-40e4-8b27-d9069b8d968d")
ANCHOR = "1a" * 32
OVERLAY_DIGEST = "sha256:" + "5" * 64


def _public_key() -> str:
    key = Ed25519PublicKey.from_public_bytes(bytes(range(32)))
    return (
        key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode(
            "ascii"
        )
        + " secp-worker"
    )


SSH_PUBLIC_KEY = _public_key()
_, SSH_FINGERPRINT = validate_public_ssh_key(SSH_PUBLIC_KEY)
ANCHOR_FINGERPRINT = compute_verification_anchor_fingerprint(ANCHOR)


def _settings(**updates):
    values = {
        "discovery_controlled_integration_enabled": True,
        "discovery_worker_managed_bundle": True,
        "discovery_worker_key_dir": probe.WORKER_KEY_DIR,
        "discovery_bootstrap_mount": probe.DISCOVERY_BUNDLE_PATH,
        "discovery_worker_identity_key": probe.WORKER_IDENTITY_KEY_PATH,
        "discovery_worker_identity_anchor": probe.WORKER_IDENTITY_ANCHOR_PATH,
        "discovery_admission_ca": probe.ADMISSION_CA_PATH,
        "discovery_admission_endpoint": "https://admission.internal.test:8443",
        "discovery_worker_node_organization": str(ORG_ID),
        "discovery_worker_node_label": "site-worker-01",
        "temporal_task_queue": probe.ORDINARY_TASK_QUEUE,
    }
    values.update(updates)
    return SimpleNamespace(**values)


def _seals(**updates):
    values = {
        "generic_activation_subprocess_sealed": True,
        "generic_executor_subprocess_sealed": True,
        "plan_only_process_sealed": False,
        "real_provisioning_disabled": True,
    }
    values.update(updates)
    return values


def _node(**updates):
    values = {
        "id": NODE_ID,
        "organization_id": ORG_ID,
        "node_label": "site-worker-01",
        "ssh_public_key": SSH_PUBLIC_KEY,
        "ssh_public_key_fingerprint": SSH_FINGERPRINT,
        "admission_anchor_hex": ANCHOR,
        "admission_anchor_fingerprint": ANCHOR_FINGERPRINT,
        "revision": 3,
        "worker_identity_registration_id": REGISTRATION_ID,
    }
    values.update(updates)
    return probe.PublicNodeRecord(**values)


def _lifecycle(**updates):
    values = {
        "bootstrap_status": None,
        "worker_identity_approved": False,
        "worker_identity_current": False,
        "live_read_authorization_approved": False,
        "live_read_authorization_current": False,
        "bundle_available": False,
        "discovery_contacted": False,
        "candidate_executable": None,
    }
    values.update(updates)
    return probe.LifecycleRecord(**values)


def _local_keys(**updates):
    values = {
        "ssh_public_key_fingerprint": SSH_FINGERPRINT,
        "admission_anchor_fingerprint": ANCHOR_FINGERPRINT,
    }
    values.update(updates)
    return probe.LocalKeyRecord(**values)


def _run(
    *,
    settings=None,
    readiness=None,
    seals=None,
    node=None,
    lifecycle=None,
    keys=None,
    loop_started=None,
    runtime_overlay=None,
):
    return probe.run_probe(
        settings=settings or _settings(),
        readiness_reader=readiness or (lambda: (True, probe.ORDINARY_TASK_QUEUE)),
        seal_reader=seals or _seals,
        node_reader=node or (lambda _org, _label: _node()),
        lifecycle_reader=lifecycle or (lambda _org, _node: _lifecycle()),
        key_reader=keys or _local_keys,
        loop_started_reader=loop_started or (lambda: True),
        runtime_overlay_reader=runtime_overlay or (lambda: OVERLAY_DIGEST),
    )


def test_activation_is_false_by_default_and_only_observes_local_preflight_facts():
    calls: list[str] = []

    def readiness():
        calls.append("readiness")
        return True, probe.ORDINARY_TASK_QUEUE

    def seals():
        calls.append("seals")
        return _seals()

    def unexpected(*_args):
        calls.append("unexpected")
        raise AssertionError("disabled activation must not inspect the database")

    result = probe.run_probe(
        settings=SimpleNamespace(
            discovery_controlled_integration_enabled=False,
            discovery_worker_managed_bundle=False,
        ),
        readiness_reader=readiness,
        seal_reader=seals,
        node_reader=unexpected,
    )

    assert result["ok"] is False
    assert result["reason_code"] == "activation_disabled"
    assert result["health"] == {
        "ready": True,
        "ordinary_queue": True,
        "bundle_prep_loop_started": False,
    }
    assert result["worker_keys"] == {
        "metadata_safe": False,
        "public_node_matches_local_keys": False,
    }
    assert result["safety_seals"] == _seals()
    assert calls == ["readiness", "seals"]


def test_success_is_bounded_public_only_and_queries_exact_configured_binding():
    observed: list[tuple[uuid.UUID, str]] = []

    def read_node(organization_id: uuid.UUID, node_label: str):
        observed.append((organization_id, node_label))
        return _node()

    result = _run(node=read_node)
    encoded = probe._json_bytes(result)

    assert result["ok"] is True and result["reason_code"] == "ok"
    assert observed == [(ORG_ID, "site-worker-01")]
    assert result["ordinary_task_queue"] == "secp-orchestration"
    assert result["configuration"] == {
        "controlled_integration_enabled": True,
        "worker_managed_bundle": True,
        "fixed_paths_valid": True,
        "admission_configured": True,
        "runtime_overlay_loaded": True,
    }
    assert result["runtime_overlay_sha256"] == OVERLAY_DIGEST
    assert result["health"] == {
        "ready": True,
        "ordinary_queue": True,
        "bundle_prep_loop_started": True,
    }
    assert result["worker_keys"] == {
        "metadata_safe": True,
        "public_node_matches_local_keys": True,
    }
    assert result["safety_seals"] == _seals()
    assert result["worker_node"] == {
        "id": str(NODE_ID),
        "revision": 3,
        "ssh_public_key_fingerprint": SSH_FINGERPRINT,
        "admission_anchor_fingerprint": ANCHOR_FINGERPRINT,
        "public_material_only": True,
    }
    assert result["lifecycle"] == {
        "bootstrap_status": None,
        "worker_identity_approved": False,
        "worker_identity_current": False,
        "live_read_authorization_approved": False,
        "live_read_authorization_current": False,
        "bundle_available": False,
        "discovery_contacted": False,
        "candidate_executable": None,
    }
    assert len(encoded) <= 4096
    assert SSH_PUBLIC_KEY.encode() not in encoded
    assert ANCHOR.encode() not in encoded
    assert str(REGISTRATION_ID).encode() not in encoded
    assert all(value is False for value in result["probe_effects"].values())


@pytest.mark.parametrize("observed", ["bad", "sha256:" + "A" * 64])
def test_runtime_overlay_must_be_content_addressed_before_loop_or_database(observed):
    calls: list[str] = []

    def unexpected(*_args):
        calls.append("unexpected")
        raise AssertionError("unverified overlay must precede the bundle/database probes")

    result = probe.run_probe(
        settings=_settings(),
        readiness_reader=lambda: (True, probe.ORDINARY_TASK_QUEUE),
        seal_reader=_seals,
        runtime_overlay_reader=lambda: observed,
        loop_started_reader=unexpected,
        node_reader=unexpected,
    )

    assert result["reason_code"] == "runtime_overlay_unverified"
    assert result["configuration"]["runtime_overlay_loaded"] is False
    assert result["runtime_overlay_sha256"] is None
    assert calls == []


def test_later_lifecycle_is_injected_and_emits_only_closed_public_facts():
    observed: list[tuple[uuid.UUID, object, object, object]] = []

    def read_lifecycle(organization_id: uuid.UUID, node: probe.PublicNodeRecord):
        observed.append(
            (
                organization_id,
                node.id,
                node.ssh_public_key,
                node.admission_anchor_hex,
            )
        )
        return _lifecycle(
            bootstrap_status="bound",
            worker_identity_approved=True,
            worker_identity_current=True,
            live_read_authorization_approved=True,
            live_read_authorization_current=True,
            bundle_available=True,
            discovery_contacted=True,
            candidate_executable=False,
        )

    result = _run(lifecycle=read_lifecycle)
    encoded = probe._json_bytes(result)

    assert result["ok"] is True
    assert observed == [(ORG_ID, NODE_ID, SSH_PUBLIC_KEY, ANCHOR)]
    assert result["lifecycle"] == {
        "bootstrap_status": "bound",
        "worker_identity_approved": True,
        "worker_identity_current": True,
        "live_read_authorization_approved": True,
        "live_read_authorization_current": True,
        "bundle_available": True,
        "discovery_contacted": True,
        "candidate_executable": False,
    }
    assert SSH_PUBLIC_KEY.encode() not in encoded
    assert ANCHOR.encode() not in encoded
    assert str(REGISTRATION_ID).encode() not in encoded


def test_local_persisted_keys_must_match_the_published_node_before_loop_is_proven():
    result = _run(keys=lambda: _local_keys(ssh_public_key_fingerprint="SHA256:" + "B" * 43))

    assert result["ok"] is False
    assert result["reason_code"] == "worker_publication_key_mismatch"
    assert result["worker_node"] is None
    assert result["health"]["bundle_prep_loop_started"] is False
    assert result["worker_keys"] == {
        "metadata_safe": False,
        "public_node_matches_local_keys": False,
    }


def test_stale_matching_public_node_cannot_prove_current_bundle_loop_start():
    observations: list[str] = []

    def stale_node(_organization_id, _node_label):
        observations.append("stale-node-read")
        return _node()

    result = _run(loop_started=lambda: False, node=stale_node)

    assert result["ok"] is False
    assert result["reason_code"] == "bundle_prep_loop_not_started"
    assert result["health"]["bundle_prep_loop_started"] is False
    assert result["worker_node"] is None
    # A database row whose keys happen to match is no longer consulted as loop-start evidence.
    assert observations == []


def test_untyped_bundle_loop_observation_fails_closed_before_database():
    result = _run(loop_started=lambda: 1)

    assert result["reason_code"] == "bundle_prep_loop_observation_invalid"
    assert result["worker_node"] is None


def test_default_loop_observation_binds_marker_to_live_readiness_pid(monkeypatch):
    from secp_worker import bundle_loop_marker, health

    observed: list[int] = []

    def stale_marker(*, expected_worker_pid: int) -> bool:
        observed.append(expected_worker_pid)
        return False

    monkeypatch.setattr(health, "_ready_path", lambda: probe.HEALTH_MARKER_PATH)
    monkeypatch.setattr(health, "readiness_process_id", lambda: 41)
    monkeypatch.setattr(bundle_loop_marker, "is_current", stale_marker)

    # The synthetic marker reader above returns False, but records the exact PID it was asked to
    # bind. A stale database node is irrelevant unless this local process-instance check passes.
    assert probe._default_loop_started() is False
    assert observed == [41]


def test_local_key_read_failure_is_closed_without_secret_or_path_text():
    def failed():
        raise RuntimeError("PRIVATE KEY at /var/run/secp/worker-keys/admission_key")

    result = _run(keys=failed)
    encoded = probe._json_bytes(result)

    assert result["reason_code"] == "worker_key_observation_failed"
    assert b"PRIVATE KEY" not in encoded
    assert b"RuntimeError" not in encoded


@pytest.mark.parametrize(
    "lifecycle",
    [
        _lifecycle(bootstrap_status="foreign"),
        _lifecycle(worker_identity_current=True),
        _lifecycle(
            bootstrap_status="bound",
            live_read_authorization_current=True,
        ),
        _lifecycle(
            bootstrap_status="pending",
            live_read_authorization_approved=True,
        ),
        _lifecycle(
            bootstrap_status="bound",
            discovery_contacted=True,
        ),
        _lifecycle(
            bootstrap_status="bound",
            candidate_executable=False,
        ),
        _lifecycle(
            bootstrap_status="bound",
            candidate_executable="false",
        ),
    ],
)
def test_inconsistent_or_untyped_lifecycle_observation_fails_closed(lifecycle):
    result = _run(lifecycle=lambda _org, _node: lifecycle)

    assert result["ok"] is False
    assert result["reason_code"] == "worker_lifecycle_observation_invalid"
    assert result["worker_node"] is None
    assert result["lifecycle"] == {
        "bootstrap_status": None,
        "worker_identity_approved": False,
        "worker_identity_current": False,
        "live_read_authorization_approved": False,
        "live_read_authorization_current": False,
        "bundle_available": False,
        "discovery_contacted": False,
        "candidate_executable": None,
    }


def test_lifecycle_query_failure_is_closed_and_suppresses_exception_text():
    def failed(_org, _node):
        raise RuntimeError("postgresql://admin:password@db.internal/production")

    result = _run(lifecycle=failed)

    assert result["reason_code"] == "worker_lifecycle_query_failed"
    serialized = json.dumps(result)
    assert "password" not in serialized
    assert "db.internal" not in serialized


def test_default_lifecycle_projection_follows_exact_bindings_and_latest_snapshot(
    session, principal
):
    """Exercise the real bounded SELECT projection against hermetic SQLite state."""

    import copy
    from datetime import UTC, datetime, timedelta

    from conftest import VALID_PROVISIONING_SCOPE, onboard_and_activate
    from secp_api.enums import (
        DiscoveryCandidatePlanStatus,
        DiscoveryContactState,
        DiscoveryDecisionCode,
        DiscoveryEligibility,
        DiscoveryJobStatus,
        LiveReadAuthorizationStatus,
        ProxmoxBootstrapStatus,
        TargetDiscoveryStatus,
        WorkerDiscoveryAdmissionStatus,
        WorkerIdentityMechanism,
        WorkerIdentityStatus,
    )
    from secp_api.models import (
        DiscoveryCandidatePlan,
        DiscoveryJob,
        DiscoverySnapshot,
        LiveReadAuthorization,
        ProxmoxReadOnlyBootstrapSession,
        TargetDiscoveryEnrollment,
        WorkerDiscoveryAdmission,
        WorkerIdentityRegistration,
    )
    from secp_api.services import targets, worker_nodes
    from secp_api.worker_admission_contract import WORKER_ADMISSION_PURPOSE

    now = datetime.now(UTC)
    target = targets.register_target(
        session,
        principal,
        display_name="Projection target",
        plugin_name="proxmox",
        config={"base_url": "https://projection.invalid:8006/api2/json", "verify_tls": True},
        secret_ref="env:SECP_PROVIDER_SECRET__PROJECTION",
        scope_policy={"provisioning": copy.deepcopy(VALID_PROVISIONING_SCOPE)},
        address_spaces=[{"cidr_block": "10.83.0.0/16", "subnet_prefix": 24}],
    )
    onboarding = onboard_and_activate(session, principal, target)
    node = worker_nodes.publish_worker_node(
        session,
        organization_id=principal.organization_id,
        node_label="site-worker-01",
        ssh_public_key=SSH_PUBLIC_KEY,
        admission_anchor_hex=ANCHOR,
    )
    node = worker_nodes.approve_and_link_worker_node_identity(
        session,
        principal,
        node_id=node.id,
        expected_node_revision=node.revision,
        expected_ssh_public_key_fingerprint=node.ssh_public_key_fingerprint,
        expected_admission_anchor_fingerprint=node.admission_anchor_fingerprint,
        deployment_binding="production-worker",
        proof_id="pr5f.activation-probe-review",
        issuer="secp.operator",
        deployment_binding_review_confirmed=True,
        verification_anchor_review_confirmed=True,
        rotation_revocation_review_confirmed=True,
    )
    registration = session.get(WorkerIdentityRegistration, node.worker_identity_registration_id)
    assert registration is not None
    # An unrelated ordinary-worker mechanism may coexist in the organization.  It is not an
    # Ed25519 signed-nonce admission candidate and must not make the linked node look ambiguous.
    session.add(
        WorkerIdentityRegistration(
            organization_id=principal.organization_id,
            mechanism=WorkerIdentityMechanism.mtls_workload_identity,
            identity_label="ordinary-worker-existing",
            deployment_binding="ordinary-worker-deployment",
            verification_anchor_fingerprint="sha256:" + "a" * 64,
            identity_version=1,
            expiry=now + timedelta(days=1),
            evidence_fingerprint="sha256:" + "b" * 64,
            status=WorkerIdentityStatus.approved,
            revision=1,
            created_by=principal.user_id,
            approved_by=principal.user_id,
            approved_at=now,
        )
    )
    endpoint_hash = "sha256:" + "2" * 64
    authorization = LiveReadAuthorization(
        organization_id=principal.organization_id,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        connection_hash="sha256:" + "3" * 64,
        boundary_hash="sha256:" + "4" * 64,
        endpoint_binding_hash=endpoint_hash,
        authorization_version=1,
        authorization_expiry=now + timedelta(days=1),
        collector_contract_version="secp.test/read-only-v1",
        endpoint_allowlist_version="secp.test/allowlist-v1",
        evidence_source="live_readonly_proxmox",
        verification_level="live_verified",
        status=LiveReadAuthorizationStatus.approved,
        created_by=principal.user_id,
        approved_by=principal.user_id,
        approved_at=now,
    )
    session.add(authorization)
    session.flush()
    session.add(
        ProxmoxReadOnlyBootstrapSession(
            organization_id=principal.organization_id,
            execution_target_id=target.id,
            onboarding_id=onboarding.id,
            account="secpdisc",
            pve_role="SECPDiscoveryReadOnly",
            worker_ssh_public_key=SSH_PUBLIC_KEY,
            worker_ssh_public_key_fingerprint=SSH_FINGERPRINT,
            status=ProxmoxBootstrapStatus.bound,
            revision=3,
            ssh_port=22,
            endpoint_binding_hash=endpoint_hash,
            live_read_authorization_id=authorization.id,
            authorization_version=authorization.authorization_version,
            expires_at=now + timedelta(days=1),
            created_by=principal.user_id,
        )
    )
    enrollment = TargetDiscoveryEnrollment(
        organization_id=principal.organization_id,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        display_name="Projection enrollment",
        ownership_label="projection-read-only",
        resource_profile="small_lab",
        status=TargetDiscoveryStatus.plan_ready,
        decision_code=DiscoveryDecisionCode.pending,
        enrollment_version=1,
        revision=1,
        created_by=principal.user_id,
    )
    session.add(enrollment)
    session.flush()
    job = DiscoveryJob(
        enrollment_id=enrollment.id,
        organization_id=principal.organization_id,
        operation_fingerprint="sha256:" + "5" * 64,
        enrollment_version=1,
        status=DiscoveryJobStatus.completed,
        revision=1,
        attempt_count=1,
        created_by=principal.user_id,
    )
    session.add(job)
    session.flush()
    session.add(
        WorkerDiscoveryAdmission(
            organization_id=principal.organization_id,
            worker_registration_id=registration.id,
            identity_version=registration.identity_version,
            discovery_job_id=job.id,
            enrollment_id=enrollment.id,
            execution_target_id=target.id,
            onboarding_id=onboarding.id,
            live_read_authorization_id=authorization.id,
            authorization_version=authorization.authorization_version,
            endpoint_binding_hash=endpoint_hash,
            purpose=WORKER_ADMISSION_PURPOSE,
            nonce="a" * 64,
            status=WorkerDiscoveryAdmissionStatus.consumed,
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
            admitted_at=now,
            consumed_at=now,
        )
    )
    snapshot = DiscoverySnapshot(
        enrollment_id=enrollment.id,
        organization_id=principal.organization_id,
        job_id=job.id,
        enrollment_version=1,
        evidence={"schema_version": "secp.test/discovery-evidence-v1"},
        evidence_hash="sha256:" + "6" * 64,
        capacity_snapshot_hash="sha256:" + "7" * 64,
        eligibility=DiscoveryEligibility.eligible,
        worker_identity_version=registration.identity_version,
        bundle_available=True,
        contact_state=DiscoveryContactState.contacted,
        created_by=principal.user_id,
    )
    session.add(snapshot)
    session.flush()
    session.add(
        DiscoveryCandidatePlan(
            enrollment_id=enrollment.id,
            organization_id=principal.organization_id,
            snapshot_id=snapshot.id,
            plan_version=1,
            plan_hash="sha256:" + "8" * 64,
            plan_document={
                "organization_id": str(principal.organization_id),
                "enrollment_id": str(enrollment.id),
                "worker_registration_id": str(registration.id),
                "worker_identity_version": registration.identity_version,
                "executable": False,
            },
            node="pve-test",
            storage="local-lvm",
            ownership_tag="secp.test/projection",
            capacity_snapshot_hash=snapshot.capacity_snapshot_hash,
            evidence_hash=snapshot.evidence_hash,
            worker_identity_version=registration.identity_version,
            enrollment_version=enrollment.enrollment_version,
            expires_at=now + timedelta(hours=1),
            status=DiscoveryCandidatePlanStatus.draft,
            created_by=principal.user_id,
        )
    )
    session.commit()

    public_node = probe._default_node_reader(principal.organization_id, "site-worker-01")
    assert public_node is not None and public_node.id == node.id
    lifecycle = probe._default_lifecycle_reader(principal.organization_id, public_node)

    assert lifecycle == _lifecycle(
        bootstrap_status="bound",
        worker_identity_approved=True,
        worker_identity_current=True,
        live_read_authorization_approved=True,
        live_read_authorization_current=True,
        bundle_available=True,
        discovery_contacted=True,
        candidate_executable=False,
    )

    # A newer failed snapshot wins. The projection must never skip it to report the older contacted
    # candidate as current.
    retry = DiscoveryJob(
        enrollment_id=enrollment.id,
        organization_id=principal.organization_id,
        operation_fingerprint="sha256:" + "9" * 64,
        enrollment_version=1,
        status=DiscoveryJobStatus.failed,
        revision=1,
        attempt_count=1,
        created_by=principal.user_id,
    )
    session.add(retry)
    session.flush()
    session.add(
        DiscoverySnapshot(
            enrollment_id=enrollment.id,
            organization_id=principal.organization_id,
            job_id=retry.id,
            enrollment_version=1,
            evidence={"schema_version": "secp.test/discovery-evidence-v1"},
            evidence_hash="sha256:" + "a" * 64,
            capacity_snapshot_hash="sha256:" + "b" * 64,
            eligibility=DiscoveryEligibility.unverifiable,
            reason_code="bundle_unavailable_state",
            worker_identity_version=registration.identity_version,
            bundle_available=False,
            contact_state=DiscoveryContactState.bundle_unavailable,
            created_by=principal.user_id,
        )
    )
    session.commit()

    latest = probe._default_lifecycle_reader(principal.organization_id, public_node)
    assert latest.bundle_available is False
    assert latest.discovery_contacted is False
    assert latest.candidate_executable is None


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"discovery_worker_key_dir": "/tmp/foreign"}, "fixed_path_configuration_invalid"),
        ({"discovery_bootstrap_mount": "/tmp/foreign"}, "fixed_path_configuration_invalid"),
        (
            {"discovery_worker_identity_key": "/tmp/private"},
            "fixed_path_configuration_invalid",
        ),
        (
            {"discovery_admission_ca": "/etc/ssl/certs/system.pem"},
            "fixed_path_configuration_invalid",
        ),
        (
            {"temporal_task_queue": "secp-controlled-live-v1"},
            "ordinary_queue_configuration_invalid",
        ),
        (
            {"discovery_admission_endpoint": "http://controller.invalid"},
            "admission_configuration_invalid",
        ),
        (
            {"discovery_admission_endpoint": "https://user:secret@controller.invalid"},
            "admission_configuration_invalid",
        ),
        ({"discovery_worker_node_organization": "not-a-uuid"}, "worker_node_binding_invalid"),
        ({"discovery_worker_node_label": "bad label"}, "worker_node_binding_invalid"),
    ],
)
def test_invalid_configuration_refuses_before_health_seals_or_database(updates, reason):
    def unexpected(*_args):
        raise AssertionError("configuration refusal must precede every observation")

    result = probe.run_probe(
        settings=_settings(**updates),
        readiness_reader=unexpected,
        seal_reader=unexpected,
        node_reader=unexpected,
    )

    assert result["ok"] is False and result["reason_code"] == reason
    serialized = json.dumps(result, sort_keys=True)
    assert "secret" not in serialized
    assert "controller.invalid" not in serialized
    for untrusted_value in updates.values():
        assert str(untrusted_value) not in serialized


@pytest.mark.parametrize("readiness", [(False, "secp-orchestration"), (True, "wrong-queue")])
def test_unhealthy_or_wrong_queue_refuses_before_seals_and_database(readiness):
    def unexpected(*_args):
        raise AssertionError("worker readiness refusal must precede later probes")

    result = probe.run_probe(
        settings=_settings(),
        readiness_reader=lambda: readiness,
        seal_reader=unexpected,
        node_reader=unexpected,
    )

    assert result["reason_code"] == "ordinary_worker_not_ready"
    assert result["worker_node"] is None


@pytest.mark.parametrize(
    "drift",
    [
        {"generic_activation_subprocess_sealed": False},
        {"generic_executor_subprocess_sealed": False},
        {"plan_only_process_sealed": True},
        {"real_provisioning_disabled": False},
    ],
)
def test_any_safety_seal_drift_refuses_before_database(drift):
    def unexpected(*_args):
        raise AssertionError("seal refusal must precede the database query")

    result = _run(seals=lambda: _seals(**drift), node=unexpected)

    assert result["reason_code"] == "safety_seal_drift"
    assert result["worker_node"] is None


def test_missing_node_and_database_exception_are_distinct_closed_reasons():
    missing = _run(node=lambda _org, _label: None)

    def failed(_org, _label):
        raise RuntimeError("postgresql://user:password@internal.example/db")

    query_failed = _run(node=failed)

    assert missing["reason_code"] == "worker_node_missing"
    assert query_failed["reason_code"] == "worker_node_query_failed"
    assert "password" not in json.dumps(query_failed)
    assert "internal.example" not in json.dumps(query_failed)


@pytest.mark.parametrize(
    "updates",
    [
        {"ssh_public_key": "-----BEGIN OPENSSH PRIVATE KEY-----"},
        {"ssh_public_key": SSH_PUBLIC_KEY.rsplit(" ", 1)[0] + " endpoint-password"},
        {"ssh_public_key_fingerprint": "SHA256:" + "A" * 43},
        {"admission_anchor_hex": "f" * 64},
        {"admission_anchor_fingerprint": "sha256:" + "0" * 64},
        {"revision": 0},
        {"revision": True},
        {"organization_id": uuid.uuid4()},
        {"node_label": "other-worker"},
    ],
)
def test_malformed_mismatched_or_private_node_material_is_never_emitted(updates):
    result = _run(node=lambda _org, _label: _node(**updates))

    assert result["reason_code"] == "worker_node_public_material_invalid"
    assert result["worker_node"] is None
    serialized = json.dumps(result)
    assert "PRIVATE KEY" not in serialized
    assert SSH_PUBLIC_KEY not in serialized


def test_public_node_repr_never_contains_loaded_material():
    row = _node(ssh_public_key="-----BEGIN OPENSSH PRIVATE KEY-----", admission_anchor_hex="b" * 64)

    rendered = repr(row)

    assert rendered == "PublicNodeRecord(<public-only projection>)"
    assert "PRIVATE KEY" not in rendered


def test_lifecycle_repr_is_closed():
    rendered = repr(
        _lifecycle(
            bootstrap_status="bound",
            worker_identity_approved=True,
            worker_identity_current=True,
        )
    )

    assert rendered == "LifecycleRecord(<closed public-only projection>)"


def test_unexpected_settings_error_collapses_without_leaking_exception_text():
    class BrokenSettings:
        def __getattr__(self, _name):
            raise RuntimeError("SECP_DATABASE_URL=postgresql://admin:topsecret@db.internal")

    result = probe.run_probe(settings=BrokenSettings())

    assert result["reason_code"] == "probe_failed"
    serialized = json.dumps(result)
    assert "topsecret" not in serialized
    assert "db.internal" not in serialized


def test_cli_arguments_are_refused_without_executing_probe(monkeypatch, capfd):
    monkeypatch.setattr(
        probe,
        "run_probe",
        lambda: (_ for _ in ()).throw(AssertionError("run_probe must not execute")),
    )

    code = probe._main(["--path", "/tmp/foreign"])
    captured = capfd.readouterr()
    payload = json.loads(captured.out)

    assert code == 1
    assert payload["reason_code"] == "arguments_forbidden"
    assert "/tmp/foreign" not in captured.out


def test_module_source_has_no_operator_temporal_workflow_or_process_invocation():
    source = probe.__file__
    assert source is not None
    text = open(source, encoding="utf-8").read()  # noqa: PTH123 - fixed imported module source

    for forbidden in (
        "temporalio",
        "operator_bootstrap",
        "run_plan_generation(",
        "subprocess.",
        "os.system",
        "httpx",
        "paramiko",
        "session.add(",
        "session.commit(",
        "session.flush(",
    ):
        assert forbidden not in text
