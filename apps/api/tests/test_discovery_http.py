"""SECP-B5 — HTTP surface for read-only target discovery (drives the real ASGI app).

Proves: validation errors never echo a token-shaped input; the API surfaces only safe enrollment /
evidence / candidate-plan fields (never SSH host/account/port/key path/known_hosts/fingerprint,
Proxmox endpoint/token, or raw output); the candidate plan is declared non-executable (apply
sealed);
approval requires the exact plan hash and is fail-closed; and no privileged value can be passed in.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from secp_api.enums import IsolationModel, OnboardingMode, OnboardingStatus, TargetStatus
from secp_api.models import ExecutionTarget, TargetDiscoveryEnrollment, TargetOnboarding

MARKER = "s3cr3t-hunter2"
MALICIOUS = f"PVEAPIToken=user@pam!tok={MARKER}"

# Unmistakable sensitive markers seeded onto the target so a real transport /
# secret leak is caught by an EXACT value match instead of a probabilistic bare
# substring. The port lives inside the full endpoint value; it is never checked
# as a lone "8006" substring (which is valid hexadecimal and appears by chance
# in content-addressed hashes/ids — the original false positive).
ENDPOINT_MARKER = "https://host.example:8006/api2/json"
SECRET_REF_MARKER = f"vault:secp/proxmox/svc-account:{MARKER}"

# Exact transport/secret field NAMES that must never appear as a key anywhere in
# a discovery response. Compared by EXACT normalized name — never as a substring
# — so safe keys that merely contain one of these words (ownership_marker,
# endpoint_binding_hash, worker_identity_version, …) are allowed.
_FORBIDDEN_KEYS = frozenset(
    {
        "ssh",
        "ssh_host",
        "ssh_port",
        "endpoint",
        "base_url",
        "host",
        "port",
        "token",
        "api_token",
        "known_hosts",
        "private_key",
        "fingerprint",
    }
)

# Sensitive VALUE substrings (real transport/secret material and the exact
# seeded markers) that must never appear anywhere in a serialized response body.
# Opaque hashes/ids/ownership markers may contain arbitrary hexadecimal
# (including "8006") and are deliberately NOT matched here.
_FORBIDDEN_VALUES = (
    ENDPOINT_MARKER,
    SECRET_REF_MARKER,
    MARKER,
    "host.example",
    "secpops",
    "known_hosts",
    "SHA256:",  # SSH key-fingerprint prefix (distinct from lowercase sha256: hashes)
    "PVEAPIToken",
    "BEGIN OPENSSH",
    "/mnt/",
    "private_key",
)


def _iter_keys(obj: Any) -> Iterator[str]:
    """Yield every dict key anywhere in a (possibly nested) JSON structure."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield str(key)
            yield from _iter_keys(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_keys(item)


def assert_discovery_response_safe(payload: Any, raw_text: str) -> None:
    """Structural + seeded-value safety check for a discovery response.

    Structural: no explicit transport/secret field NAME (exact, normalized)
    appears as a key at any depth. Value: no sensitive/seeded material appears
    anywhere in the serialized body. Replaces the removed probabilistic bare
    "8006" substring heuristic without weakening the leak check.
    """
    leaked_keys = sorted({k for k in _iter_keys(payload) if k.lower() in _FORBIDDEN_KEYS})
    assert not leaked_keys, f"discovery response exposed forbidden field name(s): {leaked_keys}"
    for value in _FORBIDDEN_VALUES:
        assert value not in raw_text, f"discovery response leaked sensitive value: {value!r}"


@pytest.fixture
def client(engine):
    from secp_api.db import session_scope
    from secp_api.main import create_app
    from secp_api.seed import bootstrap_dev

    with session_scope() as s:
        bootstrap_dev(s)
    app = create_app()
    app.router.on_startup.clear()
    return TestClient(app)


def _seed_and_discover(engine) -> str:
    """Create a target+onboarding+enrollment and run the read-only engine (fake eligible source) to
    produce a candidate plan. Returns the enrollment id."""
    from secp_api.db import get_sessionmaker
    from secp_api.models import DiscoveryJob, Organization, User
    from secp_api.services import target_discovery as svc
    from secp_worker.target_discovery.engine import DiscoveryComposition, run_discovery
    from secp_worker.target_discovery.seams import InventoryFacts, StorageOption

    class _Src:
        def read_inventory(self):
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

        def probe_candidate_presence(self, locators):
            from secp_worker.target_discovery.seams import LocatorPresence

            return {loc.observe_key(): LocatorPresence(False, None) for loc in locators}

    factory = get_sessionmaker()
    with factory() as s:
        org = s.query(Organization).order_by(Organization.created_at.asc()).first()
        user = s.query(User).filter(User.organization_id == org.id).first()

        class _P:
            user_id = user.id
            organization_id = org.id
            permissions = frozenset()

            def require(self, *_a):
                return None

            def require_org(self, *_a):
                return None

        target = ExecutionTarget(
            organization_id=org.id,
            display_name="s",
            plugin_name="proxmox",
            # Seed unmistakable endpoint + secret markers so any leak of the
            # target's transport/secret material is caught by an exact match.
            config={"base_url": ENDPOINT_MARKER, "verify_tls": True},
            config_hash="sha256:" + "ab" * 32,
            secret_ref=SECRET_REF_MARKER,
            status=TargetStatus.active,
            scope_policy={},
            created_by=user.id,
        )
        s.add(target)
        s.flush()
        s.add(
            TargetOnboarding(
                organization_id=org.id,
                execution_target_id=target.id,
                onboarding_mode=OnboardingMode.existing_environment,
                isolation_model=IsolationModel.logical,
                status=OnboardingStatus.active,
                declared_boundary={},
                boundary_hash="sha256:" + "cd" * 32,
                created_by=user.id,
            )
        )
        s.flush()
        # SECP-B6 F-IDENTITY: a candidate plan is only approvable when it binds a real approved
        # worker identity (version > 0), so register + approve one before discovery.
        _approve_worker_identity(s, _P())
        enrollment = svc.request_discovery(s, _P(), execution_target_id=target.id)
        job = s.query(DiscoveryJob).filter(DiscoveryJob.enrollment_id == enrollment.id).one()
        run_discovery(
            s, job, composition=DiscoveryComposition(probe_source=_Src()), now=datetime.now(UTC)
        )
        s.commit()
        return str(enrollment.id)


def _approve_worker_identity(session, principal) -> None:
    """Register + evidence + approve one worker identity for the principal's org (SECP-B6)."""
    from secp_api.enums import (
        WorkerIdentityEvidenceKind,
        WorkerIdentityEvidenceStatus,
        WorkerIdentityMechanism,
    )
    from secp_api.services import worker_identity as wi
    from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint

    row = wi.register_worker_identity(
        session,
        principal,
        mechanism=WorkerIdentityMechanism.mtls_workload_identity,
        identity_label="staging-worker-a",
        deployment_binding="deploy-01",
        verification_anchor_fingerprint=compute_verification_anchor_fingerprint("anchor-v1"),
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


def test_validation_422_never_echoes_input(client, engine):
    resp = client.post(
        "/api/v1/target-discovery",
        json={
            "execution_target_id": "00000000-0000-0000-0000-000000000001",
            "logical_name": MALICIOUS,
        },
    )
    assert resp.status_code == 422
    assert MARKER not in resp.text and MALICIOUS not in resp.text and "@pam" not in resp.text
    assert resp.json() == {"error": {"code": "invalid_target_discovery_input"}}
    from secp_api.db import get_sessionmaker

    with get_sessionmaker()() as s:
        assert s.query(TargetDiscoveryEnrollment).count() == 0


def test_discovery_lifecycle_and_safe_fields(client, engine):
    enrollment_id = _seed_and_discover(engine)

    # Enrollment is plan_ready with safe fields only.
    r = client.get(f"/api/v1/target-discovery/{enrollment_id}")
    assert r.status_code == 200, r.text
    enr = r.json()
    assert enr["status"] == "plan_ready" and enr["ownership_label"].startswith("secp-discover-")
    for unsafe in ("ssh", "token", "endpoint", "host", "port", "key", "fingerprint"):
        assert unsafe not in {k.lower() for k in enr}

    # Evidence: safe capability/eligibility outcome, no raw/SSH fields.
    r = client.get(f"/api/v1/target-discovery/{enrollment_id}/evidence")
    ev = r.json()
    assert ev["eligibility"] == "eligible" and ev["node"] == "pve-a"
    assert ev["nested_available"] is True
    assert ev["cpu_total"] == 16 and ev["selected_storage"] == "local-lvm"
    assert ev["bundle_available"] is True and ev["contact_state"] == "contacted"

    # Candidate plan: safe categories + node/storage labels + generated identifiers; non-executable.
    r = client.get(f"/api/v1/target-discovery/{enrollment_id}/candidate-plan")
    plan = r.json()
    assert plan["executable"] is False
    assert plan["node"] == "pve-a" and plan["storage"] == "local-lvm"
    kinds = {res["kind"] for res in plan["resources"]}
    assert "isolated_bridge" in kinds and "control_plane_vm" in kinds
    plan_hash = plan["plan_hash"]

    # Apply-status: explicit sealed notice.
    r = client.get(f"/api/v1/target-discovery/{enrollment_id}/apply-status")
    assert r.json()["live_apply_sealed"] is True
    assert "sealed" in r.json()["message"].lower()

    # Bootstrap availability: safe boolean only, no location.
    r = client.get(f"/api/v1/target-discovery/{enrollment_id}/bootstrap-availability")
    assert r.json() == {"available": False, "reason_code": "worker_local_bootstrap_not_mounted"}

    # No response leaks any SSH/endpoint/raw material: structural (no explicit
    # transport/secret field name at any depth) + exact seeded-value checks.
    for path in ("", "/evidence", "/candidate-plan", "/bootstrap-availability", "/apply-status"):
        resp = client.get(f"/api/v1/target-discovery/{enrollment_id}{path}")
        assert_discovery_response_safe(resp.json(), resp.text)

    # Approve with the WRONG hash → refused; with the EXACT hash → approved.
    assert (
        client.post(
            f"/api/v1/target-discovery/{enrollment_id}/approve",
            json={"expected_plan_hash": "sha256:" + "00" * 32},
        ).status_code
        == 400
    )
    r = client.post(
        f"/api/v1/target-discovery/{enrollment_id}/approve",
        json={"expected_plan_hash": plan_hash},
    )
    assert r.status_code == 200 and r.json()["status"] == "approved"


def test_discovery_safety_helper_structural_and_value_checks():
    """Regression for the removed probabilistic bare-"8006" heuristic: opaque
    hashes/ids/ownership markers may contain arbitrary hex (incl. "8006") and are
    accepted, while an explicit port/endpoint field or the seeded endpoint value
    is rejected."""
    # Safe: opaque content-addressed hash + ownership marker + resource ref that
    # all happen to contain the "8006" hex sequence — accepted (no assertion).
    safe = {
        "status": "plan_ready",
        "plan_hash": "sha256:aabbccddee0011223344c8006923ff00112233445566778899aabbccddeeff11",
        "ownership_marker": "secp-owned:deadbeef8006cafe",
        "worker_identity_version": 2,
        "resources": [{"kind": "isolated_bridge", "resource_ref": "secp64c8006-bridge-0"}],
    }
    assert_discovery_response_safe(safe, json.dumps(safe))

    # Rejected: an explicit port field (structural).
    with pytest.raises(AssertionError):
        assert_discovery_response_safe({"port": 8006}, json.dumps({"port": 8006}))

    # Rejected: an explicit endpoint/base_url field (structural, at any depth).
    nested = {"config": {"base_url": ENDPOINT_MARKER}}
    with pytest.raises(AssertionError):
        assert_discovery_response_safe(nested, json.dumps(nested))

    # Rejected: the seeded endpoint value appearing anywhere in the body (value).
    leaky = {"note": f"connected to {ENDPOINT_MARKER}"}
    with pytest.raises(AssertionError):
        assert_discovery_response_safe(leaky, json.dumps(leaky))


def test_request_schema_rejects_unsafe_fields():
    from secp_api.schemas_target_discovery import DiscoveryRequest

    assert set(DiscoveryRequest.model_fields) == {
        "execution_target_id",
        "resource_profile",
        "logical_name",
    }
    model = DiscoveryRequest(
        execution_target_id="00000000-0000-0000-0000-000000000001",
        ssh_host="10.0.0.5",
        api_token="PVEAPIToken=x",
        node="pve-a",
        vmid=9000,
        command="rm -rf /",
    )
    dumped = model.model_dump()
    for leaked in ("ssh_host", "api_token", "node", "vmid", "command"):
        assert leaked not in dumped
