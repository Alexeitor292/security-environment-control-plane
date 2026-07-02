"""SECP-002B-1B-0.1 — network approach + isolation profile onboarding fields.

Provider-neutral, fake-only. Proves persistence, the allowed enum values, server-side
rejection of roadmap isolation profiles, existing-segment ⊆ approved-segment validation,
backward compatibility for pre-0.1 boundaries, and that fail-closed execution + the
live-evidence seal are unchanged. Nothing real is contacted.
"""

from __future__ import annotations

import copy

import pytest
from fastapi.testclient import TestClient
from tests.conftest import VALID_PROVISIONING_SCOPE  # type: ignore


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


def _register_target(client, slug="wiz"):
    body = {
        "display_name": f"Wizard target {slug}",
        "plugin_name": "proxmox",
        "config": {"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
        "secret_ref": f"env:SECP_PROVIDER_SECRET__{slug.upper()}",
        "scope_policy": {"provisioning": copy.deepcopy(VALID_PROVISIONING_SCOPE)},
        "address_spaces": [{"cidr_block": "10.60.0.0/16", "subnet_prefix": 24}],
    }
    r = client.post("/api/v1/targets", json=body)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _boundary(**overrides) -> dict:
    b = {
        "nodes": ["pve-node-1", "pve-node-2"],
        "storage": ["local-lvm"],
        "network_segments": ["vmbr0"],
        "cidrs": ["10.60.0.0/16"],
        "vmid_range": {"start": 9000, "end": 9100},
        "quotas": {
            "max_teams": 4,
            "max_vms": 20,
            "max_containers": 10,
            "max_total_vcpu": 64,
            "max_total_memory_mb": 131072,
            "max_total_disk_gb": 2048,
        },
        "external_connectivity": {"policy": "deny"},
        "credential_scope": "least_privilege",
    }
    b.update(overrides)
    return b


def _create(client, target_id, boundary, mode="existing_environment", iso="logical"):
    return client.post(
        f"/api/v1/targets/{target_id}/onboarding",
        json={"onboarding_mode": mode, "isolation_model": iso, "declared_boundary": boundary},
    )


# --- persistence + computed API fields ---------------------------------------


def test_persists_network_approach_and_isolation_profile(client):
    tid = _register_target(client, "persist")
    boundary = _boundary(
        network_approach="secp_managed_dedicated_segment",
        isolation_profile="fully_segregated",
    )
    r = _create(client, tid, boundary)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["network_approach"] == "secp_managed_dedicated_segment"
    assert out["isolation_profile"] == "fully_segregated"
    # Durable in the hashed declared boundary too.
    assert out["declared_boundary"]["network_approach"] == "secp_managed_dedicated_segment"
    assert out["declared_boundary"]["isolation_profile"] == "fully_segregated"
    # And still readable on GET.
    got = client.get(f"/api/v1/onboarding/{out['id']}").json()
    assert got["network_approach"] == "secp_managed_dedicated_segment"


def test_default_network_approach_is_existing_segment(client):
    tid = _register_target(client, "defaults")
    r = _create(client, tid, _boundary())  # no new keys supplied
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["network_approach"] == "use_approved_existing_segment"
    assert out["isolation_profile"] == "fully_segregated"


def test_both_network_approaches_are_accepted(client):
    tid = _register_target(client, "approaches")
    for approach in ("use_approved_existing_segment", "secp_managed_dedicated_segment"):
        r = _create(client, tid, _boundary(network_approach=approach))
        assert r.status_code == 201, r.text
        assert r.json()["network_approach"] == approach


# --- server-side rejection of roadmap isolation profiles ---------------------


@pytest.mark.parametrize(
    "profile",
    ["internet_egress_only", "controlled_service_access", "advanced_custom_policy"],
)
def test_future_isolation_profiles_are_rejected_server_side(client, profile):
    tid = _register_target(client, f"future{profile[:4]}")
    r = _create(client, tid, _boundary(isolation_profile=profile))
    assert r.status_code == 422, r.text
    assert "not available yet" in r.text


def test_unknown_network_approach_is_rejected(client):
    tid = _register_target(client, "unknownapp")
    r = _create(client, tid, _boundary(network_approach="wormhole"))
    assert r.status_code == 422, r.text


# --- existing-segment ⊆ approved segments ------------------------------------


def test_network_segment_outside_approved_is_refused(client):
    tid = _register_target(client, "seg")
    # vmbr9 is not in the target's approved bridges (only vmbr0).
    r = _create(client, tid, _boundary(network_segments=["vmbr0", "vmbr9"]))
    assert r.status_code == 422, r.text
    assert "broader than the target" in r.text or "network_segments" in r.text


# --- backward compatibility (pre-0.1 records) --------------------------------


def test_backward_compatible_defaults_for_pre_0_1_boundary():
    """A pre-0.1 stored boundary (no network/isolation keys) reads back with safe defaults."""
    import uuid
    from datetime import UTC, datetime

    from secp_api.schemas_onboarding import OnboardingOut

    legacy_row = {
        "id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "execution_target_id": uuid.uuid4(),
        "onboarding_mode": "existing_environment",
        "isolation_model": "logical",
        "status": "active",
        # A pre-0.1 boundary: the new keys are simply absent.
        "declared_boundary": {"nodes": ["pve-node-1"], "cidrs": ["10.60.0.0/16"]},
        "boundary_hash": "sha256:legacy",
        "approved_target_config_hash": None,
        "approved_scope_policy_hash": None,
        "approved_preflight_id": None,
        "approved_preflight_evidence_hash": None,
        "approved_boundary_hash": None,
        "approved_verification_level": None,
        "decided_at": None,
        "decision_reason": "",
        "activated_at": None,
        "created_at": datetime.now(UTC),
    }
    out = OnboardingOut.model_validate(legacy_row)
    assert out.network_approach == "use_approved_existing_segment"
    assert out.isolation_profile == "fully_segregated"


# --- fail-closed execution + live seal unchanged -----------------------------


def test_new_fields_do_not_unlock_live_or_break_execution(session, principal, lab_env):
    """A boundary carrying the new fields still flows to active with a computed effective
    boundary, and the live-evidence seal is unchanged."""
    from secp_api.enums import (
        CollectorKind,
        IsolationModel,
        OnboardingMode,
        VerificationLevel,
    )
    from secp_api.errors import LiveEvidenceSealedError
    from secp_api.onboarding import boundary_from_scope, simulate_boundary_checks
    from secp_api.services import onboarding as onb
    from secp_api.services import targets

    env = lab_env()  # default fully_segregated boundary; plan+manifest+gate already exercised
    assert env.plan.effective_boundary_hash  # effective boundary still computed + bound

    # A fresh onboarding whose boundary declares the new fields still cannot mint live evidence.
    t = targets.register_target(
        session,
        principal,
        display_name="SealNew",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
        secret_ref="env:SECP_PROVIDER_SECRET__SEALNEW",
        scope_policy={"provisioning": copy.deepcopy(VALID_PROVISIONING_SCOPE)},
    )
    session.commit()
    boundary = boundary_from_scope(t.scope_policy)
    boundary["network_approach"] = "secp_managed_dedicated_segment"
    boundary["isolation_profile"] = "fully_segregated"
    ob = onb.create_onboarding(
        session,
        principal,
        target_id=t.id,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=IsolationModel.logical,
        declared_boundary=boundary,
    )
    checks = simulate_boundary_checks(ob.declared_boundary, ob.isolation_model)
    with pytest.raises(LiveEvidenceSealedError):
        onb.record_preflight_result(
            session,
            ob.id,
            evidence_record=None,
            checks=checks,
            verification_level=VerificationLevel.live_verified.value,
            collector_kind=CollectorKind.provider_worker.value,
            collector_identity="x",
        )
