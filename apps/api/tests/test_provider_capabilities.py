"""The provider-capability surface is DERIVED, and the false claim is gone.

``GET /providers/capabilities`` served a hardcoded ``provisioning_enabled: False`` with the note
"Proxmox provisioning is deferred to SECP-002B", for six merges after #105-#110 shipped exactly
that provisioning. Its docstring said its purpose was to tell the UI provisioning was not enabled.
A frontend was about to drive a provider security table from it — which would have moved a false
claim out of hand-written UI copy and into an API response, where it reads as observed.

Two things are pinned here, and the second is what stops the defect recurring:

* the misleading keys are ABSENT, not corrected — a boolean cannot carry a three-valued answer;
* the operation set is ENUMERATED FROM THE LIVE MODULE, so a capability that exists and is not
  reported fails this file. A hand-kept list would have to be updated by the same person who
  forgot, which is how the original constant went stale.
"""

from __future__ import annotations

import dataclasses
import uuid

import pytest
from fastapi.testclient import TestClient
from secp_api.auth import Principal
from secp_api.enums import Permission
from secp_api.provider_capabilities import CapabilityState, build_report
from secp_api.range_enums import RangeOperationKind
from secp_api.range_scenarios import KNOWN_PROVIDERS
from secp_api.services import proxmox_commands


@pytest.fixture
def client(engine, principal):
    from secp_api.db import get_sessionmaker
    from secp_api.deps import current_principal
    from secp_api.main import create_app

    app = create_app()
    app.router.on_startup.clear()
    _ = get_sessionmaker()
    app.dependency_overrides[current_principal] = lambda: principal
    return TestClient(app)


# --- the false claim is gone ------------------------------------------------------


def test_the_stale_provisioning_claim_is_absent_from_the_response(client):
    """Absent, not corrected to ``true``.

    The key is what a client reads; leaving it with a better value keeps a two-valued field for a
    three-valued question, and the next person to change what this build supports has to remember
    to update a constant. The whole point is that there is no constant.
    """
    body = client.get("/api/v1/providers/capabilities").json()
    for gone in ("provisioning_enabled", "milestone", "note"):
        assert gone not in body, (
            f"'{gone}' is still served. It was a literal that stopped being true six merges before "
            "anyone noticed; a corrected literal would go stale the same way."
        )


def test_no_response_field_carries_the_old_deferral_language(client):
    """The specific sentence that was false, and anything shaped like it."""
    text = client.get("/api/v1/providers/capabilities").text.lower()
    for phrase in (
        "deferred to secp-002b",
        "provisioning is not enabled",
        "provisioning is deferred",
    ):
        assert phrase not in text


def test_the_source_module_holds_no_provisioning_constant():
    """The constant itself is gone from the router, not merely unreferenced."""
    import secp_api.routers.providers as providers

    assert not hasattr(providers, "PROVISIONING_ENABLED")


# --- the capability set is enumerated from the live modules ------------------------


def test_every_implemented_operation_is_reported(client):
    """Enumerated from ``CommandKind``, so a new command with no capability entry fails HERE.

    This is the test that replaces the constant's job. A capability surface can only be trusted if
    it is impossible to add a capability without it appearing, and that means deriving the set from
    the same enum the command surface dispatches on rather than from a list in this file.
    """
    body = client.get("/api/v1/providers/capabilities").json()
    reported = {item["operation"] for item in body["operations"]}
    expected = {kind.value for kind in proxmox_commands.CommandKind}
    missing = sorted(expected - reported)
    extra = sorted(reported - expected)
    assert reported == expected, (
        f"the capability report and the live command surface disagree. Missing from the report: "
        f"{missing}; reported but not implemented: {extra}"
    )


def test_every_reported_operation_names_the_permission_it_actually_requires(client):
    """The published permission must be the one the command service enforces, not a description."""
    body = client.get("/api/v1/providers/capabilities").json()
    by_operation = {item["operation"]: item for item in body["operations"]}
    for kind, permission in proxmox_commands.COMMAND_PERMISSIONS.items():
        assert by_operation[kind.value]["required_permission"] == permission.value


def test_the_lifecycle_operations_come_from_the_live_operation_kind_enum(client):
    body = client.get("/api/v1/providers/capabilities").json()
    proxmox = next(item for item in body["providers"] if item["provider"] == "proxmox")
    assert set(proxmox["lifecycle_operations"]) == {k.value for k in RangeOperationKind}


def test_every_known_provider_is_reported(client):
    body = client.get("/api/v1/providers/capabilities").json()
    assert {item["provider"] for item in body["providers"]} == set(KNOWN_PROVIDERS)


# --- the three states the old boolean conflated -----------------------------------


def _principal_with(permissions) -> Principal:
    return Principal(
        user_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="cap@local.test",
        permissions=frozenset(permissions),
    )


def test_supported_but_unauthorized_is_distinct_from_not_supported():
    """The distinction the old ``provisioning_enabled: false`` destroyed.

    One is fixed by granting a permission. The other cannot be fixed in this build at all. Told the
    same thing for both, an operator either chases a permission that would not help or gives up on
    a capability that is present.
    """
    nobody = build_report(_principal_with(set()))
    states = {item.operation: item.state for item in nobody.operations}
    assert states, "the report must not be empty"
    assert all(state is CapabilityState.supported_unauthorized for state in states.values()), (
        "with no permissions every implemented operation is supported-but-unauthorized; reporting "
        "not_supported here would say this build cannot provision, which is false"
    )
    assert CapabilityState.not_supported not in set(states.values())

    everyone = build_report(_principal_with(Permission))
    assert all(item.state is CapabilityState.supported_authorized for item in everyone.operations)


def test_holding_one_permission_authorizes_only_its_own_operations():
    """Per-operation, not a single global flag."""
    report = build_report(_principal_with({Permission.exercise_destroy}))
    by_operation = {item.operation: item for item in report.operations}
    destroy_ops = [
        kind.value
        for kind, permission in proxmox_commands.COMMAND_PERMISSIONS.items()
        if permission is Permission.exercise_destroy
    ]
    assert destroy_ops
    for operation in destroy_ops:
        assert by_operation[operation].state is CapabilityState.supported_authorized
    for operation, item in by_operation.items():
        if operation not in destroy_ops:
            assert item.state is CapabilityState.supported_unauthorized


def test_an_unimplemented_command_reports_not_supported(monkeypatch):
    """A command declared but not implemented must not be advertised.

    The report looks the handler up on the live module rather than trusting the enum, so an
    operation that exists only as a name reports ``not_supported``. Provoked here, because a
    capability check nobody has seen fail is a capability check nobody knows works.
    """
    from secp_api import provider_capabilities

    monkeypatch.setattr(
        provider_capabilities,
        "_is_implemented",
        lambda kind: kind is not proxmox_commands.CommandKind.request_reset,
    )
    report = build_report(_principal_with(Permission))
    states = {item.operation: item.state for item in report.operations}
    assert states["request_reset"] is CapabilityState.not_supported
    assert states["request_execution"] is CapabilityState.supported_authorized


def test_the_rollups_cannot_disagree_with_the_operation_list(client):
    """Folded once, on the way out. A summary that contradicts its detail is worse than none."""
    body = client.get("/api/v1/providers/capabilities").json()
    by_state: dict[str, list[str]] = {}
    for item in body["operations"]:
        by_state.setdefault(item["state"], []).append(item["operation"])
    assert body["authorized_operations"] == by_state.get("supported_authorized", [])
    assert body["unauthorized_operations"] == by_state.get("supported_unauthorized", [])
    assert body["unsupported_operations"] == by_state.get("not_supported", [])


# --- discovery is checked, not carried forward ------------------------------------


def test_discovery_is_read_only_because_the_contract_was_checked(client):
    body = client.get("/api/v1/providers/capabilities").json()
    assert body["discovery"] == "read-only"
    # And it says HOW it knows, so the claim is auditable rather than asserted.
    assert "validate_target" in body["discovery_detail"]
    assert "discover" in body["discovery_detail"]


def test_a_mutating_discovery_contract_stops_the_read_only_claim(monkeypatch):
    """The claim must fail closed when it stops being checkable.

    If the discovery protocol ever gains a method that could change a target, the honest answer is
    ``undetermined`` — not a carried-forward "read-only". Reporting safety that is no longer
    established is the direction that gets something run against production.
    """
    from secp_plugin_api.v1 import discovery as discovery_contract

    class MutatingProtocol:
        def validate_target(self): ...
        def discover(self): ...
        def apply_changes(self): ...

    monkeypatch.setattr(discovery_contract, "DiscoveryProtocol", MutatingProtocol)
    report = build_report(_principal_with(Permission))
    assert report.discovery == CapabilityState.undetermined.value
    assert "apply_changes" in report.discovery_detail


# --- the surface still requires authentication -------------------------------------


def test_the_capability_surface_requires_authentication(engine):
    from secp_api.main import create_app

    app = create_app()
    app.router.on_startup.clear()
    unauthenticated = TestClient(app)
    response = unauthenticated.get(
        "/api/v1/providers/capabilities", headers={"Authorization": "Bearer nope"}
    )
    assert response.status_code in (401, 403)


def test_no_secret_reaches_the_capability_surface(client):
    text = client.get("/api/v1/providers/capabilities").text
    for marker in ("PRIVATE KEY", "secret_ref", "password", "token"):
        assert marker not in text


def test_the_capability_surface_is_in_the_published_openapi(client):
    spec = client.get("/openapi.json").json()
    assert "/api/v1/providers/capabilities" in spec["paths"]
    schema = spec["components"]["schemas"]["ProviderCapabilitiesOut"]
    assert "provisioning_enabled" not in schema.get("properties", {})
    assert "operations" in schema["properties"]
    # The state vocabulary a client branches on is published as a closed enum.
    states = set(spec["components"]["schemas"]["CapabilityState"]["enum"])
    assert states == {state.value for state in CapabilityState}


def test_dataclasses_import_is_used():
    """Guard against an unused import drifting in; keeps the module honest under ruff."""
    assert dataclasses.is_dataclass(build_report(_principal_with(set())))
