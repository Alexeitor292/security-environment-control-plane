"""The gate that decides ``provider_schema_validation``.

The property under test is one-directional and worth stating plainly: it must be impossible to
reach ``verified`` by asserting it. Every test here is therefore a test that some *missing fact*
produces ``unverified`` — plus exactly one that a complete, honest fact set produces ``verified``,
because a gate that never opens is not a gate.
"""

from __future__ import annotations

import dataclasses

import pytest
from secp_worker.provisioning.provider_schema_evidence import (
    EXPECTED_SCHEMA_FORMAT_VERSION,
    SCHEMA_VALIDATION_UNVERIFIED,
    SCHEMA_VALIDATION_VERIFIED,
    IsolationProofs,
    ProviderSchemaEvidence,
    schema_validation_reasons,
    schema_validation_status,
)

_TYPES = frozenset(
    {
        "proxmox_virtual_environment_container",
        "proxmox_virtual_environment_vm",
        "proxmox_virtual_environment_firewall_rules",
    }
)


def _complete() -> ProviderSchemaEvidence:
    """A fact set in which every required step actually happened.

    The digests are obviously synthetic. That is fine and is the point of the split between this
    module and the runner: this gate's job is to require the facts, not to originate them.
    """
    return ProviderSchemaEvidence(
        opentofu_version="1.9.0",
        opentofu_executable_digest="sha256:" + "a" * 64,
        provider_source="registry.opentofu.org/bpg/proxmox",
        provider_version="0.84.1",
        provider_package_digest="sha256:" + "b" * 64,
        lockfile_digest="sha256:" + "c" * 64,
        mirror_digest="sha256:" + "d" * 64,
        rendered_workspace_hash="sha256:" + "e" * 64,
        offline_init_succeeded=True,
        configuration_validation_succeeded=True,
        schema_extraction_succeeded=True,
        schema_format_version=EXPECTED_SCHEMA_FORMAT_VERSION,
        types_required_by_rendered_modules=_TYPES,
        # The provider offers everything the modules use, and more.
        types_present_in_provider_schema=_TYPES | {"proxmox_virtual_environment_sdn_vnet"},
        isolation=IsolationProofs(
            backend_disabled=True,
            no_provider_credentials_present=True,
            network_egress_denied=True,
            no_proxmox_endpoint_configured=True,
        ),
    )


def test_a_complete_honest_fact_set_verifies():
    evidence = _complete()
    assert schema_validation_reasons(evidence) == ()
    assert schema_validation_status(evidence) == SCHEMA_VALIDATION_VERIFIED


def test_absent_evidence_is_unverified_and_says_so():
    """The default for every caller that has not run the check — which today is all of them."""
    assert schema_validation_status(None) == SCHEMA_VALIDATION_UNVERIFIED
    assert schema_validation_reasons(None) == ("no schema-validation evidence was recorded",)


@pytest.mark.parametrize(
    "field",
    [
        "opentofu_version",
        "opentofu_executable_digest",
        "provider_source",
        "provider_version",
        "provider_package_digest",
        "lockfile_digest",
        "mirror_digest",
        "rendered_workspace_hash",
    ],
)
def test_every_identity_field_is_load_bearing(field):
    """Blanking any ONE of the eight identities refuses.

    Parameterised over the fields rather than spot-checking two of them: a document that names
    seven of eight pinned artifacts is not seven-eighths of a pin, it is an unpinned toolchain with
    good paperwork.
    """
    evidence = dataclasses.replace(_complete(), **{field: "   "})
    assert schema_validation_status(evidence) == SCHEMA_VALIDATION_UNVERIFIED
    assert any(field in reason for reason in schema_validation_reasons(evidence))


@pytest.mark.parametrize(
    "field",
    ["offline_init_succeeded", "configuration_validation_succeeded", "schema_extraction_succeeded"],
)
def test_every_command_must_have_succeeded(field):
    evidence = dataclasses.replace(_complete(), **{field: False})
    assert schema_validation_status(evidence) == SCHEMA_VALIDATION_UNVERIFIED


@pytest.mark.parametrize(
    "field",
    [
        "backend_disabled",
        "no_provider_credentials_present",
        "network_egress_denied",
        "no_proxmox_endpoint_configured",
    ],
)
def test_every_isolation_proof_is_separately_required(field):
    """Four proofs, four separate failures.

    ``providers schema -json`` starts the provider plugin, so provider code runs in a child
    process. These four are what make that acceptable, and any one of them missing is enough to
    refuse — a collapsed ``isolated: bool`` would have hidden which.
    """
    evidence = _complete()
    broken = dataclasses.replace(
        evidence, isolation=dataclasses.replace(evidence.isolation, **{field: False})
    )
    assert schema_validation_status(broken) == SCHEMA_VALIDATION_UNVERIFIED
    assert any(field in reason for reason in schema_validation_reasons(broken))


def test_a_missing_provider_type_refuses_and_names_it():
    """The check the whole exercise exists for.

    A pin can satisfy every digest and still be the wrong provider version. Here the rendered
    modules need a firewall-rules type the pinned provider does not offer; the refusal names it, so
    the operator learns which resource the pin cannot build rather than discovering it at apply
    time against real infrastructure.
    """
    evidence = dataclasses.replace(
        _complete(),
        types_present_in_provider_schema=_TYPES - {"proxmox_virtual_environment_firewall_rules"},
    )
    assert schema_validation_status(evidence) == SCHEMA_VALIDATION_UNVERIFIED
    assert any(
        "proxmox_virtual_environment_firewall_rules" in reason
        for reason in schema_validation_reasons(evidence)
    )


def test_an_empty_required_set_does_not_pass_vacuously():
    """ "Nothing was required, so everything is covered" is the trap this check must not fall into.

    An empty required set means the collection step did not run or found nothing — not that the
    configuration genuinely uses no provider types, which would make the provider pointless. Set
    subtraction alone would have called this full coverage.
    """
    evidence = dataclasses.replace(
        _complete(),
        types_required_by_rendered_modules=frozenset(),
        types_present_in_provider_schema=frozenset(),
    )
    assert evidence.missing_types() == ()  # subtraction alone is satisfied ...
    assert schema_validation_status(evidence) == SCHEMA_VALIDATION_UNVERIFIED  # ... the gate is not


def test_an_unexpected_schema_format_version_refuses():
    """A format change could move the keys the coverage check reads, so it fails closed."""
    evidence = dataclasses.replace(_complete(), schema_format_version="2.0")
    assert schema_validation_status(evidence) == SCHEMA_VALIDATION_UNVERIFIED


def test_the_plan_document_derives_the_field_and_carries_the_reasons():
    """The field is no longer settable by a caller's bool: it comes from the evidence or not at
    all."""
    import inspect

    from secp_worker.provisioning.plan_document import build_plan_document

    assert "provider_schema_verified" not in inspect.signature(build_plan_document).parameters

    change_set = {"summary": {"count": 0, "by_action": {}}, "resources": [], "workspace_hash": "w"}
    desired_state = {"network": {"vnets": []}, "guests": []}

    without = build_plan_document(change_set, "hash-1", desired_state=desired_state)
    assert without["provider_schema_validation"] == SCHEMA_VALIDATION_UNVERIFIED
    assert without["provider_schema_validation_reasons"] == [
        "no schema-validation evidence was recorded"
    ]

    with_evidence = build_plan_document(
        change_set, "hash-1", desired_state=desired_state, schema_evidence=_complete()
    )
    assert with_evidence["provider_schema_validation"] == SCHEMA_VALIDATION_VERIFIED
    assert with_evidence["provider_schema_validation_reasons"] == []
