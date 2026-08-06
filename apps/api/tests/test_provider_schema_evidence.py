"""The authority split behind ``provider_schema_validation``.

The property under test is adversarial, not descriptive: a caller who is *trying* to make a plan
document say ``verified`` — with truthful-looking digests, complete facts and a cooperative test
harness — must fail unless a real attested producer minted the authority.

The first version of this gate did not have that property. It modelled the facts as one public
frozen dataclass and derived the status from them, so a fixture that filled in every field and set
four booleans produced ``verified``. That fixture was the bypass, and it lived in this file. These
tests are written to catch that class of mistake rather than to restate the happy path.

Layer 1 (observation) is exercised for its REASONS. Layer 2 (attestation) is exercised for its
REFUSALS.
"""

from __future__ import annotations

import copy
import dataclasses
import pickle

import pytest
from secp_worker.provisioning.provider_schema_evidence import (
    EXPECTED_SCHEMA_FORMAT_VERSION,
    REVIEWED_COMMAND_SEQUENCE,
    SCHEMA_VALIDATION_UNVERIFIED,
    SCHEMA_VALIDATION_VERIFIED,
    IsolationObservations,
    ProviderSchemaAttestation,
    ProviderSchemaAttestationRefused,
    ProviderSchemaObservation,
    SchemaAttestationBinding,
    issue_provider_schema_attestation,
    schema_validation_reasons,
    schema_validation_status,
)

_EXEC_ID = "secp-002b-1b-pr5b/plan-only-executor/v3"
_EXEC_DIGEST = "sha256:" + "f" * 64
_WORKSPACE = "sha256:" + "e" * 64

_TYPES = frozenset(
    {
        "proxmox_virtual_environment_sdn_vnet",
        "proxmox_virtual_environment_vm",
        "proxmox_virtual_environment_container",
    }
)

_PROVEN = IsolationObservations(
    backend_disabled=True,
    no_provider_credentials_present=True,
    network_egress_denied=True,
    no_proxmox_endpoint_configured=True,
)


def _observation(**overrides) -> ProviderSchemaObservation:
    """A COMPLETE observation — every step happened. Still authorises nothing on its own."""
    base = dict(
        opentofu_version="1.12.5",
        opentofu_executable_digest="sha256:" + "a" * 64,
        provider_source="registry.opentofu.org/bpg/proxmox",
        provider_version="0.111.1",
        provider_package_digest="sha256:" + "b" * 64,
        lockfile_digest="sha256:" + "c" * 64,
        mirror_digest="sha256:" + "d" * 64,
        rendered_workspace_hash=_WORKSPACE,
        offline_init_succeeded=True,
        configuration_validation_succeeded=True,
        schema_extraction_succeeded=True,
        schema_format_version=EXPECTED_SCHEMA_FORMAT_VERSION,
        types_required_by_rendered_modules=_TYPES,
        types_present_in_provider_schema=_TYPES | {"proxmox_virtual_environment_firewall_ipset"},
        isolation=_PROVEN,
    )
    base.update(overrides)
    return ProviderSchemaObservation(**base)


def _binding(observation: ProviderSchemaObservation, **overrides) -> SchemaAttestationBinding:
    base = dict(
        executor_implementation_id=_EXEC_ID,
        executor_implementation_digest=_EXEC_DIGEST,
        opentofu_version=observation.opentofu_version,
        opentofu_executable_digest=observation.opentofu_executable_digest,
        provider_source=observation.provider_source,
        provider_version=observation.provider_version,
        provider_package_digest=observation.provider_package_digest,
        lockfile_digest=observation.lockfile_digest,
        mirror_digest=observation.mirror_digest,
        rendered_workspace_hash=observation.rendered_workspace_hash,
        command_sequence=REVIEWED_COMMAND_SEQUENCE,
        command_result_digests=("sha256:1", "sha256:2", "sha256:3"),
        schema_format_version=observation.schema_format_version,
        types_required_by_rendered_modules=observation.types_required_by_rendered_modules,
        types_present_in_provider_schema=observation.types_present_in_provider_schema,
        isolation=observation.isolation,
    )
    base.update(overrides)
    return SchemaAttestationBinding(**base)


def _mint(observation=None, **binding_overrides) -> ProviderSchemaAttestation:
    """Mint through the PRIVATE token, standing in for the producer that does not exist yet.

    Importing the private token here is deliberate and is the same thing the plan-only capability
    tests do. ``test_provider_schema_authority.py`` asserts no SHIPPED module does it, which is what
    keeps the containment real rather than notional.
    """
    from secp_worker.provisioning.provider_schema_evidence import _SCHEMA_ATTESTATION_TOKEN

    obs = observation if observation is not None else _observation()
    return issue_provider_schema_attestation(
        _SCHEMA_ATTESTATION_TOKEN,
        _binding(obs, **binding_overrides),
        observation=obs,
        expected_executor_implementation_id=_EXEC_ID,
        expected_executor_implementation_digest=_EXEC_DIGEST,
    )


def _status(attestation, observation=None, **overrides) -> str:
    kwargs = dict(
        expected_workspace_hash=_WORKSPACE,
        expected_executor_implementation_id=_EXEC_ID,
        expected_executor_implementation_digest=_EXEC_DIGEST,
    )
    kwargs.update(overrides)
    return schema_validation_status(attestation, observation, **kwargs)


def _reasons(attestation, observation=None, **overrides) -> tuple[str, ...]:
    kwargs = dict(
        expected_workspace_hash=_WORKSPACE,
        expected_executor_implementation_id=_EXEC_ID,
        expected_executor_implementation_digest=_EXEC_DIGEST,
    )
    kwargs.update(overrides)
    return schema_validation_reasons(attestation, observation, **kwargs)


# --- the bypass this restructure exists to close --------------------------------------------------


def test_a_fully_truthful_public_fact_object_still_cannot_verify():
    """THE regression test for the original defect.

    Every fact is present, every command succeeded, every isolation property is observed, the type
    coverage is complete — a caller doing everything right except actually running the toolchain.
    The answer is still ``unverified``, because an observation is a record and not an authority.
    """
    observation = _observation()
    assert observation.reasons() == ()  # nothing about the RECORD is deficient ...
    assert _status(None, observation) == SCHEMA_VALIDATION_UNVERIFIED  # ... and it still cannot
    assert _reasons(None, observation) == (
        "a complete observation was recorded but no attestation was minted for it",
    )


@pytest.mark.parametrize(
    "impostor",
    [
        {"binding": "anything"},
        dataclasses.make_dataclass("FakeAttestation", [("binding", object)])(binding=None),
        object(),
        "sha256:looks-official",
    ],
    ids=["dict", "lookalike_dataclass", "bare_object", "string"],
)
def test_an_authority_lookalike_is_refused_by_type(impostor):
    """Duck typing is the obvious hole: anything with a ``.binding`` would otherwise be read."""
    assert _status(impostor) == SCHEMA_VALIDATION_UNVERIFIED
    assert _reasons(impostor)[0].startswith(
        "schema-validation authority was offered by something that is not an attestation"
    )


def test_the_attestation_cannot_be_constructed_without_the_private_token():
    with pytest.raises(TypeError, match="cannot be constructed directly"):
        ProviderSchemaAttestation(object(), _binding(_observation()))


def test_minting_refuses_a_caller_without_the_private_token():
    observation = _observation()
    with pytest.raises(ProviderSchemaAttestationRefused, match="only the attested"):
        issue_provider_schema_attestation(
            object(),
            _binding(observation),
            observation=observation,
            expected_executor_implementation_id=_EXEC_ID,
            expected_executor_implementation_digest=_EXEC_DIGEST,
        )


# --- a real attestation verifies, and only for what it was minted for -----------------------------


def test_a_minted_attestation_verifies_its_own_plan():
    """A gate that never opens is not a gate."""
    assert _status(_mint()) == SCHEMA_VALIDATION_VERIFIED
    assert _reasons(_mint()) == ()


def test_an_attestation_minted_for_another_plan_cannot_verify_this_one():
    """The non-transferability property, stated as the scenario it prevents: a plan that WAS
    validated is approved, and its attestation is then offered for a different rendered
    workspace."""
    other = _observation(rendered_workspace_hash="sha256:" + "9" * 64)
    attestation = _mint(other)
    assert _status(attestation) == SCHEMA_VALIDATION_UNVERIFIED
    assert any("different rendered workspace" in r for r in _reasons(attestation))


def test_an_attestation_cannot_be_copied_at_all():
    """Copy-then-edit is the obvious forgery, and it does not get as far as the edit.

    ``copy.copy`` and ``copy.deepcopy`` both route through ``__reduce_ex__`` for this object, which
    is refused — so the serialization refusal is doing more work than "you cannot write it to a
    file". Asserted here rather than assumed, because the reverse (a slots object that copies
    without ``__reduce_ex__``) is equally plausible and would have made this a silent hole.
    """
    attestation = _mint()
    with pytest.raises(TypeError, match="cannot be pickled"):
        copy.deepcopy(attestation)
    with pytest.raises(TypeError, match="cannot be pickled"):
        copy.copy(attestation)


def test_an_in_place_edited_binding_still_fails_at_read():
    """The forgery that copying cannot reach: mutate the private slot directly.

    This is the belt to the serialization refusal's braces. Even with full access to the object's
    internals, the binding is re-checked against the plan at READ time, so an edited workspace hash
    is refused rather than believed.
    """
    attestation = _mint()
    object.__setattr__(
        attestation,
        "_ProviderSchemaAttestation__binding",
        dataclasses.replace(attestation.binding, rendered_workspace_hash="sha256:" + "0" * 64),
    )
    assert _status(attestation) == SCHEMA_VALIDATION_UNVERIFIED
    assert any("different rendered workspace" in r for r in _reasons(attestation))


@pytest.mark.parametrize(
    "field,value",
    [
        ("provider_version", "0.66.1"),
        ("provider_package_digest", "sha256:" + "0" * 64),
        ("opentofu_executable_digest", "sha256:" + "0" * 64),
        ("opentofu_version", "1.12.4"),
        ("lockfile_digest", "sha256:" + "0" * 64),
        ("mirror_digest", "sha256:" + "0" * 64),
    ],
)
def test_a_toolchain_fact_cannot_be_changed_and_re_minted(field, value):
    """An attestation is a claim about a specific toolchain, and it may not exceed its own record.

    ``provider_version="0.66.1"`` is the real case rather than a synthetic one: that is the version
    pinned in ``proxmox_bundle.py`` today, and it is reported not to contain the SDN resource types
    this repository renders.
    """
    from secp_worker.provisioning.provider_schema_evidence import _SCHEMA_ATTESTATION_TOKEN

    observation = _observation()
    with pytest.raises(ProviderSchemaAttestationRefused, match="disagrees with the observation"):
        issue_provider_schema_attestation(
            _SCHEMA_ATTESTATION_TOKEN,
            _binding(observation, **{field: value}),
            observation=observation,
            expected_executor_implementation_id=_EXEC_ID,
            expected_executor_implementation_digest=_EXEC_DIGEST,
        )


def test_a_stale_executor_identity_fails_at_mint_and_at_read():
    """Both ends, because either alone leaves a hole.

    Mint-time only would let an attestation outlive a later grammar change; read-time only would let
    a producer mint against a boundary that never existed.
    """
    from secp_worker.provisioning.provider_schema_evidence import _SCHEMA_ATTESTATION_TOKEN

    observation = _observation()
    stale = "secp-002b-1b-pr5b/plan-only-executor/v2"

    with pytest.raises(ProviderSchemaAttestationRefused, match="executor implementation id"):
        issue_provider_schema_attestation(
            _SCHEMA_ATTESTATION_TOKEN,
            _binding(observation, executor_implementation_id=stale),
            observation=observation,
            expected_executor_implementation_id=_EXEC_ID,
            expected_executor_implementation_digest=_EXEC_DIGEST,
        )

    # Minted honestly against v2's identity, then offered to a v3 document.
    v2_attestation = issue_provider_schema_attestation(
        _SCHEMA_ATTESTATION_TOKEN,
        _binding(observation, executor_implementation_id=stale),
        observation=observation,
        expected_executor_implementation_id=stale,
        expected_executor_implementation_digest=_EXEC_DIGEST,
    )
    assert _status(v2_attestation) == SCHEMA_VALIDATION_UNVERIFIED
    assert any("different executor implementation id" in r for r in _reasons(v2_attestation))


def test_a_stale_executor_digest_fails_at_read():
    attestation = _mint()
    assert (
        _status(attestation, expected_executor_implementation_digest="sha256:" + "0" * 64)
        == SCHEMA_VALIDATION_UNVERIFIED
    )


def test_serialization_cannot_manufacture_authority():
    """Pickling is refused rather than unimplemented: a picklable authority object is a file, and a
    file can be produced by something other than the run it describes."""
    attestation = _mint()
    with pytest.raises(TypeError, match="cannot be pickled"):
        pickle.dumps(attestation)
    with pytest.raises(TypeError, match="cannot be serialized"):
        attestation.__getstate__()
    assert "redacted" in repr(attestation)
    assert "redacted" in f"{attestation}"


# --- minting refuses anything short of a complete, agreeing run -----------------------------------


def test_minting_refuses_an_incomplete_observation():
    from secp_worker.provisioning.provider_schema_evidence import _SCHEMA_ATTESTATION_TOKEN

    observation = _observation(configuration_validation_succeeded=False)
    with pytest.raises(ProviderSchemaAttestationRefused, match="observation is incomplete"):
        issue_provider_schema_attestation(
            _SCHEMA_ATTESTATION_TOKEN,
            _binding(observation),
            observation=observation,
            expected_executor_implementation_id=_EXEC_ID,
            expected_executor_implementation_digest=_EXEC_DIGEST,
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"command_sequence": ("init", "plan", "show")},
        {"command_sequence": ("validate", "providers")},
        {"command_result_digests": ("sha256:1", "sha256:2")},
        {"command_result_digests": ("sha256:1", "  ", "sha256:3")},
    ],
    ids=["wrong_sequence", "short_sequence", "too_few_results", "blank_result"],
)
def test_minting_refuses_a_command_record_that_does_not_match_the_reviewed_sequence(overrides):
    from secp_worker.provisioning.provider_schema_evidence import _SCHEMA_ATTESTATION_TOKEN

    observation = _observation()
    with pytest.raises(ProviderSchemaAttestationRefused):
        issue_provider_schema_attestation(
            _SCHEMA_ATTESTATION_TOKEN,
            _binding(observation, **overrides),
            observation=observation,
            expected_executor_implementation_id=_EXEC_ID,
            expected_executor_implementation_digest=_EXEC_DIGEST,
        )


# --- layer 1 still gives an operator something to act on ------------------------------------------


def test_absent_evidence_says_so():
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
def test_every_identity_field_is_load_bearing_in_the_observation(field):
    """A document naming seven of eight pinned artifacts is not seven-eighths of a pin."""
    observation = _observation(**{field: "   "})
    assert any(field in reason for reason in observation.reasons())


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
    observation = _observation(isolation=dataclasses.replace(_PROVEN, **{field: False}))
    assert any(field in reason for reason in observation.reasons())


def test_isolation_observations_default_to_unproven():
    """An unobserved isolation property is not isolation, so the defaults must be ``False``."""
    assert IsolationObservations().unmet() == (
        "backend_disabled",
        "no_provider_credentials_present",
        "network_egress_denied",
        "no_proxmox_endpoint_configured",
    )


def test_a_missing_provider_type_is_named():
    """The check the whole exercise exists for, using a type the current 0.66.1 pin is reported to
    lack."""
    observation = _observation(
        types_present_in_provider_schema=_TYPES - {"proxmox_virtual_environment_sdn_vnet"}
    )
    assert any("proxmox_virtual_environment_sdn_vnet" in reason for reason in observation.reasons())


def test_a_missing_type_survives_into_the_gate():
    """Not only the observation: an attestation carrying the same gap must not verify either.

    Minted through the private token with a deliberately narrowed schema, so this exercises the
    gate's own coverage check rather than the observation's.
    """
    from secp_worker.provisioning.provider_schema_evidence import _SCHEMA_ATTESTATION_TOKEN

    observation = _observation()
    gapped = _binding(
        observation,
        types_present_in_provider_schema=_TYPES - {"proxmox_virtual_environment_sdn_vnet"},
    )
    # Minting refuses it first, which is the earlier and better refusal ...
    with pytest.raises(ProviderSchemaAttestationRefused):
        issue_provider_schema_attestation(
            _SCHEMA_ATTESTATION_TOKEN,
            gapped,
            observation=observation,
            expected_executor_implementation_id=_EXEC_ID,
            expected_executor_implementation_digest=_EXEC_DIGEST,
        )
    # ... and if one were minted anyway, the read-time check still refuses.
    forged = _mint()
    object.__setattr__(forged, "_ProviderSchemaAttestation__binding", gapped)
    assert _status(forged) == SCHEMA_VALIDATION_UNVERIFIED
    assert any("missing types the rendered modules use" in r for r in _reasons(forged))


def test_an_empty_required_set_does_not_pass_vacuously():
    """ "Nothing was required, so everything is covered" is the trap set subtraction walks into."""
    observation = _observation(
        types_required_by_rendered_modules=frozenset(),
        types_present_in_provider_schema=frozenset(),
    )
    assert observation.missing_types() == ()  # subtraction alone is satisfied ...
    assert any("no provider types were collected" in r for r in observation.reasons())  # gate isn't


def test_an_unexpected_schema_format_version_is_a_reason():
    assert any("format version" in r for r in _observation(schema_format_version="2.0").reasons())


# --- the plan document reads the gate, not a caller's word ----------------------------------------


def _change_set() -> dict:
    return {
        "summary": {"count": 0, "by_action": {}},
        "resources": [],
        "workspace_hash": _WORKSPACE,
    }


def test_the_plan_document_cannot_be_told_the_answer():
    import inspect

    from secp_worker.provisioning.plan_document import build_plan_document

    params = inspect.signature(build_plan_document).parameters
    assert "provider_schema_verified" not in params

    desired_state = {"network": {"vnets": []}, "guests": []}

    # No evidence at all.
    bare = build_plan_document(_change_set(), "h", desired_state=desired_state)
    assert bare["provider_schema_validation"] == SCHEMA_VALIDATION_UNVERIFIED
    assert bare["provider_schema_validation_reasons"] == [
        "no schema-validation evidence was recorded"
    ]

    # A complete public observation — the original bypass — still cannot.
    observed = build_plan_document(
        _change_set(), "h", desired_state=desired_state, schema_observation=_observation()
    )
    assert observed["provider_schema_validation"] == SCHEMA_VALIDATION_UNVERIFIED

    # A real attestation, for this workspace, under this executor identity.
    verified = build_plan_document(
        _change_set(),
        "h",
        desired_state=desired_state,
        schema_attestation=_mint(),
        expected_executor_implementation_id=_EXEC_ID,
        expected_executor_implementation_digest=_EXEC_DIGEST,
    )
    assert verified["provider_schema_validation"] == SCHEMA_VALIDATION_VERIFIED
    assert verified["provider_schema_validation_reasons"] == []


def test_the_plan_document_refuses_an_attestation_for_a_different_workspace():
    from secp_worker.provisioning.plan_document import build_plan_document

    other = _change_set()
    other["workspace_hash"] = "sha256:" + "7" * 64
    document = build_plan_document(
        other,
        "h",
        desired_state={"network": {"vnets": []}, "guests": []},
        schema_attestation=_mint(),
        expected_executor_implementation_id=_EXEC_ID,
        expected_executor_implementation_digest=_EXEC_DIGEST,
    )
    assert document["provider_schema_validation"] == SCHEMA_VALIDATION_UNVERIFIED
    assert any(
        "different rendered workspace" in r for r in document["provider_schema_validation_reasons"]
    )


#: The exact top-level members `secp-proxmox/plan-document/v1` carried before this change,
#: transcribed from ``origin/main``. Pinned here rather than recomputed, so that this test is a
#: second, independent source of truth about the v1 shape rather than a restatement of the code it
#: is checking.
_V1_MEMBERS = frozenset(
    {
        "plan_document_version",
        "execution_status",
        "approval_starts_apply",
        "change_set_hash",
        "desired_state_hash",
        "change_set_version",
        "workspace_hash",
        "kind",
        "provenance",
        "provider_schema_validation",
        "summary",
        "resources",
        "segments",
        "guests",
        "egress",
        # Added after the dict literal rather than inside it, because it hashes the document it
        # belongs to. Transcribing this list by reading the literal alone misses it — which this
        # test caught on its first run, and is the reason the pin is worth having.
        "plan_document_hash",
    }
)


def test_the_change_is_additive_so_v1_readers_still_read_v1():
    """The compatibility claim behind leaving ``PLAN_DOCUMENT_VERSION`` at v1, made checkable.

    ``provider_schema_validation_reasons`` IS a new document member — a consumer-visible addition,
    not an internal detail. What makes keeping v1 correct is that the change is purely additive
    under the document's additive-field policy: no v1 member is removed or renamed, and
    ``provider_schema_validation`` keeps the same two-value domain. A v1 reader that ignores
    unknown members reads exactly what it read before.

    This is the test that would go red if a later change quietly dropped or renamed a v1 member
    while leaving the version literal alone.
    """
    from secp_worker.provisioning.plan_document import PLAN_DOCUMENT_VERSION, build_plan_document

    document = build_plan_document(
        _change_set(), "h", desired_state={"network": {"vnets": []}, "guests": []}
    )

    assert (
        document["plan_document_version"]
        == PLAN_DOCUMENT_VERSION
        == "secp-proxmox/plan-document/v1"
    )

    removed = _V1_MEMBERS - set(document)
    assert removed == set(), f"v1 members disappeared without a version bump: {sorted(removed)}"

    added = set(document) - _V1_MEMBERS
    assert added == {"provider_schema_validation_reasons"}, (
        "a member was added beyond the reviewed additive one; additive compatibility is a claim "
        f"about the whole document, not about one field: {sorted(added)}"
    )

    # The status field's value domain is unchanged — the other half of "a v1 reader reads what it
    # read before". A reader switching on these two literals still terminates.
    assert document["provider_schema_validation"] in {
        SCHEMA_VALIDATION_VERIFIED,
        SCHEMA_VALIDATION_UNVERIFIED,
    }


def test_a_v1_reader_that_ignores_unknown_members_is_unaffected():
    """Simulates the actual consumer contract rather than asserting it in prose.

    A v1 reader projects the members it knows about. The projection of the new document must equal
    the projection of one built with the field absent — which is the operational meaning of
    "existing readers may ignore the field".
    """
    from secp_worker.provisioning.plan_document import build_plan_document

    desired_state = {"network": {"vnets": []}, "guests": []}
    new_document = build_plan_document(_change_set(), "h", desired_state=desired_state)
    v1_projection = {k: v for k, v in new_document.items() if k in _V1_MEMBERS}

    with_attestation = build_plan_document(
        _change_set(),
        "h",
        desired_state=desired_state,
        schema_attestation=_mint(),
        expected_executor_implementation_id=_EXEC_ID,
        expected_executor_implementation_digest=_EXEC_DIGEST,
    )
    other_projection = {k: v for k, v in with_attestation.items() if k in _V1_MEMBERS}

    # Same members, same types; only the status VALUE differs, which is the field doing its job.
    assert set(v1_projection) == set(other_projection) == _V1_MEMBERS
    assert v1_projection["provider_schema_validation"] == SCHEMA_VALIDATION_UNVERIFIED
    assert other_projection["provider_schema_validation"] == SCHEMA_VALIDATION_VERIFIED


def test_the_plan_document_refuses_an_attestation_when_no_identity_is_supplied():
    """Omitting the expected identity must fail CLOSED rather than skip the check."""
    from secp_worker.provisioning.plan_document import build_plan_document

    document = build_plan_document(
        _change_set(),
        "h",
        desired_state={"network": {"vnets": []}, "guests": []},
        schema_attestation=_mint(),
    )
    assert document["provider_schema_validation"] == SCHEMA_VALIDATION_UNVERIFIED
