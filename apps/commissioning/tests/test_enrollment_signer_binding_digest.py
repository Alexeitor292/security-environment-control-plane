"""The plane-neutral enrollment-signer BINDING DIGESTS (SECP-PR5H-B2, 2b-3c-c, Defect-3 E).

Defect-3 E: the readiness surface published every RAW installation identifier it held, so any peer
that reached it learned the install's complete public identity. The management observer never needed
those values — it holds them independently — it only needs to know whether the API's view AGREES.
This module is the ONE definition of that comparison, imported by BOTH planes.

This suite proves the properties the comparison rests on:

* DOMAIN SEPARATION — the two digests embed their own versioned schema literal, so the identical
  field payload digests differently under each domain and a token minted for one can never be
  replayed as the other;
* COMPLETENESS — the marker digest covers the marker contract's COMPLETE binding field set (it is
  imported, never re-listed, so it cannot silently narrow to a subset);
* SENSITIVITY — changing ANY covered field changes the digest;
* STABILITY — the same inputs digest identically across calls, argument orders and call styles, so
  two independently computed digests can be compared for equality;
* MINIMIZATION — a digest discloses none of its inputs;
* STRICTNESS — an absent, wrongly typed, empty, oversized or bool-as-uid input is a bounded refusal,
  never a plausible-looking token.
"""

from __future__ import annotations

import pytest
from secp_commissioning.canonical import canonical_json, is_sha256_digest, sha256_digest
from secp_commissioning.controller_enrollment_signer import ENROLLMENT_SIGNER_SOCKET_PATH
from secp_commissioning.enrollment_signer_binding_digest import (
    ACTIVE_IDENTITY_BINDING_DIGEST_FIELDS,
    ENROLLMENT_SIGNER_ACTIVE_IDENTITY_BINDING_DIGEST_SCHEMA,
    ENROLLMENT_SIGNER_MARKER_BINDING_DIGEST_SCHEMA,
    ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH,
    ENROLLMENT_SIGNER_READINESS_GATE_FILE_BYTES,
    ENROLLMENT_SIGNER_READINESS_GATE_HEADER,
    ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH,
    MARKER_BINDING_DIGEST_FIELDS,
    EnrollmentSignerBindingDigestError,
    _binding_digest,
    active_identity_binding_digest,
    marker_binding_digest,
    marker_binding_digest_for,
)
from secp_commissioning.enrollment_signer_marker import (
    ENROLLMENT_SIGNER_MARKER_BINDING_FIELDS,
    build_marker,
)
from secp_commissioning.enrollment_signer_role import ENROLLMENT_SIGNER_DB_ROLE

_ROW_ID = "0f2a5f6c-1111-4222-8333-444455556666"
_TOKEN = f"{_ROW_ID}|2026-07-28 00:00:00+00:00"
_INSTALL = "controller-a0000001"
_RELEASE = "sha256:" + "1" * 64
_KEY_ID = "sha256:" + "2" * 64
_MGMT = "sha256:" + "3" * 64
_BOOTSTRAP = "sha256:" + "4" * 64
_CA = "sha256:" + "5" * 64

_MARKER_BINDING: dict[str, object] = {
    "installation_id": _INSTALL,
    "release_digest": _RELEASE,
    "active_identity_row_id": _ROW_ID,
    "activation_token": _TOKEN,
    "controller_key_id": _KEY_ID,
    "management_identity_digest": _MGMT,
    "bootstrap_evidence_digest": _BOOTSTRAP,
    "api_uid": 10001,
    "api_gid": 10001,
    "signer_role_name": ENROLLMENT_SIGNER_DB_ROLE,
    "uds_contract_identity": ENROLLMENT_SIGNER_SOCKET_PATH,
    "locator_ca_digest": _CA,
}

_IDENTITY_BINDING: dict[str, object] = {
    "active_identity_row_id": _ROW_ID,
    "activation_token": _TOKEN,
    "installation_id": _INSTALL,
    "release_digest": _RELEASE,
    "controller_key_id": _KEY_ID,
}


def _marker():
    return build_marker(recorded_at="2026-07-28T00:00:00Z", **_MARKER_BINDING)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- the closed contract


def test_the_marker_digest_covers_the_complete_binding_never_a_subset() -> None:
    """The field set is IMPORTED from the marker contract, so a digest can never drift into
    covering fewer fields than a consumer is required to compare."""
    assert MARKER_BINDING_DIGEST_FIELDS == ENROLLMENT_SIGNER_MARKER_BINDING_FIELDS
    assert len(MARKER_BINDING_DIGEST_FIELDS) == 12
    assert set(_MARKER_BINDING) == set(MARKER_BINDING_DIGEST_FIELDS)


def test_the_active_identity_digest_field_set_is_closed() -> None:
    assert ACTIVE_IDENTITY_BINDING_DIGEST_FIELDS == (
        "active_identity_row_id",
        "activation_token",
        "installation_id",
        "release_digest",
        "controller_key_id",
    )
    assert set(_IDENTITY_BINDING) == set(ACTIVE_IDENTITY_BINDING_DIGEST_FIELDS)


def test_the_schema_literals_are_exported_and_pinned() -> None:
    """Both planes pin these exact strings; a version bump is a deliberate, visible break."""
    assert ENROLLMENT_SIGNER_MARKER_BINDING_DIGEST_SCHEMA == (
        "secp.enrollment-signer-marker-binding-digest/v1"
    )
    assert ENROLLMENT_SIGNER_ACTIVE_IDENTITY_BINDING_DIGEST_SCHEMA == (
        "secp.enrollment-signer-active-identity-binding-digest/v1"
    )


def test_the_readiness_gate_transport_constants_are_plane_neutral() -> None:
    """The management writer needs these and may never import ``secp_api``, so they live here."""
    assert ENROLLMENT_SIGNER_READINESS_GATE_HEADER == "X-SECP-Enrollment-Signer-Readiness-Gate"
    assert ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH == (
        "/etc/secp/controller/enrollment-signer-readiness-gate.secret"
    )
    assert ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH == (
        "/run/secp/enrollment-signer-readiness-gate.secret"
    )
    assert ENROLLMENT_SIGNER_READINESS_GATE_FILE_BYTES == 65
    # distinct from the worker-admission proxy gate, which this plane also never imports
    assert "admission" not in ENROLLMENT_SIGNER_READINESS_GATE_HEADER.lower()
    assert ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH != (
        ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH
    )


def test_the_module_imports_neither_plane() -> None:
    """Plane-neutral by construction: BOTH planes import this rule, so it may import neither."""
    import ast

    import secp_commissioning.enrollment_signer_binding_digest as module

    source = module.__file__
    assert source is not None
    with open(source, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert not any(name.split(".")[0] in {"secp_api", "secp_management"} for name in imported)
    # and nothing that could reach a filesystem, a socket, or a subprocess
    assert not any(
        name.split(".")[0] in {"os", "socket", "subprocess", "pathlib"} for name in imported
    )


# --------------------------------------------------------------------------- domain separation


def test_the_two_domains_digest_the_same_payload_differently() -> None:
    """The strict domain-separation property, on the shared rule itself: identical fields, different
    schema literal -> different digest. Neither domain's token can be replayed as the other."""
    fields = {"a": "1", "b": "2"}
    marker_domain = _binding_digest(ENROLLMENT_SIGNER_MARKER_BINDING_DIGEST_SCHEMA, fields)
    identity_domain = _binding_digest(
        ENROLLMENT_SIGNER_ACTIVE_IDENTITY_BINDING_DIGEST_SCHEMA, fields
    )
    assert marker_domain != identity_domain
    assert is_sha256_digest(marker_domain) and is_sha256_digest(identity_domain)


def test_a_consistent_install_yields_two_different_digests() -> None:
    """The same install, digested under both domains — the five shared facts do not collapse the
    two tokens into one."""
    marker = marker_binding_digest(**_MARKER_BINDING)  # type: ignore[arg-type]
    identity = active_identity_binding_digest(**_IDENTITY_BINDING)  # type: ignore[arg-type]
    assert marker != identity
    assert is_sha256_digest(marker) and is_sha256_digest(identity)


def test_the_domain_separator_cannot_be_displaced_by_a_payload_field() -> None:
    """Belt and braces on top of the closed field set: even a payload carrying its own ``schema``
    key cannot override the code-owned domain literal."""
    assert _binding_digest(
        ENROLLMENT_SIGNER_MARKER_BINDING_DIGEST_SCHEMA,
        {"schema": ENROLLMENT_SIGNER_ACTIVE_IDENTITY_BINDING_DIGEST_SCHEMA},
    ) == _binding_digest(ENROLLMENT_SIGNER_MARKER_BINDING_DIGEST_SCHEMA, {})


def test_the_schema_literal_is_inside_the_digested_object() -> None:
    """Not merely a prefix or a comment: the domain separator is part of the canonical preimage."""
    assert marker_binding_digest(**_MARKER_BINDING) == sha256_digest(  # type: ignore[arg-type]
        {"schema": ENROLLMENT_SIGNER_MARKER_BINDING_DIGEST_SCHEMA, **_MARKER_BINDING}
    )
    assert active_identity_binding_digest(**_IDENTITY_BINDING) == sha256_digest(  # type: ignore[arg-type]
        {"schema": ENROLLMENT_SIGNER_ACTIVE_IDENTITY_BINDING_DIGEST_SCHEMA, **_IDENTITY_BINDING}
    )


# --------------------------------------------------------------------------- stability


def test_the_digests_are_stable_across_calls_and_argument_order() -> None:
    """Two independently computed digests are compared for EQUALITY, so the rule must be
    order-independent and repeatable — otherwise the comparison would false-negative."""
    reordered = dict(reversed(list(_MARKER_BINDING.items())))
    assert marker_binding_digest(**_MARKER_BINDING) == marker_binding_digest(**reordered)  # type: ignore[arg-type]
    assert marker_binding_digest(**_MARKER_BINDING) == marker_binding_digest(**_MARKER_BINDING)  # type: ignore[arg-type]
    assert active_identity_binding_digest(**_IDENTITY_BINDING) == active_identity_binding_digest(  # type: ignore[arg-type]
        **_IDENTITY_BINDING  # type: ignore[arg-type]
    )


def test_the_parsed_marker_and_the_explicit_fields_agree() -> None:
    """The API digests the PARSED marker model; management digests its own candidate binding. Both
    entry points must produce the identical token or the comparison is meaningless."""
    assert marker_binding_digest_for(_marker()) == marker_binding_digest(**_MARKER_BINDING)  # type: ignore[arg-type]


def test_any_object_carrying_the_binding_attributes_is_accepted() -> None:
    """Management passes its OWN candidate-binding object, not a parsed marker."""

    class _Candidate:
        pass

    candidate = _Candidate()
    for field, value in _MARKER_BINDING.items():
        setattr(candidate, field, value)
    assert marker_binding_digest_for(candidate) == marker_binding_digest(**_MARKER_BINDING)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- sensitivity


@pytest.mark.parametrize("field", MARKER_BINDING_DIGEST_FIELDS)
def test_changing_any_marker_binding_field_changes_the_digest(field: str) -> None:
    baseline = marker_binding_digest(**_MARKER_BINDING)  # type: ignore[arg-type]
    current = _MARKER_BINDING[field]
    changed = current + 1 if isinstance(current, int) else f"{current}-drift"
    drifted = marker_binding_digest(**{**_MARKER_BINDING, field: changed})  # type: ignore[arg-type]
    assert drifted != baseline


@pytest.mark.parametrize("field", ACTIVE_IDENTITY_BINDING_DIGEST_FIELDS)
def test_changing_any_identity_binding_field_changes_the_digest(field: str) -> None:
    baseline = active_identity_binding_digest(**_IDENTITY_BINDING)  # type: ignore[arg-type]
    drifted = active_identity_binding_digest(  # type: ignore[arg-type]
        **{**_IDENTITY_BINDING, field: f"{_IDENTITY_BINDING[field]}-drift"}
    )
    assert drifted != baseline


def test_a_field_value_cannot_be_shifted_between_neighbouring_fields() -> None:
    """Canonical JSON keys the values to their field NAMES, so swapping two equal-typed fields is a
    different preimage — a digest can never be satisfied by a rearranged binding."""
    swapped = {
        **_MARKER_BINDING,
        "management_identity_digest": _BOOTSTRAP,
        "bootstrap_evidence_digest": _MGMT,
    }
    assert marker_binding_digest(**swapped) != marker_binding_digest(**_MARKER_BINDING)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- minimization


def test_a_digest_discloses_none_of_its_inputs() -> None:
    marker = marker_binding_digest(**_MARKER_BINDING)  # type: ignore[arg-type]
    identity = active_identity_binding_digest(**_IDENTITY_BINDING)  # type: ignore[arg-type]
    for token in marker, identity:
        assert token.startswith("sha256:") and len(token) == 71
        for value in _MARKER_BINDING.values():
            assert str(value) not in token
        assert ENROLLMENT_SIGNER_SOCKET_PATH not in token
        assert ENROLLMENT_SIGNER_DB_ROLE not in token


# --------------------------------------------------------------------------- strictness


@pytest.mark.parametrize(
    "field",
    ["installation_id", "release_digest", "signer_role_name", "activation_token"],
)
@pytest.mark.parametrize("bad", [None, 1, True, b"bytes", "", "x" * 129, ["list"]])
def test_a_malformed_string_field_refuses(field: str, bad: object) -> None:
    with pytest.raises(EnrollmentSignerBindingDigestError) as exc:
        marker_binding_digest(**{**_MARKER_BINDING, field: bad})  # type: ignore[arg-type]
    assert str(exc.value) == f"enrollment_signer_binding_digest_field_invalid:{field}"


@pytest.mark.parametrize("field", ["api_uid", "api_gid"])
@pytest.mark.parametrize("bad", [None, "10001", 0, -1, True, 2**31, 1.0])
def test_a_malformed_posix_id_refuses(field: str, bad: object) -> None:
    """``True`` is never a uid (bool is an int subclass) and root (0) is never the enabled API
    peer — both are refused rather than silently digested."""
    with pytest.raises(EnrollmentSignerBindingDigestError) as exc:
        marker_binding_digest(**{**_MARKER_BINDING, field: bad})  # type: ignore[arg-type]
    assert str(exc.value) == f"enrollment_signer_binding_digest_field_invalid:{field}"


@pytest.mark.parametrize("field", MARKER_BINDING_DIGEST_FIELDS)
def test_an_object_missing_a_binding_attribute_refuses(field: str) -> None:
    class _Partial:
        pass

    candidate = _Partial()
    for name, value in _MARKER_BINDING.items():
        if name != field:
            setattr(candidate, name, value)
    with pytest.raises(EnrollmentSignerBindingDigestError) as exc:
        marker_binding_digest_for(candidate)
    assert str(exc.value) == f"enrollment_signer_binding_digest_field_missing:{field}"


def test_a_refusal_never_echoes_a_field_value() -> None:
    with pytest.raises(EnrollmentSignerBindingDigestError) as exc:
        marker_binding_digest(**{**_MARKER_BINDING, "installation_id": "x" * 400})  # type: ignore[arg-type]
    rendered = f"{exc.value!r} {exc.value} {exc.value.args!r}"
    assert "x" * 400 not in rendered
    assert rendered.count("x") < 10  # only the code-owned field name survives


def test_the_preimage_is_canonical_json() -> None:
    """The digest is over the canonical rendering both planes already use, so two hosts and two
    Python processes cannot disagree about the bytes."""
    preimage = canonical_json(
        {"schema": ENROLLMENT_SIGNER_MARKER_BINDING_DIGEST_SCHEMA, **_MARKER_BINDING}
    )
    assert preimage == canonical_json(
        {**_MARKER_BINDING, "schema": ENROLLMENT_SIGNER_MARKER_BINDING_DIGEST_SCHEMA}
    )
    assert marker_binding_digest(**_MARKER_BINDING) == sha256_digest(  # type: ignore[arg-type]
        {"schema": ENROLLMENT_SIGNER_MARKER_BINDING_DIGEST_SCHEMA, **_MARKER_BINDING}
    )
