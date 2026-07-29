"""Plane-neutral enrollment-signer enablement MARKER contract (SECP-PR5H-B2, 2b-3c-c, R7).

The root-owned marker file is the SOLE positive production authority that enables the API's
enrollment-signer client. It is written by the MANAGEMENT installer's finalization adapter and read
by the API loader, the API signer dependency, the management engine's replay/status revalidation,
and the management runtime observer. Five readers of one security decision is five chances to drift,
so the schema, the bytes contract, and the parser live HERE — in the ONE module both planes may
import — and every participant uses this single strict frozen model. Management and the API
therefore accept and reject EXACTLY the same marker bytes, by construction.

The bytes contract is deliberately unforgiving; a marker is machine-written by exactly one code path
(:func:`render_marker_bytes`), never hand-edited, so anything that is not byte-identical to the
canonical rendering is treated as corrupt (→ SEALED):

* the file is EXACTLY ``canonical_json(object)`` encoded UTF-8 — no BOM, no trailing newline, no
  insignificant whitespace, keys in sorted order (a re-render of the parsed object must equal the
  input byte for byte);
* the JSON object is CLOSED — exactly the fourteen code-owned keys, no extra key, no missing key,
  and a repeated key is refused outright rather than silently last-wins collapsed;
* every value is exactly typed (a bool is never an int, a numeric string is never an int), bounded,
  and grammar-checked: ``sha256:<64 lowercase hex>`` for every digest, a bounded installation id /
  row id / activation token, an exact fixed schema/version, an exact fixed signer role name and an
  exact fixed UDS contract path;
* the enabled API peer is a NON-ROOT uid/gid pair (0 is never a legitimate marker peer).

This module is PURE and OFFLINE: it opens no socket, touches no filesystem, imports neither
``secp_api`` nor ``secp_management``, and never echoes a marker value — every refusal is a bounded
closed reason code (optionally suffixed with a code-owned FIELD NAME, never a field VALUE). Reading
the file, proving its root-owned filesystem posture, and comparing the parsed binding against
authoritative runtime facts stay with the respective plane; only the schema + bytes contract is
shared.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, NoReturn

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from secp_commissioning.canonical import canonical_json, is_sha256_digest
from secp_commissioning.controller_enrollment_signer import ENROLLMENT_SIGNER_SOCKET_PATH
from secp_commissioning.enrollment_signer_role import ENROLLMENT_SIGNER_DB_ROLE
from secp_commissioning.errors import CommissioningError

#: The single fixed, code-owned marker path. The root installer writes it LAST and bind-mounts it
#: read-only into the API container at exactly this path; ``ManagementLocations`` renders the same
#: constant. It is NEVER a config / env / descriptor / HTTP input.
ENROLLMENT_SIGNER_MARKER_PATH = "/etc/secp/controller/enrollment-signer.enabled"

#: The ONE accepted schema/version literal. A marker carrying any other value is refused — there is
#: no best-effort upgrade and no version negotiation.
ENROLLMENT_SIGNER_MARKER_SCHEMA = "secp.enrollment-signer-enablement/v1"

#: Bounded upper limit for the marker file (the canonical rendering is a few hundred bytes).
ENROLLMENT_SIGNER_MARKER_MAX_BYTES = 8 * 1024

#: The CLOSED key set of the marker object (the JSON keys, not the model attribute names). Missing
#: or extra keys both refuse; ``schema`` is exposed on the model as ``schema_id`` because pydantic
#: reserves the ``schema`` attribute name.
ENROLLMENT_SIGNER_MARKER_FIELDS = (
    "schema",
    "installation_id",
    "release_digest",
    "active_identity_row_id",
    "activation_token",
    "controller_key_id",
    "uds_contract_identity",
    "api_uid",
    "api_gid",
    "signer_role_name",
    "locator_ca_digest",
    "management_identity_digest",
    "bootstrap_evidence_digest",
    "recorded_at",
)

#: The COMPLETE set of binding fields a marker must match the running install on (model attribute
#: names). ``recorded_at`` is deliberately excluded — it is a provenance stamp, not a binding — and
#: ``schema`` is the contract itself. A consumer compares ALL of these, never a subset.
ENROLLMENT_SIGNER_MARKER_BINDING_FIELDS = (
    "installation_id",
    "release_digest",
    "active_identity_row_id",
    "activation_token",
    "controller_key_id",
    "management_identity_digest",
    "bootstrap_evidence_digest",
    "api_uid",
    "api_gid",
    "signer_role_name",
    "uds_contract_identity",
    "locator_ca_digest",
)

# --- bounds + grammars ---------------------------------------------------------------------------
_MAX_POSIX_ID = 2**31 - 1
_DIGEST_LEN = 71  # "sha256:" + 64 hex
_RECORDED_AT_LEN = 20  # "YYYY-MM-DDTHH:MM:SSZ"
_RECORDED_AT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Grammars mirrored (never imported — the commissioning plane may not depend on either plane) from
# the authoritative producers, so every value a real install can persist passes and nothing looser
# does. ``installation_id`` matches the signing-lease grammar, so a marker that could not pass
# ``SigningIdentityLease`` construction can never enable a signer either.
_INSTALLATION_ID = re.compile(r"[a-z0-9][a-z0-9-]{7,63}")
_ROW_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
# the immutable per-activation token is EXACTLY ``<row id>|<activated_at>`` on both planes.
_ACTIVATION_TOKEN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}\|[A-Za-z0-9][A-Za-z0-9 ._:+-]{0,63}"
)
_RECORDED_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class EnrollmentSignerMarkerError(CommissioningError):
    """A bounded, closed marker refusal — a reason code (optionally ``code:field_name``) and nothing
    else. It never carries a marker value, the raw bytes, a path, or a third-party exception."""


def _reject(reason_code: str) -> NoReturn:
    raise EnrollmentSignerMarkerError(reason_code)


# --------------------------------------------------------------------------- the strict model


class EnrollmentSignerMarker(BaseModel):
    """The strict, closed, FROZEN enablement-marker binding shared by both planes.

    Extra / missing fields and wrong types are refused, every value is bounded, and the model is
    immutable, so a parsed marker can never be mutated between the parse and the binding check. It
    binds the marker to the exact installation / release / active identity / activation / key / UDS
    contract / API peer / role / locator CA — a mismatch on any one is a fact the caller seals on.
    It carries NO secret content (only public installation facts).
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_id: str = Field(alias="schema", min_length=1, max_length=64)
    installation_id: str = Field(min_length=8, max_length=64)
    release_digest: str = Field(min_length=_DIGEST_LEN, max_length=_DIGEST_LEN)
    active_identity_row_id: str = Field(min_length=1, max_length=64)
    activation_token: str = Field(min_length=3, max_length=128)
    controller_key_id: str = Field(min_length=_DIGEST_LEN, max_length=_DIGEST_LEN)
    # NOTE: broker_unit_identity is intentionally NOT in the marker — the API cannot independently
    # authenticate it, so it is not a runtime-enablement binding; it lives only in management
    # installation evidence. No decorative, never-validated field is left in the marker.
    uds_contract_identity: str = Field(min_length=1, max_length=128)
    api_uid: int = Field(ge=1, le=_MAX_POSIX_ID)
    api_gid: int = Field(ge=1, le=_MAX_POSIX_ID)
    signer_role_name: str = Field(min_length=1, max_length=64)
    locator_ca_digest: str = Field(min_length=_DIGEST_LEN, max_length=_DIGEST_LEN)
    management_identity_digest: str = Field(min_length=_DIGEST_LEN, max_length=_DIGEST_LEN)
    bootstrap_evidence_digest: str = Field(min_length=_DIGEST_LEN, max_length=_DIGEST_LEN)
    recorded_at: str = Field(min_length=_RECORDED_AT_LEN, max_length=_RECORDED_AT_LEN)

    def to_canonical_object(self) -> dict[str, Any]:
        """The exact JSON object (aliased keys) this marker renders to."""
        return self.model_dump(by_alias=True)

    def to_canonical_bytes(self) -> bytes:
        """The exact canonical file bytes for this marker — no trailing newline. Round-trips through
        :func:`parse_marker_bytes` by construction, so the writer and the readers cannot drift."""
        return canonical_json(self.to_canonical_object()).encode("utf-8")


# --------------------------------------------------------------------------- field validation


def _is_schema(value: object) -> bool:
    return value == ENROLLMENT_SIGNER_MARKER_SCHEMA


def _is_digest(value: object) -> bool:
    return is_sha256_digest(value)


def _is_installation_id(value: object) -> bool:
    return isinstance(value, str) and _INSTALLATION_ID.fullmatch(value) is not None


def _is_row_id(value: object) -> bool:
    return isinstance(value, str) and _ROW_ID.fullmatch(value) is not None


def _is_activation_token(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= 128
        and _ACTIVATION_TOKEN.fullmatch(value) is not None
    )


def _is_uds_contract(value: object) -> bool:
    return value == ENROLLMENT_SIGNER_SOCKET_PATH


def _is_signer_role(value: object) -> bool:
    return value == ENROLLMENT_SIGNER_DB_ROLE


def _is_posix_id(value: object) -> bool:
    # ``type(...) is int`` excludes ``bool`` EXACTLY (bool is an int subclass): ``true`` is never a
    # uid. The enabled API peer is non-root by contract, so 0 is never a legitimate marker peer.
    return type(value) is int and 1 <= value <= _MAX_POSIX_ID


def _is_recorded_at(value: object) -> bool:
    if not isinstance(value, str) or _RECORDED_AT.fullmatch(value) is None:
        return False
    try:  # a well-shaped but impossible date (month 13, day 32) is still refused
        datetime.strptime(value, _RECORDED_AT_FORMAT)  # noqa: DTZ007 - grammar pins the Z offset
    except ValueError:
        return False
    return True


#: field name -> exact predicate. Every closed key is validated; there is no permissive default.
_VALIDATORS: dict[str, Any] = {
    "schema": _is_schema,
    "installation_id": _is_installation_id,
    "release_digest": _is_digest,
    "active_identity_row_id": _is_row_id,
    "activation_token": _is_activation_token,
    "controller_key_id": _is_digest,
    "uds_contract_identity": _is_uds_contract,
    "api_uid": _is_posix_id,
    "api_gid": _is_posix_id,
    "signer_role_name": _is_signer_role,
    "locator_ca_digest": _is_digest,
    "management_identity_digest": _is_digest,
    "bootstrap_evidence_digest": _is_digest,
    "recorded_at": _is_recorded_at,
}


def _validate_object(obj: dict[str, Any]) -> EnrollmentSignerMarker:
    """Validate a decoded marker object against the CLOSED schema and return the frozen model. The
    single validation path for both the parser and the renderer, so the two can never disagree."""
    for field in ENROLLMENT_SIGNER_MARKER_FIELDS:
        if field not in obj:
            _reject(f"enrollment_signer_marker_field_missing:{field}")
    if len(obj) != len(ENROLLMENT_SIGNER_MARKER_FIELDS):
        _reject("enrollment_signer_marker_field_unknown")  # never echoes the unknown key
    if not _is_schema(obj["schema"]):
        _reject("enrollment_signer_marker_schema_unknown")
    for field, is_valid in _VALIDATORS.items():
        if not is_valid(obj[field]):
            _reject(f"enrollment_signer_marker_field_invalid:{field}")
    try:  # defence in depth: the strict frozen model re-proves types + bounds independently
        return EnrollmentSignerMarker.model_validate(obj)
    except ValidationError:
        _reject("enrollment_signer_marker_model_invalid")


# --------------------------------------------------------------------------- the parser


class _DuplicateKey(ValueError):
    """A repeated key in the marker object — refused rather than last-wins collapsed."""


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateKey
        obj[key] = value
    return obj


def _refuse_constant(_value: str) -> NoReturn:
    raise ValueError("non_finite")  # NaN / Infinity / -Infinity are not canonical JSON


def parse_marker_bytes(raw: bytes) -> EnrollmentSignerMarker:
    """Parse + validate EXACT marker file bytes, or raise a bounded
    :class:`EnrollmentSignerMarkerError`.

    The accepted bytes are exactly one canonical rendering: bounded length, strict UTF-8, a JSON
    OBJECT with no repeated key, whose re-rendering under :func:`canonical_json` equals the input
    byte for byte (so a reordered key, an added space, an indent, a BOM, or a trailing newline all
    refuse), carrying exactly the closed field set with exact types, bounds and grammars.
    """
    if not isinstance(raw, bytes | bytearray):
        _reject("enrollment_signer_marker_bytes_invalid")
    data = bytes(raw)
    if not (1 <= len(data) <= ENROLLMENT_SIGNER_MARKER_MAX_BYTES):
        _reject("enrollment_signer_marker_size_invalid")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        _reject("enrollment_signer_marker_not_utf8")
    try:
        obj = json.loads(text, object_pairs_hook=_object_pairs, parse_constant=_refuse_constant)
    except _DuplicateKey:
        _reject("enrollment_signer_marker_duplicate_key")
    except ValueError:  # includes JSONDecodeError and the refused non-finite constants
        _reject("enrollment_signer_marker_not_json")
    if not isinstance(obj, dict):
        _reject("enrollment_signer_marker_not_object")
    if canonical_json(obj).encode("utf-8") != data:
        _reject("enrollment_signer_marker_not_canonical")
    return _validate_object(obj)


def parse_marker_bytes_or_none(raw: bytes) -> EnrollmentSignerMarker | None:
    """:func:`parse_marker_bytes` for the fail-closed callers: ``None`` instead of a raise. A caller
    that treats absence and corruption identically (→ SEALED) wants this one."""
    try:
        return parse_marker_bytes(raw)
    except EnrollmentSignerMarkerError:
        return None


# --------------------------------------------------------------------------- the renderer


def build_marker(
    *,
    installation_id: str,
    release_digest: str,
    active_identity_row_id: str,
    activation_token: str,
    controller_key_id: str,
    uds_contract_identity: str,
    api_uid: int,
    api_gid: int,
    signer_role_name: str,
    locator_ca_digest: str,
    management_identity_digest: str,
    bootstrap_evidence_digest: str,
    recorded_at: str,
) -> EnrollmentSignerMarker:
    """Build a validated marker. The schema literal is supplied by CODE (never by a caller) and the
    candidate runs through the SAME validation the parser uses, so an unrenderable marker refuses at
    the writer instead of producing a file the readers would seal on."""
    return _validate_object(
        {
            "schema": ENROLLMENT_SIGNER_MARKER_SCHEMA,
            "installation_id": installation_id,
            "release_digest": release_digest,
            "active_identity_row_id": active_identity_row_id,
            "activation_token": activation_token,
            "controller_key_id": controller_key_id,
            "uds_contract_identity": uds_contract_identity,
            "api_uid": api_uid,
            "api_gid": api_gid,
            "signer_role_name": signer_role_name,
            "locator_ca_digest": locator_ca_digest,
            "management_identity_digest": management_identity_digest,
            "bootstrap_evidence_digest": bootstrap_evidence_digest,
            "recorded_at": recorded_at,
        }
    )


def render_marker_bytes(
    *,
    installation_id: str,
    release_digest: str,
    active_identity_row_id: str,
    activation_token: str,
    controller_key_id: str,
    uds_contract_identity: str,
    api_uid: int,
    api_gid: int,
    signer_role_name: str,
    locator_ca_digest: str,
    management_identity_digest: str,
    bootstrap_evidence_digest: str,
    recorded_at: str,
) -> bytes:
    """The ONE way to produce marker file bytes. The output round-trips through
    :func:`parse_marker_bytes` by construction, so the management writer and the five readers cannot
    drift; a candidate that would not parse raises here rather than being written."""
    return build_marker(
        installation_id=installation_id,
        release_digest=release_digest,
        active_identity_row_id=active_identity_row_id,
        activation_token=activation_token,
        controller_key_id=controller_key_id,
        uds_contract_identity=uds_contract_identity,
        api_uid=api_uid,
        api_gid=api_gid,
        signer_role_name=signer_role_name,
        locator_ca_digest=locator_ca_digest,
        management_identity_digest=management_identity_digest,
        bootstrap_evidence_digest=bootstrap_evidence_digest,
        recorded_at=recorded_at,
    ).to_canonical_bytes()


_MISSING = object()


def marker_binding_matches(marker: EnrollmentSignerMarker, binding: object) -> bool:
    """Whether ``marker`` equals ``binding`` on the COMPLETE binding field set (no subset). Any
    missing or mismatched field is False — the caller seals. ``binding`` is any object carrying the
    authoritative runtime facts as attributes (the API's runtime binding, the management candidate
    marker), so neither plane has to re-list the fields."""
    for field in ENROLLMENT_SIGNER_MARKER_BINDING_FIELDS:
        expected = getattr(binding, field, _MISSING)
        if expected is _MISSING or getattr(marker, field) != expected:
            return False
    return True


__all__ = [
    "ENROLLMENT_SIGNER_MARKER_BINDING_FIELDS",
    "ENROLLMENT_SIGNER_MARKER_FIELDS",
    "ENROLLMENT_SIGNER_MARKER_MAX_BYTES",
    "ENROLLMENT_SIGNER_MARKER_PATH",
    "ENROLLMENT_SIGNER_MARKER_SCHEMA",
    "EnrollmentSignerMarker",
    "EnrollmentSignerMarkerError",
    "build_marker",
    "marker_binding_matches",
    "parse_marker_bytes",
    "parse_marker_bytes_or_none",
    "render_marker_bytes",
]
