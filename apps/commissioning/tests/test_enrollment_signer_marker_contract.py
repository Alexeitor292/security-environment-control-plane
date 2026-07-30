"""Plane-neutral enrollment-signer enablement MARKER contract (SECP-PR5H-B2, 2b-3c-c, R7).

Hermetic + pure (no filesystem, no network, no plane import). Proves the ONE strict frozen model +
parser both planes share:

* the exact canonical marker round-trips (render -> parse -> equal) and the renderer is the ONLY
  producer of accepted bytes;
* the bytes contract refuses everything else — a duplicate key, an extra key, EACH missing key, a
  wrong value type (string/bool/float for an int), a reordered key, added spacing/indentation, a
  BOM, a trailing newline, non-UTF-8, an oversized file, a non-object top level, a NaN constant;
* the value contract refuses a wrong schema, a malformed digest, a malformed activation token, a
  foreign signer role, a foreign UDS path, a root or out-of-range uid/gid, and an impossible
  timestamp;
* every refusal is a bounded closed reason code that never echoes the offending value;
* the module imports neither plane, so it can be the shared contract.

The API's ``load_valid_marker`` is exercised on the IDENTICAL bytes so the two planes' accept/reject
sets are proven equal rather than assumed equal.
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest
from pydantic import ValidationError
from secp_commissioning.canonical import canonical_json
from secp_commissioning.controller_enrollment_signer import ENROLLMENT_SIGNER_SOCKET_PATH
from secp_commissioning.enrollment_signer_marker import (
    ENROLLMENT_SIGNER_MARKER_BINDING_FIELDS,
    ENROLLMENT_SIGNER_MARKER_FIELDS,
    ENROLLMENT_SIGNER_MARKER_MAX_BYTES,
    ENROLLMENT_SIGNER_MARKER_PATH,
    ENROLLMENT_SIGNER_MARKER_SCHEMA,
    EnrollmentSignerMarker,
    EnrollmentSignerMarkerError,
    build_marker,
    marker_binding_matches,
    parse_marker_bytes,
    parse_marker_bytes_or_none,
    render_marker_bytes,
)
from secp_commissioning.enrollment_signer_role import ENROLLMENT_SIGNER_DB_ROLE

_D = "sha256:" + "a" * 64
_ROW = "0f2b7e2a-6f5e-4c1d-9d8a-2b1c3d4e5f60"
_TOKEN = f"{_ROW}|2026-07-28 00:00:00+00:00"

_FIELDS = {
    "installation_id": "controller-abc12345",
    "release_digest": _D,
    "active_identity_row_id": _ROW,
    "activation_token": _TOKEN,
    "controller_key_id": "sha256:" + "b" * 64,
    "uds_contract_identity": ENROLLMENT_SIGNER_SOCKET_PATH,
    "api_uid": 10001,
    "api_gid": 10001,
    "signer_role_name": ENROLLMENT_SIGNER_DB_ROLE,
    "locator_ca_digest": "sha256:" + "c" * 64,
    "management_identity_digest": "sha256:" + "d" * 64,
    "bootstrap_evidence_digest": "sha256:" + "e" * 64,
    "recorded_at": "2026-07-28T00:00:00Z",
}


def _obj(**over: object) -> dict:
    obj: dict = {"schema": ENROLLMENT_SIGNER_MARKER_SCHEMA, **_FIELDS}
    obj.update(over)
    return obj


def _bytes(**over: object) -> bytes:
    return canonical_json(_obj(**over)).encode("utf-8")


def _reason(raw: bytes) -> str:
    with pytest.raises(EnrollmentSignerMarkerError) as exc:
        parse_marker_bytes(raw)
    return str(exc.value.reason_code)


def _refuses(raw: bytes) -> str:
    """Refused by the parser AND by the fail-closed wrapper; returns the bounded reason code."""
    reason = _reason(raw)
    assert parse_marker_bytes_or_none(raw) is None
    return reason


# --------------------------------------------------------------------------- the happy path


def test_the_exact_canonical_marker_round_trips():
    rendered = render_marker_bytes(**_FIELDS)
    assert rendered == _bytes()  # the renderer emits exactly the canonical bytes
    parsed = parse_marker_bytes(rendered)
    assert isinstance(parsed, EnrollmentSignerMarker)
    assert parsed == build_marker(**_FIELDS)
    assert parsed.to_canonical_bytes() == rendered  # render -> parse -> render is a fixed point
    assert parsed.to_canonical_object() == _obj()
    assert parsed.schema_id == ENROLLMENT_SIGNER_MARKER_SCHEMA
    assert parsed.api_uid == 10001 and parsed.signer_role_name == ENROLLMENT_SIGNER_DB_ROLE


def test_the_model_is_frozen_and_closed():
    parsed = parse_marker_bytes(_bytes())
    with pytest.raises(ValidationError):  # frozen: no mutation between parse and binding check
        parsed.api_uid = 0
    assert not hasattr(parsed, "broker_unit_identity")  # no decorative unvalidated field
    assert set(_obj()) == set(ENROLLMENT_SIGNER_MARKER_FIELDS)
    assert set(ENROLLMENT_SIGNER_MARKER_BINDING_FIELDS) == set(ENROLLMENT_SIGNER_MARKER_FIELDS) - {
        "schema",
        "recorded_at",
    }


def test_the_fixed_contract_constants_are_the_shared_ones():
    assert ENROLLMENT_SIGNER_MARKER_PATH == "/etc/secp/controller/enrollment-signer.enabled"
    assert ENROLLMENT_SIGNER_MARKER_SCHEMA == "secp.enrollment-signer-enablement/v1"
    assert _obj()["uds_contract_identity"] == ENROLLMENT_SIGNER_SOCKET_PATH
    assert _obj()["signer_role_name"] == ENROLLMENT_SIGNER_DB_ROLE


# --------------------------------------------------------------------------- the bytes contract


def test_duplicate_key_refuses():
    body = canonical_json(_obj())
    dupe = (body[:-1] + ',"api_uid":0}').encode("utf-8")  # a second, later api_uid
    assert _refuses(dupe) == "enrollment_signer_marker_duplicate_key"
    # ... even when the repeated value is IDENTICAL (no last-wins collapse is tolerated)
    same = (body[:-1] + ',"api_uid":10001}').encode("utf-8")
    assert _refuses(same) == "enrollment_signer_marker_duplicate_key"


def test_extra_field_refuses_without_echoing_the_key():
    reason = _refuses(_bytes(broker_unit_identity=_D))
    assert reason == "enrollment_signer_marker_field_unknown"
    assert "broker_unit_identity" not in reason
    assert _refuses(_bytes(extra=1)) == "enrollment_signer_marker_field_unknown"


@pytest.mark.parametrize("field", ENROLLMENT_SIGNER_MARKER_FIELDS)
def test_each_missing_field_refuses(field):
    obj = _obj()
    obj.pop(field)
    assert _refuses(canonical_json(obj).encode("utf-8")) == (
        f"enrollment_signer_marker_field_missing:{field}"
    )


@pytest.mark.parametrize("bad", ["10001", True, False, 10001.0, None, [10001], {"v": 1}])
def test_wrong_type_for_an_int_field_refuses(bad):
    assert _refuses(_bytes(api_uid=bad)) == "enrollment_signer_marker_field_invalid:api_uid"
    assert _refuses(_bytes(api_gid=bad)) == "enrollment_signer_marker_field_invalid:api_gid"


@pytest.mark.parametrize("bad", [1, True, None, [_D], {"v": _D}])
def test_wrong_type_for_a_string_field_refuses(bad):
    assert _refuses(_bytes(installation_id=bad)).startswith(
        "enrollment_signer_marker_field_invalid:"
    )


def test_noncanonical_key_order_refuses():
    obj = _obj()
    reordered = {k: obj[k] for k in reversed(list(obj))}
    raw = json.dumps(reordered, separators=(",", ":")).encode("utf-8")
    assert raw != _bytes() and json.loads(raw) == obj
    assert _refuses(raw) == "enrollment_signer_marker_not_canonical"


@pytest.mark.parametrize(
    "raw",
    [
        json.dumps(_obj(), sort_keys=True).encode("utf-8"),  # default ", " / ": " separators
        json.dumps(_obj(), sort_keys=True, indent=2).encode("utf-8"),  # pretty printed
        b" " + canonical_json(_obj()).encode("utf-8"),  # leading whitespace
        canonical_json(_obj()).encode("utf-8") + b" ",  # trailing space
        b"\xef\xbb\xbf" + canonical_json(_obj()).encode("utf-8"),  # UTF-8 BOM
    ],
)
def test_noncanonical_spacing_refuses(raw):
    assert _refuses(raw) in {
        "enrollment_signer_marker_not_canonical",
        "enrollment_signer_marker_not_json",
    }


def test_a_trailing_newline_refuses_explicitly():
    """EXPLICIT: the marker file is EXACTLY the canonical bytes. The single code-owned writer never
    appends a newline, so a trailing newline (or CRLF) is corruption, not cosmetics."""
    body = canonical_json(_obj()).encode("utf-8")
    assert parse_marker_bytes(body).api_uid == 10001
    assert _refuses(body + b"\n") == "enrollment_signer_marker_not_canonical"
    assert _refuses(body + b"\r\n") == "enrollment_signer_marker_not_canonical"
    assert _refuses(b"\n" + body) == "enrollment_signer_marker_not_canonical"


@pytest.mark.parametrize(
    "raw",
    [
        b"",  # empty
        b"not json",
        b"{",
        b'{"schema":"secp.enrollment-signer-enablement/v1"}',  # object, but not the closed set
        b"[]",  # not an object
        b'"a string"',
        b"123",
        b"null",
    ],
)
def test_malformed_or_non_object_bytes_refuse(raw):
    assert _refuses(raw).startswith("enrollment_signer_marker_")


def test_non_utf8_bytes_refuse():
    assert _refuses(b"\xff\xfe" + canonical_json(_obj()).encode("utf-8")) == (
        "enrollment_signer_marker_not_utf8"
    )
    assert _refuses(canonical_json(_obj()).encode("utf-16")) == "enrollment_signer_marker_not_utf8"


def test_oversized_marker_refuses():
    padded = _bytes(installation_id="a" * (ENROLLMENT_SIGNER_MARKER_MAX_BYTES + 64))
    assert len(padded) > ENROLLMENT_SIGNER_MARKER_MAX_BYTES
    assert _refuses(padded) == "enrollment_signer_marker_size_invalid"


def test_non_finite_json_constant_refuses():
    body = canonical_json(_obj()).replace('"api_uid":10001', '"api_uid":NaN').encode("utf-8")
    assert _refuses(body) == "enrollment_signer_marker_not_json"


def test_non_bytes_input_refuses():
    assert _reason(canonical_json(_obj())) == "enrollment_signer_marker_bytes_invalid"
    assert _reason(None) == "enrollment_signer_marker_bytes_invalid"


def test_a_nested_object_can_never_smuggle_a_value():
    # the closed key set means no nested container is reachable at all
    assert _refuses(_bytes(installation_id={"installation_id": "controller-abc12345"})).startswith(
        "enrollment_signer_marker_field_invalid:"
    )


# --------------------------------------------------------------------------- the value contract


@pytest.mark.parametrize(
    "schema",
    ["other/v9", "secp.enrollment-signer-enablement/v2", "", "SECP.ENROLLMENT-SIGNER/V1", 1],
)
def test_wrong_schema_refuses(schema):
    assert _refuses(_bytes(schema=schema)) == "enrollment_signer_marker_schema_unknown"


_DIGEST_FIELDS = (
    "release_digest",
    "controller_key_id",
    "locator_ca_digest",
    "management_identity_digest",
    "bootstrap_evidence_digest",
)


@pytest.mark.parametrize("field", _DIGEST_FIELDS)
@pytest.mark.parametrize(
    "bad",
    [
        "a" * 64,  # no algorithm prefix
        "sha256:" + "A" * 64,  # uppercase hex
        "sha256:" + "a" * 63,  # too short
        "sha256:" + "a" * 65,  # too long
        "sha512:" + "a" * 64,  # wrong algorithm
        "sha256:" + "g" * 64,  # not hex
        "sha256:",
        "",
    ],
)
def test_bad_digest_grammar_refuses(field, bad):
    assert _refuses(_bytes(**{field: bad})) == f"enrollment_signer_marker_field_invalid:{field}"


@pytest.mark.parametrize(
    "bad",
    [
        "tok-abcdef",  # no <row id>|<activated_at> separator
        "|2026-07-28 00:00:00+00:00",  # empty row-id half
        f"{_ROW}|",  # empty timestamp half
        f"{_ROW}|a|b",  # more than one separator
        f"{_ROW}|2026-07-28\x0000:00:00",  # embedded NUL
        f"{_ROW}|2026-07-28\n00:00:00",  # embedded newline
        "x" * 200,  # unbounded
        f"{'a' * 120}|{'b' * 120}",  # each half bounded too
    ],
)
def test_bad_activation_token_grammar_refuses(bad):
    assert _refuses(_bytes(activation_token=bad)) == (
        "enrollment_signer_marker_field_invalid:activation_token"
    )


@pytest.mark.parametrize(
    "bad", ["postgres", "secp_enrollment_signer_2", "SECP_ENROLLMENT_SIGNER", "", "public"]
)
def test_wrong_fixed_signer_role_refuses(bad):
    assert _refuses(_bytes(signer_role_name=bad)) == (
        "enrollment_signer_marker_field_invalid:signer_role_name"
    )


@pytest.mark.parametrize(
    "bad",
    [
        "/tmp/evil.sock",  # noqa: S108 - a hostile path is exactly what must refuse
        "/run/secp/enrollment-signer.sock2",
        "/run/secp/../secp/enrollment-signer.sock",
        "run/secp/enrollment-signer.sock",
        "",
    ],
)
def test_wrong_fixed_uds_contract_refuses(bad):
    assert _refuses(_bytes(uds_contract_identity=bad)) == (
        "enrollment_signer_marker_field_invalid:uds_contract_identity"
    )


@pytest.mark.parametrize("bad", [0, -1, 2**31, 2**63, -(2**31)])
def test_out_of_range_or_root_api_peer_refuses(bad):
    assert _refuses(_bytes(api_uid=bad)) == "enrollment_signer_marker_field_invalid:api_uid"
    assert _refuses(_bytes(api_gid=bad)) == "enrollment_signer_marker_field_invalid:api_gid"


@pytest.mark.parametrize(
    "bad",
    [
        "controller-ABC12345",  # uppercase
        "-controller-1234",  # leading separator
        "short",  # under the 8-char floor
        "controller_abc12345",  # underscore
        "a" * 65,  # over the 64-char ceiling
        "controller abc12345",  # space
        "",
    ],
)
def test_oversized_or_malformed_installation_id_refuses(bad):
    assert _refuses(_bytes(installation_id=bad)) == (
        "enrollment_signer_marker_field_invalid:installation_id"
    )


@pytest.mark.parametrize("bad", ["row/1", "row 1", "-row", "x" * 65, "", "row\n1"])
def test_malformed_active_identity_row_id_refuses(bad):
    assert _refuses(_bytes(active_identity_row_id=bad)) == (
        "enrollment_signer_marker_field_invalid:active_identity_row_id"
    )


@pytest.mark.parametrize(
    "bad",
    [
        "2026-07-28T00:00:00+00:00",  # not the fixed Z rendering
        "2026-07-28 00:00:00Z",  # missing the T
        "2026-13-01T00:00:00Z",  # impossible month
        "2026-02-30T00:00:00Z",  # impossible day
        "2026-07-28T25:00:00Z",  # impossible hour
        "2026-07-28T00:00:00.500Z",  # fractional seconds are not the fixed rendering
        "26-07-28T00:00:00Z",
        "",
    ],
)
def test_malformed_recorded_at_refuses(bad):
    assert _refuses(_bytes(recorded_at=bad)) == (
        "enrollment_signer_marker_field_invalid:recorded_at"
    )


def test_a_refusal_never_echoes_the_offending_value():
    secretish = "controller-" + "z" * 40
    reason = _refuses(_bytes(installation_id=secretish + "!"))
    assert secretish not in reason and len(reason) <= 120


def test_the_renderer_refuses_an_unrenderable_candidate():
    """A marker the parser would seal on can never be WRITTEN: the writer validates first."""
    with pytest.raises(EnrollmentSignerMarkerError) as exc:
        render_marker_bytes(**{**_FIELDS, "signer_role_name": "postgres"})
    assert str(exc.value.reason_code) == "enrollment_signer_marker_field_invalid:signer_role_name"
    with pytest.raises(EnrollmentSignerMarkerError):
        render_marker_bytes(**{**_FIELDS, "api_uid": 0})


# --------------------------------------------------------------------------- binding comparison


class _Binding:
    def __init__(self, **over: object) -> None:
        for field in ENROLLMENT_SIGNER_MARKER_BINDING_FIELDS:
            setattr(self, field, _FIELDS[field])
        for key, value in over.items():
            setattr(self, key, value)


def test_marker_binding_matches_on_the_complete_field_set():
    marker = parse_marker_bytes(_bytes())
    assert marker_binding_matches(marker, _Binding())


@pytest.mark.parametrize("field", ENROLLMENT_SIGNER_MARKER_BINDING_FIELDS)
def test_any_binding_field_mismatch_or_absence_refuses(field):
    marker = parse_marker_bytes(_bytes())
    other = 4242 if isinstance(_FIELDS[field], int) else "sha256:" + "9" * 64
    assert not marker_binding_matches(marker, _Binding(**{field: other}))
    incomplete = _Binding()
    delattr(incomplete, field)  # a partial binding is never a match (no subset comparison)
    assert not marker_binding_matches(marker, incomplete)


# --------------------------------------------------------------------------- plane neutrality


_MODULE = (
    pathlib.Path(__file__).resolve().parents[1]
    / "secp_commissioning"
    / "enrollment_signer_marker.py"
)


def test_the_shared_contract_imports_neither_plane():
    tree = ast.parse(_MODULE.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    assert not roots & {"secp_api", "secp_management", "secp_worker", "sqlalchemy", "socket"}
    import secp_commissioning.enrollment_signer_marker as mod

    assert "secp_api" not in str(mod.__file__)


# --------------------------------------------------------------------------- cross-plane parity


def _api_load(tmp_path, raw: bytes, monkeypatch):
    from secp_api import enrollment_signer_marker as api_mod

    monkeypatch.setattr(api_mod, "_fs_safe", lambda path: True)  # POSIX posture gate is API-side
    path = tmp_path / "enrollment-signer.enabled"
    path.write_bytes(raw)
    return api_mod.load_valid_marker(path=str(path))


_PARITY_CASES = [
    _bytes(),  # the exact canonical marker
    _bytes(schema="other/v9"),
    _bytes(extra=1),
    _bytes(api_uid="10001"),
    _bytes(api_uid=True),
    _bytes(api_uid=0),
    _bytes(release_digest="a" * 64),
    _bytes(signer_role_name="postgres"),
    _bytes(uds_contract_identity="/tmp/evil.sock"),  # noqa: S108
    _bytes(activation_token="tok-abcdef"),
    _bytes(recorded_at="2026-13-01T00:00:00Z"),
    canonical_json(_obj()).encode("utf-8") + b"\n",
    json.dumps(_obj(), sort_keys=True, indent=2).encode("utf-8"),
    (canonical_json(_obj())[:-1] + ',"api_uid":0}').encode("utf-8"),
    b"not json",
    b"",
]


@pytest.mark.parametrize("raw", _PARITY_CASES, ids=[str(i) for i in range(len(_PARITY_CASES))])
def test_management_and_api_accept_and_reject_the_identical_bytes(raw, tmp_path, monkeypatch):
    """R7's headline invariant: the API loader's verdict on some bytes is EXACTLY the shared
    parser's verdict on the same bytes — one contract, five consumers, no drift."""
    shared = parse_marker_bytes_or_none(raw)
    api = _api_load(tmp_path, raw, monkeypatch)
    assert (shared is None) == (api is None)
    if shared is not None:
        assert api == shared and type(api) is type(shared)


def test_the_api_module_re_exports_the_shared_contract():
    from secp_api import enrollment_signer_marker as api_mod
    from secp_commissioning import enrollment_signer_marker as shared

    assert api_mod.EnrollmentSignerMarker is shared.EnrollmentSignerMarker
    assert api_mod.parse_marker_bytes is shared.parse_marker_bytes
    assert api_mod.render_marker_bytes is shared.render_marker_bytes
    assert api_mod.MARKER_PATH == shared.ENROLLMENT_SIGNER_MARKER_PATH
