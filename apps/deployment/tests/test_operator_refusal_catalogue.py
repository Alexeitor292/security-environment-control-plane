"""The refusal catalogue is exhaustive, consistent, and cannot silently rot (WS-E).

A catalogue that drifts from the code is worse than none — it would tell an operator a gap is
closable when it is not. Two complementary guards keep it honest:

* :func:`test_every_refusal_literal_in_verify_is_catalogued` SCANS this module's own refusal
  literals, so adding a new reason code without cataloguing it fails here rather than surfacing
  to an operator as an unexplained string.
* the behavioural guard in ``test_operator_productization`` drives an all-unmet ladder and
  requires every rung's reason code to classify.

It also pins the property that actually protects the seals: every gap that only a separately
reviewed code change could close is classified as such, so the reported remediation can never
imply that an operator could open the controlled-live path from the host.
"""

from __future__ import annotations

import pathlib
import re

from secp_operator_deployment.verify import (
    CATALOGUE_PREFIXES,
    DIMENSIONS,
    PROVENANCE_EXIT_CODES,
    REFUSAL_CATALOGUE,
    REMEDIATION_CLASSES,
    REMEDIATION_REVIEWED_CODE,
    STATUS_EXIT_CODES,
    classify_reason_code,
)

_VERIFY_SRC = pathlib.Path(__file__).resolve().parents[1] / "secp_operator_deployment" / "verify.py"

# The exact shapes a bounded reason code is produced in inside verify.py.
_REFUSAL_PATTERNS = (
    re.compile(r'return False, "([a-z0-9_]+)"'),
    re.compile(r'^\s*return "([a-z0-9_]+)"', re.MULTILINE),
    re.compile(r'getattr\(exc, "reason_code", "([a-z0-9_]+)"\)'),
    re.compile(r'"reason_code": "([a-z0-9_]+)"'),
    re.compile(r'profile_load_reason = "([a-z0-9_]+)"'),
)

# Status names are NOT reason codes; they are returned by _resolve_status / the report builders.
_STATUS_NAMES = set(STATUS_EXIT_CODES) | set(PROVENANCE_EXIT_CODES)


def _refusal_literals() -> set[str]:
    text = _VERIFY_SRC.read_text(encoding="utf-8")
    found: set[str] = set()
    for pattern in _REFUSAL_PATTERNS:
        found.update(pattern.findall(text))
    return found - _STATUS_NAMES


# --------------------------------------------------------------------------- exhaustiveness


def test_the_scan_actually_matches_something():
    """Guard the guard: a regex that silently stops matching would make this suite vacuous."""
    literals = _refusal_literals()
    assert len(literals) >= 20, f"the refusal scan found only {len(literals)} literals"
    # spot-check that known codes from distinct code paths are being found
    assert "compositions_object_invalid" in literals
    assert "plan_gate_disabled" in literals
    assert "host_observation_type_invalid" in literals


def test_every_refusal_literal_in_verify_is_catalogued():
    uncatalogued = sorted(c for c in _refusal_literals() if classify_reason_code(c) is None)
    assert not uncatalogued, f"uncatalogued reason codes in verify.py: {uncatalogued}"


# --------------------------------------------------------------------------- internal consistency


def test_catalogue_entries_are_well_formed():
    for code, entry in REFUSAL_CATALOGUE.items():
        assert code == code.lower(), f"{code} must be lowercase"
        assert " " not in code, f"{code} must be a bounded token"
        assert set(entry) == {"dimension", "remediation"}, code
        assert entry["dimension"] in DIMENSIONS, code
        assert entry["remediation"] in REMEDIATION_CLASSES, code


def test_classify_is_total_and_never_raises():
    assert classify_reason_code(None) is None
    assert classify_reason_code("") is None
    assert classify_reason_code("not_a_real_code_xyz") is None
    assert classify_reason_code(object()) is None  # type: ignore[arg-type]


def test_prefixed_profile_codes_classify_to_the_profile_dimension():
    for prefix in CATALOGUE_PREFIXES:
        classified = classify_reason_code(prefix + "some_field")
        assert classified is not None, prefix
        assert classified["dimension"] == "B"


def test_classification_is_a_copy_so_a_caller_cannot_mutate_the_catalogue():
    classified = classify_reason_code("identity_mismatch")
    classified["dimension"] = "Z"
    assert REFUSAL_CATALOGUE["identity_mismatch"]["dimension"] == "B"


# --------------------------------------------------------------------------- the seal property


def test_gaps_that_only_a_reviewed_code_change_can_close_are_marked_as_such():
    """These are NOT operator-closable, and the catalogue must never imply otherwise."""
    for code in (
        "seal_drift_detected",  # a seal constant drifted
        "attestation_provider_not_reviewed",  # the reviewed runtime-provider set is a code constant
        "plan_gate_disabled",  # the plan-execution gate is a reviewed code default
        "composition_sealed",
        "readiness_gate_disabled",
        "eligibility_gate_disabled",
    ):
        assert REFUSAL_CATALOGUE[code]["remediation"] == REMEDIATION_REVIEWED_CODE, code


def test_catalogue_covers_every_reported_dimension():
    covered = {entry["dimension"] for entry in REFUSAL_CATALOGUE.values()}
    assert covered == DIMENSIONS


_BOUNDED_TOKEN = re.compile(r"^[a-z][a-z0-9_]{3,63}$")


def test_no_catalogue_entry_leaks_a_path_endpoint_or_credential_shape():
    """Every code is a bounded snake_case token — never a path, URL, address, or value."""
    for code in REFUSAL_CATALOGUE:
        assert _BOUNDED_TOKEN.match(code), code
        assert "/" not in code and "\\" not in code
        assert "http" not in code
        assert "." not in code and ":" not in code
