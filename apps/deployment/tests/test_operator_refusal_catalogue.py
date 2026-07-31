"""The refusal catalogue is exhaustive, consistent, and drift-guarded (WS-E).

A catalogue that drifts from the code is worse than none — it would tell an operator a gap is
closable when it is not. Two complementary guards keep it honest:

* :func:`test_every_refusal_literal_in_verify_is_catalogued` SCANS ``verify.py`` for refusal
  literals, so adding a new reason code in one of the matched shapes without cataloguing it fails
  here rather than surfacing to an operator as an unexplained string.
* the behavioural guard in ``test_operator_productization`` drives an all-unmet ladder and
  requires every rung's reason code to classify.

Scope, stated plainly rather than implied. The scan recognises five syntactic shapes and so covers
26 of the 79 catalogued codes. Thirteen of the other 53 are raised by ``verify.py`` ITSELF in
shapes no pattern matches — eleven as inline positional arguments to ``rung()`` (bare, or as the
``x or "literal"`` fallback), ``compositions_not_supplied`` inside a parenthesised conditional, and
``queue_not_distinct`` as a conditional dict-literal value in ``_queue_section``; two more
(``identity_mismatch``, ``install_untrusted``) are filtered out DELIBERATELY because they double as
status names. The remaining 40 are raised in ``profile.py``, ``manifest.py``, ``compositions.py``,
``runtime_seams.py``, ``cli.py`` and ``secp_worker``.

The scan also proves only one direction — every scanned literal is catalogued, never that every
catalogued entry is still reachable — so a STALE entry is unpoliced here.

Widening the scan is deliberately not the fix for either gap: an uncatalogued code already degrades
VISIBLY at the point of use, where ``build_prerequisite_ladder`` sets ``reason_catalogued: False``
and the report carries that to the operator, so a wider scan would look far more thorough while
remaining exactly as shape-fragile.

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


# The EXACT set the patterns above match today. Pinned as a SET, not a floor: a floor cannot see a
# swap — six codes could vanish and six appear and ``>= 20`` would still pass.
_SCANNED_LITERALS = frozenset(
    {
        "classification_invalid",
        "composition_type_invalid",
        "compositions_object_invalid",
        "eligibility_gate_disabled",
        "executor_factory_invalid",
        "host_observation_type_invalid",
        "manifest_unavailable",
        "plan_execution_composition_invalid",
        "plan_gate_disabled",
        "process_digest_invalid",
        "process_registration_invalid",
        "profile_type_invalid",
        "provenance_contract_version_invalid",
        "provenance_expected_binding_invalid",
        "provenance_implementation_id_invalid",
        "provenance_manifest_digest_invalid",
        "provenance_package_version_invalid",
        "provenance_profile_binding_invalid",
        "provenance_type_invalid",
        "provenance_untrusted_install",
        "provider_identity_invalid",
        "provider_source_invalid",
        "queue_separation_unavailable",
        "readiness_gate_disabled",
        "renderer_digest_invalid",
        "renderer_registration_invalid",
    }
)


def test_the_scan_matches_exactly_the_pinned_literal_set():
    """Guard the guard: a regex that silently stops matching would make this suite vacuous."""
    found = _refusal_literals()
    assert not (found - _SCANNED_LITERALS), (
        f"new refusal literal(s) in verify.py: {sorted(found - _SCANNED_LITERALS)} — "
        "catalogue them, then add them to _SCANNED_LITERALS"
    )
    assert not (_SCANNED_LITERALS - found), (
        f"the scan stopped matching known literal(s): {sorted(_SCANNED_LITERALS - found)} — "
        "a pattern rotted, or the code path was removed"
    )


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
