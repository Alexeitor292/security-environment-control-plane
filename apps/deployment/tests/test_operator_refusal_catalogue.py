"""The refusal catalogue is exhaustive, consistent, and drift-guarded (WS-E).

A catalogue that drifts from the code is worse than none — it would tell an operator a gap is
closable when it is not. Two complementary guards keep it honest:

* :func:`test_every_refusal_literal_is_catalogued` SCANS ``verify.py`` AND ``queue_check.py`` for
  refusal literals, so adding a new reason code in one of the matched shapes without cataloguing it
  fails here rather than surfacing to an operator as an unexplained string.
* the behavioural guard in ``test_operator_productization`` drives an all-unmet ladder and
  requires every rung's reason code to classify.

Scope, stated plainly rather than implied, and MEASURED rather than estimated — the numbers below
are asserted by :func:`test_the_scan_coverage_is_exactly_what_this_docstring_claims`, so they
cannot rot into decoration. The scan recognises five syntactic shapes across the two source files
and covers **27 of the 98** catalogued codes: 26 in ``verify.py``, and exactly one —
``operator_consumer_active`` — in ``queue_check.py``.

The ratio keeps getting WORSE as the catalogue grows, and that is the honest signal: every code
added so far has been raised in a module the scan does not read. Read the coverage as "this scan
guards one corner", never as "the catalogue is guarded".

Of the other 71, measured by asking whether the literal appears in each module outside the
catalogue block itself:

* **23 appear in ``verify.py``** in shapes no pattern matches: inline positional arguments to
  ``rung()`` (bare, or as the ``x or "literal"`` fallback), ``compositions_not_supplied`` inside a
  parenthesised conditional, ``queue_not_distinct`` as a conditional dict-literal value in
  ``_queue_section``, and the two ``expected_identities_*`` codes inside the conditional expression
  in ``_release_identity_section``. Two of the 23 (``identity_mismatch``, ``install_untrusted``)
  are filtered out DELIBERATELY because they double as status names. This measure OVER-COUNTS
  slightly and is left that way rather than tuned: ``operator_activation_sealed`` is matched
  because it is a report FIELD name in ``_read_seals``, not because ``verify.py`` refuses with it.
* **5 appear only in ``queue_check.py``** — ``attestation_provider_not_reviewed`` and
  ``controlled_live_runtime_not_provisioned``, passed positionally to ``SubmissionStop`` (the other
  two stop codes also occur in ``verify.py`` and are counted above);
  ``operator_consumer_unobservable`` as an ``x or "literal"`` fallback; ``submission_stop_open`` as
  a conditional dict-literal value; and ``submission_stop_unobservable`` reached through the
  ``STOP_UNOBSERVABLE`` module constant.
* **43 are raised elsewhere** — ``identities.py``, ``profile.py``, ``manifest.py``,
  ``compositions.py``, ``runtime_seams.py``, ``cli.py``, ``production_context.py``, ``runner.py``
  and ``secp_worker``. This bucket includes the four POSIX/backend refusals surfaced by the CLI's
  bounded guard and the nine ``expected_identities_*`` codes the pins reader raises — exactly the
  sort of addition a scan over two files cannot see. The pins codes have their own targeted guard
  in ``test_operator_release_provenance.py``, which scans ``identities.py`` directly, because they
  reach an operator through ``provenance`` and were uncatalogued until measured.

This 23/5/43 split is re-measured on every run by
:func:`test_the_blind_spot_breakdown_is_re_measured_not_remembered`, so the prose above cannot
quietly stop describing the code.

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

from secp_operator_deployment.queue_check import QUEUE_EXIT_CODES
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

_PKG = pathlib.Path(__file__).resolve().parents[1] / "secp_operator_deployment"
# Both modules that PRODUCE operator-visible reason codes from already-resolved inputs.
_SCANNED_SOURCES = (_PKG / "verify.py", _PKG / "queue_check.py")

# The measured coverage the module docstring states. Asserted below so the prose cannot drift.
_EXPECTED_COVERAGE = (27, 98)
# The measured blind-spot split: (in verify.py, in queue_check.py only, elsewhere).
_EXPECTED_BLIND_SPOTS = (23, 5, 43)

# The exact shapes a bounded reason code is produced in inside the scanned sources.
_REFUSAL_PATTERNS = (
    re.compile(r'return False, "([a-z0-9_]+)"'),
    re.compile(r'^\s*return "([a-z0-9_]+)"', re.MULTILINE),
    re.compile(r'getattr\(exc, "reason_code", "([a-z0-9_]+)"\)'),
    re.compile(r'"reason_code": "([a-z0-9_]+)"'),
    re.compile(r'profile_load_reason = "([a-z0-9_]+)"'),
)

# Status names are NOT reason codes; they are returned by the status resolvers / report builders.
_STATUS_NAMES = set(STATUS_EXIT_CODES) | set(PROVENANCE_EXIT_CODES) | set(QUEUE_EXIT_CODES)


def _refusal_literals() -> set[str]:
    found: set[str] = set()
    for source in _SCANNED_SOURCES:
        text = source.read_text(encoding="utf-8")
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
        "operator_consumer_active",  # queue_check.py — the only literal matched outside verify.py
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


def test_every_refusal_literal_is_catalogued():
    uncatalogued = sorted(c for c in _refusal_literals() if classify_reason_code(c) is None)
    assert not uncatalogued, f"uncatalogued reason codes in the scanned sources: {uncatalogued}"


def test_the_scan_coverage_is_exactly_what_this_docstring_claims():
    """The module docstring states how little this scan covers. Numbers that are only prose drift
    into decoration, so the two that matter are asserted."""
    assert (len(_refusal_literals()), len(REFUSAL_CATALOGUE)) == _EXPECTED_COVERAGE, (
        "scan coverage moved — re-measure and update BOTH the docstring and _EXPECTED_COVERAGE"
    )


def _blind_spot_split() -> tuple[int, int, int]:
    """Re-run the measurement the docstring reports: for every catalogued code the scan MISSES,
    does its literal appear in ``verify.py`` (outside the catalogue block, which would otherwise
    match everything), in ``queue_check.py`` only, or in neither?"""
    verify_src, queue_src = (s.read_text(encoding="utf-8") for s in _SCANNED_SOURCES)
    start = verify_src.index("REFUSAL_CATALOGUE: dict")
    verify_body = verify_src[:start] + verify_src[verify_src.index("\n}\n", start) :]

    missed = [c for c in REFUSAL_CATALOGUE if c not in _refusal_literals()]
    in_verify = [c for c in missed if f'"{c}"' in verify_body]
    in_queue = [c for c in missed if c not in in_verify and f'"{c}"' in queue_src]
    return len(in_verify), len(in_queue), len(missed) - len(in_verify) - len(in_queue)


def test_the_blind_spot_breakdown_is_re_measured_not_remembered():
    """A stated blind spot is only worth stating if it is still true. This recomputes the split
    rather than trusting the number written down when it was first measured."""
    assert _blind_spot_split() == _EXPECTED_BLIND_SPOTS, (
        "the blind-spot split moved — re-measure and update BOTH the docstring and "
        "_EXPECTED_BLIND_SPOTS"
    )


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
