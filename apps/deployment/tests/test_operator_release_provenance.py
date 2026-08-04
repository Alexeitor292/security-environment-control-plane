"""RELEASE identity on the provenance report (WS-E).

``provenance`` already answered *does the installed content recompute to its reviewed aggregate*.
It did not answer *which RELEASE is this*, even though the independent trusted pins carry
``release_source_sha`` / ``source_tree_sha`` / ``parent_sha`` and ``require_profile_agreement``
already validates them. An operator could therefore confirm the package was internally consistent
without ever learning which release they were holding — which is the comparison the command exists
to enable.

Two properties carry the weight here:

* :func:`test_the_release_identity_comes_from_the_independent_pins_not_the_profile` — a profile
  must not be able to name its own release. The authority is the SEPARATE root-controlled
  expected-identities file, and the test proves the profile is not consulted by driving a profile
  that disagrees and observing the pins win.
* :func:`test_provenance_ok_never_claims_the_release_signature_was_checked` — this package verifies
  no signature. The risk is not that it claims to; it is that ``provenance_ok`` gets READ as one.
  ``release_signature_checked`` is present and ``False`` on every report, including the ok one, so
  the answer is in the payload rather than only in a runbook.

Scope kept deliberately tight, and stated: profile-to-pins AGREEMENT is dimension B and belongs to
``verify``. It is not re-derived here. Half-deriving the same fact in two commands is how the two
end up disagreeing.

Nothing here constructs a ``Worker``, submits a workflow, resolves a credential, or contacts any
infrastructure.
"""

from __future__ import annotations

import json

import pytest
from _deploy_support import SOURCE_SHA, SOURCE_TREE_SHA, valid_expected
from secp_operator_deployment.cli import VerifyDeps, run
from secp_operator_deployment.verify import (
    PROVENANCE_EXIT_CODES,
    build_provenance_report,
    classify_reason_code,
)

_AGG = "sha256:" + "a" * 64


def _report(**over):  # noqa: ANN003, ANN201
    kwargs = dict(
        source_aggregate=_AGG,
        installed_aggregate=_AGG,
        installed_trust_ok=True,
        covered_module_count=15,
        expected=valid_expected(),
    )
    kwargs.update(over)
    return build_provenance_report(**kwargs)


# --------------------------------------------------------------------------- the identity itself


def test_the_release_identity_is_reported_from_the_trusted_pins():
    section = _report()["release_identity"]
    assert section["available"] is True
    assert section["release_source_sha"] == SOURCE_SHA
    assert section["source_tree_sha"] == SOURCE_TREE_SHA
    assert section["authority"] == "independent_expected_identities"
    assert section["reason_code"] is None


def test_parent_sha_is_not_emitted_even_when_the_pins_carry_one():
    """It was emitted, and has been removed.

    The justification for this section is *these are the values you compare against the signed
    release* — and a signed release names its own commit and tree, not its parent. That argument
    never reached ``parent_sha``, which was also the only one of the three carrying commit-graph
    shape. A field that cannot be justified individually does not belong in a section whose whole
    defence is that every value in it is one an operator must compare.
    """
    section = _report(expected=valid_expected(parent_sha="c" * 40))["release_identity"]
    assert "parent_sha" not in section
    assert "c" * 40 not in json.dumps(_report(expected=valid_expected(parent_sha="c" * 40)))


def test_emission_is_bounded_structurally_not_by_convention():
    """``ExpectedDeploymentIdentities`` carries many fields; exactly two are emitted, by NAMED
    attribute read. The risk this pins is a future refactor to ``asdict()`` or iteration, which
    would turn every added field into an automatic leak."""
    import dataclasses

    from secp_operator_deployment.identities import ExpectedDeploymentIdentities

    all_fields = {f.name for f in dataclasses.fields(ExpectedDeploymentIdentities)}
    emitted = {"release_source_sha", "source_tree_sha"}
    assert emitted < all_fields

    # Scoped to the SECTION, deliberately. The report's other sections legitimately carry package
    # version / contract / implementation id, but they read them from MODULE CONSTANTS, not from
    # the pins — so asserting over the whole payload would flag a value that never came from here.
    section_blob = json.dumps(_report()["release_identity"])
    pins = valid_expected()
    for name in sorted(all_fields - emitted):
        value = getattr(pins, name)
        if isinstance(value, str) and len(value) > 8:  # bounded, comparable values only
            assert value not in section_blob, f"{name} leaked into release_identity"

    # The sensitive class the reviewer named, checked explicitly rather than only by sweep.
    for name in ("ordinary_task_queue", "operator_task_queue", "operator_service_name"):
        assert getattr(pins, name) not in section_blob, name


def test_the_release_identity_comes_from_the_independent_pins_not_the_profile():
    """A profile must not be able to name its own release.

    ``build_provenance_report`` takes no profile at all, which is the structural guarantee. This
    pins it: passing a profile-shaped object carrying a DIFFERENT release sha changes nothing,
    because it is not a parameter the builder has.
    """
    import inspect

    params = inspect.signature(build_provenance_report).parameters
    assert "profile" not in params, "provenance must not grow a profile input"
    assert "expected" in params

    section = _report(expected=valid_expected(release_source_sha="d" * 40))["release_identity"]
    assert section["release_source_sha"] == "d" * 40  # the PINS decided, nothing else


# --------------------------------------------------------------------------- refusal paths


def test_absent_pins_report_unavailable_rather_than_omitting_the_question():
    section = _report(expected=None)["release_identity"]
    assert section["available"] is False
    assert section["release_source_sha"] is None
    assert section["source_tree_sha"] is None
    assert section["reason_code"] == "expected_identities_not_provisioned"
    assert classify_reason_code(section["reason_code"]) == {
        "dimension": "B",
        "remediation": "reviewed_deployment_material",
    }


def test_a_supplied_read_failure_reason_is_preserved():
    """The CLI's bounded read failure must survive into the report, not be replaced by a generic."""
    section = _report(expected=None, expected_reason="expected_identities_type_invalid")[
        "release_identity"
    ]
    assert section["reason_code"] == "expected_identities_type_invalid"


def test_a_foreign_pins_object_is_refused_by_exact_type_without_being_read():
    """A duck-typed pins object is exactly how a false release identity would get in."""

    class _Forged:
        release_source_sha = "e" * 40
        source_tree_sha = "f" * 40
        parent_sha = None

        def __getattribute__(self, name):  # noqa: ANN001, ANN204
            raise AssertionError(f"foreign pins object was read: {name}")

    section = _report(expected=_Forged())["release_identity"]
    assert section["available"] is False
    assert section["release_source_sha"] is None
    assert section["reason_code"] == "expected_identities_type_invalid"


# --------------------------------------------------------------------------- the stated limits


def test_provenance_ok_never_claims_the_release_signature_was_checked():
    """The failure mode is an operator READING ``provenance_ok`` as a verified release."""
    report = _report()
    assert report["status"] == "provenance_ok"
    assert report["release_identity"]["release_signature_checked"] is False


@pytest.mark.parametrize(
    "over",
    [
        {},
        dict(expected=None),
        dict(installed_trust_ok=False),
        dict(source_aggregate=None),
        dict(installed_aggregate="sha256:" + "b" * 64),
    ],
)
def test_the_signature_claim_is_false_on_every_reachable_report(over):
    assert _report(**over)["release_identity"]["release_signature_checked"] is False


def test_the_release_identity_does_not_change_the_verdict():
    """Two facts, never merged. A missing release identity does not make the aggregate untrusted,
    and an untrusted aggregate does not blank the release identity."""
    assert _report(expected=None)["status"] == "provenance_ok"
    untrusted = _report(installed_trust_ok=False)
    assert untrusted["status"] == "provenance_untrusted"
    assert untrusted["release_identity"]["available"] is True


def test_provenance_does_not_re_derive_profile_agreement():
    """Dimension B belongs to ``verify``. Deriving it in two places is how they come to disagree."""
    assert "identity_agreement" not in _report()
    assert "profile" not in _report()


# --------------------------------------------------------------------------- shape + CLI


def test_the_section_shape_is_exact():
    """Pinned as a SET so a new emitted field is always a deliberate edit here."""
    expected_keys = {
        "available",
        "release_source_sha",
        "source_tree_sha",
        "authority",
        "release_signature_checked",
        "reason_code",
    }
    assert set(_report()["release_identity"]) == expected_keys
    # The unavailable path must not have a different shape — a caller reading one and not the other
    # would otherwise meet a missing key exactly when things are already going wrong.
    assert set(_report(expected=None)["release_identity"]) == expected_keys


def test_every_reason_code_the_pins_reader_can_raise_is_catalogued():
    """The production codes, not the synthetic ones.

    ``read_expected_identities`` raises specific codes — ``expected_identities_not_installed``,
    ``..._unreadable``, ``..._not_json`` and so on — and the ``provenance`` pins read passes them
    straight through. They were ALL uncatalogued while the generic codes the tests happened to use
    classified fine, so an operator meeting a real one got an unexplained string.

    Scans the reader's own source, so a newly added refusal fails here rather than in the field.
    """
    import pathlib
    import re

    src = (
        pathlib.Path(__file__).resolve().parents[1] / "secp_operator_deployment" / "identities.py"
    ).read_text(encoding="utf-8")
    raised = set(re.findall(r'IdentityError\("([a-z0-9_]+)"\)', src))

    assert len(raised) >= 9, f"the scan stopped matching IdentityError literals: {sorted(raised)}"
    uncatalogued = sorted(c for c in raised if classify_reason_code(c) is None)
    assert not uncatalogued, f"uncatalogued codes reachable from the pins read: {uncatalogued}"


def test_the_report_stays_json_serialisable_and_deterministic():
    a = json.dumps(_report(), sort_keys=True, separators=(",", ":"))
    b = json.dumps(_report(), sort_keys=True, separators=(",", ":"))
    assert a == b
    assert json.loads(a)["release_identity"]["available"] is True


def test_no_secret_bearing_profile_value_rides_along_with_the_release_identity():
    """The release shas are release IDENTIFIERS and are meant to be read. Nothing else is: no
    queue name, endpoint, path or credential may appear alongside them."""
    blob = json.dumps(_report(), sort_keys=True)
    for leaked in (
        "secp-orchestration",
        "secp-controlled-live-v1",
        "/etc/secp",
        "https://",
        "TEST-TOKEN",
        "vault",
    ):
        assert leaked not in blob, leaked


def test_the_cli_provenance_command_carries_the_release_identity():
    deps = VerifyDeps(
        source_aggregate=_AGG,
        installed_aggregate=_AGG,
        installed_trust_ok=True,
        expected=valid_expected(),
    )
    code, payload = run(["provenance", "--json"], deps)
    assert code == 0 == PROVENANCE_EXIT_CODES[payload["status"]]
    assert payload["release_identity"]["release_source_sha"] == SOURCE_SHA
    assert payload["release_identity"]["release_signature_checked"] is False


def test_the_cli_still_reports_a_release_identity_when_the_install_is_untrusted():
    """The identity is what an operator escalates WITH, so it must survive the failure path."""
    deps = VerifyDeps(
        source_aggregate=_AGG,
        installed_aggregate=None,
        installed_trust_ok=False,
        installed_trust_reason="manifest_trust_non_posix",
        expected=valid_expected(),
    )
    code, payload = run(["provenance", "--json"], deps)
    assert code == 15
    assert payload["status"] == "provenance_untrusted"
    assert payload["release_identity"]["release_source_sha"] == SOURCE_SHA
