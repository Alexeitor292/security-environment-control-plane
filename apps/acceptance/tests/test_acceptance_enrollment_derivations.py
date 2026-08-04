"""Hermetic guards for the enrollment + identity stage driver.

These tests create no host and contact nothing. They exist because
:mod:`secp_acceptance.enrollment` holds product paths and product identity derivations as REVIEWED
LITERALS rather than importing the management and API planes at run time — the same idiom
:mod:`secp_worker.enrollment_health_probes` uses for the two management document paths. A literal
that is merely *believed* to byte-match the product is a comparison between two values that can
silently start disagreeing, so every one of them is proven here against the product's own constant.

The test layer may import both planes; the harness may not. That asymmetry is the whole point.

DIRECTION OF FAILURE MATTERS
----------------------------
If a derivation drifted, a cross-host comparison would start failing and the check would record
``unproven`` — noisy, not silent, which is the safe direction. The dangerous drift is in the
PREDICATES: a conjunction that reads two absent values as agreement turns a run in which enrollment
never happened into a passing identity stage. Those predicates are pure functions here and are
tested against exactly that attack.

The embedded host programs are EXECUTED, not merely parsed. A syntax error or a wrong ``sys.argv``
index inside one of them would otherwise surface only in the container tier, minutes into a
privileged run.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest
from secp_acceptance.enrollment import (
    CONTROLLER_API_LOCATOR_PATH,
    ENROLLMENT_API_PREFIX,
    MANAGEMENT_WORKER_IDENTITY_PATH,
    OPERATOR_TOKEN_FILE_ENV,
    REQUIRED_INVITATION_KEYS,
    STATE_HEALTHY,
    WORKER_ENROLLMENT_PRIVATE_PATH,
    WORKER_ENROLLMENT_PUBLIC_PATH,
    WORKER_ENROLLMENT_ROOT,
    WORKER_ENROLLMENT_STATE_DIR,
    InvitationArtifact,
    containment_verdict,
    controller_key_fingerprint,
    observe_enroll_dry_run,
    observe_identity_survived_restart,
    observe_installation_id_agreement,
    observe_invitation_is_not_refetchable,
    observe_key_fingerprint_agreement,
    status_fingerprint,
    worker_installation_label,
)

# --------------------------------------------------------------------------- fixtures

_KEY_ID = "sha256:" + "3f" * 32
_OTHER_KEY_ID = "sha256:" + "a1" * 32
_RELEASE = "sha256:" + "b2" * 32

_CERTIFICATE_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


def _invitation_report(**overrides: object) -> dict:
    report = {
        "command": "enrollment invite create",
        "mode": "written",
        "enrollment_id": "sha256:" + "c3" * 32,
        "invitation_id": "sha256:" + "d4" * 32,
        "controller_installation_id": "controller-0011223344556677",
        "controller_key_id": _KEY_ID,
        "controller_trust_anchor_hex": "ee" * 32,
        "controller_origin": "https://controller.secp.test",
        "controller_ca_bundle_pem": _CERTIFICATE_PEM,
        "release_digest": _RELEASE,
        "transaction_id": "txn-" + "ff" * 16,
        "deployment_site_label": "secp-acc-site",
        "created_at": "2026-08-03T00:00:00Z",
        "expires_at": "2026-08-03T01:00:00Z",
        "state": "invited",
        "revision": 0,
    }
    report.update(overrides)
    return report


def _artifact(**overrides: object) -> InvitationArtifact:
    report = _invitation_report(**overrides)
    raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return InvitationArtifact(raw=raw, report=report)


# --------------------------------------------------------------------------- derivation parity

_FINGERPRINT_CORPUS = (
    "",
    "sha256:" + "ab" * 32,
    "ab" * 32,
    "sha256:short",
    "short",
    "sha256:" + "0123456789ab",
    "0123456789ab",
    "sha256:" + "0123456789a",
    "sha256:NOTHEXNOTHEXNOTHEX",
    "prefix:with:colons:" + "cd" * 32,
)


@pytest.mark.parametrize("value", _FINGERPRINT_CORPUS)
def test_status_fingerprint_byte_matches_the_api_projection(value: str):
    """The harness's fingerprint IS the controller's, including the conditional.

    The conditional is the part worth pinning: a short non-hex tail renders EMPTY on both sides, and
    the emptiness has to agree or the harness would compare a real fingerprint against a blank one.
    """
    from secp_api.worker_enrollment_contract import _fingerprint

    assert status_fingerprint(value) == _fingerprint(value)


@pytest.mark.parametrize("key_id", [_KEY_ID, _OTHER_KEY_ID, "sha256:" + "0" * 64, "bare-key-id"])
def test_worker_installation_label_byte_matches_the_worker_transport(key_id: str):
    """The label the harness compares against is the label the WORKER actually submits.

    This is the derivation that would have been easy to get wrong: the controller's
    ``worker_installation_id`` is derived from the enrollment KEY, not from the management
    bootstrap's ``installation_id``, and checking the bootstrap one would compare two unrelated
    values that can never match.
    """
    from secp_worker.enrollment_http_transport import _installation_from_key

    assert worker_installation_label(key_id) == _installation_from_key(key_id)


@pytest.mark.parametrize("key_id", [_KEY_ID, _OTHER_KEY_ID, "sha256:abc", "no-colon-here"])
def test_controller_key_fingerprint_byte_matches_secpctl(key_id: str):
    """The fingerprint the dry run shows an operator is the one the harness recomputes."""
    from secp_management.enrollment_cli import (
        controller_key_fingerprint as product_fingerprint,
    )

    assert controller_key_fingerprint(key_id) == product_fingerprint(key_id)


def test_every_reviewed_path_byte_matches_its_product_constant():
    """A drifted path does not fail loudly — it observes an ABSENT file, which several predicates
    would otherwise be free to interpret as a clean negative result."""
    from secp_management.controller_api_locator import (
        CONTROLLER_API_LOCATOR_PATH as product_locator,
    )
    from secp_management.operator_auth import OPERATOR_TOKEN_FILE_ENV as product_env
    from secp_worker.enrollment_health_probes import (
        MANAGEMENT_WORKER_IDENTITY_PATH as product_identity,
    )
    from secp_worker.enrollment_key import (
        WORKER_ENROLLMENT_KEY_PATH as product_private,
    )
    from secp_worker.enrollment_key import (
        WORKER_ENROLLMENT_PUBLIC_PATH as product_public,
    )
    from secp_worker.enrollment_key import (
        WORKER_ENROLLMENT_ROOT as product_root,
    )
    from secp_worker.enrollment_state_store import (
        WORKER_ENROLLMENT_STATE_DIR as product_state,
    )

    assert WORKER_ENROLLMENT_ROOT == product_root
    assert WORKER_ENROLLMENT_PRIVATE_PATH == product_private
    assert WORKER_ENROLLMENT_PUBLIC_PATH == product_public
    assert WORKER_ENROLLMENT_STATE_DIR == product_state
    assert MANAGEMENT_WORKER_IDENTITY_PATH == product_identity
    assert CONTROLLER_API_LOCATOR_PATH == product_locator
    assert OPERATOR_TOKEN_FILE_ENV == product_env


def test_invitation_contract_constants_match_the_product():
    """The required-field tuple and the API prefix are quoted from the product, not invented."""
    from secp_management.enrollment_cli import _REQUIRED_INVITATION_KEYS, _STATE_HEALTHY
    from secp_management.enrollment_controller_client import _API_PREFIX

    assert REQUIRED_INVITATION_KEYS == _REQUIRED_INVITATION_KEYS
    assert ENROLLMENT_API_PREFIX == _API_PREFIX
    assert STATE_HEALTHY == _STATE_HEALTHY


def test_the_supported_cli_surface_exists_under_the_names_the_driver_uses():
    """The driver spells the enrollment group ``enrollment invite create``.

    An earlier defect had the documentation say ``invitation create``, which does not exist. A
    harness written against the wrong name refuses at the argument parser, and that refusal is
    indistinguishable from a product that could not create an invitation — so the names are proven
    against the real parser here rather than trusted.
    """
    from secp_management.cli import build_parser

    parser = build_parser()
    for argv in (
        ["--json", "enrollment", "invite", "create", "--site", "s", "--write", "--confirm"],
        ["--json", "enrollment", "status", "--enrollment-id", "sha256:" + "0" * 64],
        ["--json", "worker", "enroll", "--invitation", "/run/x.json"],
        ["--json", "worker", "enroll", "--invitation", "/run/x.json", "--write", "--confirm"],
        ["--json", "worker", "enrollment", "status", "--invitation", "/run/x.json"],
    ):
        assert parser.parse_args(argv) is not None

    with pytest.raises(SystemExit):
        parser.parse_args(["enrollment", "invitation", "create", "--site", "s"])


# --------------------------------------------------------------------------- the invitation


def test_a_legitimate_invitation_passes_the_products_own_forbidden_scan():
    """The invitation is the one artifact that crosses hosts, so it is scanned with the product's
    own scanner. A certificate chain is public material and must pass."""
    assert _artifact().carries_no_secret_material() is True


def test_an_invitation_carrying_a_private_key_is_refused():
    """The scan is not decorative: substitute a PRIVATE KEY block for the certificate chain and the
    artifact reports that it carries secret material."""
    poisoned = _artifact(
        controller_ca_bundle_pem="-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
    )
    assert poisoned.carries_no_secret_material() is False


def test_the_invitation_projection_carries_no_origin_certificate_or_identifier():
    """Nothing in the projection is a host address, a certificate, or a raw identifier — only the
    shape facts the check asserts on."""
    projected = json.dumps(_artifact().projection())
    assert "controller.secp.test" not in projected
    assert "BEGIN CERTIFICATE" not in projected
    assert "txn-" not in projected


# --------------------------------------------------------------------------- one-shot


def test_a_status_projection_carrying_no_redeemable_field_proves_non_refetchability():
    """The real ``EnrollmentStatusOut`` field set, taken from the API schema rather than typed out
    here, must contain none of the redeemable invitation fields."""
    from secp_api.schemas_enrollment import EnrollmentStatusOut

    status = dict.fromkeys(EnrollmentStatusOut.model_fields, "value")
    observed = observe_invitation_is_not_refetchable(status)
    assert observed["not_refetchable"] is True
    assert observed["redeemable_fields_in_status"] == []


def test_a_status_projection_that_leaked_invitation_material_fails_the_check():
    """If a future status projection grew an invitation field, the check must fail rather than keep
    reporting the one-shot property it no longer has."""
    observed = observe_invitation_is_not_refetchable(
        {"enrollment_id": "x", "invitation_id": "sha256:leaked"}
    )
    assert observed["not_refetchable"] is False
    assert observed["redeemable_fields_in_status"] == ["invitation_id"]


# --------------------------------------------------------------------------- agreement predicates
#
# These are the false-pass attacks. Every predicate below must refuse to read two ABSENCES as
# agreement, because a run in which the exchange never reached the controller produces exactly that.


def test_two_absent_fingerprints_are_not_agreement():
    observed = observe_key_fingerprint_agreement(
        worker_key_id="", status_report={"worker_key_fingerprint": ""}
    )
    assert observed["agree"] is False


def test_two_absent_installation_ids_are_not_agreement():
    observed = observe_installation_id_agreement(
        worker_key_id="", status_report={"worker_installation_id": ""}
    )
    assert observed["agree"] is False


def test_an_absent_worker_key_never_manufactures_an_installation_label():
    """The asymmetry that made this worth its own test.

    ``worker_installation_label("")`` is ``"worker-"`` — a NON-EMPTY value derived from no
    observation at all. A predicate that only checked "the derived side is non-empty" would treat it
    as a real identity, and a controller that had recorded the literal ``worker-`` would match it.
    The gate is on the key id, so an absent observation derives nothing.
    """
    assert worker_installation_label("") == "worker-"
    observed = observe_installation_id_agreement(
        worker_key_id="", status_report={"worker_installation_id": "worker-"}
    )
    assert observed["derived_present"] is False
    assert observed["agree"] is False


def test_a_malformed_worker_key_id_never_agrees_with_anything():
    """Only a key id the worker could have derived from a real anchor is admissible on either
    predicate."""
    for bad in ("", "not-a-key-id", "sha256:short", "sha256:" + "Z" * 64):
        assert (
            observe_key_fingerprint_agreement(
                worker_key_id=bad, status_report={"worker_key_fingerprint": status_fingerprint(bad)}
            )["agree"]
            is False
        )
        assert (
            observe_installation_id_agreement(
                worker_key_id=bad,
                status_report={"worker_installation_id": worker_installation_label(bad)},
            )["agree"]
            is False
        )


def test_a_fingerprint_agrees_only_with_the_controllers_own_projection_of_the_same_key():
    """The positive case is derived through the product's own projection, so the test cannot pass by
    both sides sharing this module's arithmetic."""
    from secp_api.worker_enrollment_contract import _fingerprint

    recorded = _fingerprint(_KEY_ID)
    assert (
        observe_key_fingerprint_agreement(
            worker_key_id=_KEY_ID, status_report={"worker_key_fingerprint": recorded}
        )["agree"]
        is True
    )
    assert (
        observe_key_fingerprint_agreement(
            worker_key_id=_OTHER_KEY_ID, status_report={"worker_key_fingerprint": recorded}
        )["agree"]
        is False
    )


def test_an_installation_id_agrees_only_with_the_label_the_worker_would_submit():
    from secp_worker.enrollment_http_transport import _installation_from_key

    recorded = _installation_from_key(_KEY_ID)
    assert (
        observe_installation_id_agreement(
            worker_key_id=_KEY_ID, status_report={"worker_installation_id": recorded}
        )["agree"]
        is True
    )
    assert (
        observe_installation_id_agreement(
            worker_key_id=_OTHER_KEY_ID, status_report={"worker_installation_id": recorded}
        )["agree"]
        is False
    )


def test_the_bootstrap_installation_id_is_not_what_the_controller_records():
    """A guard against the exact wrong comparison. The management bootstrap's ``installation_id``
    for a worker is derived from the release aggregate, not from the enrollment key, so a harness
    that compared it against the controller's ``worker_installation_id`` would be comparing two
    unrelated values — and would fail permanently while looking like a product defect."""
    bootstrap_style = "worker-" + ("b2" * 32)[:16]
    assert worker_installation_label(_KEY_ID) != bootstrap_style


# --------------------------------------------------------------------------- dry run


def test_the_dry_run_check_recomputes_the_fingerprint_from_the_invitation():
    """The shown fingerprint is compared against one derived from the ARTIFACT, so a report echoing
    its own field back cannot satisfy the check."""
    artifact = _artifact()
    shown = controller_key_fingerprint(_KEY_ID)
    good = observe_enroll_dry_run(
        {"mode": "dry_run", "controller_key_fingerprint": shown}, artifact
    )
    assert good["fingerprint_matches_invitation"] is True
    assert good["no_mutation_claimed"] is True

    other = controller_key_fingerprint(_OTHER_KEY_ID)
    wrong = observe_enroll_dry_run(
        {"mode": "dry_run", "controller_key_fingerprint": other}, artifact
    )
    assert wrong["fingerprint_matches_invitation"] is False


def test_an_absent_fingerprint_never_satisfies_the_dry_run_check():
    observed = observe_enroll_dry_run({"mode": "dry_run"}, _artifact())
    assert observed["fingerprint_shown"] is False
    assert observed["fingerprint_matches_invitation"] is False


# --------------------------------------------------------------------------- key protection
#
# `_is_protected_file` is the predicate that decides whether the worker's enrollment key counts as
# protected, and it is a pure function of a metadata dict — so every way a key can be UNPROTECTED is
# testable here, with no filesystem and on every platform. The drift matrix below is the reason the
# symlink and permission tests further down are allowed to be POSIX-only: the predicate itself is
# fully covered here, and those two prove only that the PROBE reports the metadata faithfully.

_PROTECTED = {
    "present": True,
    "regular": True,
    "symlink": False,
    "directory": False,
    "nlink": 1,
    "uid": 0,
    "gid": 0,
    "mode": 0o600,
}


def test_the_reviewed_protected_observation_is_accepted():
    from secp_acceptance.enrollment import _is_protected_file

    assert _is_protected_file(_PROTECTED, mode=0o600) is True


@pytest.mark.parametrize(
    ("drift", "why"),
    [
        ({"present": False}, "an absent key is not a protected key"),
        ({"regular": False}, "a device node or fifo is not a key file"),
        ({"symlink": True}, "a symlink points somewhere this check never inspected"),
        ({"directory": True}, "a directory at the key path is drift, not a key"),
        ({"nlink": 2}, "a second name is a second path the key can be read from"),
        ({"uid": 1000}, "a key another uid owns is a key another uid can rewrite"),
        ({"gid": 1000}, "a foreign group on a root-owned key is drift"),
        ({"mode": 0o644}, "a world-readable private key is not protected"),
        ({"mode": 0o660}, "a group-writable private key is not protected"),
        ({"mode": 0o700}, "the mode is EXACT; near-enough is not the reviewed mode"),
    ],
)
def test_every_drifted_observation_is_refused(drift: dict, why: str):
    """One assertion per way the key can stop being protected.

    ``mode`` is checked for EXACT equality rather than "no group/other bits", mirroring
    ``secp_worker.enrollment_key._require_stat``: a key at 0o700 is not more protected than one at
    0o600, it is drift from the reviewed state, and a predicate that shrugged at it would also shrug
    at whatever produced the drift.
    """
    from secp_acceptance.enrollment import _is_protected_file

    assert _is_protected_file({**_PROTECTED, **drift}, mode=0o600) is False, why


def test_the_public_anchor_is_held_to_its_own_mode():
    """The two halves have different reviewed modes, and passing the private mode for the public
    anchor (or the reverse) must not be accepted by accident."""
    from secp_acceptance.enrollment import _is_protected_file

    anchor = {**_PROTECTED, "mode": 0o644}
    assert _is_protected_file(anchor, mode=0o644) is True
    assert _is_protected_file(anchor, mode=0o600) is False
    assert _is_protected_file(_PROTECTED, mode=0o644) is False


# --------------------------------------------------------------------------- containment


def test_containment_requires_a_real_key_digest():
    """An unreadable key yields an empty digest. "Empty appears in no set" is trivially true and
    must never be read as containment."""
    verdict = containment_verdict(
        key_digest="",
        controller_root_present=False,
        scan_complete=True,
        scanned_files=10,
        scanned_digests=frozenset(),
    )
    assert verdict["contained"] is False
    assert verdict["key_digest_observed"] is False


def test_an_incomplete_controller_scan_is_not_absence():
    """The single most important line in this stage: a walk that hit its cap has not looked
    everywhere it claimed to."""
    verdict = containment_verdict(
        key_digest="aa" * 32,
        controller_root_present=False,
        scan_complete=False,
        scanned_files=20001,
        scanned_digests=frozenset({"bb" * 32}),
    )
    assert verdict["contained"] is False
    assert verdict["controller_scan_complete"] is False


def test_a_whole_file_copy_on_the_controller_fails_containment():
    digest = "aa" * 32
    verdict = containment_verdict(
        key_digest=digest,
        controller_root_present=False,
        scan_complete=True,
        scanned_files=42,
        scanned_digests=frozenset({digest}),
    )
    assert verdict["contained"] is False
    assert verdict["no_whole_file_copy_on_controller"] is False


def test_the_enrollment_root_existing_on_the_controller_fails_containment():
    verdict = containment_verdict(
        key_digest="aa" * 32,
        controller_root_present=True,
        scan_complete=True,
        scanned_files=42,
        scanned_digests=frozenset(),
    )
    assert verdict["contained"] is False


def test_containment_holds_only_when_all_three_parts_hold():
    verdict = containment_verdict(
        key_digest="aa" * 32,
        controller_root_present=False,
        scan_complete=True,
        scanned_files=42,
        scanned_digests=frozenset({"bb" * 32}),
    )
    assert verdict["contained"] is True


# --------------------------------------------------------------------------- restart persistence


def test_two_absent_identities_do_not_survive_a_restart():
    """Nothing before and nothing after is not persistence."""
    observed = observe_identity_survived_restart(before={}, after={})
    assert observed["survived"] is False


def test_a_changed_key_id_does_not_survive_a_restart():
    observed = observe_identity_survived_restart(
        before={"key_id": _KEY_ID, "step": "healthy"},
        after={"key_id": _OTHER_KEY_ID, "step": "healthy"},
    )
    assert observed["survived"] is False
    assert observed["key_id_unchanged"] is False


def test_a_lost_marker_does_not_survive_a_restart():
    observed = observe_identity_survived_restart(
        before={"key_id": _KEY_ID, "step": "healthy"},
        after={"key_id": _KEY_ID, "step": ""},
    )
    assert observed["survived"] is False
    assert observed["marker_unchanged"] is False


def test_an_unchanged_identity_and_marker_survive_a_restart():
    observed = observe_identity_survived_restart(
        before={"key_id": _KEY_ID, "step": "healthy"},
        after={"key_id": _KEY_ID, "step": "healthy"},
    )
    assert observed["survived"] is True


# --------------------------------------------------------------------------- outcome classification
#
# THE VACUITY THESE TESTS ARE WRITTEN AGAINST
# -------------------------------------------
# A run-level assertion such as ``evidence.outcome == "failed"`` became unfalsifiable the moment a
# single-stage recorder could never be complete: it passes for a reason unrelated to what it
# watches, and would keep passing if a violation were encoded as ``observed``. Nothing here
# asserts a run
# outcome. Every assertion is at CHECK level — which outcome a specific observation earns — because
# that is the property this stage owns.
#
# Each classifier gets all three branches, and the pairs below are the point: the SAME check must
# reach different outcomes for "could not look" and "looked and found it".


def test_a_verdict_cannot_carry_a_reason_it_should_not_have():
    """The reason/outcome pairing is enforced where the verdict is decided, not at the recorder, so
    an incoherent pair cannot travel."""
    from secp_acceptance import AcceptanceError
    from secp_acceptance.enrollment import (
        OUTCOME_OBSERVED,
        OUTCOME_UNPROVEN,
        CheckVerdict,
    )

    assert CheckVerdict(OUTCOME_OBSERVED).is_pass is True
    with pytest.raises(AcceptanceError):
        CheckVerdict(OUTCOME_OBSERVED, "acceptance_observation_unavailable")
    with pytest.raises(AcceptanceError):
        CheckVerdict(OUTCOME_UNPROVEN)


def test_neither_violated_nor_unproven_is_ever_a_pass():
    """The single most important property of the three-valued scheme."""
    from secp_acceptance.enrollment import (
        OUTCOME_UNPROVEN,
        OUTCOME_VIOLATED,
        REASON_COULD_NOT_LOOK,
        REASON_PROHIBITED_STATE,
        CheckVerdict,
    )

    assert CheckVerdict(OUTCOME_VIOLATED, REASON_PROHIBITED_STATE).is_pass is False
    assert CheckVerdict(OUTCOME_UNPROVEN, REASON_COULD_NOT_LOOK).is_pass is False


def test_an_incomplete_containment_scan_is_unproven_but_a_found_key_is_violated():
    """The pair that makes the distinction real.

    Both are failures, and a scheme that only had ``unproven`` would render them identically — so a
    private key FOUND on the controller would be reported as an absence of evidence.
    """
    from secp_acceptance.enrollment import (
        OUTCOME_UNPROVEN,
        OUTCOME_VIOLATED,
        classify_private_key_containment,
        containment_verdict,
    )

    digest = "aa" * 32
    could_not_look = containment_verdict(
        key_digest=digest,
        controller_root_present=False,
        scan_complete=False,
        scanned_files=1,
        scanned_digests=frozenset(),
    )
    found_it = containment_verdict(
        key_digest=digest,
        controller_root_present=False,
        scan_complete=True,
        scanned_files=99,
        scanned_digests=frozenset({digest}),
    )
    clean = containment_verdict(
        key_digest=digest,
        controller_root_present=False,
        scan_complete=True,
        scanned_files=99,
        scanned_digests=frozenset({"bb" * 32}),
    )

    assert classify_private_key_containment(could_not_look).outcome == OUTCOME_UNPROVEN
    assert classify_private_key_containment(found_it).outcome == OUTCOME_VIOLATED
    assert classify_private_key_containment(clean).is_pass is True


def test_an_unreadable_key_is_unproven_not_containment():
    from secp_acceptance.enrollment import (
        OUTCOME_UNPROVEN,
        classify_private_key_containment,
        containment_verdict,
    )

    verdict = classify_private_key_containment(
        containment_verdict(
            key_digest="",
            controller_root_present=False,
            scan_complete=True,
            scanned_files=99,
            scanned_digests=frozenset(),
        )
    )
    assert verdict.outcome == OUTCOME_UNPROVEN


def test_an_unreadable_status_is_unproven_but_a_refetchable_invitation_is_violated():
    from secp_acceptance.enrollment import (
        OUTCOME_UNPROVEN,
        OUTCOME_VIOLATED,
        classify_invitation_one_shot,
    )

    leaked = observe_invitation_is_not_refetchable({"invitation_id": "sha256:leaked"})
    clean = observe_invitation_is_not_refetchable({"enrollment_id": "x", "state": "healthy"})

    assert classify_invitation_one_shot(clean, status_readable=False).outcome == OUTCOME_UNPROVEN
    assert classify_invitation_one_shot(leaked, status_readable=True).outcome == OUTCOME_VIOLATED
    assert classify_invitation_one_shot(clean, status_readable=True).is_pass is True


def test_a_missing_identity_is_unproven_but_a_disagreeing_one_is_violated():
    """A disagreement means the controller holds an identity that is not this worker's — observed,
    not unobserved. An absent side means the exchange may never have reached the controller."""
    from secp_acceptance.enrollment import (
        OUTCOME_UNPROVEN,
        OUTCOME_VIOLATED,
        classify_identity_agreement,
    )
    from secp_api.worker_enrollment_contract import _fingerprint

    absent = observe_key_fingerprint_agreement(
        worker_key_id=_KEY_ID, status_report={"worker_key_fingerprint": ""}
    )
    disagreeing = observe_key_fingerprint_agreement(
        worker_key_id=_KEY_ID, status_report={"worker_key_fingerprint": _fingerprint(_OTHER_KEY_ID)}
    )
    agreeing = observe_key_fingerprint_agreement(
        worker_key_id=_KEY_ID, status_report={"worker_key_fingerprint": _fingerprint(_KEY_ID)}
    )

    assert classify_identity_agreement(absent).outcome == OUTCOME_UNPROVEN
    assert classify_identity_agreement(disagreeing).outcome == OUTCOME_VIOLATED
    assert classify_identity_agreement(agreeing).is_pass is True


def test_the_same_three_way_split_applies_to_the_installation_id():
    from secp_acceptance.enrollment import (
        OUTCOME_UNPROVEN,
        OUTCOME_VIOLATED,
        classify_identity_agreement,
    )
    from secp_worker.enrollment_http_transport import _installation_from_key

    assert (
        classify_identity_agreement(
            observe_installation_id_agreement(
                worker_key_id="", status_report={"worker_installation_id": ""}
            )
        ).outcome
        == OUTCOME_UNPROVEN
    )
    assert (
        classify_identity_agreement(
            observe_installation_id_agreement(
                worker_key_id=_KEY_ID,
                status_report={"worker_installation_id": _installation_from_key(_OTHER_KEY_ID)},
            )
        ).outcome
        == OUTCOME_VIOLATED
    )


def test_a_measured_release_divergence_is_violated_not_unproven():
    """The program's most consequential product finding, and the outcome it earns.

    Both digests were READ. They differ. The harness settled the question rather than failing to
    look at it, so this is ``violated``. Recording it ``unproven`` would report a measured,
    reproducible disagreement as "we could not tell" — understating it in exactly the direction that
    gets a finding deprioritised.
    """
    from secp_acceptance.enrollment import (
        OUTCOME_UNPROVEN,
        OUTCOME_VIOLATED,
        classify_release_agreement,
    )

    measured_divergence = {
        "installed_present": True,
        "enrolled_present": True,
        "agree": False,
    }
    unreadable = {"installed_present": False, "enrolled_present": True, "agree": False}
    matching = {"installed_present": True, "enrolled_present": True, "agree": True}

    assert classify_release_agreement(measured_divergence).outcome == OUTCOME_VIOLATED
    assert classify_release_agreement(unreadable).outcome == OUTCOME_UNPROVEN
    assert classify_release_agreement(matching).is_pass is True


def test_every_violated_reason_is_a_harness_reason_never_a_product_one():
    """``violated`` is the HARNESS reporting what it saw. A product code here would attribute the
    harness's own observation to a product refusal that never happened.

    The contract ships ONE code for every violation rather than one per check, because the check id
    already names the property. An earlier draft of this module proposed four bespoke codes; this
    guard is what would have caught them never landing.
    """
    from secp_acceptance.enrollment import REASON_COULD_NOT_LOOK, REASON_PROHIBITED_STATE
    from secp_acceptance.reasons import HARNESS_REASONS, PRODUCT_REASONS

    for code in (REASON_PROHIBITED_STATE, REASON_COULD_NOT_LOOK):
        assert code in HARNESS_REASONS, "a harness outcome needs a harness reason"
        assert code not in PRODUCT_REASONS


def test_every_classifier_emits_only_contract_reasons():
    """Swept across all four classifiers and all three branches, so a bespoke code cannot survive in
    one seldom-exercised path."""
    from secp_acceptance.enrollment import (
        classify_identity_agreement,
        classify_invitation_one_shot,
        classify_private_key_containment,
        classify_release_agreement,
    )
    from secp_acceptance.reasons import ALL_REASONS, HARNESS_REASONS

    verdicts = [
        classify_private_key_containment({"key_digest_observed": False}),
        classify_private_key_containment(
            {"key_digest_observed": True, "controller_scan_complete": False}
        ),
        classify_private_key_containment(
            {"key_digest_observed": True, "controller_scan_complete": True, "contained": False}
        ),
        classify_invitation_one_shot({}, status_readable=False),
        classify_invitation_one_shot({"not_refetchable": False}, status_readable=True),
        classify_identity_agreement({"derived_present": False, "recorded_present": False}),
        classify_identity_agreement(
            {"derived_present": True, "recorded_present": True, "agree": False}
        ),
        classify_release_agreement({"installed_present": False, "enrolled_present": True}),
        classify_release_agreement(
            {"installed_present": True, "enrolled_present": True, "agree": False}
        ),
    ]
    assert verdicts, "the sweep must actually produce verdicts"
    for verdict in verdicts:
        assert verdict.reason_code in ALL_REASONS
        assert verdict.reason_code in HARNESS_REASONS
        assert verdict.is_pass is False


def test_the_module_imports_the_outcome_vocabulary_and_never_redeclares_it():
    """Structural, because the obvious runtime check cannot fail.

    ``enrollment.OUTCOME_OBSERVED is reasons.OUTCOME_OBSERVED`` looks like an identity assertion and
    is not one: CPython interns short string literals, so a local ``OUTCOME_OBSERVED = "observed"``
    shadowing the import satisfies it. That version of this test was written, and a mutant that
    replaced the import with local literals survived it.

    So the property is asserted where it is actually decidable — in the module's own syntax. The
    names must arrive by ``from secp_acceptance.reasons import ...`` and must never be assigned at
    module level. A drifted local copy would type-check, read correctly, and be refused by the
    evidence loader at the end of a privileged run.
    """
    import ast

    from secp_acceptance import enrollment, reasons

    pinned = {"OUTCOME_OBSERVED", "OUTCOME_UNPROVEN", "OUTCOME_VIOLATED", "PASSING_OUTCOMES"}
    tree = ast.parse(pathlib.Path(enrollment.__file__).read_text(encoding="utf-8"))

    imported = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "secp_acceptance.reasons"
        for alias in node.names
    }
    assert pinned <= imported, f"not imported from the contract: {sorted(pinned - imported)}"

    assigned = {
        target.id
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    } | {
        node.target.id
        for node in tree.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    assert not (pinned & assigned), f"redeclared locally: {sorted(pinned & assigned)}"

    # and the values really are the vocabulary's members
    for outcome in (
        enrollment.OUTCOME_OBSERVED,
        enrollment.OUTCOME_UNPROVEN,
        enrollment.OUTCOME_VIOLATED,
    ):
        assert outcome in reasons.OUTCOMES


def test_the_pass_predicate_is_the_contract_allowlist_not_a_local_denylist():
    """``violated`` must not pass, and neither must a fifth outcome added later.

    The predicate defers to ``PASSING_OUTCOMES``. A denylist ("pass unless unproven") would have
    admitted ``violated`` the moment it was introduced — which is precisely what happened to the
    contract's own predicate before it was repaired.
    """
    from secp_acceptance.enrollment import CheckVerdict
    from secp_acceptance.reasons import (
        OUTCOME_OBSERVED,
        OUTCOME_UNPROVEN,
        OUTCOME_VIOLATED,
        PASSING_OUTCOMES,
    )

    assert OUTCOME_VIOLATED not in PASSING_OUTCOMES
    assert OUTCOME_UNPROVEN not in PASSING_OUTCOMES
    assert OUTCOME_OBSERVED in PASSING_OUTCOMES
    assert CheckVerdict(OUTCOME_OBSERVED).is_pass is True
    assert CheckVerdict(OUTCOME_VIOLATED, "acceptance_prohibited_state_observed").is_pass is False
    assert CheckVerdict(OUTCOME_UNPROVEN, "acceptance_observation_unavailable").is_pass is False


# --------------------------------------------------------------------------- the embedded programs
#
# Executed, not merely parsed. These run inside a host in the container tier, where a wrong argv
# index costs a privileged rebuild to discover.


def _run_embedded(script: str, *args: str) -> object:
    completed = subprocess.run(  # noqa: S603 - argv list, harness-authored script, no shell
        [sys.executable, "-", *args],
        input=script.encode("utf-8"),
        capture_output=True,
        check=True,
        timeout=120,
    )
    return json.loads(completed.stdout.decode("utf-8"))


def test_the_stat_program_projects_metadata_and_reports_an_absent_path():
    from secp_acceptance.enrollment import _STAT_SCRIPT

    observed = _run_embedded(_STAT_SCRIPT, sys.executable, "/nonexistent/secp/acceptance/path")
    assert isinstance(observed, list) and len(observed) == 2
    assert observed[0]["present"] is True
    assert observed[0]["regular"] is True
    assert observed[1] == {"present": False}


def test_the_stat_program_does_not_follow_a_symlink(tmp_path):
    """``lstat``, not ``stat`` — and this is a security property, not a style choice.

    A key path replaced by a symlink to an attacker-readable copy is exactly the substitution
    ``secp_worker.enrollment_key._require_stat`` refuses. If the probe resolved the link it would
    report the TARGET's metadata: a plain root-owned 0600 regular file with ``symlink: false``, and
    :func:`_is_protected_file` would call the swapped key protected.
    """
    from secp_acceptance.enrollment import _STAT_SCRIPT, _is_protected_file

    target = tmp_path / "real"
    target.write_bytes(b"x")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):  # unprivileged Windows cannot create symlinks
        pytest.skip("requires POSIX symlink creation")
    (observed,) = _run_embedded(_STAT_SCRIPT, str(link))
    assert observed["symlink"] is True
    assert observed["regular"] is False
    assert _is_protected_file(observed, mode=observed["mode"]) is False


def test_the_stat_program_reports_a_hardlinked_file_and_the_predicate_refuses_it(tmp_path):
    """A second name for the key file is a second path from which it can be read.

    ``secp_worker.enrollment_key._require_stat`` refuses ``nlink != 1`` for exactly that reason, and
    this is the cross-platform half of the same property — the symlink case above needs privileges
    Windows does not grant, so without this one the whole "the key cannot be reached another way"
    projection would go unverified outside CI.
    """
    from secp_acceptance.enrollment import _STAT_SCRIPT, _is_protected_file

    target = tmp_path / "material"
    target.write_bytes(b"x")

    try:
        os.link(target, tmp_path / "second-name")
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("requires POSIX hard links")
    (observed,) = _run_embedded(_STAT_SCRIPT, str(target))
    assert observed["nlink"] == 2
    assert _is_protected_file(observed, mode=observed["mode"]) is False


def test_the_file_digest_program_digests_a_file_and_reports_an_unreadable_one(tmp_path):
    import hashlib

    from secp_acceptance.enrollment import _FILE_DIGEST_SCRIPT

    target = tmp_path / "material"
    target.write_bytes(b"acceptance-only\n")
    observed = _run_embedded(_FILE_DIGEST_SCRIPT, str(target), str(tmp_path / "absent"))
    assert observed == [hashlib.sha256(b"acceptance-only\n").hexdigest(), ""]


def test_the_tree_digest_program_finds_a_planted_file_and_reports_completeness(tmp_path):
    """Executed against a planted tree, so the walk is proven to FIND a matching whole file — a
    negative-result search that could not find anything would report a clean containment on every
    run."""
    import hashlib

    from secp_acceptance.enrollment import _TREE_DIGEST_SCRIPT

    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    (nested / "planted").write_bytes(b"private-key-lookalike\n")
    observed = _run_embedded(
        _TREE_DIGEST_SCRIPT, "1000", "1048576", str(tmp_path), "/nonexistent/secp/root"
    )
    assert observed["complete"] is True
    assert observed["files"] == 1
    assert hashlib.sha256(b"private-key-lookalike\n").hexdigest() in observed["digests"]


def test_the_tree_digest_program_reports_an_oversized_file_as_incomplete(tmp_path):
    """A file the walk declined to read leaves the search unable to claim absence."""
    from secp_acceptance.enrollment import _TREE_DIGEST_SCRIPT

    (tmp_path / "big").write_bytes(b"0" * 64)
    observed = _run_embedded(_TREE_DIGEST_SCRIPT, "1000", "8", str(tmp_path))
    assert observed["complete"] is False
    assert observed["digests"] == []


def test_the_tree_digest_program_reports_a_capped_walk_as_incomplete(tmp_path):
    """The cap exists so a runaway walk cannot exhaust the harness — and hitting it must never be
    reported as having looked everywhere."""
    from secp_acceptance.enrollment import _TREE_DIGEST_SCRIPT

    for index in range(5):
        (tmp_path / f"file{index}").write_bytes(bytes([index]))
    observed = _run_embedded(_TREE_DIGEST_SCRIPT, "2", "1048576", str(tmp_path))
    assert observed["complete"] is False


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX mode bits")
def test_the_tree_digest_program_reports_an_unreadable_file_as_incomplete(tmp_path):
    """An unreadable file is the quietest way a containment search can lie.

    The walk cannot digest it, so it cannot say the key is not in it. Recording that as a complete
    scan would let the strongest-sounding check in the identity stage rest on a directory the
    process could not read.
    """

    blocked = tmp_path / "blocked"
    blocked.write_bytes(b"unreadable\n")
    os.chmod(blocked, 0o000)
    if os.access(blocked, os.R_OK):  # running as root defeats the mode bits
        pytest.skip("requires a non-root POSIX process")
    from secp_acceptance.enrollment import _TREE_DIGEST_SCRIPT

    observed = _run_embedded(_TREE_DIGEST_SCRIPT, "1000", "1048576", str(tmp_path))
    assert observed["complete"] is False


def test_the_installed_release_program_projects_the_digest_and_tolerates_an_absent_document(
    tmp_path,
):
    from secp_acceptance.enrollment import _INSTALLED_RELEASE_SCRIPT

    document = tmp_path / "worker-identity.json"
    document.write_text(json.dumps({"role": "worker", "release_digest": _RELEASE}))
    assert _run_embedded(_INSTALLED_RELEASE_SCRIPT, str(document)) == {
        "release_digest": _RELEASE,
        "role": "worker",
    }
    assert _run_embedded(_INSTALLED_RELEASE_SCRIPT, str(tmp_path / "absent")) == {
        "release_digest": "",
        "role": "",
    }


def test_the_key_id_program_derives_the_product_key_id(tmp_path):
    """Run against the real ``key_id_for``, so the program the WORKER executes is proven to produce
    the identity the controller will later be compared against."""
    from secp_acceptance.enrollment import _KEY_ID_SCRIPT
    from secp_commissioning.enrollment_attestation import key_id_for

    public_hex = "7c" * 32
    anchor = tmp_path / "enrollment-key.pub"
    anchor.write_text(public_hex)
    assert _run_embedded(_KEY_ID_SCRIPT, str(anchor)) == {"key_id": key_id_for(public_hex)}


def test_the_inventory_program_installs_the_redirect_refusing_handler_it_defines():
    """The only embedded program that needs a live server to execute, so it is checked structurally.

    A redirect would forward the operator bearer to another origin — the one thing this request must
    never do — so both halves are pinned: the handler is DEFINED as an ``HTTPRedirectHandler``
    subclass that refuses, and the opener is built with THAT class. Checking only that the string
    ``HTTPRedirectHandler`` appears would survive a rename that leaves the opener referencing a name
    the module no longer defines: a NameError at request time, on a privileged run, minutes in.
    """
    import ast

    from secp_acceptance.enrollment import _INVENTORY_SCRIPT

    tree = ast.parse(_INVENTORY_SCRIPT)
    refusers = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        and any(
            isinstance(base, ast.Attribute) and base.attr == "HTTPRedirectHandler"
            for base in node.bases
        )
    ]
    assert len(refusers) == 1, "exactly one redirect handler must be defined"
    refuser = refusers[0]
    overrides = [n.name for n in refuser.body if isinstance(n, ast.FunctionDef)]
    assert overrides == ["redirect_request"]

    builders = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "build_opener"
    ]
    assert len(builders) == 1, "exactly one opener must be built"
    installed = {
        arg.func.id
        for arg in builders[0].args
        if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name)
    }
    assert refuser.name in installed, "the defined refuser must be the handler that is installed"

    # every name the program uses must be one it defines, imports, or binds — so a rename cannot
    # leave a dangling reference that only fails at request time
    compile(_INVENTORY_SCRIPT, "<inventory>", "exec")
    # TLS must pin the locator's CA — never system trust, never disabled
    assert "cafile=locator" in _INVENTORY_SCRIPT


# --------------------------------------------------------------------------- the lifecycle seam
#
# Handed to the lifecycle stream. The guards below are about the two things that stream can get
# wrong from outside this module: revoking with an unvalidated id, and revoking the WRONG
# enrollment.


def test_revoke_refuses_an_id_that_does_not_match_the_product_grammar():
    """The id reaches an argv, so it is validated against the same grammar the product's own client
    enforces rather than handed through and rejected downstream."""
    from secp_acceptance import AcceptanceError
    from secp_acceptance.enrollment import revoke_enrollment

    for bad in ("", "not-an-id", "sha256:short", "sha256:" + "Z" * 64, "sha256:" + "0" * 63):
        with pytest.raises(AcceptanceError):
            revoke_enrollment(None, enrollment_id=bad, expected_revision=0, token_path="/run/t")


def test_the_sacrificial_invitation_is_a_separate_enrollment_from_the_identity_one():
    """The lifecycle stream needs something it can destroy, and it must not be the enrollment the
    identity stage is asserting about.

    Pinned as a signature property: the helper takes its OWN site label, so a caller cannot reach
    for it without naming which enrollment it means. If this ever gained a default that matched the
    main run's label, destructive lifecycle work would land on the identity stage's enrollment and
    the identity stage would fail for a reason unrelated to identity.
    """
    import inspect

    from secp_acceptance.enrollment import create_sacrificial_invitation

    signature = inspect.signature(create_sacrificial_invitation)
    assert "site_label" in signature.parameters
    assert signature.parameters["site_label"].default is inspect.Parameter.empty
    assert signature.parameters["ttl_seconds"].default == 300


# --------------------------------------------------------------------------- the allowlist binders


def test_every_module_that_binds_the_pass_allowlist_is_known_to_the_guards():
    """A module that binds ``PASSING_OUTCOMES`` at import must be known to whoever narrows it.

    ``test_acceptance_outcome_allowlist.py`` proves the pass predicates are allowlists by narrowing
    ``PASSING_OUTCOMES`` and re-sealing. It patches ``recorder`` and ``evidence`` BY NAME, because a
    ``from ... import PASSING_OUTCOMES`` binds the value at import time and a patch of one module
    does not reach another. Its own comment says "BOTH modules" — an enumeration that was correct
    when written.

    This module then became the THIRD binder, and nothing would have said so. That is the shape of
    the hazard: in a half-patched world the unpatched predicate keeps answering from the REAL
    allowlist, so a narrowed run still reports its checks as passing and the test that was supposed
    to prove the allowlist is measuring only the modules someone remembered.

    So the binders are DISCOVERED from the package source rather than listed from memory. A fourth
    binder fails here, which is the moment to extend the patch set — not the moment someone notices
    a narrowing test that no longer narrows everything.

    TWO SYNTAXES BIND, NOT ONE. ``from secp_acceptance.reasons import PASSING_OUTCOMES`` is the
    obvious one. A module-level ``PASSING_OUTCOMES = reasons.PASSING_OUTCOMES`` binds the value at
    import exactly as hard, is invisible to an ``ImportFrom`` walk, and is what someone writes when
    they are avoiding a long import line. The first version of this guard saw only the first form —
    which would have made it a discovery that cannot discover the case most likely to be written by
    someone working around it. Both are detected.

    (Deliberately AST, not text. A ``grep`` for the name matches docstrings: the lifecycle stream
    ran exactly that search, got a hit in a module that only MENTIONS the constant in prose, and
    nearly reported a fourth binder that does not exist.)
    """
    import ast

    import secp_acceptance

    package = pathlib.Path(secp_acceptance.__file__).parent
    binders = set()
    for path in sorted(package.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        # form two: a module-level assignment to the name, whatever the right-hand side
        for node in tree.body:
            targets = (
                node.targets
                if isinstance(node, ast.Assign)
                else [node.target]
                if isinstance(node, ast.AnnAssign)
                else []
            )
            if (
                any(isinstance(t, ast.Name) and t.id == "PASSING_OUTCOMES" for t in targets)
                and path.name != "reasons.py"
            ):
                binders.add(path.name)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "secp_acceptance.reasons":
                if any(alias.name == "PASSING_OUTCOMES" for alias in node.names):
                    binders.add(path.name)

    assert binders == {"recorder.py", "evidence.py", "enrollment.py"}, (
        f"the set of modules binding PASSING_OUTCOMES changed: {sorted(binders)}. "
        "Every one of them must be patched by the allowlist-narrowing test, or that test "
        "silently stops measuring the ones it does not name."
    )


def test_the_binder_discovery_can_actually_fail():
    """Anti-vacuity for the sweep above: prove the discovery FINDS a binder rather than returning an
    empty set that would match nothing and pass by accident."""
    import ast

    import secp_acceptance

    package = pathlib.Path(secp_acceptance.__file__).parent
    recorder = ast.parse((package / "recorder.py").read_text(encoding="utf-8"))
    found = [
        alias.name
        for node in ast.walk(recorder)
        if isinstance(node, ast.ImportFrom) and node.module == "secp_acceptance.reasons"
        for alias in node.names
    ]
    assert "PASSING_OUTCOMES" in found, "the discovery cannot see a binder it is known to have"


def test_management_worker_status_is_independent_of_enrollment():
    """The two "healthy" facts this harness reports are genuinely different, and this pins it.

    ``observe_controller_state`` documents that the lifecycle stage's
    ``restart_worker_still_healthy`` is a MANAGEMENT-plane verdict unaffected by the defect, while
    ``controller_reports_healthy`` is the enrollment state machine. That claim is only safe while
    ``secpctl status worker`` really does ignore enrollment — so it is measured against the product
    rather than asserted in prose, and a future coupling fails here instead of quietly making one
    stage's result depend on the other's.
    """
    import ast

    import secp_management.engine as engine

    source = pathlib.Path(engine.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    status = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_worker_status"
    )
    body = (ast.get_source_segment(source, status) or "").lower()
    assert body, "the worker status implementation could not be read; this guard is not measuring"
    for token in ("enroll", "invitation", "offer_fingerprint", "worker_key_id"):
        assert token not in body, (
            f"secpctl status worker now references {token!r}; management-plane worker health and "
            "enrollment health are no longer independent, and observe_controller_state's docstring "
            "is wrong"
        )


def test_the_binder_discovery_sees_an_alias_binding_not_only_an_import():
    """The second form, proven on a synthetic module rather than trusted.

    A discovery that only understood ``from ... import`` would be blind to exactly the shape someone
    writes when they want the constant without the long import — and blindness in a guard whose
    whole job is enumeration is worse than not having the guard, because the empty result reads as
    "no new binders".
    """
    import ast
    import textwrap

    def binders_in(source: str) -> set[str]:
        tree = ast.parse(textwrap.dedent(source))
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "secp_acceptance.reasons":
                if any(a.name == "PASSING_OUTCOMES" for a in node.names):
                    found.add("import-form")
        for node in tree.body:
            targets = (
                node.targets
                if isinstance(node, ast.Assign)
                else [node.target]
                if isinstance(node, ast.AnnAssign)
                else []
            )
            if any(isinstance(t, ast.Name) and t.id == "PASSING_OUTCOMES" for t in targets):
                found.add("assign-form")
        return found

    assert binders_in("from secp_acceptance.reasons import PASSING_OUTCOMES") == {"import-form"}
    assert binders_in(
        """
        from secp_acceptance import reasons
        PASSING_OUTCOMES = reasons.PASSING_OUTCOMES
        """
    ) == {"assign-form"}
    assert binders_in(
        """
        from secp_acceptance import reasons
        PASSING_OUTCOMES: frozenset[str] = reasons.PASSING_OUTCOMES
        """
    ) == {"assign-form"}
    # late attribute access is NOT a binding and must not be reported as one
    assert (
        binders_in(
            """
        from secp_acceptance import reasons

        def is_pass(outcome):
            return outcome in reasons.PASSING_OUTCOMES
        """
        )
        == set()
    )
    # a docstring mention is not a binding either — the text-search false positive
    assert binders_in('"""PASSING_OUTCOMES is discussed here."""') == set()


def test_the_release_source_is_the_document_the_product_probe_reads():
    """The identity document, NOT the installed-release record. They are two different files.

    The release-installation stage publishes an ``installed_baseline`` fixture "for the enrollment,
    identity and lifecycle stages", and it reads
    ``ManagementLocations().release_record_path("worker")``. That is the right source for rollback
    and upgrade lineage. It is the WRONG source for this stage.

    ``enrolled_release_equals_installed_release`` exists to mirror what the product's own
    ``exact_release`` probe compares, and that probe reads the IDENTITY document. Sourcing this
    stage's side from the release record instead would produce a check that can disagree with the
    probe it is meant to reflect — passing where the product refuses, or failing where it does not.
    Either way the acceptance would be describing something other than the behaviour under test.

    So the two paths are pinned as DISTINCT, and this stage's source is pinned to the probe's. A
    future reader consolidating "two readers of the worker's release" into one would be merging two
    facts that only look alike.
    """
    from secp_management.layout import ManagementLocations
    from secp_worker.enrollment_health_probes import MANAGEMENT_WORKER_IDENTITY_PATH as probe_path

    locations = ManagementLocations()
    identity = locations.identity_path("worker")
    release_record = locations.release_record_path("worker")

    assert identity != release_record, "the two documents have become one; re-read this test"
    assert MANAGEMENT_WORKER_IDENTITY_PATH == identity
    assert MANAGEMENT_WORKER_IDENTITY_PATH == probe_path, (
        "this stage must read the same document the product's exact_release probe reads"
    )


# --------------------------------------------------------------------------- stage completeness


def test_the_container_stage_records_every_check_both_stages_declare():
    """The omission failure, caught without a fleet.

    ``open_stage`` commits the run to covering every check the stage declares, and a check that is
    never recorded reads exactly like a check that passed — the evidence document's completeness
    predicate is the only thing standing between those two, and it only runs at seal time, at the
    end of a privileged run that costs minutes to reach.

    So the check ids the container module mentions are read out of its SOURCE and compared against
    the two stages' declared sets. Adding a check to ``CHECKS_BY_STAGE`` without recording it, or
    deleting a recording call, fails here instead of at seal time.

    This is a completeness check, not a correctness one: it proves each id is MENTIONED, not that
    the right outcome is recorded for it. The classifier tests above own that half.
    """
    import ast

    from secp_acceptance.reasons import CHECKS_BY_STAGE, STAGE_ENROLLMENT, STAGE_IDENTITY

    module = pathlib.Path(__file__).parent / "test_acceptance_container_enrollment.py"
    tree = ast.parse(module.read_text(encoding="utf-8"))
    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }

    declared = set(CHECKS_BY_STAGE[STAGE_ENROLLMENT]) | set(CHECKS_BY_STAGE[STAGE_IDENTITY])
    assert declared, "the stages declare no checks; this guard is not measuring anything"

    missing = sorted(declared - literals)
    assert not missing, (
        f"the container stage never names these checks, so opening its stages would commit the run "
        f"to coverage it cannot deliver: {missing}"
    )


def test_the_container_stage_opens_only_the_two_stages_it_owns():
    """Opening a third stage would commit the run to checks this stream does not produce.

    The lifecycle stage is the live temptation: this module performs a worker restart, and its
    two natural check ids live there. Recording them would need ``open_stage(STAGE_LIFECYCLE)``,
    which commits to all nine lifecycle checks — seven of which belong to another stream.
    """
    import ast

    module = pathlib.Path(__file__).parent / "test_acceptance_container_enrollment.py"
    tree = ast.parse(module.read_text(encoding="utf-8"))
    opened = {
        node.args[0].id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "open_stage"
        and node.args
        and isinstance(node.args[0], ast.Name)
    }
    assert opened == {"STAGE_ENROLLMENT", "STAGE_IDENTITY"}, (
        f"this stream owns two stages; it opens {sorted(opened)}"
    )


def test_the_container_stage_node_count_is_registered():
    """The workflow pins the container-tier node count from this mapping, so a module that adds
    nodes without registering them makes the tier witness disagree with reality."""
    from secp_acceptance.tier import EXPECTED_CONTAINER_NODES_BY_MODULE

    assert EXPECTED_CONTAINER_NODES_BY_MODULE["test_acceptance_container_enrollment.py"] == 12


def test_the_container_stage_never_stubs_the_process_seam():
    """A stage that patches ``shell.run`` bypasses the very thing the completion gate counts.

    Patching ``subprocess.run`` INSIDE the seam is the supported way to get a fast loop; patching
    the seam itself produces a document that looks real and is not.
    """
    module = pathlib.Path(__file__).parent / "test_acceptance_container_enrollment.py"
    source = module.read_text(encoding="utf-8")
    for forbidden in ("monkeypatch.setattr", "shell.run", "mock.patch", "MagicMock"):
        assert forbidden not in source, f"the container stage must not stub the seam: {forbidden}"


def test_the_two_restart_observers_share_no_key_and_neither_says_state():
    """The third name collision in this harness, guarded rather than merely documented.

    ``state`` names two different facts: the worker's LOCAL restart marker
    (``unknown``/``offer_verified``/``healthy``) and the controller's AUTHORITATIVE enrollment
    state. ``observe_restart_marker`` renames its side to ``step`` for exactly that reason, and the
    rename is load-bearing rather than cosmetic — the container stage merges it with
    ``observe_worker_key_identity`` into one dict, so a shared key would let one observer silently
    overwrite the other and the restart proof would compare the wrong value while still passing.

    Two properties, both cheap and neither previously enforced: the marker observer must never
    surface ``state``, and the two observers merged either side of the restart must have DISJOINT
    key sets.

    This is the same species as the ``healthy`` collision and the two release documents. The domain
    names things after WHAT THEY DESCRIBE rather than WHICH SOURCE THEY CAME FROM, so the names
    collide before the facts do.
    """
    import ast

    from secp_acceptance import enrollment

    source = pathlib.Path(enrollment.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    def returned_keys(function_name: str) -> set[str]:
        fn = next(
            n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == function_name
        )
        keys: set[str] = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
                keys |= {
                    k.value
                    for k in node.value.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)
                }
        return keys

    marker = returned_keys("observe_restart_marker")
    identity = returned_keys("observe_worker_key_identity")

    assert marker, "the marker observer's keys could not be read; this guard is not measuring"
    assert identity, "the identity observer's keys could not be read; this guard is not measuring"
    assert "state" not in marker, (
        "observe_restart_marker surfaces 'state', which is the controller's word for a different "
        "fact; the local marker is 'step'"
    )
    assert not (marker & identity), (
        f"the two observers merged across the restart share keys {sorted(marker & identity)}; one "
        "would overwrite the other and the restart proof would compare the wrong value"
    )


# --------------------------------------------------------------------------- operator provisioning


def test_the_subject_matches_the_installation_stage_in_whichever_state_this_tree_is_in():
    """The one string both halves of the credential must agree on.

    The Keycloak user is created WITH this id, so the token's ``sub`` equals the
    ``app_user.subject`` the installation stage provisions. Disagree and the lookup finds no row,
    the request is unauthenticated, and it reads as a token defect — the failure the other stream
    warned about and the symmetric one I nearly caused from this side.

    Non-vacuous before and after the installation module arrives: today it pins the literal, so a
    typo fails; once that module is present it pins equality against its constant instead.
    """
    from secp_acceptance.enrollment import ACCEPTANCE_OPERATOR_SUBJECT

    try:
        from secp_acceptance.install import ACCEPTANCE_OPERATOR_SUBJECT as theirs
    except ImportError:
        assert ACCEPTANCE_OPERATOR_SUBJECT == "5ec9ad00-0000-4000-8000-acce97ab1e01"
        return
    assert ACCEPTANCE_OPERATOR_SUBJECT == theirs


def test_provisioning_returns_none_rather_than_raising_when_nothing_is_provisioned():
    """The honesty rule, at the one seam where the whole stage's authentication depends on it.

    A fixture that raises aborts the run and records NOTHING, and recording nothing is
    indistinguishable from passing. ``None`` lets every controller-side check record ``unproven``
    with a reason.

    Passing ``None`` as the host is deliberate: if either guard were removed the call would reach
    the host seam and fail on the ``None``, so this cannot pass by accident.
    """
    from secp_acceptance.enrollment import provision_operator_realm

    assert provision_operator_realm(None, admin_password="", client_secret="x") is None
    assert provision_operator_realm(None, admin_password="x", client_secret="") is None
    assert provision_operator_realm(None) is None


def test_provisioning_invents_no_credential_of_its_own():
    """Every secret is injected. A credential this module made up would be a value nobody could
    trace to a source, and the run would authenticate with something no reviewer had approved."""
    import inspect

    from secp_acceptance.enrollment import provision_operator_realm

    signature = inspect.signature(provision_operator_realm)
    assert signature.parameters["admin_password"].default == ""
    assert signature.parameters["client_secret"].default == ""


def test_the_realm_program_sets_the_user_id_explicitly():
    """The one-field mistake that costs a day.

    Keycloak puts the user id in ``sub``. Create the user without an explicit ``id`` and Keycloak
    assigns a random UUID, the controller-side row lookup returns zero rows, and every request is
    unauthenticated — presenting as a token or realm defect, which it is not.
    """
    import ast

    from secp_acceptance.enrollment import _REALM_SCRIPT

    tree = ast.parse(_REALM_SCRIPT)
    users_call = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "call"
        and node.args
        and "users" in ast.dump(node.args[0])
    ]
    assert len(users_call) == 1, "exactly one user-creation call is expected"
    payload = users_call[0].args[1]
    keys = {k.value for k in payload.keys if isinstance(k, ast.Constant)}
    assert "id" in keys, "the user must be created with an explicit id, or `sub` will not match"


def test_the_realm_program_declares_itself_disposable():
    """The realm carries the same warning the reviewed skeleton in the tree carries, so anyone who
    finds it in a running Keycloak knows what it is without reading this module."""
    from secp_acceptance.enrollment import _REALM_SCRIPT

    assert "DISPOSABLE" in _REALM_SCRIPT
    assert "UNSAFE FOR PRODUCTION" in _REALM_SCRIPT


def test_the_token_lands_somewhere_that_cannot_outlive_the_host():
    from secp_acceptance.enrollment import OPERATOR_TOKEN_HOST_PATH

    assert OPERATOR_TOKEN_HOST_PATH.startswith("/run/")


def test_the_realm_program_is_valid_python():
    from secp_acceptance.enrollment import _REALM_SCRIPT

    compile(_REALM_SCRIPT, "<realm>", "exec")


def test_the_operator_token_is_written_with_the_mode_the_product_requires():
    """0600, and the mode is the whole protection.

    ``ProtectedTokenFileProvider`` refuses anything that is not a plain, unlinked file owned by the
    invoking uid at EXACTLY 0600 — so a token written 0644 would be readable by every process on the
    host AND then refused by the product, presenting as an auth failure rather than as the exposure
    it is.

    This mutant survived the first sweep of this section: every other property of the provisioning
    path was pinned and the one that makes the file protected was not. Read out of the AST so the
    mode is checked where it is written rather than inferred from a docstring.
    """
    import ast

    from secp_acceptance import enrollment
    from secp_management.operator_auth import ProtectedTokenFileProvider  # noqa: F401

    tree = ast.parse(pathlib.Path(enrollment.__file__).read_text(encoding="utf-8"))
    fn = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "provision_operator_realm"
    )
    modes = [
        kw.value.value
        for node in ast.walk(fn)
        if isinstance(node, ast.Call)
        for kw in node.keywords
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant)
    ]
    assert modes == ["0600"], (
        f"the operator token must be written 0600 and nothing else; found {modes}"
    )
