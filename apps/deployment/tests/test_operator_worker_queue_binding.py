"""The operator's trusted pins are BOUND to the queue the shipped worker polls (queue-integration).

WHAT WAS OPEN, AND WHY NOTHING SAW IT
-------------------------------------
Three artefacts carry the ordinary queue name, and until this branch each was checked only against
its own neighbours:

* the **code literals** — six of them across five packages, proven equal to each other by
  ``tests/test_task_queue_consistency.py``. That guard reads only code, so profile/pins drift is
  invisible to it BY CONSTRUCTION, not by oversight.
* the **deployment profile** — read by ``queue_check``/``verify``'s ``isolation`` section, which
  tags itself ``authority: deployment_profile`` precisely so a green cannot be misread.
* the **independent trusted pins** — which ``require_profile_agreement`` binds the profile to.

The cycle never closed. ``require_profile_agreement`` makes the profile and the pins agree with EACH
OTHER; ``assert_expected_package_identity`` anchored the pins to code for eleven identities and, of
all the security-sensitive values, left exactly the queue pair unanchored. So profile == pins ==
"some-other-queue" verified green, correctly, on a host whose worker polls "secp-orchestration".
Measured at the merge head before this change: ``require_profile_agreement`` passed,
``assert_expected_package_identity`` passed, and ``build_queue_report`` returned
``queue_isolated_and_dormant`` with ``exit_code`` 0 and ``isolation.ok`` True.

WHAT THIS FILE PROVES, AND HOW IT AVOIDS PROVING NOTHING
--------------------------------------------------------
The load-bearing test is :func:`test_the_binding_follows_the_worker_not_a_copied_literal`. Asserting
that the pins equal "secp-orchestration" would pass just as well against a second hardcoded copy of
that string — the very defect being removed. So the binding is demonstrated by MOVING the worker's
declaration on the loaded ``Settings`` field and showing the operator-side verdict moves with it, in
BOTH directions: the value that was valid becomes refused, and the new value becomes accepted. A
copied literal cannot produce that pair of outcomes.

Every refusal is asserted on the EXACT ``reason_code``, so a swapped code cannot pass as the right
one. Set-membership comparison of the refusal codes is done in
``tests/test_queue_contract_integration.py``; this file asserts codes individually. (An earlier
version of this paragraph claimed the set comparison happened here too — it does not, and the
sentence was describing a stronger check than the code performs.)
"""

from __future__ import annotations

import pytest
from _deploy_support import ORDINARY_QUEUE, valid_expected, valid_profile
from secp_operator_deployment.identities import (
    IdentityError,
    assert_expected_package_identity,
    require_profile_agreement,
    worker_ordinary_task_queue,
)

#: The reason code the anchor raises. Named once so every assertion below refers to one string.
DRIFT_CODE = "expected_ordinary_queue_not_worker_queue"
SHARED_CODE = "expected_operator_queue_not_distinct"

#: A queue name no plane declares. Deliberately a plausible near-miss rather than nonsense — the
#: realistic drift is a version bump or a rename, not a typo that would be noticed by eye.
DRIFTED = "secp-orchestration-v2"


def _refusal(**over) -> str:
    """Run the pins-vs-code cross-check and return the bounded reason code it refused with."""
    with pytest.raises(IdentityError) as exc:
        assert_expected_package_identity(valid_expected(**over))
    return exc.value.reason_code


# --------------------------------------------------------------------------- the authority itself


def test_the_authority_is_the_setting_the_worker_hands_to_the_worker_constructor():
    """``worker_ordinary_task_queue`` reads the ``Settings`` attribute ``main`` actually uses.

    Read here from the loaded pydantic field independently of the production helper, so this is an
    agreement between two readings and not the helper agreeing with itself.
    """
    from secp_api.config import Settings

    field_default = Settings.model_fields["temporal_task_queue"].default
    assert worker_ordinary_task_queue() == field_default
    # Non-vacuity: an empty or None authority would make every comparison below trivially true.
    assert isinstance(field_default, str) and field_default != ""


def test_the_authority_is_not_redeclared_inside_the_deployment_package():
    """The fix must not add a SEVENTH copy of the name — it must bind to an existing one.

    Keyed on the package's own source rather than on the helper's return value: a helper that
    returned the right string while the package also hardcoded it would satisfy every other test in
    this file and reintroduce exactly the defect being closed.
    """
    import ast
    import pathlib

    import secp_operator_deployment

    pkg = pathlib.Path(secp_operator_deployment.__file__).parent
    offenders = []
    for path in sorted(pkg.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        literals = [
            n.value
            for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
        ]
        if worker_ordinary_task_queue() in literals:
            offenders.append(path.name)
    assert offenders == [], f"the deployment package hardcodes the ordinary queue name: {offenders}"


# --------------------------------------------------------------------------- the binding is real


def test_valid_pins_still_pass_so_the_check_is_not_simply_broken():
    """The control. Without it, every refusal below could be a check that refuses everything."""
    assert_expected_package_identity(valid_expected())  # no raise
    assert valid_expected().ordinary_task_queue == ORDINARY_QUEUE


def test_pins_naming_a_queue_the_worker_does_not_poll_are_refused():
    assert _refusal(ordinary_task_queue=DRIFTED) == DRIFT_CODE


def test_the_binding_follows_the_worker_not_a_copied_literal(monkeypatch):
    """Move the worker's declaration; the operator-side verdict must move with it.

    This is the whole point of the file. The four cells below are the 2x2 that separates a real
    binding from a coincidence: under the mutated authority the previously-VALID name is refused and
    the previously-INVALID name is accepted. A second hardcoded copy of "secp-orchestration" would
    pass cells 1 and 2 and fail cells 3 and 4.
    """
    from secp_api.config import Settings

    field = Settings.model_fields["temporal_task_queue"]
    original = field.default
    assert original == ORDINARY_QUEUE  # premise of the two "before" cells

    # cell 1 + 2 — before the mutation
    assert_expected_package_identity(valid_expected(ordinary_task_queue=original))  # accepted
    assert _refusal(ordinary_task_queue=DRIFTED) == DRIFT_CODE  # refused

    monkeypatch.setattr(field, "default", DRIFTED)

    # The substitution LANDED on the loaded object — checked on the object the production code
    # reads, not on source text, and through a second independent reading of it.
    assert Settings.model_fields["temporal_task_queue"].default == DRIFTED
    assert worker_ordinary_task_queue() == DRIFTED
    assert worker_ordinary_task_queue() != original

    # cell 3 + 4 — after the mutation, both verdicts have INVERTED
    assert_expected_package_identity(valid_expected(ordinary_task_queue=DRIFTED))  # now accepted
    assert _refusal(ordinary_task_queue=original) == DRIFT_CODE  # now refused


def test_the_previously_invisible_drift_is_now_the_only_new_refusal():
    """Profile and pins agreeing with each other on a wrong name is now caught — and ONLY that.

    Three separate readings, each asserted directly: ``require_profile_agreement`` still PASSES on
    the drifted pair (unchanged behaviour), ``assert_expected_package_identity`` REFUSES it with
    the exact code, and a correct deployment passes BOTH. That is what makes the new refusal the
    only one added.

    An earlier docstring here claimed the comparison was made "as SETS", with counts unable to
    hide a swap. This body builds no set and compares no before/after totals — the set comparison
    lives in ``tests/test_queue_contract_integration.py``, which genuinely does it over the
    refusal codes. Corrected rather than reworded: the sentence described a stronger check than
    the code performs.
    """
    profile = valid_profile(ordinary_task_queue=DRIFTED)
    expected = valid_expected(ordinary_task_queue=DRIFTED)

    # Unchanged: the two artefacts still agree with EACH OTHER. This is the state that used to be
    # indistinguishable from a correct deployment.
    require_profile_agreement(profile, expected)  # no raise — deliberately still passes

    # Changed: the pins can no longer agree with a queue the worker does not poll.
    with pytest.raises(IdentityError) as exc:
        assert_expected_package_identity(expected)
    assert exc.value.reason_code == DRIFT_CODE

    # And a fully correct deployment is untouched on both checks.
    require_profile_agreement(valid_profile(), valid_expected())
    assert_expected_package_identity(valid_expected())


def test_pins_alone_cannot_authorize_a_shared_queue():
    """``assert_expected_package_identity`` is called with the pins BEFORE the profile is resolved
    (``verify`` and ``compositions`` both do this), so the pins must be independently incapable of
    declaring one queue for both roles."""
    authority = worker_ordinary_task_queue()
    assert _refusal(operator_task_queue=authority) == SHARED_CODE


def test_no_catalogued_reason_code_is_declared_twice():
    """A colliding code would silently re-label an unrelated failure — and leave NO trace.

    ``REFUSAL_CATALOGUE`` is a dict literal, so a duplicate key is not an error: Python keeps the
    last and the collision is invisible at runtime. Both the count and the key set look healthy
    afterwards, which is why this is read from the SOURCE by AST rather than from the loaded dict.

    Supersedes an earlier version of this test that compared the new codes against
    ``_AGREEMENT_FIELDS``. Those are the 29 profile-vs-pins AGREEMENT codes, every one of them
    ``*_mismatch``; the codes added here are IDENTITY codes raised by
    ``assert_expected_package_identity`` and all begin ``expected_``. The two sets are disjoint by
    naming convention, so that assertion was structurally guaranteed to pass and established
    nothing about the 101 codes an operator actually meets.
    """
    import ast
    import pathlib

    import secp_operator_deployment.verify as verify_module

    tree = ast.parse(pathlib.Path(verify_module.__file__).read_text(encoding="utf-8"))
    catalogue_keys: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.AnnAssign)
            and getattr(node.target, "id", None) == "REFUSAL_CATALOGUE"
        ):
            assert isinstance(node.value, ast.Dict), "REFUSAL_CATALOGUE is no longer a dict literal"
            catalogue_keys = [k.value for k in node.value.keys if isinstance(k, ast.Constant)]
    assert catalogue_keys, "the catalogue literal was not found; this guard is reading nothing"

    duplicates = {code for code in catalogue_keys if catalogue_keys.count(code) > 1}
    assert duplicates == set(), f"reason codes declared more than once: {sorted(duplicates)}"

    # Non-vacuity: the AST read really did reach every entry, so an empty/partial parse cannot
    # masquerade as "no duplicates".
    assert len(catalogue_keys) == len(verify_module.REFUSAL_CATALOGUE)

    # The two codes this branch adds are among them, exactly once each.
    for code in (DRIFT_CODE, SHARED_CODE):
        assert catalogue_keys.count(code) == 1, code
    assert DRIFT_CODE != SHARED_CODE


def test_both_new_codes_are_catalogued_for_the_operator():
    """An uncatalogued refusal leaves an operator with a string and no remediation class."""
    from secp_operator_deployment.verify import REMEDIATION_CLASSES, classify_reason_code

    for code in (DRIFT_CODE, SHARED_CODE):
        entry = classify_reason_code(code)
        assert entry is not None, f"{code} is uncatalogued"
        assert entry["dimension"] == "B"
        assert entry["remediation"] in REMEDIATION_CLASSES


def test_the_refusal_reaches_the_operators_verify_report():
    """The check is only worth having if the READ-ONLY command an operator runs surfaces it.

    ``verify`` catches the IdentityError and reports it, so this asserts on the emitted section
    rather than on an exception — the form the operator actually meets.
    """
    from _deploy_support import host_evidence
    from secp_operator_deployment.verify import build_verification

    report = build_verification(
        profile=valid_profile(ordinary_task_queue=DRIFTED),
        expected=valid_expected(ordinary_task_queue=DRIFTED),
        host_observation=host_evidence(),
    )
    identity = report["identity_agreement"]
    assert identity["expected_provided"] is True
    assert identity["agrees"] is False
    assert identity["reason_code"] == DRIFT_CODE

    # Control: the same report on a correct deployment agrees, so the assertion above is about the
    # drift and not about this report never agreeing.
    ok = build_verification(
        profile=valid_profile(), expected=valid_expected(), host_observation=host_evidence()
    )
    assert ok["identity_agreement"]["agrees"] is True
    assert ok["identity_agreement"]["reason_code"] is None
    # The queue_separation section still reports GREEN on the drifted deployment — it reads the
    # profile, and the profile is internally consistent. That is not a defect in it; it is why the
    # identity anchor above had to exist. Pinned here so the division of labour stays legible.
    assert report["queue_separation"]["ok"] is True
    assert report["queue_separation"]["authority"] == "deployment_profile"
