"""The container tier for the ``enrollment`` and ``identity`` stages.

Drives the real supported interfaces across the two hosts and records all eleven checks the two
stages declare. Gated by :mod:`secp_acceptance.tier`: without ``SECP_ACCEPTANCE_TIER=container``
every node here is DESELECTED, and with it an absent runtime is a hard refusal rather than a skip.

ONE DRIVE, SHARED
-----------------
The exchange runs ONCE, in a module-scoped fixture, and every check reads its result. That is not an
optimisation — the invitation is single-use by design, so a per-test drive would need a fresh
invitation each time and each check would then be asserting about a different enrollment. The whole
point of the identity stage is that its assertions are about ONE exchange.

EVERY CHECK IS RECORDED, INCLUDING THE ONES THAT CANNOT BE SETTLED
------------------------------------------------------------------
``open_stage`` commits the run to covering every check the stage declares, and a check that is
omitted reads exactly like a check that passed. So each of the eleven records something. Where the
harness could not make the observation it records ``unproven``; where it observed the state the
check exists to rule out it records ``violated``. Neither is a pass.

Two groups are currently unsettleable, for two different reasons, and the distinction is load-
bearing:

* **No operator credential is provisioned yet.** Every controller-side command authenticates as an
  operator, and the acceptance fleet has no identity provider standing up a run-scoped realm. Those
  checks record ``unproven`` — the harness could not look.
* **The release aggregates cannot agree.** The invitation carries the CONTROLLER bundle's aggregate
  and the worker's record carries the WORKER bundle's; ``role`` is part of the canonical manifest
  the aggregate addresses, so no pair of role-checked bundles can make them equal. That one is
  ``violated`` where it is measured — a settled question, not a failure to look.

NOTHING HERE STUBS THE PROCESS SEAM
-----------------------------------
Every host effect goes through :mod:`secp_acceptance.shell`. A stage that stubs its host calls
fails the completion gate, and rightly: patching the seam bypasses the thing under test and yields a
document that looks real and is not. If a fast local loop is ever needed, patch ``subprocess.run``
INSIDE the seam.
"""

from __future__ import annotations

import uuid

import pytest
from secp_acceptance.enrollment import (
    InvitationArtifact as _Artifact,
)
from secp_acceptance.enrollment import (
    classify_identity_agreement,
    classify_invitation_one_shot,
    classify_private_key_containment,
    classify_release_agreement,
    controller_enrollment_status,
    create_invitation,
    deliver_invitation,
    observe_controller_state,
    observe_enroll_dry_run,
    observe_enrollment_inventory,
    observe_identity_survived_restart,
    observe_installation_id_agreement,
    observe_invitation_is_not_refetchable,
    observe_key_fingerprint_agreement,
    observe_private_key_containment,
    observe_release_agreement,
    observe_restart_marker,
    observe_worker_enrollment_key,
    observe_worker_key_identity,
    worker_enroll,
    worker_enroll_dry_run,
)
from secp_acceptance.reasons import STAGE_ENROLLMENT, STAGE_IDENTITY

pytestmark = pytest.mark.container_tier

#: The harness could not make the observation at all.
UNAVAILABLE = "acceptance_observation_unavailable"
#: The harness observed the exact state a check exists to rule out.
PROHIBITED = "acceptance_prohibited_state_observed"


@pytest.fixture(scope="module")
def site_label() -> str:
    """A run-scoped deployment-site label, so two runs never share a grouping."""
    return f"secp-acc-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def operator_token_path() -> str | None:
    """The protected operator token, or ``None`` when no credential is provisioned.

    ``None`` is the CURRENT STATE, not an error path: the acceptance fleet stands up no identity
    provider, and every controller command authenticates as an operator against one. Returning
    ``None`` rather than raising lets each controller-side check record ``unproven`` with a reason,
    which is the honest outcome — the alternative is a stage that errors out and records nothing,
    and a stage that records nothing is indistinguishable from a stage that passed.

    When a run-scoped realm exists this resolves to the token file and nothing else here changes.
    """
    return None


@pytest.fixture(scope="module")
def drive(acceptance_run, controller_host, worker_host, site_label, operator_token_path):
    """Run the exchange ONCE and hand every check the same result.

    Opens both stages up front. That is deliberate: opening a stage commits the run to covering all
    of its checks, so opening them here — before anything can fail — means a mid-drive failure still
    leaves the run obliged to account for all eleven, rather than quietly reducing its own scope.
    """
    acceptance_run.open_stage(STAGE_ENROLLMENT)
    acceptance_run.open_stage(STAGE_IDENTITY)

    result: dict[str, object] = {
        "artifact": None,
        "invitation_path": None,
        "dry_run": None,
        "enroll": None,
        "status": None,
        "token": operator_token_path,
    }
    if operator_token_path is None:
        return result

    code, artifact = create_invitation(
        controller_host,
        site_label=site_label,
        ttl_seconds=3600,
        token_path=operator_token_path,
    )
    if not isinstance(artifact, _Artifact):
        result["create_refusal"] = artifact
        return result
    result["artifact"] = artifact
    result["invitation_path"] = deliver_invitation(worker_host, artifact)
    result["dry_run"] = worker_enroll_dry_run(worker_host, str(result["invitation_path"]))[1]
    result["enroll"] = worker_enroll(worker_host, str(result["invitation_path"]))[1]
    result["status"] = controller_enrollment_status(
        controller_host,
        enrollment_id=artifact.enrollment_id,
        token_path=operator_token_path,
    )[1]
    return result


def _unproven(run, check: str, stage: str, why: str) -> None:
    run.unproven(check, stage, reason_code=UNAVAILABLE, observation={"unavailable": why})


# --------------------------------------------------------------------------- enrollment stage


def test_invitation_created(acceptance_run, drive):
    artifact = drive["artifact"]
    if artifact is None:
        _unproven(acceptance_run, "invitation_created", STAGE_ENROLLMENT, "no_operator_credential")
        return
    observed = artifact.projection()
    acceptance_run.observe("invitation_created", STAGE_ENROLLMENT, observed)
    assert observed["carries_no_secret_material"] is True
    assert observed["enrollment_id_wellformed"] is True


def test_invitation_is_one_shot(acceptance_run, drive):
    status = drive["status"]
    if status is None:
        _unproven(
            acceptance_run, "invitation_is_one_shot", STAGE_ENROLLMENT, "no_operator_credential"
        )
        return
    observed = observe_invitation_is_not_refetchable(status)
    verdict = classify_invitation_one_shot(observed, status_readable=True)
    if verdict.is_pass:
        acceptance_run.observe("invitation_is_one_shot", STAGE_ENROLLMENT, observed)
    else:
        acceptance_run.violated(
            "invitation_is_one_shot",
            STAGE_ENROLLMENT,
            reason_code=PROHIBITED,
            observation=observed,
        )
        pytest.fail(f"the status projection carries invitation material: {observed}")


def test_worker_enroll_dry_run_shows_fingerprint(acceptance_run, drive):
    artifact, report = drive["artifact"], drive["dry_run"]
    if artifact is None or report is None:
        _unproven(
            acceptance_run,
            "worker_enroll_dry_run_shows_fingerprint",
            STAGE_ENROLLMENT,
            "no_operator_credential",
        )
        return
    observed = observe_enroll_dry_run(report, artifact)
    acceptance_run.observe("worker_enroll_dry_run_shows_fingerprint", STAGE_ENROLLMENT, observed)
    assert observed["fingerprint_matches_invitation"] is True
    assert observed["no_mutation_claimed"] is True


def test_worker_enroll_reached_healthy(acceptance_run, drive):
    """Currently unreachable, and the reason is a product defect this harness measured.

    The worker's ``exact_release`` health probe requires the invitation's release digest to equal
    the worker's installed one. They are the aggregates of two different signed manifests whose
    ``role`` field is part of the canonical bytes, so no pair of role-checked bundles can make them
    equal, and the driver refuses ``enrollment_worker_health_incomplete`` before signing a result.
    """
    report = drive["enroll"]
    if report is None:
        _unproven(
            acceptance_run,
            "worker_enroll_reached_healthy",
            STAGE_ENROLLMENT,
            "no_operator_credential",
        )
        return
    observed = {
        "state": report.get("state"),
        "reason_code": report.get("reason_code", ""),
        "already_healthy": report.get("already_healthy"),
    }
    if report.get("state") == "healthy":
        acceptance_run.observe("worker_enroll_reached_healthy", STAGE_ENROLLMENT, observed)
        return
    # The drive stopped short, so what a COMPLETED enrollment would report was never observable.
    # That is `unproven`, not `violated` — the distinction the release check below does NOT share.
    acceptance_run.unproven(
        "worker_enroll_reached_healthy",
        STAGE_ENROLLMENT,
        reason_code=UNAVAILABLE,
        observation=observed,
    )


def test_controller_reports_healthy(acceptance_run, drive):
    status = drive["status"]
    if status is None:
        _unproven(
            acceptance_run, "controller_reports_healthy", STAGE_ENROLLMENT, "no_operator_credential"
        )
        return
    observed = observe_controller_state(status)
    if observed["healthy"]:
        acceptance_run.observe("controller_reports_healthy", STAGE_ENROLLMENT, observed)
        return
    acceptance_run.unproven(
        "controller_reports_healthy",
        STAGE_ENROLLMENT,
        reason_code=UNAVAILABLE,
        observation=observed,
    )


def test_enrollment_inventory_lists_enrollment(acceptance_run, controller_host, drive):
    """Recorded through the supported HTTPS API, not through a product client.

    There is no ``secpctl enrollment list`` and the management client has no list method, so this
    one observation is harness-authored. The origin, CA and bearer all come from the same
    bootstrap-recorded sources the product's own client uses; the caller declares the gap.
    """
    artifact, token = drive["artifact"], drive["token"]
    if artifact is None or token is None:
        _unproven(
            acceptance_run,
            "enrollment_inventory_lists_enrollment",
            STAGE_ENROLLMENT,
            "no_operator_credential",
        )
        return
    observed = observe_enrollment_inventory(
        controller_host, token_path=str(token), enrollment_id=artifact.enrollment_id
    )
    if observed["listed"]:
        acceptance_run.observe("enrollment_inventory_lists_enrollment", STAGE_ENROLLMENT, observed)
        return
    acceptance_run.unproven(
        "enrollment_inventory_lists_enrollment",
        STAGE_ENROLLMENT,
        reason_code=UNAVAILABLE,
        observation=observed,
    )


# --------------------------------------------------------------------------- identity stage


def test_worker_enrollment_key_protected(acceptance_run, worker_host, drive):
    observed = observe_worker_enrollment_key(worker_host)
    if observed["private_protected"] and observed["public_present"]:
        acceptance_run.observe("worker_enrollment_key_protected", STAGE_IDENTITY, observed)
        return
    if not observed["private_protected"] and observed.get("private_mode") is not None:
        # The pair EXISTS and its protection is wrong — observed, not unobserved.
        acceptance_run.violated(
            "worker_enrollment_key_protected",
            STAGE_IDENTITY,
            reason_code=PROHIBITED,
            observation=observed,
        )
        pytest.fail(f"the worker enrollment key is not protected as reviewed: {observed}")
    _unproven(
        acceptance_run, "worker_enrollment_key_protected", STAGE_IDENTITY, "no_enrollment_key"
    )


def _worker_key_id(worker_host) -> str:
    try:
        return observe_worker_key_identity(worker_host)["key_id"]
    except Exception:  # noqa: BLE001 - an unreadable anchor is an absent observation
        return ""


def test_worker_key_fingerprint_matches_controller(acceptance_run, worker_host, drive):
    status = drive["status"]
    observed = observe_key_fingerprint_agreement(
        worker_key_id=_worker_key_id(worker_host), status_report=status or {}
    )
    verdict = classify_identity_agreement(observed)
    _record(
        acceptance_run,
        "worker_key_fingerprint_matches_controller",
        STAGE_IDENTITY,
        verdict,
        observed,
    )


def test_worker_installation_id_matches_controller(acceptance_run, worker_host, drive):
    status = drive["status"]
    observed = observe_installation_id_agreement(
        worker_key_id=_worker_key_id(worker_host), status_report=status or {}
    )
    verdict = classify_identity_agreement(observed)
    _record(
        acceptance_run,
        "worker_installation_id_matches_controller",
        STAGE_IDENTITY,
        verdict,
        observed,
    )


def test_worker_private_key_never_left_worker(acceptance_run, worker_host, controller_host):
    """A whole-file search, and the residual is declared rather than implied.

    This catches a copy of the key file. It does NOT catch the key embedded inside a larger
    controller-side blob — a database page, an archive, a log line — because searching for embedded
    bytes would require transporting the private key off the worker, which is the thing under test.
    """
    try:
        observed = observe_private_key_containment(worker_host, controller_host)
    except Exception:  # noqa: BLE001 - an unavailable probe is an absent observation
        _unproven(
            acceptance_run,
            "worker_private_key_never_left_worker",
            STAGE_IDENTITY,
            "containment_probe_unavailable",
        )
        return
    verdict = classify_private_key_containment(observed)
    _record(
        acceptance_run, "worker_private_key_never_left_worker", STAGE_IDENTITY, verdict, observed
    )
    if verdict.outcome == "violated":
        pytest.fail("the worker's private enrollment key was found on the controller host")


def test_enrolled_release_equals_installed_release(acceptance_run, worker_host, drive):
    """The measured divergence. ``violated``, not ``unproven`` — see the module docstring."""
    artifact = drive["artifact"]
    if artifact is None:
        _unproven(
            acceptance_run,
            "enrolled_release_equals_installed_release",
            STAGE_IDENTITY,
            "no_operator_credential",
        )
        return
    observed = observe_release_agreement(worker_host, artifact=artifact)
    verdict = classify_release_agreement(observed)
    _record(
        acceptance_run,
        "enrolled_release_equals_installed_release",
        STAGE_IDENTITY,
        verdict,
        observed,
    )


def _record(run, check: str, stage: str, verdict, observation: dict) -> None:
    """Route a three-valued verdict to the recorder verb that matches it.

    One place, so a stage cannot record ``observed`` for a verdict that says otherwise. The
    ``is_pass`` branch is taken from the verdict rather than re-derived here, and the verdict's own
    predicate defers to the contract allowlist.
    """
    if verdict.is_pass:
        run.observe(check, stage, observation)
    elif verdict.outcome == "violated":
        run.violated(check, stage, reason_code=verdict.reason_code, observation=observation)
    else:
        run.unproven(check, stage, reason_code=verdict.reason_code, observation=observation)


# --------------------------------------------------------------------------- restart persistence


def test_identity_survives_a_worker_restart(fleet, worker_host, drive):
    """Performed here, recorded nowhere in this stage.

    The restart proves the identity is durable, which strengthens the identity stage's observations
    — but the CHECK IDS for it (``restart_worker_still_healthy``,
    ``restart_enrollment_state_survived``) belong to the lifecycle stage, and opening that stage
    would commit this run to all nine of its checks. So the observation is asserted here and the
    recording is the lifecycle stream's, using the same driver.
    """
    path = drive["invitation_path"]
    if path is None:
        pytest.skip("requires a POSIX fleet with a provisioned operator credential")
    from secp_acceptance.enrollment import restart_worker_host

    before = {
        **observe_worker_key_identity(worker_host),
        **observe_restart_marker(worker_host, str(path)),
    }
    restart_worker_host(fleet)
    after = {
        **observe_worker_key_identity(worker_host),
        **observe_restart_marker(worker_host, str(path)),
    }
    survived = observe_identity_survived_restart(before=before, after=after)
    assert survived["survived"] is True, f"identity did not survive the restart: {survived}"
