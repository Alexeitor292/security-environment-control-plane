"""Drive the lifecycle stage's management-plane checks against a real worker host.

Six of the nine lifecycle checks are statements about the MANAGEMENT plane — restart, upgrade,
rollback — and none of them depends on enrollment. That is worth stating because the names invite
the opposite reading: ``restart_worker_still_healthy`` sounds like it needs a healthy enrollment and
does not. ``secpctl status worker`` derives its verdict from record revalidation, document
integrity, the observer and the end-state gate; there is no enrollment term in it. So these six run,
and mean what they say, on a fleet whose enrollment never reached ``healthy``.

The remaining three (``restart_enrollment_state_survived`` and the two ``recovery_required``
checks) need an enrollment to EXIST, not to be healthy, and are driven from the enrollment stream's
seams at integration.

WHY THIS TAKES A RECORDER RATHER THAN IMPORTING ONE
---------------------------------------------------
:class:`StageRecorder` here is a structural PROTOCOL, not an implementation. The installation
stream owns the concrete recorder that writes into the shared run, and this module is deliberately
written so it can be handed that object without importing it — no cross-stream import, private or
public, and nothing to rename when the streams integrate. It also makes every function below
testable against a recorder that only counts, which is what lets the hermetic tests assert that a
stage records exactly once per check on every path.

THE ORDERING IS LOAD-BEARING
----------------------------
The upgrade is attempted BEFORE the rollback, because ``rollback worker`` is the uninstall verb —
it removes the five managed documents — and every check after it would be observing a host with no
installation. The failed-upgrade injection runs before the good upgrade for the same reason in
reverse: if its restoration were imperfect, the checks that follow fail loudly instead of quietly
proceeding over a damaged install.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from secp_acceptance.hosts import Host
from secp_acceptance.lifecycle import (
    CLASSIFIED_MANAGED,
    CLASSIFIED_OTHER,
    LINEAR,
    REPORT_REFUSED,
    classification_verdict,
    document_snapshot,
    linear_successor_binding,
    managed_upgrade_classification,
    restoration_verdict,
    secpctl,
    upgraded_identity_verdict,
)
from secp_acceptance.reasons import STAGE_LIFECYCLE

#: The bounded reason a check carries when the harness could not make its observation at all.
UNOBSERVED = "acceptance_observation_unavailable"


@runtime_checkable
class StageRecorder(Protocol):
    """What this module needs from whatever records into the shared acceptance run.

    Structural rather than nominal on purpose: the concrete recorder belongs to another stream, and
    depending on its NAME would be a cross-stream coupling that breaks at integration — silently,
    if the name were private.
    """

    def observed(self, check: str, observation: object) -> None: ...

    def unproven(self, check: str, *, reason: str, observation: object) -> None: ...

    def violated(self, check: str, *, observation: object) -> None: ...

    def expect_refusal(
        self, check: str, *, expected: str, actual: str | None, observation: object
    ) -> bool:
        """Record a refusal the scenario REQUIRED, and return whether it was the expected one.

        The verb the failure-injection stage is built on. "The product refused" and "the product
        refused FOR THE REASON THAT MAKES THIS TEST MEANINGFUL" are different claims, and only the
        second is a pass — a refusal carrying some other bounded code is ``unproven`` with
        ``acceptance_unexpected_reason_code``, and no refusal at all is the worst outcome available
        to this stage.

        Without that distinction a failure-injection check is satisfied by ANY refusal, including
        one caused by the harness handing the product a malformed argument. The stage would then
        report that the product rejects tampered artifacts on the strength of it having rejected
        something.
        """
        ...


def _record(
    recorder: StageRecorder,
    check: str,
    *,
    ok: bool,
    observation: dict[str, object],
    reason: str,
    violated: bool = False,
) -> bool:
    """Record exactly one result for ``check``, and return whether it was positive.

    Every path through this function records. There is deliberately no way to call it and record
    nothing, which is what stops a stage being opened and then half-covered — the failure the
    recorder's stage contract exists to prevent.
    """
    if ok:
        recorder.observed(check, observation)
        return True
    if violated:
        recorder.violated(check, observation=observation)
        return False
    recorder.unproven(check, reason=reason, observation=observation)
    return False


# --------------------------------------------------------------------------- restart


def drive_restart(recorder: StageRecorder, worker: Host, restart: dict[str, object]) -> bool:
    """``restart_worker_still_healthy`` — still healthy after a real reboot of its host.

    ``restart`` is the enrollment stream's :func:`restart_worker_host` result: it restarts the host
    container and waits on the FLEET's own readiness predicate rather than a second, weaker
    definition of "up". This function only asks the management plane what it thinks afterwards.

    A restart that did not complete is ``unproven`` — the worker's health after a reboot that never
    happened is not evidence about durability.
    """
    check = "restart_worker_still_healthy"
    if not restart.get("restarted"):
        return _record(
            recorder,
            check,
            ok=False,
            observation={"restarted": False},
            reason=UNOBSERVED,
        )
    report = secpctl(worker, ("status", "worker"))
    healthy = report.flag("ok")
    observation: dict[str, object] = {
        "restarted": True,
        "report_readable": report.readable,
        "status_ok": healthy,
        "drift": (report.text("dimensions", "drift") or "")[:64],
    }
    if healthy is None:
        # No `ok` field at all: a report shape this harness does not understand. Not an unhealthy
        # worker — an unreadable answer, and the two must not blur.
        return _record(recorder, check, ok=False, observation=observation, reason=UNOBSERVED)
    # A worker that came back UNHEALTHY is a positive observation of the state this check rules out.
    return _record(
        recorder,
        check,
        ok=healthy,
        observation=observation,
        reason=UNOBSERVED,
        violated=not healthy,
    )


# --------------------------------------------------------------------------- upgrade


def drive_upgrade(
    recorder: StageRecorder,
    worker: Host,
    *,
    baseline: dict[str, object],
    successor: dict[str, object],
    successor_dir: str,
    observe_release,
    operator_dormancy=None,
) -> None:
    """The three upgrade checks, in the order the engine settles them.

    ``observe_release`` is the installation stream's ``observe_installed_release`` bound to this
    host — passed in rather than imported for the same reason as the recorder. It is called AFTER
    the write to obtain the second of the two independent readings the identity check needs.

    ``operator_dormancy`` is the queue stream's ``resolve_operator_unit_dormant`` already applied to
    a before/after pair, or ``None`` when that observation could not be made. Its verdict is adopted
    UNTRANSLATED: it is three-valued in the same vocabulary, and a translation layer here would be
    one more place for the values to collapse.
    """
    lineage = linear_successor_binding(baseline=baseline, successor=successor)

    # 1. classification, from the DRY RUN — settled before any host op, so a refused upgrade leaves
    #    the host untouched and the check still means something.
    plan = secpctl(worker, ("bootstrap", "worker", "--bundle", successor_dir))
    classified = classification_verdict(plan)
    observation: dict[str, object] = {
        **classified.observation,
        "lineage": lineage.verdict,
        "expected_classification": managed_upgrade_classification(),
    }
    admitted = _record(
        recorder,
        "upgrade_classified_managed_upgrade",
        ok=classified.verdict == CLASSIFIED_MANAGED,
        observation=observation,
        reason=classified.reason_code or UNOBSERVED,
        # A classification we READ that is not the required one is observed-false — but only when
        # the bundle really was a linear successor. If the lineage itself could not be established
        # we do not know what the product should have said, so nothing is proven either way.
        violated=classified.verdict == CLASSIFIED_OTHER and lineage.verdict == LINEAR,
    )

    # 2. the write, and the identity it produces
    if not admitted:
        # Nothing was written, so there is nothing to reobserve and no identity to bind. Both
        # remaining checks are unproven — recorded, never omitted.
        for check in ("upgrade_written_and_reobserved", "upgrade_operator_still_disabled"):
            _record(
                recorder,
                check,
                ok=False,
                observation={"upgrade_attempted": False},
                reason=UNOBSERVED,
            )
        return

    written = secpctl(
        worker, ("bootstrap", "worker", "--bundle", successor_dir, "--write", "--confirm")
    )
    after = observe_release()
    evidence = secpctl(worker, ("evidence", "worker"))
    ok, identity_observation = upgraded_identity_verdict(
        before=baseline, after=after, evidence=evidence
    )
    identity_observation["write_reported"] = written.text("mode") or ""
    identity_observation["write_refused"] = written.status == REPORT_REFUSED
    _record(
        recorder,
        "upgrade_written_and_reobserved",
        ok=ok and written.ok,
        observation=identity_observation,
        reason=written.reason_code or UNOBSERVED,
    )

    # 3. the operator unit is still dormant afterwards. An upgrade that activated it is the single
    #    prohibited state this stage shares with the queue stage.
    _record_dormancy(recorder, operator_dormancy)


def _record_dormancy(recorder: StageRecorder, verdict: object) -> None:
    """Adopt the queue stream's dormancy verdict for ``upgrade_operator_still_disabled``.

    Untranslated. That module already answers in a three-valued vocabulary with the product's own
    classifiers behind it — including the ``None`` an unrecognised systemd state produces, which
    must never collapse into "not enabled" — and re-deriving any of that here would be a second
    implementation to keep in step.
    """
    check = "upgrade_operator_still_disabled"
    if verdict is None:
        _record(
            recorder,
            check,
            ok=False,
            observation={"operator_unit_observed": False},
            reason=UNOBSERVED,
        )
        return
    state = getattr(verdict, "verdict", None)
    observation = dict(getattr(verdict, "observation", {}) or {})
    cause = getattr(verdict, "cause", None) or UNOBSERVED
    _record(
        recorder,
        check,
        ok=state == "held",
        observation=observation,
        reason=cause,
        violated=state == "violated",
    )


# --------------------------------------------------------------------------- rollback


def drive_rollback(recorder: StageRecorder, worker: Host) -> None:
    """The two rollback checks — the UNINSTALL verb, which is what ``secpctl rollback`` is.

    Runs LAST in the stage. It removes the five managed documents, so every check that needs an
    installation must already have been made. The dry run is verified to have removed nothing by
    re-reading the documents afterwards, because a plan that mutated would otherwise satisfy the
    same report as one that did not.
    """
    before = document_snapshot(worker, "worker")
    plan = secpctl(worker, ("rollback", "worker"))
    after_plan = document_snapshot(worker, "worker")
    listed = plan.field("removable_bindings")[1]
    bindings = listed if isinstance(listed, list) else []
    untouched = restoration_verdict(before, after_plan)
    _record(
        recorder,
        "rollback_plan_lists_documents",
        ok=bool(plan.ok and bindings and untouched.verdict == "restored"),
        observation={
            "listed": len(bindings),
            "declared_dry_run": plan.text("mode") == "dry_run",
            "documents_untouched_by_the_plan": untouched.verdict,
            "present_before": len(before.present_kinds),
        },
        reason=plan.reason_code or UNOBSERVED,
    )

    written = secpctl(worker, ("rollback", "worker", "--write", "--confirm"))
    after_write = document_snapshot(worker, "worker")
    removed = written.field("removed_bindings")[1]
    removed_list = removed if isinstance(removed, list) else []
    # Proven ABSENT, not merely reported gone. The snapshot distinguishes a document that is not
    # there from one the probe could not read, which is the difference between a removal we
    # observed and a removal we assumed.
    observation: dict[str, object] = {
        "removed_reported": len(removed_list),
        "listed_by_plan": len(bindings),
        "snapshot_complete": after_write.complete,
        "still_present": len(after_write.present_kinds),
        "ordinary_worker_restarted": written.flag("ordinary_worker_restarted"),
    }
    _record(
        recorder,
        "rollback_removed_documents",
        ok=bool(
            written.ok
            and removed_list
            and sorted(removed_list) == sorted(bindings)
            and after_write.complete
            and not after_write.present_kinds
        ),
        observation=observation,
        # Documents still present after a reported removal is a positive observation of the
        # prohibited state — but only when the snapshot was complete enough to say so.
        violated=bool(written.ok and after_write.complete and after_write.present_kinds),
        reason=written.reason_code or UNOBSERVED,
    )


__all__ = [
    "INJECTIONS",
    "STAGE_LIFECYCLE",
    "UNOBSERVED",
    "StageRecorder",
    "drive_dry_run_default",
    "drive_failure_injection",
    "drive_restart",
    "drive_rollback",
    "drive_upgrade",
]


# --------------------------------------------------------------------------- failure injection


#: Each injection: the check, the bounded PRODUCT code its refusal must carry, and a short note on
#: what is being injected. Read as a table because the stage's whole content is "we broke exactly
#: one thing and the product named it" — and the code it must name is what makes each row a
#: measurement rather than an assertion that something went wrong.
INJECTIONS: tuple[tuple[str, str, str], ...] = (
    (
        "wrong_role_bundle_refused",
        "release_role_mismatch",
        "a CONTROLLER bundle offered to the worker",
    ),
    ("tampered_artifact_refused", "release_artifact_digest_mismatch", "one artifact byte changed"),
    (
        "non_linear_upgrade_refused",
        "worker_upgrade_not_linear_successor",
        "parent_sha alone changed",
    ),
)


def drive_failure_injection(
    recorder: StageRecorder,
    worker: Host,
    *,
    bundles: dict[str, str],
) -> None:
    """The refusal-shaped injections that need only a worker host and a set of broken bundles.

    ``bundles`` maps each check id to the bundle directory prepared for it. A check with no bundle
    is recorded ``unproven`` rather than skipped: the stage contract commits the run to covering
    every declared check, and a missing fixture is a fact about the run, not a licence to omit.

    EACH INJECTION BREAKS EXACTLY ONE THING
    ---------------------------------------
    That is what makes the refusal attributable. A bundle that was both wrong-role AND tampered
    would refuse with whichever the engine checked first, and the row that did not fire would be
    unfalsifiable — passing because its sibling's defect was found. The single-field discipline is
    the same one that makes ``non_linear_upgrade_refused`` a measurement: it differs from the
    admitted upgrade in ``parent_sha`` alone.
    """
    for check, expected, _note in INJECTIONS:
        bundle = bundles.get(check)
        if not bundle:
            _record(
                recorder,
                check,
                ok=False,
                observation={"bundle_prepared": False},
                reason=UNOBSERVED,
            )
            continue
        report = secpctl(worker, ("bootstrap", "worker", "--bundle", bundle))
        # `actual=None` means the product did not refuse at all — the worst outcome for an
        # injection, and the recorder records it as such rather than as a pass.
        recorder.expect_refusal(
            check,
            expected=expected,
            actual=report.reason_code if report.status == REPORT_REFUSED else None,
            observation={
                "bundle_prepared": True,
                "refused": report.status == REPORT_REFUSED,
                "reason_code": (report.reason_code or "")[:64],
                "expected": expected,
            },
        )


def drive_dry_run_default(recorder: StageRecorder, worker: Host, invitation: str) -> None:
    """``enroll_without_write_confirm_is_dry_run`` — the DEFAULT is proven, not assumed.

    Not refusal-shaped, and that is the point: the claim is that omitting ``--write --confirm``
    yields a plan rather than a mutation. An installer whose "dry run" wrote anyway would satisfy
    a refusal-shaped check by not refusing, so this asserts the product's own declared mode.
    """
    check = "enroll_without_write_confirm_is_dry_run"
    report = secpctl(worker, ("worker", "enroll", "--invitation", invitation))
    mode = report.text("mode") or ""
    observation: dict[str, object] = {
        "report_readable": report.readable,
        "declared_mode": mode[:32],
        "declared_dry_run": mode == "dry_run",
    }
    if not report.readable:
        _record(recorder, check, ok=False, observation=observation, reason=UNOBSERVED)
        return
    # A product that WROTE without being asked is a positive observation of the prohibited state.
    _record(
        recorder,
        check,
        ok=mode == "dry_run",
        observation=observation,
        reason=report.reason_code or UNOBSERVED,
        violated=mode == "written",
    )
