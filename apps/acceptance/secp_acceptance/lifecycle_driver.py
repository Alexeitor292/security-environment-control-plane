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
    "STAGE_LIFECYCLE",
    "UNOBSERVED",
    "StageRecorder",
    "drive_restart",
    "drive_rollback",
    "drive_upgrade",
]
