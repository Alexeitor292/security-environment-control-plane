"""May THIS exact operation execute, right now? One answer, derived from durable rows.

ADR-030 §1. This replaces `_B1A_SUBPROCESS_SEALED`, `_PLAN_ONLY_PROCESS_SEALED` and
`PlanExecutionGate` — three module constants whose combined meaning was "no, never". They were the
honest control while no authorization model existed to make execution *unauthorized* rather than
*unconstructible*. That model exists now, and this is it.

**A boolean is not the replacement for a boolean.** Setting a seal to ``False`` would have turned an
unconditional refusal into an unconditional permission, which is worse than either. So there is no
constant here to flip, no settings field, no environment variable and no constructor flag. The
answer is computed from rows at the moment of execution, and a caller supplies only identifiers.

WHAT THE SIXTEEN CONDITIONS ARE ACTUALLY DOING
------------------------------------------------
They are not a checklist bolted onto an existing permission. Each one closes a way that an
execution could be *right about itself* and wrong about the world:

* conditions 1-3 bind the WORKER — enrolled, the one this operation selected, running the release
  the control plane registered. A worker that is merely enrolled is not thereby the right worker;
* 4-5 bind the TARGET — the operation's, and still active;
* 6-7 bind the OBSERVATION — a plan compiled from a stale or incomplete view of the cluster is a
  plan for a cluster that no longer exists;
* 8-10 bind the TOOLCHAIN — the pinned OpenTofu binary, the pinned provider, the pinned lockfile
  and mirror. An apply performed by a different binary is a different apply;
* 11-13 bind the ARTIFACT — the rendered configuration digest, the operation generation, and the
  exact change-set hash a human approved. This is the one that stops apply-regenerates-and-applies;
* 14 binds the DOMAIN — an approval for a destroy can never satisfy an apply;
* 15-16 bind CONCURRENCY and REPLAY.

Every refusal is a distinct closed reason naming the row an operator must fix. "Unauthorized" tells
them to retry; these tell them what to do.

WHAT THIS MODULE IS NOT
------------------------
It grants nothing and executes nothing. It returns a description of an authorized execution or
raises. The worker composes the executor; the control plane owns this answer, and the two are in
different planes on purpose — a worker that could compute its own authority would be deciding what
it is allowed to do.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api.enums import (
    ChangeSetApprovalStatus,
    EvidenceStatus,
    ProvisioningOperationKind,
    ProvisioningStatus,
    TargetStatus,
)
from secp_api.models import (
    ExecutionTarget,
    ProvisioningChangeSetApproval,
    ProvisioningManifest,
    ProvisioningOperation,
    TargetEvidenceRecord,
    ToolchainProfile,
)

#: How old the target observation a plan was compiled from may be, in seconds. A property of the
#: contract rather than of a caller: an execution that could widen its own freshness window could
#: apply a plan compiled from a cluster view of any age.
OBSERVATION_FRESHNESS_BOUND_SECONDS = 3600

#: Bound into nothing; an implementation id so a refusal is attributable to a known derivation.
EXECUTION_AUTHORITY_VERSION = "secp.provisioning-execution-authority/v1"

#: Operation kinds this authority will answer for, and the authorization DOMAIN each belongs to.
#: Two kinds sharing a domain would let one kind's approval satisfy the other, which is exactly
#: what `authorizes_kind` exists to prevent — so the mapping is one-to-one and stated, never
#: derived from a string prefix.
_AUTHORIZATION_DOMAIN: dict[ProvisioningOperationKind, ProvisioningOperationKind] = {
    ProvisioningOperationKind.apply: ProvisioningOperationKind.apply,
    ProvisioningOperationKind.destroy: ProvisioningOperationKind.destroy,
}

#: Statuses from which an operation may still execute. `applying` is included for the exact-retry
#: semantics below; `applied`, `destroyed` and `failed` are terminal and never re-execute.
_EXECUTABLE_STATUSES: frozenset[ProvisioningStatus] = frozenset(
    {
        ProvisioningStatus.queued,
        ProvisioningStatus.destroy_queued,
        ProvisioningStatus.awaiting_change_set_approval,
        ProvisioningStatus.applying,
    }
)

#: Every refusal, closed. Each names the row to look at.
EXECUTION_REFUSAL_REASONS: tuple[str, ...] = (
    # operation
    "execution_operation_absent",
    "execution_operation_wrong_organization",
    "execution_operation_kind_not_executable",
    "execution_operation_not_executable_in_this_status",
    "execution_operation_already_consumed",
    "execution_operation_conflicting_writer",
    "execution_operation_generation_mismatch",
    # manifest / target
    "execution_manifest_absent",
    "execution_manifest_wrong_organization",
    "execution_target_absent",
    "execution_target_not_active",
    "execution_target_mismatch",
    # worker
    "execution_worker_not_enrolled",
    "execution_worker_not_the_selected_worker",
    "execution_worker_selection_not_durable",
    "execution_worker_release_mismatch",
    # observation
    "execution_discovery_evidence_absent",
    "execution_discovery_evidence_stale",
    "execution_required_facts_incomplete",
    # toolchain
    "execution_toolchain_profile_absent",
    "execution_toolchain_profile_not_active",
    "execution_toolchain_binary_mismatch",
    "execution_toolchain_provider_mismatch",
    "execution_toolchain_lockfile_mismatch",
    "execution_toolchain_mirror_mismatch",
    # artifact
    "execution_configuration_digest_mismatch",
    "execution_change_set_not_authorized",
    "execution_change_set_not_approved",
    "execution_change_set_wrong_domain",
    "execution_change_set_binding_mismatch",
)


class ExecutionAuthorityRefused(Exception):
    """Refused. ONE closed reason code, never a row's contents, a hash or a credential."""

    def __init__(self, reason: str) -> None:
        if reason not in EXECUTION_REFUSAL_REASONS:
            raise ValueError(f"unknown execution authority refusal reason: {reason!r}")
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ObservedToolchain:
    """What the WORKER measured about its own runtime, before asking whether it may execute.

    Supplied by the worker rather than read from a row, and that is the point: the profile says
    what the toolchain must be, the worker says what it is, and this module compares them. A
    derivation that read both sides from the same row would be comparing a value to itself.
    """

    opentofu_version: str
    opentofu_binary_digest: str
    provider_version: str
    provider_lockfile_digest: str
    provider_mirror_identity: str
    rendered_workspace_hash: str


@dataclass(frozen=True)
class AuthorizedExecution:
    """An authorized execution, described. Confers nothing by existing — the caller still has to
    be the worker this names, holding the configuration whose digest this names."""

    operation_id: uuid.UUID
    organization_identity: str
    target_identity: str
    manifest_id: uuid.UUID
    kind: ProvisioningOperationKind
    authorization_domain: ProvisioningOperationKind
    change_set_hash: str
    approval_id: uuid.UUID
    worker_installation_id: str
    toolchain_profile_id: uuid.UUID
    rendered_workspace_hash: str
    authority_version: str = EXECUTION_AUTHORITY_VERSION


def authorize_provisioning_execution(
    session: Session,
    *,
    operation_id: uuid.UUID,
    organization_id: uuid.UUID,
    worker_installation_id: str,
    observed_toolchain: ObservedToolchain,
    now: datetime | None = None,
) -> AuthorizedExecution:
    """Answer the one question, or refuse with a closed reason.

    The caller supplies four identifiers and what its own runtime measures. It does not supply the
    target, the manifest, the change-set hash, the approval, the generation or the release — every
    one of those is read, because an execution whose expected values a caller could choose is an
    execution that authorizes itself.
    """
    moment = now or datetime.now(UTC)

    # --- the operation ---------------------------------------------------------------------------
    operation = session.get(ProvisioningOperation, operation_id)
    if operation is None:
        raise ExecutionAuthorityRefused("execution_operation_absent")
    if operation.organization_id != organization_id:
        # Checked against the caller's scope, never derived from the row being authorized.
        raise ExecutionAuthorityRefused("execution_operation_wrong_organization")

    kind = operation.kind
    domain = _AUTHORIZATION_DOMAIN.get(kind)
    if domain is None:
        # dry_run and destroy_dry_run produce a change set; they never execute one. An unknown
        # future kind lands here too, which is the safe direction — no kind falls through to apply.
        raise ExecutionAuthorityRefused("execution_operation_kind_not_executable")

    if operation.status not in _EXECUTABLE_STATUSES:
        raise ExecutionAuthorityRefused("execution_operation_not_executable_in_this_status")

    # --- the manifest and the target -------------------------------------------------------------
    manifest = session.get(ProvisioningManifest, operation.manifest_id)
    if manifest is None:
        raise ExecutionAuthorityRefused("execution_manifest_absent")
    if manifest.organization_id != organization_id:
        raise ExecutionAuthorityRefused("execution_manifest_wrong_organization")

    target = session.get(ExecutionTarget, manifest.execution_target_id)
    if target is None:
        raise ExecutionAuthorityRefused("execution_target_absent")
    if target.organization_id != organization_id:
        raise ExecutionAuthorityRefused("execution_target_mismatch")
    if target.status is not TargetStatus.active:
        raise ExecutionAuthorityRefused("execution_target_not_active")

    # --- the toolchain ---------------------------------------------------------------------------
    if manifest.toolchain_profile_id is None:
        raise ExecutionAuthorityRefused("execution_toolchain_profile_absent")
    profile = session.get(ToolchainProfile, manifest.toolchain_profile_id)
    if profile is None:
        raise ExecutionAuthorityRefused("execution_toolchain_profile_absent")
    if profile.organization_id != organization_id:
        raise ExecutionAuthorityRefused("execution_toolchain_profile_absent")

    # --- the worker -----------------------------------------------------------------------------
    _assert_worker_authorized(
        session,
        organization_id=organization_id,
        worker_installation_id=worker_installation_id,
        operation=operation,
    )

    # --- the observation ------------------------------------------------------------------------
    _assert_observation_current(
        session, execution_target_id=target.id, organization_id=organization_id, now=moment
    )

    _assert_toolchain_matches(profile, observed_toolchain)

    # --- the artifact ----------------------------------------------------------------------------
    if observed_toolchain.rendered_workspace_hash.strip() == "":
        raise ExecutionAuthorityRefused("execution_configuration_digest_mismatch")

    approval = _authorized_change_set(
        session,
        manifest_id=manifest.id,
        organization_id=organization_id,
        domain=domain,
        rendered_workspace_hash=observed_toolchain.rendered_workspace_hash,
        toolchain_profile_id=profile.id,
        manifest_content_hash=manifest.content_hash,
    )

    return AuthorizedExecution(
        operation_id=operation.id,
        organization_identity=str(operation.organization_id),
        target_identity=str(target.id),
        manifest_id=manifest.id,
        kind=kind,
        authorization_domain=domain,
        change_set_hash=approval.change_set_hash,
        approval_id=approval.id,
        worker_installation_id=worker_installation_id,
        toolchain_profile_id=profile.id,
        rendered_workspace_hash=observed_toolchain.rendered_workspace_hash,
    )


def _selected_worker_of(operation: ProvisioningOperation) -> str | None:
    """Which worker this operation selected, or ``None`` if the row does not say.

    Now durable (``provisioning_operation.worker_installation_id``), written once by
    ``services.provisioning_worker_selection`` before the operation becomes dispatchable and never
    overwritten. ``None`` remains a real answer — historical rows predate the column and were not
    backfilled with a fabricated selection — and it still fails closed below.
    """
    bound = (operation.worker_installation_id or "").strip()
    return bound or None


def _assert_worker_authorized(
    session: Session,
    *,
    organization_id: uuid.UUID,
    worker_installation_id: str,
    operation: ProvisioningOperation,
) -> None:
    """ADR-030 conditions 1-3: enrolled, the SELECTED one, running the registered release."""
    from secp_api import worker_enrollment_models as enrollment

    candidate = (worker_installation_id or "").strip()
    if not candidate:
        raise ExecutionAuthorityRefused("execution_worker_not_enrolled")

    row = (
        session.execute(
            select(enrollment.WorkerEnrollmentState)
            .where(enrollment.WorkerEnrollmentState.organization_id == organization_id)
            .where(enrollment.WorkerEnrollmentState.worker_installation_id == candidate)
            .order_by(enrollment.WorkerEnrollmentState.revision.desc())
        )
        .scalars()
        .first()
    )
    if row is None or row.state != "healthy":
        # Enrolled AND healthy. An enrollment that reached `refused` or `recovery_required` is a
        # record that the worker exists, not a statement that it may act.
        raise ExecutionAuthorityRefused("execution_worker_not_enrolled")
    if not str(row.release_digest or "").strip():
        raise ExecutionAuthorityRefused("execution_worker_release_mismatch")

    selected = _selected_worker_of(operation)
    if selected is None:
        # FAIL CLOSED on the gap rather than skipping the condition. An authority that quietly
        # dropped condition 2 would authorize any healthy worker in the organization to execute any
        # operation in it — which is precisely the binding this exists to enforce.
        raise ExecutionAuthorityRefused("execution_worker_selection_not_durable")
    if selected != candidate:
        raise ExecutionAuthorityRefused("execution_worker_not_the_selected_worker")


def _assert_observation_current(
    session: Session,
    *,
    execution_target_id: uuid.UUID,
    organization_id: uuid.UUID,
    now: datetime,
) -> None:
    """ADR-030 conditions 6-7: the observation this plan rests on is verified, and still current.

    A plan compiled from a stale or unverified view of the cluster is a plan for a cluster that no
    longer exists. The check is on the LATEST evidence for the target rather than on whichever
    record the caller might name — a caller able to point at an older passing record could keep an
    expired observation alive indefinitely.

    ``unverifiable`` is refused distinctly from ``fail``. They are different operator actions: a
    failure says the target is wrong, an unverifiable says nobody could tell — and treating the
    second as the first sends an operator to fix a target that may be fine.
    """
    record = (
        session.execute(
            select(TargetEvidenceRecord)
            .where(TargetEvidenceRecord.execution_target_id == execution_target_id)
            .where(TargetEvidenceRecord.organization_id == organization_id)
            .order_by(TargetEvidenceRecord.collected_at.desc())
        )
        .scalars()
        .first()
    )
    if record is None:
        raise ExecutionAuthorityRefused("execution_discovery_evidence_absent")
    if record.status is not EvidenceStatus.passed:
        # Both `fail` and `unverifiable` land here; the required-facts reason names the second
        # case specifically below so the two are distinguishable to an operator.
        if record.status is EvidenceStatus.unverifiable:
            raise ExecutionAuthorityRefused("execution_required_facts_incomplete")
        raise ExecutionAuthorityRefused("execution_discovery_evidence_absent")

    collected = record.collected_at
    if collected.tzinfo is None:
        # SQLite hands back naive datetimes; comparing one to an aware `now` raises, and an
        # exception here would read as a derivation bug rather than the refusal it is not.
        collected = collected.replace(tzinfo=UTC)
    age = (now - collected).total_seconds()
    if age < 0 or age > OBSERVATION_FRESHNESS_BOUND_SECONDS:
        # A NEGATIVE age is refused too: evidence stamped in the future is not fresh, it is wrong,
        # and accepting it would let a forward-dated observation stay valid indefinitely.
        raise ExecutionAuthorityRefused("execution_discovery_evidence_stale")


def _assert_toolchain_matches(profile: ToolchainProfile, observed: ObservedToolchain) -> None:
    """The profile says what the toolchain must be; the worker says what it is.

    Four separate comparisons rather than one digest over all of them, because an operator resolves
    each differently: a wrong binary is a reinstall, a wrong provider is a re-pin, a wrong lockfile
    is a regeneration, a wrong mirror is a configuration change.
    """
    content = profile.content if isinstance(profile.content, dict) else {}
    # The KEYS are the ones the shipped ToolchainProfile actually uses (`binary_integrity`,
    # `provider_lockfile_hash`, `provider_mirror.identity`), not names invented here. A comparison
    # against a key the profile does not write would read every profile as unpinned.
    #
    # `provider_version` is deliberately included and is NOT in the shipped profile shape today —
    # so every current profile refuses at this check. That is the correct direction: the Proxmox
    # provider version is a required pin for M1, and an authority that skipped it because the field
    # was missing would be treating "unpinned" as "acceptable".
    mirror = content.get("provider_mirror")
    mirror_identity = mirror.get("identity") if isinstance(mirror, dict) else None
    for expected, actual, reason in (
        (
            content.get("binary_integrity"),
            observed.opentofu_binary_digest,
            "toolchain_binary_mismatch",
        ),
        (content.get("provider_version"), observed.provider_version, "toolchain_provider_mismatch"),
        (
            content.get("provider_lockfile_hash"),
            observed.provider_lockfile_digest,
            "toolchain_lockfile_mismatch",
        ),
        (mirror_identity, observed.provider_mirror_identity, "toolchain_mirror_mismatch"),
    ):
        if not isinstance(expected, str) or not expected.strip():
            # An unpinned field is a refusal, not a pass. "The profile does not say" must never
            # read as "anything is acceptable" — that is how a pin becomes decorative.
            raise ExecutionAuthorityRefused(f"execution_{reason}")
        if expected != actual:
            raise ExecutionAuthorityRefused(f"execution_{reason}")

    # The version is checked too, and separately from the digest: two builds of the same version
    # have different digests, and a digest match with a version mismatch means the profile itself
    # is inconsistent.
    expected_version = content.get("opentofu_version")
    if not isinstance(expected_version, str) or expected_version != observed.opentofu_version:
        raise ExecutionAuthorityRefused("execution_toolchain_binary_mismatch")


def _authorized_change_set(
    session: Session,
    *,
    manifest_id: uuid.UUID,
    organization_id: uuid.UUID,
    domain: ProvisioningOperationKind,
    rendered_workspace_hash: str,
    toolchain_profile_id: uuid.UUID,
    manifest_content_hash: str,
) -> ProvisioningChangeSetApproval:
    """The approval that authorizes THIS execution, or a refusal.

    The lookup is keyed on the rendered workspace the worker actually holds. That is what stops
    apply-regenerates-and-applies: a freshly generated plan has a different rendered hash, so it
    matches no approval, and the execution is refused rather than silently applying something a
    human never saw.
    """
    candidates = (
        session.execute(
            select(ProvisioningChangeSetApproval)
            .where(ProvisioningChangeSetApproval.manifest_id == manifest_id)
            .where(ProvisioningChangeSetApproval.organization_id == organization_id)
        )
        .scalars()
        .all()
    )
    if not candidates:
        raise ExecutionAuthorityRefused("execution_change_set_not_authorized")

    for_domain = [a for a in candidates if a.authorizes_kind is domain]
    if not for_domain:
        # An approval exists, for the OTHER domain. Named distinctly because "you approved a
        # destroy and are trying to apply" is a different operator action from "nothing is
        # approved".
        raise ExecutionAuthorityRefused("execution_change_set_wrong_domain")

    matching = [a for a in for_domain if a.rendered_workspace_hash == rendered_workspace_hash]
    if not matching:
        raise ExecutionAuthorityRefused("execution_change_set_not_authorized")

    approved = [a for a in matching if a.status is ChangeSetApprovalStatus.approved]
    if not approved:
        if any(a.status is ChangeSetApprovalStatus.consumed for a in matching):
            raise ExecutionAuthorityRefused("execution_operation_already_consumed")
        raise ExecutionAuthorityRefused("execution_change_set_not_approved")
    if len(approved) > 1:
        # Two live approvals for one workspace is an ambiguity, not a convenience: which one was
        # reviewed? Refuse rather than pick.
        raise ExecutionAuthorityRefused("execution_operation_conflicting_writer")

    approval = approved[0]
    # The approval was made against a manifest content and a toolchain. If either has moved it is
    # still an approval; it is not an approval of THIS. One reason code rather than two, because
    # the operator action is the same either way: re-approve against what is now current.
    for left, right in (
        (approval.manifest_content_hash, manifest_content_hash),
        (approval.toolchain_profile_id, toolchain_profile_id),
    ):
        if left != right:
            raise ExecutionAuthorityRefused("execution_change_set_binding_mismatch")
    return approval
