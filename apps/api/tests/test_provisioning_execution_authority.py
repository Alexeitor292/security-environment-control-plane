"""May THIS exact operation execute, right now? The refusals are the content.

ADR-030 §1 replaced three module constants whose combined meaning was "no, never" with a derivation
over durable rows. A boolean is not the replacement for a boolean: flipping a seal to ``False``
would have turned an unconditional refusal into an unconditional permission, which is worse than
either. So what these tests prove is not "it can say yes" — it is that each condition says no on
its own, for its own reason, against real rows.

Nothing here executes anything. The derivation returns a description or raises.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.enums import (
    ChangeSetApprovalStatus,
    EvidenceStatus,
    ProvisioningOperationKind,
    ProvisioningStatus,
    TargetStatus,
)
from secp_api.models import (
    ProvisioningChangeSetApproval,
    ProvisioningManifest,
    ProvisioningOperation,
    TargetEvidenceRecord,
    ToolchainProfile,
)
from secp_api.provisioning_execution_authority import (
    EXECUTION_REFUSAL_REASONS,
    OBSERVATION_FRESHNESS_BOUND_SECONDS,
    AuthorizedExecution,
    ExecutionAuthorityRefused,
    ObservedToolchain,
    authorize_provisioning_execution,
)
from secp_api.services.provisioning_worker_selection import bind_provisioning_worker
from sqlalchemy import update
from tests.conftest import (  # type: ignore[import-not-found]
    VALID_TOOLCHAIN_PROFILE,
    build_provisioning_env,
)

NOW = datetime(2026, 8, 7, 12, 0, 0, tzinfo=UTC)
WORKER = "wk-exec-1"
WORKSPACE = "sha256:" + "w" * 64
MANIFEST_HASH = "sha256:" + "c" * 64

#: The profile the shipped fixture writes. It now carries the three provider pins itself, so this
#: file no longer patches one in: a test whose fixture differs from the shipped shape is a test of
#: the fixture.
PROFILE_CONTENT = dict(VALID_TOOLCHAIN_PROFILE)


def _observed(**overrides) -> ObservedToolchain:
    base = dict(
        opentofu_version=PROFILE_CONTENT["opentofu_version"],
        opentofu_binary_digest=PROFILE_CONTENT["binary_integrity"],
        provider_source=PROFILE_CONTENT["provider_source"],
        provider_version=PROFILE_CONTENT["provider_version"],
        provider_checksum=PROFILE_CONTENT["provider_checksum"],
        provider_lockfile_digest=PROFILE_CONTENT["provider_lockfile_hash"],
        provider_mirror_identity=PROFILE_CONTENT["provider_mirror"]["identity"],
        rendered_workspace_hash=WORKSPACE,
    )
    base.update(overrides)
    return ObservedToolchain(**base)


def build_manifest(session, principal, **kw) -> ProvisioningManifest:
    env = build_provisioning_env(session, principal)
    profile = ToolchainProfile(
        organization_id=principal.organization_id,
        execution_target_id=env.target.id,
        name="lab",
        version=1,
        runner_kind="opentofu",
        activation_class="isolated_lab",
        renderer_version="secp-002b-1a/renderer/v1",
        content=kw.get("profile_content", PROFILE_CONTENT),
        content_hash="sha256:" + "t" * 64,
    )
    session.add(profile)
    session.flush()

    manifest = ProvisioningManifest(
        organization_id=principal.organization_id,
        deployment_plan_id=env.plan.id,
        execution_target_id=env.target.id,
        target_config_hash=env.target.config_hash,
        toolchain_profile_id=profile.id,
        toolchain_profile_hash=profile.content_hash,
        content={"resources": []},
        content_hash=MANIFEST_HASH,
    )
    session.add(manifest)
    session.flush()
    manifest._secp_target = env.target  # test convenience only
    manifest._secp_profile = profile
    return manifest


def _enroll(session, principal, worker: str = WORKER, state: str = "healthy"):
    from secp_api import worker_enrollment_models as enrollment
    from sqlalchemy import select as _select

    existing = (
        session.execute(
            _select(enrollment.WorkerEnrollmentState).where(
                enrollment.WorkerEnrollmentState.worker_installation_id == worker
            )
        )
        .scalars()
        .first()
    )
    if existing is not None:
        existing.state = state
        session.flush()
        return

    session.add(
        enrollment.WorkerEnrollmentState(
            enrollment_id="sha256:" + hashlib.sha256(worker.encode()).hexdigest(),
            organization_id=principal.organization_id,
            deployment_site_label="site-a",
            contract_version="secp-enrollment/v1",
            state=state,
            revision=1,
            sequence=1,
            controller_installation_id="controller-installation-1",
            controller_key_id="sha256:" + "k" * 64,
            worker_installation_id=worker,
            worker_key_id="sha256:" + "a" * 64,
            release_digest="sha256:" + "r" * 64,
            transaction_id="txn-0001",
            expires_at=(NOW + timedelta(days=30)).isoformat(),
            updated_at=NOW.isoformat(),
            state_digest="sha256:" + "s" * 64,
            expires_at_ts=NOW + timedelta(days=30),
        )
    )
    session.flush()


def _evidence(session, principal, target, *, status=EvidenceStatus.passed, age_seconds=60):
    session.add(
        TargetEvidenceRecord(
            organization_id=principal.organization_id,
            onboarding_id=target.onboardings[0].id if target.onboardings else uuid.uuid4(),
            execution_target_id=target.id,
            evidence_source="worker",
            verification_level="strict",
            status=status,
            evidence_payload={"ok": True},
            findings=[],
            collected_at=NOW - timedelta(seconds=age_seconds),
            evidence_hash="sha256:" + "e" * 64,
        )
    )
    session.flush()


def _approval(session, principal, manifest, *, kind=ProvisioningOperationKind.apply, **kw):
    approval = ProvisioningChangeSetApproval(
        organization_id=principal.organization_id,
        manifest_id=manifest.id,
        toolchain_profile_id=kw.get("profile_id", manifest.toolchain_profile_id),
        authorizes_kind=kind,
        change_set_hash=kw.get("change_set_hash", "sha256:" + "5" * 64),
        rendered_workspace_hash=kw.get("workspace", WORKSPACE),
        manifest_content_hash=kw.get("manifest_hash", MANIFEST_HASH),
        toolchain_profile_hash="sha256:" + "t" * 64,
        target_scope_policy_hash="sha256:" + "p" * 64,
        reservations_hash="sha256:" + "v" * 64,
        renderer_version="secp-002b-1a/renderer/v1",
        module_bundle_hash="sha256:" + "ab" * 32,
        status=kw.get("status", ChangeSetApprovalStatus.approved),
    )
    session.add(approval)
    session.flush()
    return approval


def _scenario(session, principal, **kw):
    """A complete, authorizable execution. Each test breaks exactly one thing."""
    manifest = build_manifest(session, principal, **kw)
    target = manifest._secp_target
    if kw.get("target_status"):
        target.status = kw["target_status"]
    _enroll(session, principal, state=kw.get("enrollment_state", "healthy"))
    # Onboarding's simulated preflight ALREADY wrote a passing TargetEvidenceRecord for this target
    # (services/onboarding.py record_simulated_preflight). Layering a second one on top means an
    # "absent evidence" test still finds the fixture's record and an "aged" test still finds a fresh
    # one -- the assertion then passes or fails for a reason the test does not state. So each
    # scenario states the WHOLE evidence situation: clear the target's records, then write exactly
    # what this test means.
    #
    # Onboarding's simulated preflight ALREADY wrote a passing TargetEvidenceRecord for this target
    # (services/onboarding.py record_simulated_preflight), and it cannot be removed: the records are
    # append-only by ORM guard, and the onboarding row holds a foreign key to it. So the scenario
    # AGES it out of the way with a Core UPDATE -- the authority reads the LATEST record by
    # collected_at, so pushing the fixture's record into the far past makes the record this test
    # writes the one that decides, which is what each test's stated condition means.
    #
    # ``synchronize_session="fetch"`` rather than a blanket ``session.expire_all()``: the aged rows
    # must be visible to the ORM, but expiring the WHOLE identity map makes every later flush
    # reload every object the immutability guard walks in ``session.dirty`` -- which took this
    # module from 2 minutes to 2h39m. Synchronizing only the rows this statement touched keeps the
    # visibility and drops the cost.
    session.execute(
        update(TargetEvidenceRecord)
        .where(TargetEvidenceRecord.execution_target_id == target.id)
        .values(collected_at=NOW - timedelta(days=365)),
        execution_options={"synchronize_session": "fetch"},
    )
    if kw.get("evidence", True):
        _evidence(
            session,
            principal,
            target,
            status=kw.get("evidence_status", EvidenceStatus.passed),
            age_seconds=kw.get("evidence_age", 60),
        )
    op = ProvisioningOperation(
        organization_id=principal.organization_id,
        manifest_id=manifest.id,
        kind=kw.get("kind", ProvisioningOperationKind.apply),
        status=kw.get("status", ProvisioningStatus.queued),
        idempotency_key=uuid.uuid4().hex,
    )
    session.add(op)
    session.flush()
    if kw.get("bind", True):
        bind_provisioning_worker(
            session, operation=op, worker_installation_id=kw.get("bound_worker", WORKER)
        )
    if kw.get("approval", True):
        approval_kw = {
            k: v
            for k, v in kw.items()
            if k
            in {"change_set_hash", "workspace", "manifest_hash", "status_override", "profile_id"}
        }
        if "status_override" in approval_kw:
            approval_kw["status"] = approval_kw.pop("status_override")
        _approval(
            session,
            principal,
            manifest,
            kind=kw.get("approval_kind", op.kind),
            **approval_kw,
        )
    session.flush()
    return op, manifest, target


def _authorize(session, principal, op, **kw):
    return authorize_provisioning_execution(
        session,
        operation_id=op.id,
        organization_id=principal.organization_id,
        worker_installation_id=kw.get("worker", WORKER),
        observed_toolchain=kw.get("observed", _observed()),
        now=kw.get("now", NOW),
    )


# === it can say yes ===============================================================================


def test_a_complete_scenario_authorizes(session, principal):
    """A derivation that never authorizes is not a gate."""
    op, manifest, _target = _scenario(session, principal)
    authorized = _authorize(session, principal, op)
    assert isinstance(authorized, AuthorizedExecution)
    assert authorized.operation_id == op.id
    assert authorized.worker_installation_id == WORKER
    assert authorized.manifest_id == manifest.id
    assert authorized.kind is ProvisioningOperationKind.apply
    assert authorized.authorization_domain is ProvisioningOperationKind.apply
    assert authorized.rendered_workspace_hash == WORKSPACE


def test_it_grants_nothing_by_existing(session, principal):
    """The result describes an authorized execution. It carries no credential and no token."""
    op, _m, _t = _scenario(session, principal)
    authorized = _authorize(session, principal, op)
    text = repr(authorized)
    for secret_ish in ("token", "password", "secret", "credential"):
        assert secret_ish not in text.lower()


# === and it says no, one condition at a time ======================================================


def test_an_absent_operation_refuses(session, principal):
    class _Missing:
        id = uuid.uuid4()

    with pytest.raises(ExecutionAuthorityRefused, match="operation_absent"):
        _authorize(session, principal, _Missing())


def test_a_foreign_organization_refuses(session, principal, other_org_principal):
    op, _m, _t = _scenario(session, principal)
    with pytest.raises(ExecutionAuthorityRefused, match="wrong_organization"):
        authorize_provisioning_execution(
            session,
            operation_id=op.id,
            organization_id=other_org_principal.organization_id,
            worker_installation_id=WORKER,
            observed_toolchain=_observed(),
            now=NOW,
        )


@pytest.mark.parametrize(
    "kind", [ProvisioningOperationKind.dry_run, ProvisioningOperationKind.destroy_dry_run]
)
def test_a_dry_run_kind_is_not_executable(session, principal, kind):
    """Dry runs PRODUCE a change set; they never execute one. An unknown future kind lands here
    too, which is the safe direction — no kind falls through to apply."""
    op, _m, _t = _scenario(session, principal, kind=kind, approval_kind=kind)
    with pytest.raises(ExecutionAuthorityRefused, match="kind_not_executable"):
        _authorize(session, principal, op)


@pytest.mark.parametrize(
    "status",
    [ProvisioningStatus.applied, ProvisioningStatus.destroyed, ProvisioningStatus.failed],
)
def test_a_terminal_status_never_re_executes(session, principal, status):
    op, _m, _t = _scenario(session, principal, status=status)
    with pytest.raises(ExecutionAuthorityRefused, match="not_executable_in_this_status"):
        _authorize(session, principal, op)


def test_an_inactive_target_refuses(session, principal):
    op, _m, _t = _scenario(session, principal, target_status=TargetStatus.disabled)
    with pytest.raises(ExecutionAuthorityRefused, match="target_not_active"):
        _authorize(session, principal, op)


# --- the worker ------------------------------------------------------------------------------


def test_an_unbound_operation_refuses_rather_than_accepting_any_worker(session, principal):
    """The condition this whole slice exists for. Without the binding, ANY healthy worker in the
    organization could execute ANY operation in it."""
    op, _m, _t = _scenario(session, principal, bind=False)
    with pytest.raises(ExecutionAuthorityRefused, match="selection_not_durable"):
        _authorize(session, principal, op)


def test_a_worker_that_is_not_the_selected_one_refuses(session, principal):
    op, _m, _t = _scenario(session, principal)
    _enroll(session, principal, worker="wk-other")
    with pytest.raises(ExecutionAuthorityRefused, match="not_the_selected_worker"):
        _authorize(session, principal, op, worker="wk-other")


@pytest.mark.parametrize("state", ["refused", "recovery_required", "invited"])
def test_a_worker_whose_enrollment_is_not_healthy_refuses(session, principal, state):
    """Enrolled is a record that the worker EXISTS, not a statement that it may act."""
    op, _m, _t = _scenario(session, principal, enrollment_state=state)
    with pytest.raises(ExecutionAuthorityRefused, match="worker_not_enrolled"):
        _authorize(session, principal, op)


def test_an_unenrolled_worker_refuses(session, principal):
    op, _m, _t = _scenario(session, principal)
    with pytest.raises(ExecutionAuthorityRefused, match="worker_not_enrolled"):
        _authorize(session, principal, op, worker="wk-never-enrolled")


# --- the observation (conditions 6-7) --------------------------------------------------------


def test_absent_evidence_refuses(session, principal):
    """No record at all is refused -- asserted against the check rather than the public entry point.

    A target that reached an authorizable operation always has at least one evidence record: the
    manifest requires an active onboarding, activation writes a preflight record, and the onboarding
    row foreign-keys it, so the "no evidence" state cannot be constructed through the public path
    without asking the product to permit a deletion it correctly refuses. The state IS reachable in
    production -- a retention purge, a partial restore, a target whose evidence predates the
    organization it now sits under (the query filters on both) -- so the branch is real and is
    asserted where it can be reached.
    """
    from secp_api.provisioning_execution_authority import _assert_observation_current

    with pytest.raises(ExecutionAuthorityRefused, match="discovery_evidence_absent"):
        _assert_observation_current(
            session,
            execution_target_id=uuid.uuid4(),
            organization_id=principal.organization_id,
            now=NOW,
        )


def test_stale_evidence_refuses(session, principal):
    """A plan compiled from a stale view of the cluster is a plan for a cluster that no longer
    exists."""
    op, _m, _t = _scenario(session, principal, evidence_age=OBSERVATION_FRESHNESS_BOUND_SECONDS + 1)
    with pytest.raises(ExecutionAuthorityRefused, match="discovery_evidence_stale"):
        _authorize(session, principal, op)


def test_evidence_at_exactly_the_bound_is_still_current(session, principal):
    """A closed boundary, asserted rather than left to a rounding accident."""
    op, _m, _t = _scenario(session, principal, evidence_age=OBSERVATION_FRESHNESS_BOUND_SECONDS)
    assert _authorize(session, principal, op) is not None


def test_evidence_stamped_in_the_future_is_refused_as_stale(session, principal):
    """Not fresh — wrong. Accepting it would let a forward-dated observation stay valid
    indefinitely, which is the same defect as an unbounded window."""
    op, _m, _t = _scenario(session, principal, evidence_age=-600)
    with pytest.raises(ExecutionAuthorityRefused, match="discovery_evidence_stale"):
        _authorize(session, principal, op)


def test_unverifiable_evidence_is_distinct_from_failed_evidence(session, principal):
    """Different operator actions: a failure says the target is wrong, an unverifiable says nobody
    could tell. Collapsing them sends an operator to fix a target that may be fine."""
    op, _m, _t = _scenario(session, principal, evidence_status=EvidenceStatus.unverifiable)
    with pytest.raises(ExecutionAuthorityRefused, match="required_facts_incomplete"):
        _authorize(session, principal, op)

    op2, _m2, _t2 = _scenario(session, principal, evidence_status=EvidenceStatus.failed)
    with pytest.raises(ExecutionAuthorityRefused, match="discovery_evidence_absent"):
        _authorize(session, principal, op2)


# --- the toolchain ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,reason",
    [
        ("opentofu_binary_digest", "toolchain_binary_mismatch"),
        ("provider_source", "toolchain_provider_source_mismatch"),
        ("provider_version", "toolchain_provider_mismatch"),
        ("provider_checksum", "toolchain_provider_checksum_mismatch"),
        ("provider_lockfile_digest", "toolchain_lockfile_mismatch"),
        ("provider_mirror_identity", "toolchain_mirror_mismatch"),
        ("opentofu_version", "toolchain_binary_mismatch"),
    ],
)
def test_each_toolchain_field_refuses_separately(session, principal, field, reason):
    """Six comparisons rather than one digest over all of them: an operator resolves each
    differently — a reinstall, a re-review of the bundle, a re-pin, a rebuilt mirror artifact, a
    regeneration, a configuration change."""
    op, _m, _t = _scenario(session, principal)
    with pytest.raises(ExecutionAuthorityRefused, match=reason):
        _authorize(session, principal, op, observed=_observed(**{field: "something-else"}))


@pytest.mark.parametrize(
    "missing,reason",
    [
        ("binary_integrity", "toolchain_binary_mismatch"),
        ("provider_source", "toolchain_provider_source_mismatch"),
        ("provider_version", "toolchain_provider_mismatch"),
        ("provider_checksum", "toolchain_provider_checksum_mismatch"),
        ("provider_lockfile_hash", "toolchain_lockfile_mismatch"),
    ],
)
def test_an_unpinned_profile_field_is_a_refusal_not_a_pass(session, principal, missing, reason):
    """ "The profile does not say" must never read as "anything is acceptable" — that is how a pin
    becomes decoration.

    Asserted per field rather than once, because each pin is read at its own line: a refactor that
    dropped one comparison would leave the other four passing this test. The profile is built by
    DELETING a key from the shipped fixture rather than by writing a bespoke dict, so the case stays
    tied to the real shape as it evolves.
    """
    unpinned = {k: v for k, v in VALID_TOOLCHAIN_PROFILE.items() if k != missing}
    op, _m, _t = _scenario(session, principal, profile_content=unpinned)
    with pytest.raises(ExecutionAuthorityRefused, match=reason):
        _authorize(session, principal, op)


def test_the_shipped_profile_fixture_pins_every_field_the_authority_reads(session, principal):
    """The complement of the test above, and the reason it is not vacuous.

    If the shipped fixture were missing a pin, every "wrong value" case above would still pass —
    for the wrong reason, refusing on absence rather than on disagreement. This asserts the fixture
    authorizes cleanly, so those refusals are genuinely about the value.
    """
    op, _m, _t = _scenario(session, principal)
    assert _authorize(session, principal, op) is not None


# --- the artifact ----------------------------------------------------------------------------


def test_a_freshly_generated_plan_matches_no_approval(session, principal):
    """THE apply-regenerates-and-applies test. A new render has a different workspace hash, so it
    matches no approval and is refused rather than silently applying what nobody reviewed."""
    op, _m, _t = _scenario(session, principal)
    regenerated = _observed(rendered_workspace_hash="sha256:" + "9" * 64)
    with pytest.raises(ExecutionAuthorityRefused, match="change_set_not_authorized"):
        _authorize(session, principal, op, observed=regenerated)


def test_an_approval_for_the_other_domain_never_satisfies_this_one(session, principal):
    """A destroy approval can never authorize an apply."""
    op, _m, _t = _scenario(
        session,
        principal,
        kind=ProvisioningOperationKind.apply,
        approval_kind=ProvisioningOperationKind.destroy,
    )
    with pytest.raises(ExecutionAuthorityRefused, match="change_set_wrong_domain"):
        _authorize(session, principal, op)


@pytest.mark.parametrize(
    "status,reason",
    [
        (ChangeSetApprovalStatus.pending, "change_set_not_approved"),
        (ChangeSetApprovalStatus.rejected, "change_set_not_approved"),
        (ChangeSetApprovalStatus.consumed, "operation_already_consumed"),
    ],
)
def test_an_unapproved_or_consumed_change_set_refuses(session, principal, status, reason):
    op, _m, _t = _scenario(session, principal)
    from sqlalchemy import select as _select

    approval = session.execute(_select(ProvisioningChangeSetApproval)).scalars().first()
    approval.status = status
    session.flush()
    with pytest.raises(ExecutionAuthorityRefused, match=reason):
        _authorize(session, principal, op)


def test_two_live_approvals_for_one_workspace_refuse_rather_than_picking(session, principal):
    """Which one was reviewed? Refusing is the only honest answer."""
    op, manifest, _t = _scenario(session, principal)
    _approval(session, principal, manifest, change_set_hash="sha256:" + "6" * 64)
    with pytest.raises(ExecutionAuthorityRefused, match="conflicting_writer"):
        _authorize(session, principal, op)


def test_an_approval_bound_to_different_manifest_content_refuses(session, principal):
    """Still an approval; not an approval of THIS."""
    op, manifest, _t = _scenario(session, principal, approval=False)
    _approval(session, principal, manifest, manifest_hash="sha256:" + "0" * 64)
    with pytest.raises(ExecutionAuthorityRefused, match="binding_mismatch"):
        _authorize(session, principal, op)


# === the vocabulary ==============================================================================


def test_every_refusal_reason_is_in_the_closed_set():
    with pytest.raises(ValueError, match="unknown execution authority refusal reason"):
        ExecutionAuthorityRefused("something_new")
    assert len(EXECUTION_REFUSAL_REASONS) == len(set(EXECUTION_REFUSAL_REASONS))
    for reason in EXECUTION_REFUSAL_REASONS:
        assert reason.startswith("execution_"), reason


def test_no_ambient_bypass_exists_on_the_surface():
    """ADR-030 §2. Permission originates in the durable operation; nothing widens what may
    execute."""
    import ast
    import inspect
    import pathlib

    params = set(inspect.signature(authorize_provisioning_execution).parameters)
    assert params == {
        "session",
        "operation_id",
        "organization_id",
        "worker_installation_id",
        "observed_toolchain",
        "now",
    }
    for banned in ("armed", "real", "enabled", "unsealed", "force", "allow", "override"):
        assert banned not in params, banned

    source = pathlib.Path(inspect.getfile(authorize_provisioning_execution)).read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    # No settings, no environment: the answer cannot depend on how the process was started.
    for banned in ("os", "subprocess"):
        assert banned not in imported, banned

    # Names, not raw text. The module's own docstring says it consults no environment variable and
    # no settings object; a substring scan over the source reads that sentence as a violation of
    # itself. Walking the AST asks whether the CODE names them, which is the property meant.
    referenced = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
    }
    for banned in ("environ", "getenv", "get_settings", "Settings"):
        assert banned not in referenced, banned
