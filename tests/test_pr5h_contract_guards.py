"""PR5H-A contract guards: vocabulary alignment, concurrency structure, and the rehydration choke.

Three guard families that a future refactor must not be able to defeat quietly:

* **Vocabulary alignment** — an addition to one closed vocabulary (states, steps, error codes,
  grammars, canonical field order) fails CI until every authoritative location is deliberately
  updated: the management contract, the API mirror, the ORM models, the migration, the repository,
  the service and the recovery sweep.
* **Concurrency structure** — the critical controls (row lock + CAS, conditional nonce consumption,
  stage ordering, retry-before-stale-token, sweep locking/scoping/cursor/caps, per-candidate
  transactions, bounded rollback, conflict-code unification) are pinned structurally *and*
  behaviourally, so removing one is caught even if the call count still looks right.
* **Rehydration choke point** — every read, status, transition, retry and sweep path crosses the one
  validator, and no path silently repairs a corrupt row.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_PKG = REPO / "apps" / "api" / "secp_api"
REPOSITORY = API_PKG / "worker_enrollment_repository.py"
SERVICE = API_PKG / "services" / "worker_enrollment.py"
RECOVERY = API_PKG / "services" / "worker_enrollment_recovery.py"
MIRROR = API_PKG / "worker_enrollment_contract.py"
MGMT_CONTRACT = REPO / "apps" / "management" / "secp_management" / "enrollment.py"
MIGRATION = (
    REPO
    / "apps"
    / "api"
    / "migrations"
    / "versions"
    / "b6e2f4a9c1d7_worker_enrollment_foundation.py"
)

for _extra in ("apps/api", "apps/management", "apps/deployment", "apps/commissioning"):
    sys.path.insert(0, str(REPO / _extra))


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _function(path: Path, name: str) -> ast.FunctionDef:
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{path.name} has no function {name!r}")


def _statement_index(fn: ast.FunctionDef, predicate) -> int | None:
    for index, stmt in enumerate(fn.body):
        if predicate(stmt):
            return index
    return None


def _mentions(stmt: ast.AST, needle: str) -> bool:
    return needle in ast.unparse(stmt)


def _migration_module():
    """Load the migration by path. It deliberately keeps its OWN frozen vocabulary snapshot (a
    migration must not drift with evolving model code), so the guard compares those VALUES rather
    than source text — adding a state or step without updating the migration then fails here."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("pr5h_migration_under_guard", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- family 5: vocabulary alignment ---------------------------------------------------------------


def test_states_align_across_every_authoritative_location() -> None:
    import secp_management.enrollment as mgmt
    from secp_api.worker_enrollment_contract import ALL_STATES
    from secp_api.worker_enrollment_models import WORKER_ENROLLMENT_STATES

    mgmt_states = (
        mgmt.INVITED,
        mgmt.WORKER_BOUND,
        mgmt.OFFER_TRANSPORTED,
        mgmt.RESULT_TRANSPORTED,
        mgmt.VERIFIED,
        mgmt.HEALTHY,
        mgmt.REFUSED,
        mgmt.RECOVERY_REQUIRED,
    )
    assert ALL_STATES == mgmt_states
    assert tuple(WORKER_ENROLLMENT_STATES) == mgmt_states
    # the migration's frozen CHECK vocabulary must enumerate exactly the same closed set
    assert _migration_module()._STATES == mgmt_states


def test_transitions_align_between_the_management_contract_and_the_mirror() -> None:
    import secp_management.enrollment as mgmt
    from secp_api.worker_enrollment_contract import ACTIVE, ADVANCE

    assert ADVANCE == mgmt._ADVANCE
    assert ACTIVE == mgmt._ACTIVE


def test_the_five_worker_receipt_steps_align_and_exclude_lifecycle_transitions() -> None:
    """Lifecycle/sweep revisions are NOT worker step receipts — the vocabularies must not blur."""
    from secp_api.worker_enrollment_models import WORKER_ENROLLMENT_STEPS

    assert WORKER_ENROLLMENT_STEPS == (
        "bind_worker_identity",
        "record_controller_offer",
        "record_worker_result",
        "mark_verified",
        "mark_healthy",
    )
    assert _migration_module()._STEPS == WORKER_ENROLLMENT_STEPS
    for lifecycle in ("refuse", "require_recovery", "expiry_recovery", "recover"):
        assert lifecycle not in WORKER_ENROLLMENT_STEPS


def test_every_surfaced_reason_code_is_in_the_closed_catalog() -> None:
    """Any bounded code raised by the contract, repository, service or sweep must be enumerable."""
    from secp_api.enums import WorkerEnrollmentErrorCode

    catalog = {code.value for code in WorkerEnrollmentErrorCode}
    raised: set[str] = set()
    # the API surface: everything these raise must be enumerable in the closed catalog
    for path in (MIRROR, REPOSITORY, SERVICE, RECOVERY):
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.Call):
                rendered = ast.unparse(node.func)
                if rendered.endswith(("_closed", "_refuse", "RepositoryRefusal")):
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            raised.add(arg.value)
    unknown = {code for code in raised if code.startswith("enrollment_")} - catalog
    assert not unknown, (
        f"bounded codes raised but absent from the closed catalog: {sorted(unknown)}"
    )

    # The management plane keeps its OWN codes. Only the sealed-transport refusal may differ; a NEW
    # management-only code fails here until it is deliberately acknowledged (and, if it can ever
    # cross to the API, added to the closed catalog).
    mgmt_raised: set[str] = set()
    for node in ast.walk(_tree(MGMT_CONTRACT)):
        if isinstance(node, ast.Call) and ast.unparse(node.func).endswith(
            ("_closed", "ManagementError")
        ):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    mgmt_raised.add(arg.value)
    extra = {c for c in mgmt_raised if c.startswith("enrollment_")} - catalog
    assert extra == {"enrollment_transport_not_activated"}, sorted(extra)


def test_canonical_field_order_and_state_shape_invariants_are_pinned() -> None:
    import secp_management.enrollment as mgmt
    from secp_api.worker_enrollment_contract import EnrollmentState
    from secp_api.worker_enrollment_repository import _PIPELINE_SHAPE

    # 17 contract fields + the schema marker, in declaration order, identical on both planes
    fields = [f for f in EnrollmentState.__dataclass_fields__]
    assert len(fields) == 17
    assert fields == [f for f in mgmt.EnrollmentState.__dataclass_fields__]
    # the repository's per-state presence map covers every non-terminal state plus healthy
    assert set(_PIPELINE_SHAPE) == {
        "invited",
        "worker_bound",
        "offer_transported",
        "result_transported",
        "verified",
        "healthy",
    }


def test_grammars_align_between_the_planes() -> None:
    import secp_management.enrollment as mgmt
    from secp_api.worker_enrollment_contract import (
        DEPLOYMENT_SITE_LABEL_PATTERN,
        is_deployment_site_label,
    )
    from secp_api.worker_enrollment_repository import _INSTALLATION_ID, _REASON_CODE

    assert _INSTALLATION_ID.pattern == mgmt._INSTALLATION_ID.pattern
    assert _REASON_CODE.pattern == mgmt._REASON_CODE.pattern
    # the site-label grammar has exactly one definition, re-exported by the schema layer
    from secp_api.worker_enrollment_models import DEPLOYMENT_SITE_LABEL_PATTERN as models_pattern

    assert models_pattern == DEPLOYMENT_SITE_LABEL_PATTERN
    assert is_deployment_site_label("rack-01.eu_a")


def test_digest_grammar_is_shared_not_reimplemented() -> None:
    from secp_api.worker_enrollment_repository import _digest_or_empty_ok
    from secp_commissioning.canonical import is_sha256_digest

    assert is_sha256_digest("sha256:" + "a" * 64)
    assert not is_sha256_digest("sha256:" + "a" * 63)
    assert _digest_or_empty_ok("")
    assert _digest_or_empty_ok("sha256:" + "b" * 64)
    assert not _digest_or_empty_ok("nope")


# --- family 6: concurrency + transaction structure ------------------------------------------------


def test_commit_transition_orders_history_then_cas_then_receipt() -> None:
    fn = _function(REPOSITORY, "commit_transition")
    rendered = [ast.unparse(stmt) for stmt in fn.body]
    history = next(i for i, s in enumerate(rendered) if "_append_history(" in s)
    cas = next(i for i, s in enumerate(rendered) if "_cas_head(" in s)
    receipt = next(i for i, s in enumerate(rendered) if "_write_step_receipt(" in s)
    assert history < cas < receipt, rendered


def test_cas_predicate_covers_both_revision_and_state_digest() -> None:
    fn = _function(REPOSITORY, "_cas_head")
    rendered = ast.unparse(fn)
    assert "StateRow.revision == prior.expected_revision" in rendered
    assert "StateRow.state_digest == prior.expected_state_digest" in rendered
    assert "rowcount != 1" in rendered
    assert "enrollment_revision_conflict" in rendered


def test_normal_transitions_take_a_real_dialect_derived_row_lock() -> None:
    """Pin the EXPRESSION, not the keyword: ``with_for_update=None`` would still mention the keyword
    while silently dropping the lock, and no SQLite test could detect it (SQLite emits no lock
    clause either way)."""
    fn = ast.unparse(_function(REPOSITORY, "load_for_update"))
    assert "with_for_update=_for_update(session)" in fn, "the row lock is not dialect-derived"
    # ...and the helper really asks PostgreSQL for FOR UPDATE
    helper = ast.unparse(_function(REPOSITORY, "_for_update"))
    assert "postgresql" in helper and "True" in helper


def test_invitation_consumption_is_conditional_and_inside_the_bind_transaction() -> None:
    consume = _function(REPOSITORY, "consume_invitation")
    rendered = ast.unparse(consume)
    assert "InvitationRow.consumed.is_(False)" in rendered
    assert "InvitationRow.revoked.is_(False)" in rendered
    assert "rowcount != 1" in rendered
    # ...and the bind path consumes BEFORE committing the transition, in the same transaction
    bind = _function(SERVICE, "bind_worker")
    consume_at = _statement_index(bind, lambda s: _mentions(s, "consume_invitation"))
    commit_at = _statement_index(bind, lambda s: _mentions(s, "_commit("))
    assert consume_at is not None and commit_at is not None
    assert consume_at < commit_at


def test_step_receipt_retry_precedes_stale_expected_token_rejection() -> None:
    for name in ("bind_worker", "_advance_step"):
        fn = _function(SERVICE, name)
        serve = _statement_index(fn, lambda s: _mentions(s, "_serve_receipt("))
        verify = _statement_index(fn, lambda s: _mentions(s, "_verify_expected("))
        assert serve is not None and verify is not None, name
        assert serve < verify, f"{name}: receipt dedup must precede the expected-token check"


def test_lifecycle_history_retry_precedes_stale_expected_token_rejection() -> None:
    fn = _function(SERVICE, "_lifecycle")
    serve = _statement_index(fn, lambda s: _mentions(s, "_serve_lifecycle_retry("))
    verify = _statement_index(fn, lambda s: _mentions(s, "_verify_expected("))
    assert serve is not None and verify is not None
    assert serve < verify


def test_lifecycle_retry_never_consults_a_worker_step_receipt() -> None:
    """Lifecycle transitions are proven from the revision history, never the step-receipt ledger."""
    fn = _function(SERVICE, "_serve_lifecycle_retry")
    rendered = ast.unparse(fn)
    assert "find_receipt" not in rendered
    assert "revision_row" in rendered and "max_revision" in rendered
    # ...and the lifecycle commit writes no step receipt
    lifecycle = ast.unparse(_function(SERVICE, "_lifecycle"))
    assert "step=None" in lifecycle and "input_digest=None" in lifecycle


def test_sweep_uses_for_update_skip_locked_and_a_hard_org_predicate() -> None:
    lock = ast.unparse(_function(REPOSITORY, "lock_and_load_sweep_candidate"))
    assert "with_for_update(skip_locked=True)" in lock
    assert "StateRow.organization_id == organization_id" in lock

    select = ast.unparse(_function(REPOSITORY, "select_due_active_candidates"))
    assert "StateRow.organization_id == organization_id" in select
    assert "StateRow.state.in_(_ACTIVE_STATES)" in select
    assert "StateRow.expires_at_ts <= now_ts" in select


def test_sweep_cursor_order_is_exact_and_strictly_greater_than() -> None:
    select = ast.unparse(_function(REPOSITORY, "select_due_active_candidates"))
    assert "order_by(StateRow.expires_at_ts, StateRow.enrollment_id)" in select
    assert "tuple_(StateRow.expires_at_ts, StateRow.enrollment_id) > (after_ts, after_id)" in select
    assert ">= (after_ts" not in select  # must be STRICT


def test_sweep_cursor_advances_from_the_last_examined_candidate() -> None:
    fn = ast.unparse(_function(RECOVERY, "recover_expired"))
    # built from the last CANDIDATE of the window, not from a recovered outcome
    assert "candidates[-1]" in fn
    assert "len(candidates) == limit" in fn


def test_sweep_batch_and_pass_caps_cannot_be_caller_raised() -> None:
    recover = ast.unparse(_function(RECOVERY, "recover_expired"))
    drain = ast.unparse(_function(RECOVERY, "drain_expired"))
    assert "min(int(batch_size), DEFAULT_SWEEP_BATCH)" in recover
    assert "min(int(max_passes), DEFAULT_MAX_PASSES)" in drain


def test_each_sweep_candidate_gets_an_independent_transaction_and_bounded_rollback() -> None:
    fn = _function(RECOVERY, "_recover_one_isolated")
    rendered = ast.unparse(fn)
    assert "with session_factory() as session:" in rendered  # its OWN session/transaction
    assert "session.commit()" in rendered
    assert "_safe_rollback(session)" in rendered
    assert "session.rollback()" not in rendered  # always via the bounded helper
    safe = ast.unparse(_function(RECOVERY, "_safe_rollback"))
    assert "try:" in safe and "except Exception" in safe


def test_unexpected_infrastructure_failure_is_not_classified_as_corrupt() -> None:
    fn = ast.unparse(_function(RECOVERY, "_recover_one_isolated"))
    # the broad handler returns "failed"; only the classifier may return "corrupt"
    assert "return 'failed'" in fn
    classify = ast.unparse(_function(RECOVERY, "_classify"))
    assert "enrollment_state_corrupt" in classify and "enrollment_history_inconsistent" in classify


def test_both_conflict_detectors_surface_the_same_bounded_code() -> None:
    """A UNIQUE(enrollment_id, revision) collision and a zero-row CAS are the same conflict."""
    append = ast.unparse(_function(REPOSITORY, "_append_history"))
    cas = ast.unparse(_function(REPOSITORY, "_cas_head"))
    assert "IntegrityError" in append and "enrollment_revision_conflict" in append
    assert "enrollment_revision_conflict" in cas


# --- family 7: the rehydration choke point --------------------------------------------------------

REHYDRATION_INVARIANTS = (
    "state.digest() != row.state_digest",  # canonical digest recomputation
    "state.worker_key_id == state.controller_key_id",  # participant key separation
    "state.worker_installation_id\n        and state.worker_installation_id"
    " == state.controller_installation_id",  # participant installation separation
    "_PIPELINE_SHAPE.get(state.state)",  # per-state shape
    "is_genesis",  # revision-zero structural invariant
    "_same_instant(state.expires_at, row.expires_at_ts)",  # state shadow
    "_INSTALLATION_ID.fullmatch",  # installation grammar
    "is_deployment_site_label(row.deployment_site_label)",  # site grammar
    "_REASON_CODE.fullmatch",  # bounded reason placement
)


@pytest.mark.parametrize("invariant", REHYDRATION_INVARIANTS)
def test_rehydration_validator_still_checks_every_invariant(invariant: str) -> None:
    rendered = ast.unparse(_function(REPOSITORY, "_validate_rehydrated"))
    normalized = " ".join(rendered.split())
    assert " ".join(invariant.split()) in normalized, f"missing rehydration invariant: {invariant}"


def test_invitation_cross_check_anchors_tenancy_identity_and_all_expiry_representations() -> None:
    rendered = " ".join(ast.unparse(_function(REPOSITORY, "_cross_check_invitation")).split())
    for anchor in (
        "invitation_row.organization_id != row.organization_id",
        "invitation_row.deployment_site_label != row.deployment_site_label",
        "_same_instant(invitation_row.expires_at, invitation_row.expires_at_ts)",
        "invitation.digest() != state.enrollment_id",
        "state.controller_installation_id != invitation.controller_installation_id",
        "state.controller_key_id != invitation.controller_key_id",
        "state.transaction_id != invitation.transaction_id",
        "state.release_digest != invitation.release_digest",
        "state.expires_at != invitation.expires_at",
    ):
        assert " ".join(anchor.split()) in rendered, f"missing invitation anchor: {anchor}"


def test_every_load_path_crosses_the_single_rehydration_choke_point() -> None:
    """load_for_update, load_read_only and the sweep's locking load all build through
    ``_build_loaded``, which is the only place a row becomes a usable EnrollmentState."""
    for name in ("load_for_update", "load_read_only", "lock_and_load_sweep_candidate"):
        assert "_build_loaded(" in ast.unparse(_function(REPOSITORY, name)), name
    build = ast.unparse(_function(REPOSITORY, "_build_loaded"))
    assert "_validate_rehydrated(" in build and "_cross_check_invitation(" in build


def test_no_path_repairs_or_normalizes_a_corrupt_row() -> None:
    """The repository never writes while validating: corruption refuses and the row is preserved."""
    for name in ("_validate_rehydrated", "_cross_check_invitation", "_build_loaded"):
        rendered = ast.unparse(_function(REPOSITORY, name))
        for mutation in ("session.add(", "update(StateRow)", "session.commit(", "session.flush("):
            assert mutation not in rendered, f"{name} mutates during validation via {mutation}"


def test_enrollment_models_can_be_imported_first_without_a_circular_import() -> None:
    """Regression: ``secp_api.models`` re-exported the enrollment model CLASS NAMES, so importing
    ``secp_api.worker_enrollment_models`` first raised ImportError from a partially initialized
    module. The re-export is now a module import, which is cycle-tolerant in BOTH orders while still
    registering the four tables on ``Base.metadata``."""
    import subprocess

    for first, second in (
        ("secp_api.worker_enrollment_models", "secp_api.models"),
        ("secp_api.models", "secp_api.worker_enrollment_models"),
    ):
        script = (
            f"import {first}; import {second}\n"
            "from secp_api.models import Base\n"
            "names = sorted(t for t in Base.metadata.tables if t.startswith('worker_enrollment'))\n"
            "assert len(names) == 4, names\n"
            "print('ok')\n"
        )
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell, test-only
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            cwd=str(REPO),
        )
        assert result.returncode == 0, f"import order {first} -> {second} failed:\n{result.stderr}"
        assert "ok" in result.stdout
