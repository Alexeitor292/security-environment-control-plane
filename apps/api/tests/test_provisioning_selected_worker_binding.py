"""The selected-worker binding as an ORM invariant, independent of any migration run.

Split from ``test_provisioning_selected_worker_migration`` on purpose. That module repoints
``SECP_DATABASE_URL`` at temporary files to exercise alembic; this one uses the shared session
fixture. A module that does BOTH leaves the process-global engine bound to a database it then
deletes, and the damage lands on unrelated tests sharing the CI shard rather than on itself.

The properties here are the ORM's, not the service's: the service is the only writer by convention,
and these prove the invariant holds even when the convention is bypassed.
"""

from __future__ import annotations

import uuid

import pytest
from secp_api.enums import ProvisioningOperationKind, ProvisioningStatus
from secp_api.immutability import ImmutableResourceError
from secp_api.models import ProvisioningOperation
from secp_api.services.provisioning_worker_selection import (
    SELECTION_REFUSAL_REASONS,
    ProvisioningWorkerSelectionRefused,
    assert_dispatchable,
    bind_provisioning_worker,
    select_provisioning_worker,
)
from sqlalchemy import inspect as sa_inspect

# === the binding, on real rows ====================================================================


def _operation(session, principal, **kw) -> ProvisioningOperation:
    from secp_api.models import ProvisioningManifest
    from tests.conftest import build_provisioning_env  # type: ignore[import-not-found]

    env = build_provisioning_env(session, principal)
    manifest = ProvisioningManifest(
        organization_id=principal.organization_id,
        deployment_plan_id=env.plan.id,
        execution_target_id=env.target.id,
        target_config_hash=env.target.config_hash,
        content={"resources": []},
        content_hash="sha256:" + "c" * 64,
    )
    session.add(manifest)
    session.flush()
    op = ProvisioningOperation(
        organization_id=principal.organization_id,
        manifest_id=manifest.id,
        kind=kw.get("kind", ProvisioningOperationKind.apply),
        status=kw.get("status", ProvisioningStatus.manifest_generated),
        idempotency_key=kw.get("key", uuid.uuid4().hex),
    )
    session.add(op)
    session.flush()
    return op


def test_a_null_binding_makes_an_operation_undispatchable(session, principal):
    op = _operation(session, principal)
    assert op.worker_installation_id is None
    with pytest.raises(ProvisioningWorkerSelectionRefused, match="binding_absent"):
        assert_dispatchable(op)


def test_binding_then_dispatchable(session, principal):
    op = _operation(session, principal)
    bind_provisioning_worker(session, operation=op, worker_installation_id="wk-a")
    assert assert_dispatchable(op) == "wk-a"


def test_the_same_binding_twice_is_idempotent(session, principal):
    """A retried enqueue must not fail an operator who cannot tell whether the first attempt
    committed."""
    op = _operation(session, principal)
    first = bind_provisioning_worker(session, operation=op, worker_installation_id="wk-a")
    second = bind_provisioning_worker(session, operation=op, worker_installation_id="wk-a")
    assert first == second == "wk-a"


def test_a_different_binding_is_refused_not_silently_repointed(session, principal):
    """Re-selecting is a NEW operation, never an edit to an authorized one."""
    op = _operation(session, principal)
    bind_provisioning_worker(session, operation=op, worker_installation_id="wk-a")
    with pytest.raises(ProvisioningWorkerSelectionRefused, match="already_set"):
        bind_provisioning_worker(session, operation=op, worker_installation_id="wk-b")
    assert op.worker_installation_id == "wk-a"


def test_the_orm_layer_refuses_a_repoint_even_bypassing_the_service(session, principal):
    """The service is the only writer BY CONVENTION; this is the guard that does not depend on the
    convention being followed."""
    op = _operation(session, principal)
    bind_provisioning_worker(session, operation=op, worker_installation_id="wk-a")
    session.commit()

    op.worker_installation_id = "wk-b"
    with pytest.raises(ImmutableResourceError, match="write-once"):
        session.flush()
    session.rollback()


@pytest.mark.parametrize(
    "initial,new_value,allowed",
    [
        (None, "wk-a", True),  # the legitimate binding write
        ("wk-a", "wk-a", True),  # idempotent: a retried enqueue must not fail
        ("wk-a", "wk-b", False),  # a re-point of an authority that may already have been granted
        ("wk-a", None, False),  # clearing is a re-point to "anyone", which is worse, not better
    ],
)
def test_every_binding_transition_after_commit_and_expiration(
    session, principal, initial, new_value, allowed
):
    """The four transitions, driven through DIRECT ORM mutation with the instance EXPIRED.

    Expiration is the case that matters. Assigning to an expired attribute does not load the
    committed value unless the column declares ``active_history=True``, and without that the
    flush-time history reads ``deleted=()`` — so the guard sees no previous value and permits the
    re-point. This test failed exactly that way before the flag was added.
    """
    op = _operation(session, principal)
    if initial is not None:
        bind_provisioning_worker(session, operation=op, worker_installation_id=initial)
    session.commit()
    assert sa_inspect(op).expired is True, "the case under test requires an expired instance"

    op.worker_installation_id = new_value
    if allowed:
        session.flush()
        assert op.worker_installation_id == new_value
    else:
        with pytest.raises(ImmutableResourceError, match="write-once"):
            session.flush()
        session.rollback()


@pytest.mark.parametrize("new_value,allowed", [("wk-a", True), ("wk-b", False), (None, False)])
def test_every_binding_transition_after_a_fresh_reload(session, principal, new_value, allowed):
    """The same four rules through a row loaded fresh into a clean identity map — proving the
    invariant belongs to the MAPPING rather than to one session's in-memory state."""
    op = _operation(session, principal)
    bind_provisioning_worker(session, operation=op, worker_installation_id="wk-a")
    session.commit()
    operation_id = op.id
    session.expunge_all()

    reloaded = session.get(ProvisioningOperation, operation_id)
    reloaded.worker_installation_id = new_value
    if allowed:
        session.flush()
    else:
        with pytest.raises(ImmutableResourceError, match="write-once"):
            session.flush()
        session.rollback()


def test_the_column_declares_active_history():
    """Pinned structurally, because the flag has no visible effect until the exact expired-instance
    case — a future edit that removed it as noise would silently reopen the hole."""
    from sqlalchemy import inspect as _inspect

    attr = _inspect(ProvisioningOperation).attrs["worker_installation_id"]
    assert attr.active_history is True


def test_setting_a_binding_on_a_null_row_is_allowed_by_the_guard(session, principal):
    """One direction only: NULL -> value is the legitimate write; the guard must not block it."""
    op = _operation(session, principal)
    session.commit()
    op.worker_installation_id = "wk-a"
    session.flush()
    assert op.worker_installation_id == "wk-a"


def test_ordinary_lifecycle_columns_stay_mutable(session, principal):
    """The guard is scoped to the binding. Status, attempts and result are lifecycle state and a
    write-once rule over them would freeze the operation on creation."""
    op = _operation(session, principal)
    bind_provisioning_worker(session, operation=op, worker_installation_id="wk-a")
    session.commit()
    op.status = ProvisioningStatus.queued
    op.attempts = 1
    op.result = {"note": "x"}
    session.flush()
    assert op.status is ProvisioningStatus.queued


# === selection comes from the control plane =======================================================


def test_the_selection_surface_takes_no_worker_from_a_caller(session, principal):
    """Stronger than ignoring a caller's preference: there is nowhere to put one."""
    import inspect as _inspect

    params = set(_inspect.signature(select_provisioning_worker).parameters)
    assert params == {"session", "organization_id"}
    for banned in ("worker_installation_id", "worker", "preferred", "requested_by", "payload"):
        assert banned not in params, banned


def test_selection_refuses_when_no_worker_is_enrolled(session, principal):
    with pytest.raises(ProvisioningWorkerSelectionRefused, match="none_enrolled"):
        select_provisioning_worker(session, organization_id=principal.organization_id)


def test_every_refusal_reason_is_in_the_closed_set():
    with pytest.raises(ValueError, match="unknown provisioning worker selection reason"):
        ProvisioningWorkerSelectionRefused("something_new")
    assert len(SELECTION_REFUSAL_REASONS) == len(set(SELECTION_REFUSAL_REASONS))
    for reason in SELECTION_REFUSAL_REASONS:
        assert reason.startswith("provisioning_worker_"), reason


# === the binding is durable BEFORE the operation becomes dispatchable ===========================


def test_an_unbound_operation_is_not_dispatchable(session, principal):
    """NULL is not "open to any worker"; it is unexecutable.

    ``assert_dispatchable`` is the gate a real enqueue path must call before it transitions an
    operation into ``queued`` or ``destroy_queued``. It is asserted directly rather than through
    ``services.provisioning.advance`` because that function cannot host the gate yet -- the
    simulator execution path already drives operations into ``queued`` for organizations with no
    enrolled worker, so installing it there today would refuse the shipped dev/test flow rather
    than a real dispatch. See ``advance``'s docstring.
    """
    op = _operation(session, principal, status=ProvisioningStatus.pending_approval)
    assert op.worker_installation_id is None
    with pytest.raises(ProvisioningWorkerSelectionRefused, match="binding_absent"):
        assert_dispatchable(op)


def test_a_bound_operation_is_dispatchable(session, principal):
    """The gate refuses the unbound case only -- it is not a blanket denial of dispatch."""
    op = _operation(session, principal, status=ProvisioningStatus.pending_approval)
    bind_provisioning_worker(session, operation=op, worker_installation_id="wk-dispatch-1")
    assert assert_dispatchable(op) == "wk-dispatch-1"


def test_the_dispatchable_statuses_are_exactly_the_ones_a_worker_picks_up():
    """Pins WHICH statuses the gate has to cover, so a new queue-like status is a visible decision
    rather than a silent hole."""
    from secp_api.services.provisioning import _DISPATCHABLE_STATUSES

    assert _DISPATCHABLE_STATUSES == frozenset(
        {ProvisioningStatus.queued, ProvisioningStatus.destroy_queued}
    )


def test_no_second_path_can_make_an_operation_dispatchable():
    """A second way to reach ``queued`` would be a way around the binding gate.

    Keyed on the two facts that make the gate unbypassable rather than on a line of text:

    1. ``provisioning_lifecycle.transition`` -- the only producer of a legal provisioning status --
       is imported by exactly one non-test module, the one holding the gate. (The worker imports
       ``is_permitted``, a read-only predicate that assigns nothing.)
    2. inside that module, the functions that assign a status are exactly ``advance`` and
       ``mark_failed``.

    Naming them explicitly is deliberate. When the real executor installs the binding gate in
    ``advance``, this test is what proves there is no second function it would have to be installed
    in as well -- and a NEW status-writing function has to be added to this list by someone who then
    has to say why it does not need the gate.
    """
    import ast
    import pathlib

    api = pathlib.Path(__file__).resolve().parents[1] / "secp_api"
    worker = pathlib.Path(__file__).resolve().parents[3] / "worker" / "secp_worker"
    importers = set()
    for root in (api, worker):
        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.ImportFrom)
                    and (node.module or "").endswith("provisioning_lifecycle")
                    and any(a.name == "transition" for a in node.names)
                ):
                    importers.add(path.name)
    assert importers == {"provisioning.py"}, importers

    source = (api / "services" / "provisioning.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    writers = {}
    for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for node in ast.walk(func):
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Attribute) and t.attr == "status" for t in node.targets
            ):
                writers.setdefault(func.name, func)
    assert set(writers) == {"advance", "mark_failed"}, set(writers)
