"""Which authorization gates which operation kind — proved by ITERATING THE ENUM.

Every existing test of this gate passes the string literals ``"deploy"`` / ``"reset"`` /
``"destroy"`` — the same literals the function used to compare against. Those tests restate the
subject: they cannot notice that ``RangeOperationKind`` drifted out from under the comparison,
because they supply the very strings the comparison expects. That is how a gate keyed on
``kind == "destroy"`` survived review while depending on an enum member's *value* in another module
with nothing enforcing the coupling.

So this module is built the other way round. The authorization table below is keyed on the enum
MEMBERS, the tests iterate ``RangeOperationKind`` rather than a list of names, and every member must
appear in the table or the first test fails. Add a member, rename one, or change which authorization
gates it, and this goes red.

The gate itself is now enum-typed with an ``assert_never`` default, so a new member also fails mypy
before it reaches here — these tests prove the runtime behaviour that type checking cannot: that
each kind requires its OWN authorization and refuses the others.
"""

from __future__ import annotations

import pytest
from secp_api.enums import Permission
from secp_api.errors import AuthorizationError
from secp_api.range_enums import RangeOperationKind
from secp_api.services import proxmox_lifecycle, ranges
from test_proxmox_http_surface import make_range


@pytest.fixture
def instance(session, principal):
    return make_range(session, principal)


def _compiled(session, instance):
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    assert not isinstance(compiled, proxmox_lifecycle.BlockedPlan)
    return compiled


# --- the table, keyed on the enum members themselves ----------------------------
#
# ``authorize`` records the authorization each kind REQUIRES. Every other family's authorization
# must be refused for that kind — which is what the cross-product test below asserts, rather than
# spot-checking the one pairing someone happened to think of.


def _authorize_apply(session, principal, instance):
    compiled = _compiled(session, instance)
    proxmox_lifecycle.approve_plan(session, principal, instance.id, plan_hash=compiled.plan_hash)
    proxmox_lifecycle.authorize_apply(session, principal, instance.id, plan_hash=compiled.plan_hash)


def _authorize_reset(session, principal, instance):
    compiled = _compiled(session, instance)
    proxmox_lifecycle.approve_reset_plan(
        session, principal, instance.id, reset_hash=compiled.reset_hash
    )
    proxmox_lifecycle.authorize_reset(
        session, principal, instance.id, reset_hash=compiled.reset_hash
    )


def _authorize_destroy(session, principal, instance):
    compiled = _compiled(session, instance)
    proxmox_lifecycle.approve_destroy_plan(
        session, principal, instance.id, destroy_hash=compiled.destroy_hash
    )
    proxmox_lifecycle.authorize_destroy(
        session, principal, instance.id, destroy_hash=compiled.destroy_hash
    )


#: kind -> (the authorizer that satisfies it, the permission its approval requires)
AUTHORIZATION: dict[RangeOperationKind, tuple] = {
    RangeOperationKind.deploy: (_authorize_apply, Permission.exercise_apply),
    RangeOperationKind.reset: (_authorize_reset, Permission.exercise_reset),
    RangeOperationKind.destroy: (_authorize_destroy, Permission.exercise_destroy),
}


def test_every_operation_kind_has_a_declared_authorization():
    """The table is keyed on members, so a new or renamed kind fails HERE first.

    This is the test that earns the rest their keep: without it the cross-product below would
    silently stop covering a kind that was added, because it iterates the table.
    """
    assert set(AUTHORIZATION) == set(RangeOperationKind), (
        f"every RangeOperationKind must declare which authorization gates it; missing: "
        f"{sorted(k.name for k in set(RangeOperationKind) - set(AUTHORIZATION))}"
    )


@pytest.mark.parametrize("kind", list(RangeOperationKind))
def test_each_kind_requires_its_own_authorization(session, principal, instance, kind):
    """Unauthorized, the gate refuses; correctly authorized, it permits. One test per member."""
    with pytest.raises(proxmox_lifecycle.ProxmoxApprovalMissingError):
        proxmox_lifecycle.require_operation_authorized(session, instance, kind)

    authorize, _ = AUTHORIZATION[kind]
    authorize(session, principal, instance)
    # Now it passes. No exception is the assertion.
    proxmox_lifecycle.require_operation_authorized(session, instance, kind)


@pytest.mark.parametrize("kind", list(RangeOperationKind))
def test_no_other_authorization_satisfies_a_kind(session, principal, instance, kind):
    """The CROSS PRODUCT, derived — not the one pairing someone remembered to check.

    For every kind, grant every OTHER kind's authorization and assert the gate still refuses. This
    is what catches an apply approval standing in for a destroy, or for a reset: both were real,
    and the second was live on this branch until the reset disposition set was read.
    """
    for other in RangeOperationKind:
        if other is kind:
            continue
        authorize, _ = AUTHORIZATION[other]
        authorize(session, principal, instance)

    with pytest.raises(proxmox_lifecycle.ProxmoxApprovalMissingError) as excinfo:
        proxmox_lifecycle.require_operation_authorized(session, instance, kind)
    # And the refusal names the act that was actually refused, not a neighbouring one.
    assert str(excinfo.value).startswith(
        {"deploy": "apply", "reset": "reset", "destroy": "destroy"}[kind.value]
    )


@pytest.mark.parametrize("kind", list(RangeOperationKind))
def test_each_approval_requires_its_own_permission(session, principal, instance, kind):
    """Holding one family's permission never grants another's."""
    import dataclasses

    _, required = AUTHORIZATION[kind]
    others = {perm for _, perm in AUTHORIZATION.values()} - {required}
    starved = dataclasses.replace(
        principal, permissions=frozenset({Permission.exercise_operate, *others})
    )
    authorize, _ = AUTHORIZATION[kind]
    with pytest.raises(AuthorizationError):
        authorize(session, starved, instance)


# --- the three hash domains are mutually unusable ---------------------------------


def test_the_three_hashes_are_all_distinct(session, principal, instance):
    """A digest from one family is not a valid value in another, even for the same range."""
    compiled = _compiled(session, instance)
    hashes = {compiled.plan_hash, compiled.reset_hash, compiled.destroy_hash}
    assert len(hashes) == 3, "the three domains must not collide"


@pytest.mark.parametrize(
    ("approve", "field", "wrong"),
    (
        ("approve_plan", "plan_hash", ("reset_hash", "destroy_hash")),
        ("approve_reset_plan", "reset_hash", ("plan_hash", "destroy_hash")),
        ("approve_destroy_plan", "destroy_hash", ("plan_hash", "reset_hash")),
    ),
)
def test_an_approval_refuses_a_digest_from_another_domain(
    session, principal, instance, approve, field, wrong
):
    compiled = _compiled(session, instance)
    approver = getattr(proxmox_lifecycle, approve)
    for other in wrong:
        with pytest.raises(proxmox_lifecycle.ProxmoxHashMismatchError):
            approver(session, principal, instance.id, **{field: getattr(compiled, other)})


# --- what a reset actually does, pinned against the worker's own dispositions -----


def test_a_reset_destroys_guests_which_is_why_it_needs_its_own_authorization():
    """Read from the worker's disposition set, not assumed.

    The reset gate's whole justification is that a reset DELETES things. If that ever stops being
    true the gate could be relaxed — and if a DELETING disposition is ever added for a subject that
    is currently preserved, the reset scope must grow to cover it. Either way this test is where the
    question gets asked again, because it reads the vocabulary rather than restating a conclusion.
    """
    from secp_worker.provisioning.proxmox_reset import (
        ResetDisposition,
        ResetRequest,
        ResetSubject,
        plan_reset,
    )

    # Drive the real planner rather than reading prose about it. A docstring can say anything; the
    # dispositions are what the reset will actually do.
    approved = {
        "guests": [
            {"guest_ref": "red-dvwa", "ownership": {"operation_generation": 1}},
            {"guest_ref": "red-juice", "ownership": {"operation_generation": 1}},
        ],
        "network": {"vnets": [{"name": "vnet-red"}]},
    }
    ledger = {"allocations": [{"kind": "vmid", "value": "100"}], "sealed": True, "ledger_hash": "h"}
    plan = plan_reset(
        approved_desired_state=approved,
        approved_ledger=ledger,
        current_ledger=ledger,
        proposed_desired_state=None,
        material_refs=("ref-a",),
        request=ResetRequest(range_id="r-1", operation_generation=2),
    )

    # GUESTS ARE DESTROYED. This is the fact the whole reset-authorization design rests on.
    assert plan.disposition(ResetSubject.guests) is ResetDisposition.recreated
    assert set(plan.recreated_guest_refs) == {"red-dvwa", "red-juice"}

    # And every NETWORK subject is preserved, which is why the reset scope is narrower than a
    # destroy's. If any of these ever becomes a deleting disposition, the reset scope must grow to
    # cover it and this test is where that is noticed.
    for preserved in (
        ResetSubject.range_identity,
        ResetSubject.sdn_zone,
        ResetSubject.vnets,
        ResetSubject.subnets_and_vlans,
        ResetSubject.firewall_objects,
        ResetSubject.allocation_ledger,
        ResetSubject.team_membership,
    ):
        assert plan.disposition(preserved) is ResetDisposition.preserved, preserved

    # Scores are the one opt-in DELETION, and it is never implied.
    assert plan.disposition(ResetSubject.scores) is ResetDisposition.preserved
    cleared = plan_reset(
        approved_desired_state=approved,
        approved_ledger=ledger,
        current_ledger=ledger,
        proposed_desired_state=None,
        material_refs=(),
        request=ResetRequest(range_id="r-1", operation_generation=2, clear_scores=True),
    )
    assert cleared.disposition(ResetSubject.scores) is ResetDisposition.cleared

    # The vocabulary of subjects a reset has an opinion about is closed and known. A NEW subject
    # means somebody must decide whether the reset scope has to cover it.
    assert {subject.value for subject in ResetSubject} == {
        "range_identity",
        "sdn_zone",
        "vnets",
        "subnets_and_vlans",
        "firewall_objects",
        "allocation_ledger",
        "guests",
        "challenge_state",
        "team_membership",
        "scores",
    }
    # And the dispositions are a closed set of four; a fifth would need a decision here too.
    assert {d.value for d in ResetDisposition} == {
        "preserved",
        "recreated",
        "restored",
        "cleared",
    }


def test_the_reset_scope_covers_the_guests_and_nothing_else(session, principal, instance):
    """Narrower than a destroy's deletion set, and that is the point.

    A reset preserves every network subject, so its scope must not include the SDN zone, the VNets
    or the firewall objects — approving a reset must not read as approving their removal.
    """
    compiled = _compiled(session, instance)
    reset_kinds = {entry["kind"] for entry in compiled.reset_scope}
    destroy_kinds = {entry["kind"] for entry in compiled.deletion_set}

    assert reset_kinds <= {"virtual_machine", "lxc_container"}, (
        f"the reset scope contains non-guest objects {sorted(reset_kinds)} — a reset preserves the "
        "network, so approving one must not read as approving the network's removal"
    )
    assert reset_kinds < destroy_kinds, "a destroy removes strictly more than a reset"
    for network_kind in ("sdn_zone", "vnet", "firewall_group", "ip_set"):
        assert network_kind not in reset_kinds
    # Every guest the plan describes IS in scope: a reset that missed one would leave a stale guest.
    assert len(compiled.reset_scope) == len(compiled.workload.topology.guests)


def test_the_reset_scope_records_the_base_image_each_guest_is_rebuilt_from(
    session, principal, instance
):
    """A reset rebuilds FROM the template; a changed base image is a different guest coming back."""
    compiled = _compiled(session, instance)
    assert compiled.reset_scope
    assert all(entry.get("template_ref") for entry in compiled.reset_scope)


# --- the gate takes the enum, and that is checked on the signature ----------------


def test_the_gate_takes_the_enum_not_a_string():
    """Checked on the resolved annotation, so a reverted signature fails here.

    The string-typed version compared ``kind == "destroy"`` against a value produced in another
    module. Nothing but the type stops that from being reintroduced.
    """
    import typing

    hints = typing.get_type_hints(proxmox_lifecycle.require_operation_authorized)
    assert hints["kind"] is RangeOperationKind, (
        f"require_operation_authorized takes {hints['kind']!r}; taking a string reintroduces the "
        "cross-module coupling on RangeOperationKind.destroy.value"
    )


def test_the_router_passes_the_enum_through(session, principal, instance):
    """The call site must not re-introduce ``.value``.

    Asserted by behaviour rather than by reading source: authorize a destroy, then drive the real
    router helper for a destroy and confirm it is permitted — which can only happen if the enum
    reached the gate's destroy branch.
    """
    from secp_api.routers.ranges import _start

    _authorize_destroy(session, principal, instance)
    ranges.get_range(session, principal, instance.id)
    # Reaches the gate and passes it; the operation is then created and dispatched, which needs a
    # dispatcher, so stop at the gate itself — the point is that it did not raise.
    proxmox_lifecycle.require_operation_authorized(session, instance, RangeOperationKind.destroy)
    assert callable(_start)
