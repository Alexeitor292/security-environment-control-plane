"""What the signature covers, proved by changing things the old digest could not see.

The replaced defect: ``facts_hash`` was ``sha256({"observations": sorted((code, state) ...)})``.
Names and states only. Every value a collision decision is made from — VMIDs, CTIDs, VLAN tags,
CIDRs, subnet ids, bridge names, VNet ids, storage and template identifiers, pending SDN objects —
was outside the signature, so rewriting any of them produced a byte-identical digest and a snapshot
that still verified as authentic and compilation-eligible.

Every test below therefore holds STATES CONSTANT and changes only a value, a mapping's membership,
or which node a value is attached to. Under the old contract all of them are no-ops. Under the new
one each must move the digest.
"""

from __future__ import annotations

import pytest
from secp_api.discovery_fact_commitment import (
    FACT_COMMITMENT_VERSION,
    FactContribution,
    build_fact_commitment,
    canonical_value,
    contribution_of,
    node_accounting,
    scope_of,
)
from secp_api.discovery_observation import Observation

ORG = "org-1"
TARGET = "target-1"
CLUSTER = "sha256:" + "c" * 64
OPERATION = "op-1"
GENERATION = 3


def _observations(**overrides) -> dict[str, Observation]:
    """A two-node cluster with one of every value class the plan compiler reads."""
    base: dict[str, Observation] = {
        # scalars
        "pve_version_full": Observation.observed("9.1.1"),
        "cluster_identity": Observation.observed({"kind": "cluster", "cluster_name": "lab"}),
        # sequence-valued
        "node_names": Observation.observed(("pve-a", "pve-b")),
        # node-keyed mappings
        "node_capacity": Observation.observed({"pve-a": {"cpus": 8}, "pve-b": {"cpus": 16}}),
        "existing_vm_ids": Observation.observed({"pve-a": (100, 101), "pve-b": (200,)}),
        "existing_lxc_ids": Observation.observed({"pve-a": (900,), "pve-b": ()}),
        "storage_ids": Observation.observed({"pve-a": ("local",), "pve-b": ("local",)}),
        "bridges": Observation.observed({"pve-a": ("vmbr0",), "pve-b": ("vmbr0",)}),
        "management_cidrs": Observation.observed(
            {"pve-a": ("10.0.0.5/24",), "pve-b": ("10.0.0.6/24",)}
        ),
        # node/thing-keyed mappings
        "bridge_vlan_awareness": Observation.observed({"pve-a/vmbr0": True, "pve-b/vmbr0": True}),
        "allowed_storage_content": Observation.observed({"pve-a/local": ("iso", "vztmpl")}),
        "templates": Observation.observed({"pve-a": (9000,)}),
        # SDN
        "existing_vlan_use": Observation.observed({"vnet:v1": 100}),
        "existing_sdn_zones": Observation.observed({"z1": {"cluster_index": {"type": "vlan"}}}),
        "existing_subnets": Observation.observed({"s1": {"cidr": "10.9.0.0/24"}}),
        "pending_sdn_state": Observation.observed(
            {"zones": ({"object_id": "z9", "state": "new"},), "vnets": (), "controllers": ()}
        ),
        # an unusable one, so reason/privilege are exercised too
        "firewall_capability": Observation.permission_denied(
            missing_privilege="Sys.Audit", reason_code="denied"
        ),
    }
    base.update(overrides)
    return base


def _contributions(**overrides) -> dict[str, tuple[FactContribution, ...]]:
    base = {
        "node_names": (
            contribution_of(
                operation_code="node_index",
                rendered_path="/nodes",
                observation=Observation.observed(("pve-a", "pve-b")),
            ),
        ),
        "firewall_capability": (
            contribution_of(
                operation_code="cluster_firewall_options",
                rendered_path="/cluster/firewall/options",
                observation=Observation.permission_denied(
                    missing_privilege="Sys.Audit", reason_code="denied"
                ),
            ),
        ),
    }
    base.update(overrides)
    return base


def _commit(observations=None, required=None, contributions=None, **binding):
    kwargs = dict(
        organization_identity=ORG,
        target_identity=TARGET,
        cluster_fingerprint=CLUSTER,
        operation_identity=OPERATION,
        operation_generation=GENERATION,
    )
    kwargs.update(binding)
    return build_fact_commitment(
        observations=observations if observations is not None else _observations(),
        required_facts=required if required is not None else {},
        contributions=contributions if contributions is not None else _contributions(),
        **kwargs,
    )


def _states(commitment) -> list[tuple[str, str]]:
    """The exact tuple the OLD facts_hash covered. Every mutation below leaves this unchanged."""
    return sorted((row["code"], row["state"]) for row in commitment.canonical()["observations"])


BASE = _commit()
BASE_DIGEST = BASE.digest()


# === the digest is stable and self-consistent =====================================================


def test_the_same_observations_produce_the_same_digest():
    assert _commit().digest() == BASE_DIGEST


def test_mapping_order_does_not_change_the_digest():
    """Two runs that saw the same thing must agree, or every mutation test below is noise."""
    reordered = Observation.observed({"pve-b": {"cpus": 16}, "pve-a": {"cpus": 8}})
    assert _commit(_observations(node_capacity=reordered)).digest() == BASE_DIGEST


def test_the_commitment_names_its_own_version():
    assert BASE.canonical()["commitment_version"] == FACT_COMMITMENT_VERSION


# === value mutations that the OLD digest could not see ============================================

_VALUE_MUTATIONS = [
    # (name, field code, mutated value)
    ("vmid added", "existing_vm_ids", {"pve-a": (100, 101, 102), "pve-b": (200,)}),
    ("vmid removed", "existing_vm_ids", {"pve-a": (100,), "pve-b": (200,)}),
    ("ctid changed", "existing_lxc_ids", {"pve-a": (901,), "pve-b": ()}),
    ("vlan tag changed", "existing_vlan_use", {"vnet:v1": 200}),
    ("cidr changed", "management_cidrs", {"pve-a": ("10.0.0.5/24",), "pve-b": ("10.0.9.6/24",)}),
    ("subnet cidr changed", "existing_subnets", {"s1": {"cidr": "10.9.9.0/24"}}),
    ("bridge renamed", "bridges", {"pve-a": ("vmbr9",), "pve-b": ("vmbr0",)}),
    (
        "vlan awareness flipped",
        "bridge_vlan_awareness",
        {"pve-a/vmbr0": False, "pve-b/vmbr0": True},
    ),
    ("storage id changed", "storage_ids", {"pve-a": ("fast",), "pve-b": ("local",)}),
    ("template id changed", "templates", {"pve-a": (9001,)}),
    (
        "storage content widened",
        "allowed_storage_content",
        {"pve-a/local": ("iso", "vztmpl", "rootdir")},
    ),
    ("vnet zone changed", "existing_sdn_zones", {"z1": {"cluster_index": {"type": "qinq"}}}),
    ("version changed", "pve_version_full", "9.1.2"),
    ("cluster renamed", "cluster_identity", {"kind": "cluster", "cluster_name": "other"}),
    ("node list changed", "node_names", ("pve-a", "pve-c")),
    (
        "pending sdn object removed",
        "pending_sdn_state",
        {"zones": (), "vnets": (), "controllers": ()},
    ),
    (
        "pending sdn object altered",
        "pending_sdn_state",
        {"zones": ({"object_id": "z9", "state": "deleted"},), "vnets": (), "controllers": ()},
    ),
]


@pytest.mark.parametrize(
    "name,code,mutated", _VALUE_MUTATIONS, ids=[m[0].replace(" ", "_") for m in _VALUE_MUTATIONS]
)
def test_a_value_change_moves_the_digest_while_every_state_is_unchanged(name, code, mutated):
    mutant = _commit(_observations(**{code: Observation.observed(mutated)}))
    # The old contract's entire input is identical...
    assert _states(mutant) == _states(BASE), f"{name} changed a state; the test proves nothing"
    # ...and the new digest still moves.
    assert mutant.digest() != BASE_DIGEST, name


# === membership and node association ==============================================================


def test_dropping_one_node_from_a_node_keyed_fact_moves_the_digest():
    """The failure this catches: a three-node cluster's fact quietly describing two."""
    mutant = _commit(_observations(node_capacity=Observation.observed({"pve-a": {"cpus": 8}})))
    assert _states(mutant) == _states(BASE)
    assert mutant.digest() != BASE_DIGEST


def test_adding_a_node_that_was_never_observed_moves_the_digest():
    mutant = _commit(
        _observations(
            node_capacity=Observation.observed(
                {"pve-a": {"cpus": 8}, "pve-b": {"cpus": 16}, "pve-ghost": {"cpus": 64}}
            )
        )
    )
    assert _states(mutant) == _states(BASE)
    assert mutant.digest() != BASE_DIGEST


def test_moving_a_value_between_nodes_moves_the_digest():
    """Node association, not just membership: the same two VMIDs on the wrong hosts is a different
    cluster, and placing a guest on the node that does not hold its id is the collision."""
    swapped = Observation.observed({"pve-a": (200,), "pve-b": (100, 101)})
    mutant = _commit(_observations(existing_vm_ids=swapped))
    assert _states(mutant) == _states(BASE)
    assert sorted(scope_of(swapped.value)) == sorted(
        scope_of(BASE.observations["existing_vm_ids"].value)
    )
    assert mutant.digest() != BASE_DIGEST


def test_a_nested_mapping_key_removed_deep_inside_a_value_moves_the_digest():
    mutant = _commit(_observations(existing_sdn_zones=Observation.observed({"z1": {}})))
    assert _states(mutant) == _states(BASE)
    assert mutant.digest() != BASE_DIGEST


# === state, reason and privilege ==================================================================


def test_rewriting_a_refusal_reason_moves_the_digest():
    """permission_denied names a grant to request; a rewritten reason sends an operator away."""
    mutant = _commit(
        _observations(
            firewall_capability=Observation.permission_denied(
                missing_privilege="Sys.Audit", reason_code="something_else"
            )
        )
    )
    assert _states(mutant) == _states(BASE)  # same state, different reason
    assert mutant.digest() != BASE_DIGEST


def test_rewriting_the_missing_privilege_moves_the_digest():
    mutant = _commit(
        _observations(
            firewall_capability=Observation.permission_denied(
                missing_privilege="VM.Audit", reason_code="denied"
            )
        )
    )
    assert _states(mutant) == _states(BASE)
    assert mutant.digest() != BASE_DIGEST


def test_an_unusable_fact_carries_no_value_key_at_all():
    """A null beside a state is an invitation to read the null as the fact."""
    row = next(r for r in BASE.canonical()["observations"] if r["code"] == "firewall_capability")
    assert "value" not in row
    assert row["state"] == "permission_denied"
    assert row["missing_privilege"] == "Sys.Audit"


# === provenance ===================================================================================


def test_dropping_a_failing_contribution_moves_the_digest():
    """A refusal another source overwrote is still signed. Removing it is tampering, not tidying."""
    mutant = _commit(contributions=_contributions(firewall_capability=()))
    assert _states(mutant) == _states(BASE)
    assert mutant.digest() != BASE_DIGEST


def test_changing_which_operation_supplied_a_fact_moves_the_digest():
    mutant = _commit(
        contributions=_contributions(
            node_names=(
                contribution_of(
                    operation_code="cluster_status",
                    rendered_path="/cluster/status",
                    observation=Observation.observed(("pve-a", "pve-b")),
                ),
            )
        )
    )
    assert mutant.digest() != BASE_DIGEST


def test_a_contribution_records_a_failure_with_no_value_digest():
    (denied,) = _contributions()["firewall_capability"]
    assert denied.state == "permission_denied"
    assert denied.missing_privilege == "Sys.Audit"
    assert denied.value_digest == ""
    assert denied.scope == ()


# === binding ======================================================================================


@pytest.mark.parametrize(
    "field,value",
    [
        ("organization_identity", "org-other"),
        ("target_identity", "target-other"),
        ("cluster_fingerprint", "sha256:" + "d" * 64),
        ("operation_identity", "op-other"),
        ("operation_generation", 4),
    ],
)
def test_replaying_the_same_facts_under_a_different_binding_moves_the_digest(field, value):
    """Without this the same observations are replayable against another cluster or operation."""
    mutant = _commit(**{field: value})
    assert _states(mutant) == _states(BASE)
    assert mutant.digest() != BASE_DIGEST


# === the canonicaliser ============================================================================


def test_tuples_and_lists_canonicalise_identically():
    """They are the same JSON, and a fact must not change identity because a parser returned one."""
    assert canonical_value(("a", "b")) == canonical_value(["a", "b"])


def test_a_value_the_canonicaliser_does_not_recognise_is_still_covered():
    """A value the digest cannot see is a value nobody signed."""

    class _Odd:
        def __repr__(self) -> str:
            return "<odd:1>"

    assert canonical_value(_Odd()) == "<odd:1>"
    assert canonical_value({"k": _Odd()}) == {"k": "<odd:1>"}


def test_list_order_is_preserved_because_it_is_what_the_target_returned():
    assert canonical_value(["b", "a"]) == ["b", "a"]
    assert canonical_value(["b", "a"]) != canonical_value(["a", "b"])


# === node accounting ==============================================================================


def test_the_expected_node_set_is_inside_the_digest():
    """What "complete" MEANT is part of the signature. Without it, a snapshot accounted against a
    two-node cluster could later be read as complete for a three-node one."""
    two = _commit(expected_node_identities=("pve-a", "pve-b"))
    three = _commit(expected_node_identities=("pve-a", "pve-b", "pve-c"))
    assert _states(two) == _states(three)
    assert two.digest() != three.digest()


def test_renaming_an_expected_node_moves_the_digest():
    a = _commit(expected_node_identities=("pve-a", "pve-b"))
    b = _commit(expected_node_identities=("pve-a", "pve-z"))
    assert a.digest() != b.digest()


def test_the_expected_node_set_is_bound_directly_and_not_only_through_the_accounting():
    """With NO contributions the per-fact accounting is empty for both, so the only thing that can
    distinguish these two commitments is the expected set itself. Without this the field could be
    dropped from the canonical form and every other test would still pass — it would be carried
    incidentally by the accounting block, which vanishes the moment a run contributes nothing."""
    a = _commit(contributions={}, expected_node_identities=("pve-a", "pve-b"))
    b = _commit(contributions={}, expected_node_identities=("pve-a", "pve-b", "pve-c"))
    assert a.canonical()["node_accounting"] == b.canonical()["node_accounting"] == []
    assert a.digest() != b.digest()


def test_a_node_denied_by_one_source_stays_denied_when_another_succeeds():
    """Worst outcome wins per node. One denied read about a node is not cured by another read
    about the same node succeeding — the denied one covered something this one did not."""
    contributions = {
        "node_capacity": (
            FactContribution(
                operation_code="node_status",
                rendered_path="/nodes/pve-a/status",
                state="observed",
                subject="pve-a",
            ),
            FactContribution(
                operation_code="node_apt",
                rendered_path="/nodes/pve-a/apt/versions",
                state="permission_denied",
                subject="pve-a",
                missing_privilege="Sys.Audit",
            ),
        )
    }
    accounting = node_accounting(("pve-a",), contributions["node_capacity"])
    assert accounting == {"pve-a": "denied"}


def test_every_expected_node_lands_in_exactly_one_outcome():
    contributions = (
        FactContribution(operation_code="o", rendered_path="/p", state="observed", subject="n1"),
        FactContribution(
            operation_code="o", rendered_path="/p", state="permission_denied", subject="n2"
        ),
        FactContribution(
            operation_code="o", rendered_path="/p", state="observed_unsupported", subject="n3"
        ),
        FactContribution(
            operation_code="o", rendered_path="/p", state="probe_failed", subject="n4"
        ),
    )
    accounting = node_accounting(("n1", "n2", "n3", "n4", "n5"), contributions)
    assert accounting == {
        "n1": "observed",
        "n2": "denied",
        "n3": "unsupported",
        "n4": "failed",
        "n5": "missing",
    }


def test_a_contribution_about_a_node_outside_the_expected_set_accounts_for_nothing():
    """Accounting starts from the EXPECTED set: an answer about a node the cluster does not list
    cannot make a listed node covered."""
    contributions = (
        FactContribution(
            operation_code="o", rendered_path="/p", state="observed", subject="pve-ghost"
        ),
    )
    assert node_accounting(("pve-a",), contributions) == {"pve-a": "missing"}
