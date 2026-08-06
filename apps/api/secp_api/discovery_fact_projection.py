"""Raw observation fields to the required-fact vocabulary the compiler gates on.

These are two different vocabularies and conflating them is why a signed snapshot could look
complete while answering none of the questions compilation asks. ``/version`` produces
``pve_version_major``, ``pve_version_minor`` and ``pve_version_patch``; the required-fact table asks
for ``exact_pve_version``. A node index produces ``{node: capacity}``; the table asks whether
``node_capacity`` is known — for the whole cluster, not for whichever node answered first.

Four derivations exist here, and each closes a way a fact could look present while being unusable:

``composed``
    A required fact assembled from several raw fields. Unusable if ANY component is, and it inherits
    the component's state rather than being flattened to a generic failure.
``node-complete``
    A node-scoped fact is only observed when EVERY node named by ``node_names`` has an entry. A
    mapping covering one node of three is not a smaller answer, it is an unknown — and it is exactly
    what a plan compiler would read as "capacity is known" before placing guests on the other two.
``sdn-gated``
    Proxmox answers a privilege-denied SDN index with **200 and an empty list**, so no SDN fact may
    be trusted unless ``GET /cluster/sdn`` — a declarative permission check that 403s outright —
    succeeded. Without that, every SDN fact is ``permission_denied`` regardless of what the indexes
    returned, because an index that cannot be known to be complete cannot exclude a collision.
``control-plane-supplied``
    Identity, timestamp, producer and signature are not target observations at all. They come from
    the binding. Deriving them from a payload would let a target assert its own identity.

Nothing here defaults. A required fact with no source is ``not_implemented`` — code to write, which
is a different problem from a grant to request, and the distinction survives to the operator.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from secp_api.discovery_fact_commitment import (
    NODE_DENIED,
    NODE_OBSERVED,
    FactContribution,
    node_accounting,
)
from secp_api.discovery_observation import Observation
from secp_api.discovery_required_facts import REQUIRED_FACTS
from secp_api.enums import DiscoveryObservationState

#: The pending families whose enumeration must be complete. Imported from the control plane's ONE
#: declaration rather than restated: this module previously carried a third copy of the list, and it
#: was the copy that actually decided the answer.
from secp_api.sdn_pending_families import FABRICS_FAMILY, PENDING_FAMILIES

#: Bound into the signed binding as ``projection_implementation_id``. Two runs that saw identical
#: bytes but derived facts with different code produced different observations.
REQUIRED_FACT_PROJECTION_ID = "secp-discovery/projection/v1"

SDN_AUDIT_PRIVILEGE = "SDN.Audit"

#: Required facts taken straight from a raw field of the same name.
_DIRECT: frozenset[str] = frozenset(
    {
        "cluster_identity",
        "node_names",
        "node_online_state",
        "node_capacity",
        "kernel_version",
        "node_versions",
        "raw_host_package_version",
        "release_build_identifier",
        "bridges",
        "bridge_vlan_awareness",
        "management_bridges",
        "management_cidrs",
        "storage_ids",
        "storage_types",
        "allowed_storage_content",
        "available_capacity",
        "templates",
        "iso_and_container_template_availability",
        "existing_vm_ids",
        "existing_lxc_ids",
        "firewall_capability",
    }
)

#: Guest facts that mean nothing unless VM.Audit was demonstrated.
#:
#: Proxmox filters guest rows the caller may not see rather than refusing the read, so an index that
#: returns rows proves only that SOME guests are visible — never that all are. And unlike SDN there
#: is no declarative endpoint that 403s outright, so the effective permission map is the only
#: evidence. It is read, never inferred: a successful authentication proves the token works, and an
#: unrelated successful read proves nothing at all about guests.
_VM_GATED: frozenset[str] = frozenset({"existing_vm_ids", "existing_lxc_ids", "templates"})

VM_AUDIT_PRIVILEGE = "VM.Audit"

#: Facts that mean nothing unless the SDN read authority was demonstrated.
_SDN_GATED: frozenset[str] = frozenset(
    {
        "existing_sdn_zones",
        "existing_vnets",
        "existing_subnets",
        "existing_vlan_use",
        "pending_sdn_state",
    }
)

#: Node-scoped facts keyed by node name exactly.
_NODE_KEYED: frozenset[str] = frozenset(
    {
        "node_online_state",
        "node_capacity",
        "kernel_version",
        "node_versions",
        "raw_host_package_version",
        "release_build_identifier",
        "bridges",
        "management_bridges",
        "management_cidrs",
        "storage_ids",
        "existing_vm_ids",
        "existing_lxc_ids",
        "templates",
    }
)

#: Node-scoped facts keyed ``node/thing``, mapped to the fact that says how many ``thing`` a node
#: has. A node with no bridges is fully covered by an empty VLAN-awareness mapping; without the
#: second column that node would look permanently unobserved and refuse compilation forever.
_NODE_PREFIXED: dict[str, str] = {
    "bridge_vlan_awareness": "bridges",
    "storage_types": "storage_ids",
    "allowed_storage_content": "storage_ids",
    "available_capacity": "storage_ids",
    "iso_and_container_template_availability": "storage_ids",
}

#: Facts the CONTROL PLANE supplies. A target must never assert these about itself.
_CONTROL_PLANE_SUPPLIED: frozenset[str] = frozenset(
    {
        "target_identity",
        "observation_timestamp",
        "worker_identity",
        "evidence_signature",
        "worker_release_fingerprint",
        "target_tls_identity",
    }
)

#: ``exact_pve_version`` in the order its components are checked.
_VERSION_COMPONENTS: tuple[str, ...] = (
    "pve_version_major",
    "pve_version_minor",
    "pve_version_patch",
)

#: Facts no first-MVP operation answers. Non-blocking, and reported as code to write rather than as
#: a grant to request.
_NO_SOURCE_YET: dict[str, str] = {
    "api_feature_availability": "no_first_mvp_operation_enumerates_api_features",
    "credential_identity_reference": "credential_identity_is_not_a_target_observation",
}


#: Every derivation category. Checked against the required-fact table at import so a fact added to
#: the table without a derivation here fails immediately rather than silently projecting to
#: ``not_requested`` — an invisible permanent refusal is the worst of both outcomes.
_ALL_DERIVATIONS: frozenset[str] = (
    _DIRECT
    | _SDN_GATED
    | _CONTROL_PLANE_SUPPLIED
    | frozenset(_NO_SOURCE_YET)
    | frozenset({"exact_pve_version"})
)


class FactProjectionTableError(RuntimeError):
    """The derivation table and the required-fact table disagree."""


def _assert_table_is_total() -> None:
    required = {fact.name for fact in REQUIRED_FACTS}
    undeclared = sorted(required - _ALL_DERIVATIONS)
    invented = sorted(_ALL_DERIVATIONS - required)
    if undeclared or invented:
        raise FactProjectionTableError(
            f"required_fact_derivation_mismatch:undeclared={undeclared}:invented={invented}"
        )
    stray = sorted((_NODE_KEYED | frozenset(_NODE_PREFIXED)) - required)
    if stray:
        raise FactProjectionTableError(f"node_scope_names_not_in_the_required_table:{stray}")


_assert_table_is_total()


def _propagated(source: Observation) -> Observation:
    """Carry an unusable component's own state forward rather than flattening it.

    ``permission_denied`` and ``observed_unsupported`` demand different operator responses, and a
    composed fact that reported both as "missing" would hide which one applies.
    """
    return Observation(
        state=source.state,
        reason_code=source.reason_code or "component_unobserved",
        missing_privilege=source.missing_privilege,
    )


def _unobserved(reason: str) -> Observation:
    return Observation.not_requested(reason)


#: Reason codes are projected to operators and go into signed evidence, and their own contract says
#: "never a host, endpoint, path or credential". Identifiers interpolated into them come straight
#: from the target's JSON, so they are bounded and reduced to a safe alphabet first. A target that
#: names a vnet with a newline, a URL or four kilobytes of text cannot use a refusal message as a
#: delivery channel.
_REASON_SAFE = re.compile(r"[^A-Za-z0-9._@-]")
_MAX_REASON_IDENTIFIER = 64


def safe_identifier(value: object) -> str:
    """One target-supplied identifier, made safe to appear in an operator-facing reason."""
    text = _REASON_SAFE.sub("?", str(value))
    if len(text) > _MAX_REASON_IDENTIFIER:
        return text[:_MAX_REASON_IDENTIFIER] + "~"
    return text or "<empty>"


def _sdn_authority_established(raw: Mapping[str, Observation]) -> bool:
    """Only a successful ``GET /cluster/sdn`` counts.

    ``/access/permissions`` reporting SDN.Audit is a claim about a grant; the root read is a
    demonstrated one, and it is the endpoint that cannot answer 200-with-empty for a permission
    reason. Accepting the grant claim instead would reintroduce exactly the ambiguity the root read
    exists to remove.
    """
    authority = raw.get("sdn_read_authority")
    if authority is None or not authority.is_usable:
        return False
    value = authority.value
    return isinstance(value, dict) and value.get("cluster_sdn_readable") is True


def _vm_audit_established(raw: Mapping[str, Observation]) -> bool:
    """Only the effective permission map counts.

    Not "the guest index returned rows" — a filtered index returns rows either way — and not "the
    token authenticated", which says nothing about what it may see.
    """
    authority = raw.get("guest_read_authority")
    if authority is None or not authority.is_usable:
        return False
    value = authority.value
    return isinstance(value, dict) and value.get("vm_audit_granted") is True


def _known_nodes(raw: Mapping[str, Observation]) -> tuple[str, ...] | None:
    names = raw.get("node_names")
    if names is None or not names.is_usable or not isinstance(names.value, (tuple, list)):
        return None
    return tuple(str(n) for n in names.value)


def _node_coverage(
    name: str,
    observation: Observation,
    raw: Mapping[str, Observation],
    nodes: tuple[str, ...],
    contributions: Mapping[str, Sequence[FactContribution]],
) -> Observation:
    """Refuse a node-scoped fact that does not account for EVERY expected node.

    The rule this replaces asked whether any key beginning with a node's name appeared in the
    value. That accepted one successful storage read as certifying a whole node, and it could not
    see a node no operation was even planned for — an absence and an answer looked identical.

    Accounting now starts from the expected node set (the observed cluster inventory) and assigns
    every node exactly one outcome: observed, denied, unsupported, failed or missing. Anything but
    ``observed`` for any expected node refuses the fact for CLUSTER-WIDE use, and the refusal names
    the nodes and their outcomes so an operator knows whether to grant, retry or re-observe.
    """
    value = observation.value
    if not isinstance(value, dict):
        return Observation.malformed(f"{name}_is_not_a_node_keyed_mapping")

    accounting = node_accounting(nodes, contributions.get(name, ()))
    unaccounted = {
        node: outcome for node, outcome in accounting.items() if outcome != NODE_OBSERVED
    }

    # A node whose outcome is `observed` must also actually appear in the merged value; a source
    # that answered about a node without contributing a key for it has covered nothing.
    for node in nodes:
        if accounting.get(node) != NODE_OBSERVED:
            continue
        if not _value_covers(name, value, node, raw):
            unaccounted[node] = "answered_without_covering"

    if unaccounted:
        detail = ",".join(
            f"{safe_identifier(node)}={outcome}" for node, outcome in sorted(unaccounted.items())
        )
        if all(outcome == NODE_DENIED for outcome in unaccounted.values()):
            return Observation.permission_denied(
                missing_privilege=_denied_privilege(contributions.get(name, ())),
                reason_code=f"{name}_not_accounted_for_every_node:{detail}",
            )
        return _unobserved(f"{name}_not_accounted_for_every_node:{detail}")
    return observation


def _denied_privilege(contributions: Sequence[FactContribution]) -> str:
    """The privilege the denials named, so a refusal tells an operator what to grant."""
    named = sorted({c.missing_privilege for c in contributions if c.missing_privilege})
    return named[0] if named else "unknown_privilege"


def _value_covers(
    name: str, value: Mapping[str, object], node: str, raw: Mapping[str, Observation]
) -> bool:
    """Whether the merged value actually says something about this node."""
    if name in _NODE_KEYED:
        return node in value
    if any(str(key).startswith(f"{node}/") for key in value):
        return True
    # Vacuously covered when the node has none of the things this fact describes.
    container = raw.get(_NODE_PREFIXED[name])
    container_value = container.value if container is not None and container.is_usable else {}
    return isinstance(container_value, dict) and container_value.get(node) == ()


def _pending_sdn_completeness(observation: Observation, raw: Mapping[str, Observation]) -> str:
    """Which pending families were NOT enumerated.

    There is no read-only "does anything pend" boolean in the API, so completeness across every
    family is the only way to know — and a partial enumeration is an unknown rather than a smaller
    answer. Subnets have no cluster-wide index, so every observed vnet must have been walked.
    """
    value = observation.value if isinstance(observation.value, dict) else {}
    # ONE family list, imported rather than restated. This was a THIRD copy — the worker had
    # SDN_PENDING_FAMILIES, the control plane had PENDING_FAMILIES pinned to it, and this literal
    # was the copy that actually decided visibility_complete.
    missing = [family for family in PENDING_FAMILIES if family != "subnets" and family not in value]
    # `fabrics` is version-dependent: it exists from PVE 9.0 and a 404 on it is an ANSWER
    # (observed_unsupported), not a gap. It is required to have been ACCOUNTED for — attempted and
    # either enumerated or answered — because PUT /cluster/sdn commits pending fabrics too, so a
    # family nobody asked about makes the pending set knowably smaller than what would activate.
    if FABRICS_FAMILY not in value:
        missing.append(FABRICS_FAMILY)
    vnets = raw.get("existing_vnets")
    if vnets is None or not vnets.is_usable or not isinstance(vnets.value, dict):
        missing.append("subnets(no_vnet_index)")
    else:
        for vnet in sorted(vnets.value):
            if f"subnets@{vnet}" not in value:
                missing.append(f"subnets@{safe_identifier(vnet)}")
    return ",".join(missing)


def project_required_facts(
    raw: Mapping[str, Observation],
    *,
    control_plane_facts: Mapping[str, Observation] | None = None,
    contributions: Mapping[str, Sequence[FactContribution]] | None = None,
) -> dict[str, Observation]:
    """Every name in the required-fact table, with an observation for each. Never more, never less.

    Returning a partial mapping would put a required fact into the "absent" bucket with no state and
    no reason, which is the one outcome an operator cannot act on.
    """
    supplied = dict(control_plane_facts or {})
    sources = dict(contributions or {})
    nodes = _known_nodes(raw)
    sdn_authority = _sdn_authority_established(raw)
    vm_audit = _vm_audit_established(raw)
    out: dict[str, Observation] = {}

    for fact in REQUIRED_FACTS:
        name = fact.name

        if name in _CONTROL_PLANE_SUPPLIED:
            out[name] = supplied.get(name, _unobserved(f"{name}_not_supplied_by_the_control_plane"))
            continue

        if name in _NO_SOURCE_YET:
            out[name] = Observation.not_implemented(_NO_SOURCE_YET[name])
            continue

        if name == "exact_pve_version":
            out[name] = _exact_pve_version(raw)
            continue

        if name in _VM_GATED and not vm_audit:
            # Rows may well have arrived. They establish that SOME guests are visible, which is
            # exactly the claim that permits a VMID or CTID collision with one that is not.
            out[name] = Observation.permission_denied(
                missing_privilege=VM_AUDIT_PRIVILEGE,
                reason_code="vm_read_authority_not_established",
            )
            continue

        if name in _SDN_GATED and not sdn_authority:
            # Uniform even when the index returned rows: rows prove SOME visibility, never that the
            # answer is complete, and completeness is what excluding a collision requires.
            out[name] = Observation.permission_denied(
                missing_privilege=SDN_AUDIT_PRIVILEGE,
                reason_code="sdn_read_authority_not_established",
            )
            continue

        observation = raw.get(name)
        if observation is None:
            out[name] = _unobserved(f"{name}_not_observed_by_this_run")
            continue

        if observation.is_usable and name == "pending_sdn_state":
            incomplete = _pending_sdn_completeness(observation, raw)
            if incomplete:
                out[name] = _unobserved(f"sdn_pending_families_incomplete:{incomplete}")
                continue

        if observation.is_usable and (name in _NODE_KEYED or name in _NODE_PREFIXED):
            if nodes is None:
                out[name] = _unobserved(f"{name}_cannot_be_completeness_checked_without_node_names")
                continue
            observation = _node_coverage(name, observation, raw, nodes, sources)

        out[name] = observation

    return out


def _exact_pve_version(raw: Mapping[str, Observation]) -> Observation:
    """``major.minor.patch``, or the state of the first component that is missing.

    Provider compatibility is decided at the patch level, so a truncated ``9.1`` standing in for an
    actual ``9.1.1`` is not a partial answer — it is a different one.
    """
    parts: list[str] = []
    for component in _VERSION_COMPONENTS:
        observation = raw.get(component)
        if observation is None:
            return _unobserved(f"exact_pve_version_missing_component:{component}")
        if not observation.is_usable:
            return _propagated(observation)
        parts.append(str(observation.value))
    return Observation.observed(".".join(parts))


def required_fact_states(projected: Mapping[str, Observation]) -> tuple[tuple[str, str], ...]:
    """The ``(fact, state)`` pairs that go INSIDE the signed binding.

    Sorted so two runs that observed the same thing produce the same digest, and carrying the state
    rather than a boolean so a consumer cannot be told a fact was merely absent when the producer
    recorded it permission-denied.
    """
    return tuple(sorted((name, obs.state.value) for name, obs in projected.items()))


def usable_fact_names(projected: Mapping[str, Observation]) -> frozenset[str]:
    """The set the required-fact refusal helpers take. Never derived from ``value``."""
    return frozenset(name for name, obs in projected.items() if obs.is_usable)


def unobserved_privileges(projected: Mapping[str, Observation]) -> tuple[str, ...]:
    """Every privilege a refused fact named, so an operator is told what to grant once."""
    return tuple(
        sorted(
            {
                obs.missing_privilege
                for obs in projected.values()
                if obs.state is DiscoveryObservationState.permission_denied
                and obs.missing_privilege
            }
        )
    )
