"""Which discovery facts the compiler must refuse without, and the exact unsafe decision each one
prevents.

A fact is REQUIRED here only when its absence lets SECP make a decision that can damage something
real — a collision with a guest that already exists, an allocation into a VLAN somebody else is
using, a plan compiled against a target whose identity was never established. "It would be nice to
display" is not a reason, and every entry below names the specific wrong outcome rather than
gesturing at prudence.

The table is machine-readable on purpose. A required-fact list that lives in a document drifts from
the compiler that is supposed to enforce it, and the drift is invisible until a plan is generated
against a cluster nobody checked.

Two classifications carry most of the weight:

``required_before_compilation``
    Without it the compiled desired state may already be wrong — a VMID that is taken, a VLAN that
    collides. Compilation refuses.
``required_before_apply``
    Compilation can proceed and the operator can review a plan, but the apply must not run. These
    are facts that constrain execution rather than content.

The remaining three (`operator_context`, `optional`, `unsupported`) never block anything. A fact
classified `unsupported` is one the target genuinely cannot answer, which is different from one
SECP has not implemented — that difference lives in ``DiscoveryObservationState``, not here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FactRequirement(str, Enum):
    """How badly the compiler needs a fact."""

    required_before_compilation = "required_before_compilation"
    required_before_apply = "required_before_apply"
    operator_context = "operator_context"
    optional = "optional"
    unsupported = "unsupported"


@dataclass(frozen=True)
class RequiredFact:
    """One discovery fact and the unsafe decision its absence would permit."""

    name: str
    requirement: FactRequirement
    #: The specific wrong outcome. Empty ONLY for non-blocking classifications — a fact that blocks
    #: compilation without naming what it prevents is a fact nobody can argue with, which is how a
    #: required list grows until discovery can never complete.
    unsafe_decision: str = ""
    #: The Proxmox privilege the observation needs, where one applies. Recorded so a refusal can
    #: tell an operator what to grant rather than that something is missing.
    privilege: str = ""


#: The twelve conditions compilation must be able to EXCLUDE. Each maps to the facts that exclude
#: it; a fact is required-before-compilation precisely when some condition here depends on it.
UNSAFE_CONDITIONS: tuple[str, ...] = (
    "vmid_or_lxcid_collision",
    "vlan_collision",
    "subnet_overlap",
    "management_network_overlap",
    "foreign_sdn_ownership",
    "unsupported_storage_placement",
    "unsupported_template_or_image",
    "unsupported_firewall_capability",
    "pending_sdn_state",
    "incomplete_target_identity",
    "stale_discovery",
    "unverifiable_discovery_producer",
)

_R = FactRequirement

#: The first-Proxmox-MVP requirement table. Ordered by classification, then by name.
REQUIRED_FACTS: tuple[RequiredFact, ...] = (
    # --- required before compilation ---------------------------------------------------------
    RequiredFact(
        "exact_pve_version",
        _R.required_before_compilation,
        "compiling against a provider pinned for a PVE major/minor the target does not run; "
        "provider compatibility is decided at the patch level, so a truncated 9.1 for an actual "
        "9.1.1 is not sufficient",
        "Sys.Audit",
    ),
    RequiredFact(
        "cluster_identity",
        _R.required_before_compilation,
        "binding a plan to the wrong cluster — without it, a snapshot taken from cluster A can be "
        "compiled and applied against cluster B and nothing detects the substitution",
        "Sys.Audit",
    ),
    RequiredFact(
        "node_names",
        _R.required_before_compilation,
        "placing a guest on a node that does not exist, or spreading a range across nodes that "
        "cannot reach the same bridges",
        "Sys.Audit",
    ),
    RequiredFact(
        "existing_vm_ids",
        _R.required_before_compilation,
        "VMID collision: allocating an id already held by a guest SECP does not own, which at "
        "apply either fails loudly or — worse — is silently adopted",
        "VM.Audit",
    ),
    RequiredFact(
        "existing_lxc_ids",
        _R.required_before_compilation,
        "the same collision for containers. Recorded separately because the current probe passes "
        "`--type vm` and therefore cannot see containers at all",
        "VM.Audit",
    ),
    RequiredFact(
        "storage_ids",
        _R.required_before_compilation,
        "placing a disk on a storage that does not exist on the chosen node",
        "Datastore.Audit",
    ),
    RequiredFact(
        "allowed_storage_content",
        _R.required_before_compilation,
        "unsupported storage placement: putting a container rootfs on a storage that accepts only "
        "images, or an ISO where the storage does not accept iso content — a plan that looks valid "
        "and fails at apply",
        "Datastore.Audit",
    ),
    RequiredFact(
        "bridges",
        _R.required_before_compilation,
        "attaching a NIC to a bridge that does not exist on the target node",
        "Sys.Audit",
    ),
    RequiredFact(
        "bridge_vlan_awareness",
        _R.required_before_compilation,
        "assigning a VLAN tag on a bridge that is not VLAN-aware: the tag is silently ignored and "
        "every team lands on one flat segment — an isolation failure that looks like success",
        "Sys.Audit",
    ),
    RequiredFact(
        "existing_vlan_use",
        _R.required_before_compilation,
        "VLAN collision: allocating a tag already carrying somebody else's traffic, which bridges "
        "two environments that must not see each other",
        "SDN.Audit",
    ),
    RequiredFact(
        "existing_sdn_zones",
        _R.required_before_compilation,
        "foreign SDN ownership: creating a zone whose id already exists, or reasoning about a "
        "zone space that was never read",
        "SDN.Audit",
    ),
    RequiredFact(
        "existing_vnets",
        _R.required_before_compilation,
        "VNet id collision, and VLAN-tag collision — the tag lives on the VNet",
        "SDN.Audit",
    ),
    RequiredFact(
        "existing_subnets",
        _R.required_before_compilation,
        "subnet overlap: allocating a CIDR that intersects one already in use, which breaks "
        "routing for both",
        "SDN.Audit",
    ),
    RequiredFact(
        "pending_sdn_state",
        _R.required_before_compilation,
        "compiling against a zone/VNet/subnet set that is about to change: an object staged for "
        "deletion still occupies its id, and one staged for creation does not yet appear in the "
        "running config. Unknown pending state is NOT 'nothing pending'",
        "SDN.Audit",
    ),
    RequiredFact(
        "management_cidrs",
        _R.required_before_compilation,
        "management-network overlap: allocating a lab subnet that collides with the network the "
        "control plane and the cluster itself are reached on — the failure mode that takes the "
        "target away with it",
        "Sys.Audit",
    ),
    RequiredFact(
        "management_bridges",
        _R.required_before_compilation,
        "attaching a lab NIC to the management bridge, putting exercise traffic on the control "
        "path",
        "Sys.Audit",
    ),
    RequiredFact(
        "target_identity",
        _R.required_before_compilation,
        "incomplete target identity: a plan that cannot say which endpoint it was compiled for "
        "cannot be safely authorised for any",
    ),
    RequiredFact(
        "observation_timestamp",
        _R.required_before_compilation,
        "stale discovery: without a completion time the snapshot cannot be aged at all, so no "
        "freshness claim about it is possible",
    ),
    RequiredFact(
        "worker_identity",
        _R.required_before_compilation,
        "unverifiable discovery producer: an observation that cannot name its producer cannot be "
        "checked against the registered worker anchor",
    ),
    RequiredFact(
        "evidence_signature",
        _R.required_before_compilation,
        "unverifiable discovery producer: an unkeyed content hash is recomputable by anyone who "
        "can write the row, so it authenticates nothing",
    ),
    # --- required before apply ---------------------------------------------------------------
    RequiredFact(
        "node_online_state",
        _R.required_before_apply,
        "applying against a node that is down — the plan content is still correct, so this "
        "constrains execution rather than compilation",
        "Sys.Audit",
    ),
    RequiredFact(
        "node_capacity",
        _R.required_before_apply,
        "applying a range the node cannot host; a plan that overcommits is reviewable but must "
        "not run",
        "Sys.Audit",
    ),
    RequiredFact(
        "available_capacity",
        _R.required_before_apply,
        "applying when storage has insufficient free space",
        "Datastore.Audit",
    ),
    RequiredFact(
        "templates",
        _R.required_before_apply,
        "unsupported template: cloning from a template id that is absent. Required before apply "
        "rather than before compilation because the desired state names the template and review "
        "can catch a wrong one",
        "VM.Audit",
    ),
    RequiredFact(
        "iso_and_container_template_availability",
        _R.required_before_apply,
        "unsupported image: booting from an ISO or container template the storage does not hold",
        "Datastore.Audit",
    ),
    RequiredFact(
        "firewall_capability",
        _R.required_before_apply,
        "unsupported firewall capability: compiling firewall objects the cluster cannot enforce "
        "would produce a plan whose isolation claims cannot be met",
        "Sys.Audit",
    ),
    RequiredFact(
        "worker_release_fingerprint",
        _R.required_before_apply,
        "applying with a worker whose release differs from the one that produced the observation",
    ),
    RequiredFact(
        "target_tls_identity",
        _R.required_before_apply,
        "contacting an endpoint whose TLS identity was never pinned — the discovery transport can "
        "verify it, but an apply against an unpinned authority is the larger exposure",
    ),
    # --- operator context ----------------------------------------------------------------------
    RequiredFact("kernel_version", _R.operator_context, privilege="Sys.Audit"),
    RequiredFact("node_versions", _R.operator_context, privilege="Sys.Audit"),
    RequiredFact("storage_types", _R.operator_context, privilege="Datastore.Audit"),
    RequiredFact("release_build_identifier", _R.operator_context, privilege="Sys.Audit"),
    RequiredFact("raw_host_package_version", _R.operator_context, privilege="Sys.Audit"),
    # --- optional --------------------------------------------------------------------------------
    RequiredFact("api_feature_availability", _R.optional),
    RequiredFact("credential_identity_reference", _R.optional),
)


def _by_name() -> dict[str, RequiredFact]:
    return {fact.name: fact for fact in REQUIRED_FACTS}


def facts_required_before_compilation() -> tuple[str, ...]:
    """The names the compiler refuses without. The ONLY set it may refuse on."""
    return tuple(f.name for f in REQUIRED_FACTS if f.requirement is _R.required_before_compilation)


def facts_required_before_apply() -> tuple[str, ...]:
    return tuple(f.name for f in REQUIRED_FACTS if f.requirement is _R.required_before_apply)


def compilation_refusals(usable_facts: frozenset[str]) -> tuple[tuple[str, str], ...]:
    """``(fact, unsafe_decision)`` for every compilation-blocking fact that is not usable.

    Takes the set of USABLE facts rather than a snapshot, so the caller must have already applied
    ``Observation.is_usable``. Passing a fact whose observation state is ``permission_denied`` as
    though it were present is the mistake this signature makes awkward.

    Returns the unsafe decision alongside the name because a refusal an operator cannot act on is
    barely better than a silent one.
    """
    missing = [f for f in REQUIRED_FACTS if f.requirement is _R.required_before_compilation]
    return tuple((f.name, f.unsafe_decision) for f in missing if f.name not in usable_facts)


def apply_refusals(usable_facts: frozenset[str]) -> tuple[tuple[str, str], ...]:
    """The same, for the apply gate. Deliberately a separate call: a plan may be compiled and
    reviewed while these are still missing, and conflating the two gates would either block
    review unnecessarily or let an apply through on compilation-only evidence."""
    missing = [f for f in REQUIRED_FACTS if f.requirement is _R.required_before_apply]
    return tuple((f.name, f.unsafe_decision) for f in missing if f.name not in usable_facts)


def privileges_required() -> frozenset[str]:
    """Every distinct Proxmox privilege the required set depends on.

    Derived from the table rather than declared separately, so the credential proposal and the
    fact table cannot drift apart — the role is exactly what the required facts need and nothing
    more.
    """
    return frozenset(f.privilege for f in REQUIRED_FACTS if f.privilege)
