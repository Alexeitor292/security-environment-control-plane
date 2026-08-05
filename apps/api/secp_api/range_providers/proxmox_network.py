"""The segregated-network compiler.

The product creates the whole scenario network. An operator pre-creates nothing: no bridge, no
VLAN, no subnet, no firewall group. They declare a target and a scenario shape; this module
compiles the SDN zone, the per-segment VNets, the addressing, and the firewall objects that make
the segments genuinely unable to reach each other.

WHY THERE IS A REACHABILITY EVALUATOR IN HERE
----------------------------------------------
Generating a plausible-looking pile of DROP rules is easy and proves nothing. Firewall semantics
are order-dependent, and the classic failure is a broad ACCEPT sitting above the DENY that was
supposed to contain it — the rules read correctly one at a time and the segment is still open.

So the compiler emits rules AND ships :func:`evaluate_flow`, a first-match evaluator over the same
ordered rules the renderer will write out, plus :func:`verify_isolation`, which drives it across
every ordered pair of segments and the management plane. The isolation properties are therefore
*checked against the artifact*, not against the intent that produced it. If a future edit reorders
a rule and opens Red to Blue, :func:`verify_isolation` fails.

The evaluator models the subset of Proxmox firewall semantics the compiler actually emits:
per-direction ordered rules, first match wins, IPSet references resolved by name, CIDR source/dest
matching, and a final catch-all. It is not a Proxmox simulator and does not pretend to be one.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, replace
from enum import Enum

from secp_api.range_enums import RangeResourceKind
from secp_api.range_providers.proxmox_ipam import (
    AllocationKind,
    AllocationLedger,
    AllocationRequestLog,
    IpamPools,
)
from secp_api.range_providers.proxmox_model import (
    BlockedPlan,
    EgressGatewaySpec,
    FirewallDirection,
    FirewallRuleSpec,
    FirewallVerdict,
    IpSetSpec,
    MissingPrerequisite,
    Ownership,
    ProxmoxModelError,
    SdnZoneSpec,
    SecurityGroupSpec,
    SegmentRole,
    SegregatedNetworkPlan,
    SubnetSpec,
    TargetObservation,
    VNetSpec,
)

#: IPSet holding the Proxmox management plane. Every segment drops traffic to it, first rule.
IPSET_MANAGEMENT = "secp-mgmt"
#: IPSet holding the SECP controller/worker management interfaces.
IPSET_CONTROL_PLANE = "secp-ctlplane"

#: Off-segment destinations :func:`verify_isolation` probes to prove no default public route.
#:
#: These are RFC 5737 TEST-NET-1/TEST-NET-2 documentation addresses, reserved precisely so they can
#: appear in code and tests while routing nowhere. A real address here (a public resolver, a real
#: site) would be one refactor away from a genuine connection attempt originating from the module
#: whose entire purpose is proving no such route exists — so the probe set stays unroutable by
#: construction, not by intent.
#:
#: TEST-NET-3 (``203.0.113.0/24``) is deliberately NOT used here: it is the block the egress tests
#: use for an APPROVED destination, and keeping "must never be reachable" and "reachable only when
#: approved" in different blocks stops one from silently satisfying the other's assertion.
PUBLIC_PROBE_ADDRESSES = ("192.0.2.53", "192.0.2.200", "198.51.100.10")

#: Rule positions are spaced so the isolation block always precedes every allow, and a later edit
#: adding an allow cannot land above the denies by accident.
_POS_MANAGEMENT_DENY = 0
_POS_CONTROL_PLANE = 100
_POS_CROSS_TEAM_DENY = 200
_POS_INTRA_TEAM_ALLOW = 300
_POS_SCORING_ALLOW = 400
_POS_EGRESS_ALLOW = 500
_POS_CATCH_ALL = 8000
#: A Proxmox security group is ONE ordered list holding both directions, so positions must be
#: globally unique within the group even though matching only ever considers rules of the relevant
#: direction. Inbound rules are banded above every outbound position, which keeps each direction's
#: relative order exactly as authored while making the rendered list unambiguous.
_INBOUND_BAND = 100_000


class IsolationProperty(str, Enum):
    """The properties :func:`verify_isolation` proves. Each maps to a required product claim."""

    cross_team_blocked = "cross_team_blocked"
    management_plane_unreachable = "management_plane_unreachable"
    control_plane_unreachable = "control_plane_unreachable"
    no_default_public_route = "no_default_public_route"
    default_deny_present = "default_deny_present"
    scoring_reachable = "scoring_reachable"


@dataclass(frozen=True)
class TeamRequest:
    """One team's requested shape. ``sensor`` is opt-in; nothing else is."""

    team_ref: str
    label: str
    include_sensor: bool = False

    def __post_init__(self) -> None:
        if not self.team_ref or not self.team_ref.isalnum():
            raise ProxmoxModelError(
                f"team_ref {self.team_ref!r} must be a non-empty alphanumeric slug"
            )


@dataclass(frozen=True)
class ControlPlaneReviewedPath:
    """The ONE exact path a segment may use to reach a control-plane interface.

    Every field is required and none accepts a wildcard. A reviewed path with an open port range or
    an unspecified destination is not a reviewed path, so the constructor refuses it.
    """

    dest_cidr: str
    proto: str
    dport: str
    justification: str
    approval_reference: str

    def __post_init__(self) -> None:
        network = ipaddress.ip_network(self.dest_cidr, strict=False)
        if network.num_addresses != 1:
            raise ProxmoxModelError(
                f"reviewed control-plane path must name exactly one host, got {self.dest_cidr} "
                f"({network.num_addresses} addresses)"
            )
        if not self.dport.isdigit():
            raise ProxmoxModelError(
                f"reviewed control-plane path must name exactly one port, got {self.dport!r}"
            )
        if not self.justification or not self.approval_reference:
            raise ProxmoxModelError(
                "a reviewed control-plane path requires a justification and an approval reference"
            )


@dataclass(frozen=True)
class WebBreachLabRequest:
    """The scenario the operator asked for."""

    organization_id: str
    target_id: str
    range_id: str
    generation: int
    operation_generation: int
    teams: tuple[TeamRequest, ...]
    #: Control-plane interfaces the scenario must NOT reach (except a reviewed path).
    control_plane_cidrs: tuple[str, ...] = ()
    reviewed_control_plane_paths: tuple[ControlPlaneReviewedPath, ...] = ()
    #: The port teams submit flags / receive scoring on.
    scoring_port: int = 443
    egress: EgressGatewaySpec | None = None
    pools: IpamPools = IpamPools()

    def __post_init__(self) -> None:
        if len(self.teams) < 2:
            raise ProxmoxModelError(
                "a segregated lab needs at least two teams; with one there is nothing to segregate"
            )
        refs = [team.team_ref for team in self.teams]
        if len(set(refs)) != len(refs):
            raise ProxmoxModelError("duplicate team_ref in request")


@dataclass(frozen=True)
class IsolationFinding:
    """One proved-or-violated isolation property."""

    prop: IsolationProperty
    holds: bool
    detail: str


def _ownership(
    request: WebBreachLabRequest,
    kind: RangeResourceKind,
    team_ref: str | None = None,
) -> Ownership:
    return Ownership(
        organization_id=request.organization_id,
        target_id=request.target_id,
        range_id=request.range_id,
        generation=request.generation,
        operation_generation=request.operation_generation,
        resource_kind=kind,
        team_ref=team_ref,
    )


def _segment_purpose(team_ref: str | None, role: SegmentRole) -> str:
    return f"{team_ref or 'shared'}/{role.value}"


def _vnet_name(team_index: int | None, role: SegmentRole) -> str:
    """A readable 8-char-max VNet name. ``t1atk``, ``t2vul``, ``score``."""
    if team_index is None:
        return "score"
    suffix = {
        SegmentRole.attacker: "atk",
        SegmentRole.vulnerable: "vul",
        SegmentRole.sensor: "sen",
        SegmentRole.scoring: "sco",
    }[role]
    return f"t{team_index}{suffix}"


def compile_web_breach_lab(
    request: WebBreachLabRequest,
    observation: TargetObservation,
    ledger: AllocationLedger | None = None,
) -> tuple[SegregatedNetworkPlan, AllocationLedger] | BlockedPlan:
    """Compile the segregated network, or refuse with every missing prerequisite named.

    Returns either ``(plan, ledger)`` or a :class:`BlockedPlan`. It never returns a partially
    compiled network: a segment whose subnet could not be allocated has no safe placeholder.
    """
    ledger = ledger if ledger is not None else AllocationLedger()
    log = AllocationRequestLog()
    missing: list[MissingPrerequisite] = []

    # ---- capability prerequisites ------------------------------------------------------
    if observation.sdn_supported is None:
        missing.append(
            MissingPrerequisite(
                reason_id="proxmox.sdn_support_unknown",
                observation="TargetObservation.sdn_supported",
                detail=(
                    "whether the target supports SDN was never observed; SDN is an optional "
                    "Proxmox component and compiling VNets without it produces a plan that fails "
                    "at apply"
                ),
            )
        )
    elif observation.sdn_supported is False:
        missing.append(
            MissingPrerequisite(
                reason_id="proxmox.sdn_unsupported",
                observation="TargetObservation.sdn_supported",
                detail=(
                    "the target does not support SDN; segregated per-team VNets cannot be created "
                    "on it and no alternative isolation mechanism is approved"
                ),
            )
        )
    if observation.firewall_supported is None:
        missing.append(
            MissingPrerequisite(
                reason_id="proxmox.firewall_support_unknown",
                observation="TargetObservation.firewall_supported",
                detail=(
                    "whether the cluster firewall is enabled was never observed; without it the "
                    "compiled deny rules would not be enforced and segments would not be isolated"
                ),
            )
        )
    elif observation.firewall_supported is False:
        missing.append(
            MissingPrerequisite(
                reason_id="proxmox.firewall_unsupported",
                observation="TargetObservation.firewall_supported",
                detail=(
                    "the cluster firewall is disabled; the isolation this scenario requires cannot "
                    "be enforced"
                ),
            )
        )

    online = observation.online_nodes()
    if not online:
        missing.append(
            MissingPrerequisite(
                reason_id="proxmox.no_online_node",
                observation="TargetObservation.nodes",
                detail="no cluster node was observed online; nothing can be placed",
            )
        )

    # A scenario bridge must have been observed. Inventing one produces a zone bound to a bridge
    # that does not exist, which fails at apply with an unhelpful error.
    zone_bridge: str | None = None
    if online:
        shared_bridges = set(online[0].bridges)
        for node in online[1:]:
            shared_bridges &= set(node.bridges)
        if not shared_bridges:
            missing.append(
                MissingPrerequisite(
                    reason_id="proxmox.no_common_bridge",
                    observation="NodeObservation.bridges",
                    detail=(
                        "no bridge was observed present on every online node; an SDN zone needs "
                        "one, and picking a bridge that exists on only some nodes strands guests"
                    ),
                )
            )
        else:
            # Never the management bridge. On a stock Proxmox install the first bridge present on
            # every node IS the management bridge, so choosing by availability alone would bridge
            # the scenario straight into the management plane.
            eligible = shared_bridges - set(observation.identity.management_bridges)
            if not eligible:
                missing.append(
                    MissingPrerequisite(
                        reason_id="proxmox.no_non_management_bridge",
                        observation="NodeObservation.bridges",
                        detail=(
                            "every bridge common to the online nodes is a declared management "
                            "bridge; the scenario needs its own bridge and must never ride the "
                            "management plane"
                        ),
                    )
                )
            else:
                zone_bridge = sorted(eligible)[0]

    # ---- names, VLANs, subnets ---------------------------------------------------------
    shared_ownership = _ownership(request, RangeResourceKind.network)

    zone_name = log.run(
        lambda: ledger.allocate_name(
            ownership=shared_ownership,
            purpose="sdn-zone",
            kind=AllocationKind.zone_name,
            candidate=f"z{request.range_id.replace('-', '')[:7]}",
            observed_names=observation.sdn_names_in_use,
            observation_field="TargetObservation.sdn_names_in_use",
            reason_id="proxmox.sdn_name_inventory_missing",
            max_length=8,
        )
    )

    segments: list[tuple[str | None, SegmentRole, str]] = [(None, SegmentRole.scoring, "score")]
    for index, team in enumerate(request.teams, start=1):
        segments.append(
            (team.team_ref, SegmentRole.attacker, _vnet_name(index, SegmentRole.attacker))
        )
        segments.append(
            (team.team_ref, SegmentRole.vulnerable, _vnet_name(index, SegmentRole.vulnerable))
        )
        if team.include_sensor:
            segments.append(
                (team.team_ref, SegmentRole.sensor, _vnet_name(index, SegmentRole.sensor))
            )

    compiled: dict[str, VNetSpec] = {}
    for team_ref, role, proposed in segments:
        ownership = _ownership(request, RangeResourceKind.network, team_ref)
        purpose = _segment_purpose(team_ref, role)

        name = log.run(
            lambda o=ownership, p=purpose, c=proposed: ledger.allocate_name(
                ownership=o,
                purpose=p,
                kind=AllocationKind.vnet_name,
                candidate=c,
                observed_names=observation.sdn_names_in_use,
                observation_field="TargetObservation.sdn_names_in_use",
                reason_id="proxmox.sdn_name_inventory_missing",
                max_length=8,
            )
        )
        vlan = log.run(
            lambda o=ownership, p=purpose: ledger.allocate_int(
                ownership=o,
                kind=AllocationKind.vlan_tag,
                purpose=p,
                low=request.pools.vlan_min,
                high=request.pools.vlan_max,
                observed_in_use=observation.vlan_tags_in_use,
                observation_field="TargetObservation.vlan_tags_in_use",
                reason_id="proxmox.vlan_inventory_missing",
            )
        )
        subnet = log.run(
            lambda o=ownership, p=purpose: ledger.allocate_subnet(
                ownership=o,
                purpose=p,
                pools=request.pools,
                observed_subnets=observation.subnets_in_use,
                management_cidrs=observation.identity.management_cidrs,
            )
        )
        if name is None or vlan is None or subnet is None:
            continue
        gateway = ledger.allocate_address(
            ownership=ownership,
            purpose=f"{purpose}/gateway",
            subnet=subnet,
            kind=AllocationKind.gateway_address,
            offset=0,
        )
        compiled[name] = VNetSpec(
            name=name,
            zone_name=zone_name or "",
            vlan_tag=vlan,
            subnet=SubnetSpec(cidr=str(subnet), gateway=str(gateway), routed=False),
            role=role,
            ownership=ownership,
            alias=purpose,
        )

    missing.extend(log.blocked)
    if missing or zone_name is None or zone_bridge is None:
        if not missing:
            missing.append(
                MissingPrerequisite(
                    reason_id="proxmox.zone_unresolved",
                    observation="TargetObservation.sdn_names_in_use",
                    detail="the SDN zone name or bridge could not be resolved",
                )
            )
        return BlockedPlan(tuple(missing))

    zone = SdnZoneSpec(
        name=zone_name,
        bridge=zone_bridge,
        nodes=tuple(node.node_name for node in online),
        ownership=shared_ownership,
    )
    vnets = tuple(compiled[name] for name in sorted(compiled))

    ip_sets, groups, attachment = _compile_firewall(request, observation, vnets, ledger, log)
    missing.extend(log.blocked)
    if missing:
        return BlockedPlan(tuple(missing))

    plan = SegregatedNetworkPlan(
        zone=zone,
        vnets=vnets,
        security_groups=groups,
        ip_sets=ip_sets,
        vnet_security_group=attachment,
        egress=request.egress,
    )
    return plan, ledger


def _band_positions(rules: list[FirewallRuleSpec]) -> tuple[FirewallRuleSpec, ...]:
    """Lift inbound rules into their own position band so the whole group is globally ordered.

    Authored positions stay small and readable at the rule site (``_POS_CROSS_TEAM_DENY``, etc.);
    the band is applied once, here, rather than being baked into every constant.
    """
    banded: list[FirewallRuleSpec] = []
    for rule in rules:
        offset = 0 if rule.direction == FirewallDirection.outbound else _INBOUND_BAND
        banded.append(replace(rule, position=rule.position + offset))
    return tuple(banded)


def _compile_firewall(
    request: WebBreachLabRequest,
    observation: TargetObservation,
    vnets: tuple[VNetSpec, ...],
    ledger: AllocationLedger,
    log: AllocationRequestLog,
) -> tuple[tuple[IpSetSpec, ...], tuple[SecurityGroupSpec, ...], dict[str, str]]:
    """Build the IPSets and per-segment security groups that enforce the isolation matrix."""
    shared_ownership = _ownership(request, RangeResourceKind.network)

    ip_sets = [
        IpSetSpec(
            name=IPSET_MANAGEMENT,
            cidrs=observation.identity.management_cidrs,
            ownership=shared_ownership,
            comment="Proxmox management plane. Never reachable from any scenario segment.",
        ),
    ]
    if request.control_plane_cidrs:
        ip_sets.append(
            IpSetSpec(
                name=IPSET_CONTROL_PLANE,
                cidrs=request.control_plane_cidrs,
                ownership=shared_ownership,
                comment="SECP controller/worker management interfaces.",
            )
        )

    by_team: dict[str | None, list[VNetSpec]] = {}
    for vnet in vnets:
        by_team.setdefault(vnet.ownership.team_ref, []).append(vnet)
    scoring = [vnet for vnet in vnets if vnet.role == SegmentRole.scoring]

    # One IPSet per team holding that team's own segments — this is what makes the cross-team
    # deny a single readable rule per peer rather than an N-squared pile.
    for team_ref, team_vnets in sorted(by_team.items(), key=lambda item: item[0] or ""):
        if team_ref is None:
            continue
        name = log.run(
            lambda t=team_ref, v=team_vnets: ledger.allocate_name(
                ownership=_ownership(request, RangeResourceKind.network, t),
                purpose=f"{t}/ipset",
                kind=AllocationKind.firewall_object_name,
                candidate=f"secp-team-{t}",
                observed_names=observation.firewall_names_in_use,
                observation_field="TargetObservation.firewall_names_in_use",
                reason_id="proxmox.firewall_name_inventory_missing",
                max_length=27,
            )
        )
        if name is None:
            continue
        ip_sets.append(
            IpSetSpec(
                name=name,
                cidrs=tuple(vnet.subnet.cidr for vnet in team_vnets),
                ownership=_ownership(request, RangeResourceKind.network, team_ref),
                comment=f"All segments belonging to team {team_ref}.",
            )
        )

    team_ipset: dict[str, str] = {}
    for item in ip_sets:
        if item.ownership.team_ref is not None:
            team_ipset[item.ownership.team_ref] = item.name

    groups: list[SecurityGroupSpec] = []
    attachment: dict[str, str] = {}

    for vnet in vnets:
        team_ref = vnet.ownership.team_ref
        rules: list[FirewallRuleSpec] = []

        # 1. The management plane is unreachable. First rule, no exceptions, both directions.
        rules.append(
            FirewallRuleSpec(
                position=_POS_MANAGEMENT_DENY,
                direction=FirewallDirection.outbound,
                verdict=FirewallVerdict.drop,
                dest=f"+{IPSET_MANAGEMENT}",
                comment="Deny all traffic to the Proxmox management plane.",
            )
        )
        rules.append(
            FirewallRuleSpec(
                position=_POS_MANAGEMENT_DENY,
                direction=FirewallDirection.inbound,
                verdict=FirewallVerdict.drop,
                source=f"+{IPSET_MANAGEMENT}",
                comment="Deny inbound traffic sourced from the management plane.",
            )
        )

        # 2. Control-plane interfaces: the reviewed path first (it is narrower), then the deny.
        if request.control_plane_cidrs:
            for offset, path in enumerate(request.reviewed_control_plane_paths):
                rules.append(
                    FirewallRuleSpec(
                        position=_POS_CONTROL_PLANE + offset,
                        direction=FirewallDirection.outbound,
                        verdict=FirewallVerdict.accept,
                        dest=path.dest_cidr,
                        proto=path.proto,
                        dport=path.dport,
                        comment=(
                            f"Reviewed control-plane path ({path.approval_reference}): "
                            f"{path.justification}"
                        ),
                    )
                )
            rules.append(
                FirewallRuleSpec(
                    position=_POS_CONTROL_PLANE + 50,
                    direction=FirewallDirection.outbound,
                    verdict=FirewallVerdict.drop,
                    dest=f"+{IPSET_CONTROL_PLANE}",
                    comment="Deny all other traffic to controller/worker management interfaces.",
                )
            )

        # 3. Cross-team denial, one rule per peer team, above every allow.
        for offset, (peer_ref, peer_name) in enumerate(sorted(team_ipset.items())):
            if peer_ref == team_ref:
                continue
            rules.append(
                FirewallRuleSpec(
                    position=_POS_CROSS_TEAM_DENY + offset,
                    direction=FirewallDirection.outbound,
                    verdict=FirewallVerdict.drop,
                    dest=f"+{peer_name}",
                    comment=f"Deny all traffic to team {peer_ref}'s segments.",
                )
            )
            rules.append(
                FirewallRuleSpec(
                    position=_POS_CROSS_TEAM_DENY + 50 + offset,
                    direction=FirewallDirection.inbound,
                    verdict=FirewallVerdict.drop,
                    source=f"+{peer_name}",
                    comment=f"Deny all traffic from team {peer_ref}'s segments.",
                )
            )

        # 4. Intra-team reachability: a team's own segments talk to each other. This is the
        #    scenario itself — attacker pivoting to the vulnerable target.
        if team_ref is not None and team_ref in team_ipset:
            rules.append(
                FirewallRuleSpec(
                    position=_POS_INTRA_TEAM_ALLOW,
                    direction=FirewallDirection.outbound,
                    verdict=FirewallVerdict.accept,
                    dest=f"+{team_ipset[team_ref]}",
                    comment=f"Allow team {team_ref} to reach its own segments.",
                )
            )
            rules.append(
                FirewallRuleSpec(
                    position=_POS_INTRA_TEAM_ALLOW + 1,
                    direction=FirewallDirection.inbound,
                    verdict=FirewallVerdict.accept,
                    source=f"+{team_ipset[team_ref]}",
                    comment=f"Allow team {team_ref}'s own segments inbound.",
                )
            )

        # 5. Scoring: every team reaches the scoring boundary on exactly one port. The scoring
        #    segment itself accepts inbound from teams but initiates nothing back into them.
        for scoring_vnet in scoring:
            if vnet.role == SegmentRole.scoring:
                rules.append(
                    FirewallRuleSpec(
                        position=_POS_SCORING_ALLOW,
                        direction=FirewallDirection.inbound,
                        verdict=FirewallVerdict.accept,
                        proto="tcp",
                        dport=str(request.scoring_port),
                        comment=f"Accept scoring submissions on tcp/{request.scoring_port}.",
                    )
                )
                break
            rules.append(
                FirewallRuleSpec(
                    position=_POS_SCORING_ALLOW,
                    direction=FirewallDirection.outbound,
                    verdict=FirewallVerdict.accept,
                    dest=scoring_vnet.subnet.cidr,
                    proto="tcp",
                    dport=str(request.scoring_port),
                    comment=(
                        f"Allow the scoring/control boundary on tcp/{request.scoring_port} only."
                    ),
                )
            )

        # 6. Egress, only when an approved plan asked for it and only to named destinations.
        if request.egress is not None and request.egress.vnet_name == vnet.name:
            for offset, dest in enumerate(request.egress.allowed_destinations):
                for port_offset, port in enumerate(request.egress.allowed_ports or ("",)):
                    rules.append(
                        FirewallRuleSpec(
                            position=_POS_EGRESS_ALLOW + offset * 10 + port_offset,
                            direction=FirewallDirection.outbound,
                            verdict=FirewallVerdict.accept,
                            dest=dest,
                            proto="tcp" if port else None,
                            dport=port or None,
                            comment=(
                                f"Approved controlled egress ({request.egress.approval_reference})."
                            ),
                        )
                    )

        # 7. Default deny, last in both directions. Everything not explicitly allowed above —
        #    including every public destination — lands here.
        rules.append(
            FirewallRuleSpec(
                position=_POS_CATCH_ALL,
                direction=FirewallDirection.outbound,
                verdict=FirewallVerdict.drop,
                comment="Default deny outbound.",
            )
        )
        rules.append(
            FirewallRuleSpec(
                position=_POS_CATCH_ALL,
                direction=FirewallDirection.inbound,
                verdict=FirewallVerdict.drop,
                comment="Default deny inbound.",
            )
        )

        group_name = log.run(
            lambda v=vnet: ledger.allocate_name(
                ownership=v.ownership,
                purpose=f"{v.alias}/secgroup",
                kind=AllocationKind.firewall_object_name,
                candidate=f"secp-sg-{v.name}",
                observed_names=observation.firewall_names_in_use,
                observation_field="TargetObservation.firewall_names_in_use",
                reason_id="proxmox.firewall_name_inventory_missing",
                max_length=27,
            )
        )
        if group_name is None:
            continue
        groups.append(
            SecurityGroupSpec(
                name=group_name,
                rules=_band_positions(rules),
                ownership=vnet.ownership,
                comment=f"Isolation policy for segment {vnet.name} ({vnet.role.value}).",
            )
        )
        attachment[vnet.name] = group_name

    return tuple(ip_sets), tuple(groups), attachment


# --------------------------------------------------------------------------------------
# Reachability evaluation — the proof, not the intent
# --------------------------------------------------------------------------------------


def _resolve(token: str | None, ip_sets: dict[str, tuple[str, ...]]) -> tuple[str, ...] | None:
    """Resolve a rule's source/dest into CIDRs. ``None`` means the rule matches any address."""
    if token is None:
        return None
    if token.startswith("+"):
        return ip_sets.get(token[1:], ())
    return (token,)


def _address_matches(address: str, cidrs: tuple[str, ...] | None) -> bool:
    if cidrs is None:
        return True
    target = ipaddress.ip_address(address)
    return any(target in ipaddress.ip_network(cidr, strict=False) for cidr in cidrs)


def evaluate_flow(
    plan: SegregatedNetworkPlan,
    *,
    from_vnet: str,
    to_address: str,
    port: int | None = None,
    proto: str = "tcp",
    direction: FirewallDirection = FirewallDirection.outbound,
) -> FirewallVerdict:
    """First-match evaluation of the COMPILED rules for one flow.

    This walks the same ordered rule list the renderer emits, so a reordering that breaks isolation
    changes this answer. Returns the verdict of the first matching rule; a group with no matching
    rule at all evaluates to ``drop``, matching the default-deny posture the compiler asserts
    separately via :attr:`SecurityGroupSpec.default_policy_is_deny`.
    """
    group_name = plan.vnet_security_group.get(from_vnet)
    if group_name is None:
        raise ProxmoxModelError(f"no security group attached to VNet {from_vnet!r}")
    group = next((g for g in plan.security_groups if g.name == group_name), None)
    if group is None:
        raise ProxmoxModelError(f"security group {group_name!r} not found in plan")

    ip_sets = {item.name: item.cidrs for item in plan.ip_sets}

    for rule in group.ordered_rules():
        if not rule.enabled or rule.direction != direction:
            continue
        match_field = rule.dest if direction == FirewallDirection.outbound else rule.source
        if not _address_matches(to_address, _resolve(match_field, ip_sets)):
            continue
        if rule.proto is not None and rule.proto != proto:
            continue
        if rule.dport is not None:
            if port is None or str(port) != rule.dport:
                continue
        return rule.verdict
    return FirewallVerdict.drop


def verify_isolation(
    plan: SegregatedNetworkPlan,
    observation: TargetObservation,
    request: WebBreachLabRequest,
) -> tuple[IsolationFinding, ...]:
    """Drive :func:`evaluate_flow` across every property the product claims.

    Returns a finding per property. The caller refuses to deploy unless every ``holds`` is true;
    the findings are also what an operator reads to understand what was actually proved.
    """
    findings: list[IsolationFinding] = []

    def first_host(cidr: str) -> str:
        return str(next(iter(ipaddress.ip_network(cidr, strict=False).hosts())))

    # -- cross-team --------------------------------------------------------------------
    violations: list[str] = []
    for source in plan.vnets:
        if source.ownership.team_ref is None:
            continue
        for dest in plan.vnets:
            if (
                dest.ownership.team_ref is None
                or dest.ownership.team_ref == source.ownership.team_ref
            ):
                continue
            target = first_host(dest.subnet.cidr)
            for port in (request.scoring_port, 22, 80, 443, 8080):
                verdict = evaluate_flow(plan, from_vnet=source.name, to_address=target, port=port)
                if verdict == FirewallVerdict.accept:
                    violations.append(
                        f"{source.name} -> {dest.name} ({target}:{port}) evaluates to ACCEPT"
                    )
    findings.append(
        IsolationFinding(
            prop=IsolationProperty.cross_team_blocked,
            holds=not violations,
            detail=(
                "no team segment reaches another team's segment on any probed port"
                if not violations
                else "; ".join(violations)
            ),
        )
    )

    # -- management plane ---------------------------------------------------------------
    mgmt_violations: list[str] = []
    for source in plan.vnets:
        for cidr in observation.identity.management_cidrs:
            target = first_host(cidr)
            for port in (22, 443, 8006):
                verdict = evaluate_flow(plan, from_vnet=source.name, to_address=target, port=port)
                if verdict == FirewallVerdict.accept:
                    mgmt_violations.append(f"{source.name} -> {target}:{port} evaluates to ACCEPT")
    findings.append(
        IsolationFinding(
            prop=IsolationProperty.management_plane_unreachable,
            holds=not mgmt_violations,
            detail=(
                "no segment reaches the Proxmox management plane"
                if not mgmt_violations
                else "; ".join(mgmt_violations)
            ),
        )
    )

    # -- control plane, except the exact reviewed path -----------------------------------
    reviewed = {(path.dest_cidr, path.dport) for path in request.reviewed_control_plane_paths}
    control_violations: list[str] = []
    for source in plan.vnets:
        for cidr in request.control_plane_cidrs:
            network = ipaddress.ip_network(cidr, strict=False)
            for host in list(network.hosts())[:4] or [network.network_address]:
                for port in (22, 443, 5432, 8000):
                    is_reviewed = any(
                        host in ipaddress.ip_network(dest, strict=False) and str(port) == dport
                        for dest, dport in reviewed
                    )
                    verdict = evaluate_flow(
                        plan, from_vnet=source.name, to_address=str(host), port=port
                    )
                    if verdict == FirewallVerdict.accept and not is_reviewed:
                        control_violations.append(
                            f"{source.name} -> {host}:{port} evaluates to ACCEPT "
                            "but is not a reviewed path"
                        )
    findings.append(
        IsolationFinding(
            prop=IsolationProperty.control_plane_unreachable,
            holds=not control_violations,
            detail=(
                "control-plane interfaces are reachable only by the exact reviewed paths"
                if not control_violations
                else "; ".join(control_violations)
            ),
        )
    )

    # -- no default public route ---------------------------------------------------------
    approved_egress = plan.egress.allowed_destinations if plan.egress else ()
    public_probe = PUBLIC_PROBE_ADDRESSES
    public_violations: list[str] = []
    for source in plan.vnets:
        for address in public_probe:
            in_approved = any(
                ipaddress.ip_address(address) in ipaddress.ip_network(dest, strict=False)
                for dest in approved_egress
            )
            for port in (80, 443):
                verdict = evaluate_flow(plan, from_vnet=source.name, to_address=address, port=port)
                if verdict == FirewallVerdict.accept and not in_approved:
                    public_violations.append(
                        f"{source.name} -> {address}:{port} evaluates to ACCEPT without approval"
                    )
    routed = [vnet.name for vnet in plan.vnets if vnet.subnet.routed]
    findings.append(
        IsolationFinding(
            prop=IsolationProperty.no_default_public_route,
            holds=not public_violations and not routed,
            detail=(
                "no segment has a route to public networks and none is marked routed"
                if not public_violations and not routed
                else "; ".join(public_violations + [f"{name} is marked routed" for name in routed])
            ),
        )
    )

    # -- default deny is structurally present --------------------------------------------
    not_deny = [g.name for g in plan.security_groups if not g.default_policy_is_deny]
    findings.append(
        IsolationFinding(
            prop=IsolationProperty.default_deny_present,
            holds=not not_deny,
            detail=(
                "every security group ends in a catch-all drop in both directions"
                if not not_deny
                else f"groups without a terminal default deny: {', '.join(not_deny)}"
            ),
        )
    )

    # -- scoring is actually reachable (isolation that breaks the product is not a win) ---
    scoring_vnets = [vnet for vnet in plan.vnets if vnet.role == SegmentRole.scoring]
    unreachable: list[str] = []
    if not scoring_vnets:
        unreachable.append("no scoring segment was compiled")
    for source in plan.vnets:
        if source.role == SegmentRole.scoring:
            continue
        for scoring_vnet in scoring_vnets:
            target = first_host(scoring_vnet.subnet.cidr)
            verdict = evaluate_flow(
                plan, from_vnet=source.name, to_address=target, port=request.scoring_port
            )
            if verdict != FirewallVerdict.accept:
                unreachable.append(
                    f"{source.name} cannot reach scoring at {target}:{request.scoring_port}"
                )
    findings.append(
        IsolationFinding(
            prop=IsolationProperty.scoring_reachable,
            holds=not unreachable,
            detail=(
                f"every team segment reaches the scoring boundary on tcp/{request.scoring_port}"
                if not unreachable
                else "; ".join(unreachable)
            ),
        )
    )

    return tuple(findings)
