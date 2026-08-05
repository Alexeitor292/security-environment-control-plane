"""Scenario/provider compatibility for the shipped range catalog.

WHY THIS LAYER EXISTS, AND WHAT IT IS NOT
------------------------------------------
:mod:`secp_api.range_catalog` ships three TEMPLATES: ``juice-shop-solo``, ``web-breach-lab`` and
``proxmox-web-breach-lab``. A template is a deployable definition bound to exactly one provider —
that is the right shape for the thing a range is created from, and a :class:`RangeInstance` keeps a
foreign key to the row it was built from, so templates are never merged or renamed.

But it is the WRONG shape for a catalog an operator chooses from. Listed as templates, the Web
Breach Lab appears TWICE — once for local Docker and once for Proxmox — as if they were two
different labs. They are not: ``proxmox-web-breach-lab`` reuses :data:`DVWA_COMPONENT` and
:data:`JUICE_SHOP_COMPONENT` and both challenge tuples, by reference, precisely so the substrate can
change while the content cannot. Two entries for one lab invites an operator to believe they are
choosing between two scenarios when they are choosing a SUBSTRATE for one.

So this module adds a SCENARIO above the templates: one Web Breach Lab, with a supported-provider
list, and one concrete template per supported provider. It creates no content, defines no component,
defines no challenge and adds no template. It is a projection over what
:mod:`secp_api.range_catalog` already ships, and the identity check in
:func:`_assert_shared_content` fails loudly if a provider variant ever stops being the same lab.

BLOCKERS ARE COMPUTED, NEVER DECLARED
--------------------------------------
The dangerous version of this file is one where each provider carries a hand-written
``blocked: false``. That is a claim nobody checked, and it goes stale the moment a requirement
changes. Every blocker here is derived:

* a provider with no concrete template in the shipped catalog is UNSUPPORTED, named as such, and it
  is derived by looking — not by a flag;
* Proxmox requirements that only a live cluster observation can satisfy are reported against the
  ACTUAL recorded observation when a range is named (:func:`scenario_for_range`), using the same
  ``reason_id`` vocabulary :func:`~secp_api.services.proxmox_lifecycle.compile_plan` blocks on, so
  the catalog and the compiler can never disagree about why something cannot run;
* with no range named, the substrate-dependent requirements are reported as ``undetermined`` — NOT
  as satisfied and NOT as blocked. Nobody has looked at a cluster yet.

A blocked scenario is returned, in the list, marked blocked, with its blockers named. It is never
hidden (an operator cannot ask about a lab that is not there) and never silently eligible.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from secp_api.range_catalog import (
    CATALOG,
    CatalogTemplate,
)


class ProviderSupport(str, Enum):
    """Whether a scenario can run on a provider at all — a property of the shipped catalog."""

    #: A concrete template for this provider exists in the shipped catalog.
    supported = "supported"
    #: No template in the shipped catalog builds this scenario on this provider. This build cannot
    #: run it, and saying so is the answer; it is never rendered as "not yet checked".
    unsupported = "unsupported"


class RequirementStatus(str, Enum):
    """Whether one requirement is met. FOUR values, and the last two are the load-bearing ones.

    Two of these mean "not satisfied" and they are deliberately not one member, because they lead
    an operator to opposite actions. ``unsatisfied``/``undetermined`` mean *go and fix or check
    something, then this scenario can run here*. ``not_provided`` means *this substrate will never
    do that; deploy anyway if you do not need it*. Folding them together would either mark a
    perfectly deployable laptop lab as blocked, or — far worse in the other direction — mark a
    missing capability as an acceptable gap on a substrate where it is a hard requirement.
    """

    #: Satisfied by something this process can actually see — the shipped catalog, or a recorded
    #: observation. Never written from an assumption.
    satisfied = "satisfied"
    #: Not satisfied, and the reason is known. This BLOCKS the scenario on this provider.
    unsatisfied = "unsatisfied"
    #: Nobody has looked. This is NOT "satisfied" and it is NOT "unsatisfied": the fact needed to
    #: decide is one only a live cluster observation proves, and none was named. An operator
    #: reading this must be able to tell "we checked and it is fine" from "we have not checked",
    #: because acting on the second as though it were the first is how a plan gets applied against
    #: a cluster whose management network nobody declared. It BLOCKS: unchecked is not met.
    undetermined = "undetermined"
    #: The substrate does not implement this capability at all. The scenario still deploys and runs
    #: here; it simply does not get this property, and an operator who needs it must choose another
    #: provider. Reported as a named gap, NOT as a blocker — a local Docker lab that cannot do
    #: controlled egress is still a working lab.
    not_provided = "not_provided"


class RequirementKind(str, Enum):
    """The requirement classes the catalog reports for every scenario/provider pair.

    Every member is reported for every pair — a requirement that does not apply to a provider is
    reported ``satisfied`` with a detail saying why it does not apply, rather than being omitted.
    An omitted requirement is indistinguishable from a requirement nobody thought about.
    """

    source_template = "source_template"
    network = "network"
    storage = "storage"
    team_count = "team_count"
    scoring = "scoring"
    telemetry = "telemetry"
    controlled_egress = "controlled_egress"


@dataclass(frozen=True)
class RequirementFinding:
    """One requirement, its status, and — when it is unmet — the stable id that names why."""

    kind: RequirementKind
    status: RequirementStatus
    detail: str
    #: A stable key a client may branch on. Set on ``unsatisfied`` and ``undetermined``; ``None``
    #: on ``satisfied``, because a satisfied requirement has no reason to name.
    reason_id: str | None = None


@dataclass(frozen=True)
class ProviderCompatibility:
    """How one scenario stands on one provider."""

    provider: str
    support: ProviderSupport
    #: The concrete catalog template that builds this scenario here. ``None`` when unsupported —
    #: which is why an unsupported provider can never be deployed by accident: there is no slug.
    template_slug: str | None
    requirements: tuple[RequirementFinding, ...]
    #: Minimum and maximum teams this provider's variant accepts. ``None`` for a bound the provider
    #: does not impose; a single-team lab and an unbounded one are different facts.
    min_teams: int | None
    max_teams: int | None

    @property
    def blockers(self) -> tuple[RequirementFinding, ...]:
        """Every requirement that stops this scenario running here, in declaration order.

        ``undetermined`` counts. A requirement nobody has checked has not been met, and letting an
        unchecked requirement fall out of the blocker list is precisely how a scenario becomes
        silently eligible.

        ``not_provided`` deliberately does NOT count — see :class:`RequirementStatus`. It is
        reported by :attr:`unmet_capabilities` instead, so a laptop lab that simply has no egress
        control is not presented as undeployable.
        """
        return tuple(
            finding
            for finding in self.requirements
            if finding.status in (RequirementStatus.unsatisfied, RequirementStatus.undetermined)
        )

    @property
    def unmet_capabilities(self) -> tuple[RequirementFinding, ...]:
        """Properties this substrate will not give the scenario, though it will still run it."""
        return tuple(
            finding
            for finding in self.requirements
            if finding.status is RequirementStatus.not_provided
        )

    @property
    def blocked(self) -> bool:
        return self.support is ProviderSupport.unsupported or bool(self.blockers)


@dataclass(frozen=True)
class Scenario:
    """One lab, once, with every provider it can run on."""

    key: str
    name: str
    summary: str
    #: The provider variants, in declaration order. A blocked variant is present and marked, never
    #: dropped from this tuple.
    providers: tuple[ProviderCompatibility, ...]
    challenge_keys: tuple[str, ...]
    component_keys: tuple[str, ...]
    total_points: int

    def provider(self, name: str) -> ProviderCompatibility | None:
        return next((item for item in self.providers if item.provider == name), None)


# --------------------------------------------------------------------------------------
# Which templates realise which scenario
#
# Keyed by SLUG rather than by scanning names: a template whose name happens to contain "Web Breach
# Lab" must not join this scenario by accident, and a template renamed upstream must not silently
# leave it. Adding a provider variant is an explicit edit here, and `_assert_shared_content` then
# proves the new variant is genuinely the same lab.
# --------------------------------------------------------------------------------------

_SCENARIO_TEMPLATES: dict[str, tuple[str, ...]] = {
    "juice-shop-solo": ("juice-shop-solo",),
    "web-breach-lab": ("web-breach-lab", "proxmox-web-breach-lab"),
}

#: Every provider the catalog surface reports on, whether or not a scenario supports it. Reporting
#: an unsupported provider explicitly is the point: a client that only ever sees the providers a
#: scenario supports cannot tell "cannot run on Proxmox" from "nobody asked about Proxmox".
KNOWN_PROVIDERS: tuple[str, ...] = ("local_docker", "proxmox")


class ScenarioContentDrift(RuntimeError):
    """Two templates claim to be the same scenario but ship different content.

    Raised at import/projection time rather than tolerated, because the entire justification for
    presenting one Web Breach Lab with two substrates is that the substrate changes and the content
    does not. If that stops being true they are two labs, and pretending otherwise would tell an
    operator that a Proxmox range scores the same challenges as the Docker one when it does not.
    """


def _templates(slugs: tuple[str, ...]) -> tuple[CatalogTemplate, ...]:
    by_slug = {template.slug: template for template in CATALOG}
    return tuple(by_slug[slug] for slug in slugs if slug in by_slug)


def _assert_shared_content(key: str, templates: tuple[CatalogTemplate, ...]) -> None:
    """Prove every provider variant of a scenario ships the same components and challenges.

    Compared on the CONTENT (component keys with their pinned images, challenge keys with their
    points), not on object identity: identity would pass today only because the catalog happens to
    share the dataclass instances, and would start failing the moment someone wrote an equal-valued
    copy — which is not the failure this guards against. It guards against DIFFERENT content.
    """
    if len(templates) < 2:
        return
    first, *rest = templates

    def fingerprint(template: CatalogTemplate) -> tuple:
        return (
            tuple(sorted((c.key, c.image) for c in template.components)),
            tuple(sorted((c.key, c.points) for c in template.challenges)),
        )

    expected = fingerprint(first)
    for template in rest:
        if fingerprint(template) != expected:
            raise ScenarioContentDrift(
                f"scenario '{key}' claims '{first.slug}' and '{template.slug}' are the same lab on "
                f"different substrates, but they ship different components or challenges. Either "
                f"the content drifted (fix the catalog — the shared definitions exist so this "
                f"cannot happen) or they are genuinely two scenarios and must be listed as two."
            )


# --------------------------------------------------------------------------------------
# Requirements, per provider
# --------------------------------------------------------------------------------------


def _docker_requirements(template: CatalogTemplate) -> tuple[RequirementFinding, ...]:
    """Local Docker: everything this provider needs is decidable from the shipped catalog alone.

    Nothing here is ``undetermined``, and that is not optimism — a local-Docker range pulls pinned
    images onto one host, creates one bridge network and publishes loopback ports. There is no
    cluster fact to observe, so there is nothing this process could be uncertain ABOUT.
    """
    images = ", ".join(component.image for component in template.components)
    return (
        RequirementFinding(
            kind=RequirementKind.source_template,
            status=RequirementStatus.satisfied,
            detail=(
                f"the {len(template.components)} component image(s) are pinned in the shipped "
                f"catalog and pulled directly: {images}. No reviewed source template is involved."
            ),
        ),
        RequirementFinding(
            kind=RequirementKind.network,
            status=RequirementStatus.satisfied,
            detail=(
                "one bridge network is created for this range alone; every published port binds to "
                "127.0.0.1. No SDN, VLAN or cluster firewall is required."
            ),
        ),
        RequirementFinding(
            kind=RequirementKind.storage,
            status=RequirementStatus.satisfied,
            detail=(
                "container-local writable layers only. No shared cluster storage and no reviewed "
                "storage pool is required."
            ),
        ),
        RequirementFinding(
            kind=RequirementKind.team_count,
            status=RequirementStatus.satisfied,
            detail=(
                "a local Docker range is a single shared environment; it imposes no team floor and "
                "no team ceiling, and it segregates nothing between teams."
            ),
        ),
        RequirementFinding(
            kind=RequirementKind.scoring,
            status=RequirementStatus.satisfied,
            detail=(
                f"scoring is the native competition core, not a deployed component; "
                f"{len(template.challenges)} challenge(s) are seeded server-side and flags are "
                "stored salted-hashed. No scoring container and no scoring segment is required."
            ),
        ),
        RequirementFinding(
            kind=RequirementKind.telemetry,
            status=RequirementStatus.satisfied,
            detail=(
                "range events and per-resource records are written by the lifecycle itself. No "
                "in-range telemetry sensor is deployed on this substrate."
            ),
        ),
        RequirementFinding(
            kind=RequirementKind.controlled_egress,
            status=RequirementStatus.not_provided,
            reason_id="local_docker.no_controlled_egress",
            detail=(
                "this substrate does not implement controlled egress. Containers inherit the "
                "host's outbound network, and the range creates no egress gateway and no egress "
                "policy. The lab still deploys and runs — this is a property it does not get, not "
                "a reason it cannot start. Where controlled egress is an actual requirement, use "
                "the Proxmox variant, whose compiled firewall is what enforces it."
            ),
        ),
    )


#: The observation fields a Proxmox plan cannot be compiled without, paired with the requirement
#: class each one belongs to. These reason ids are the SAME strings
#: :func:`~secp_api.services.proxmox_lifecycle.compile_plan` and the network/workload compilers
#: block on, so a scenario listed as blocked here and a plan that refuses to compile give an
#: operator one vocabulary rather than two.
_PROXMOX_OBSERVED_FACTS: tuple[tuple[str, RequirementKind, str], ...] = (
    ("sdn_supported", RequirementKind.network, "whether the cluster supports SDN zones and VNets"),
    ("firewall_supported", RequirementKind.network, "whether the cluster firewall is available"),
    ("vlan_tags_in_use", RequirementKind.network, "which VLAN tags are already taken"),
    ("subnets_in_use", RequirementKind.network, "which subnets are already routed"),
    ("macs_in_use", RequirementKind.network, "which MAC addresses are already assigned"),
    ("vmids_in_use", RequirementKind.source_template, "which VM/LXC ids are already taken"),
    ("sdn_names_in_use", RequirementKind.network, "which SDN object names are already taken"),
    (
        "firewall_names_in_use",
        RequirementKind.network,
        "which firewall object names are already taken",
    ),
)

#: The compiler refuses a single-team Web Breach Lab outright: with one team there is nothing to
#: segregate and cross-team isolation is not a property that can be exercised, let alone proved.
PROXMOX_MIN_TEAMS = 2


def _undetermined(kind: RequirementKind, reason_id: str, detail: str) -> RequirementFinding:
    return RequirementFinding(
        kind=kind, status=RequirementStatus.undetermined, reason_id=reason_id, detail=detail
    )


def _proxmox_requirements(
    template: CatalogTemplate,
    *,
    observation: object | None,
    team_count: int | None,
) -> tuple[RequirementFinding, ...]:
    """Proxmox: substrate-dependent requirements answered against a RECORDED observation.

    ``observation`` is a :class:`~secp_api.range_providers.proxmox_model.TargetObservation` the
    worker recorded for a specific range, or ``None`` when no range was named (the plain catalog
    read). With ``None`` every substrate-dependent requirement is ``undetermined`` — never
    ``satisfied``, because nothing has looked at a cluster, and never ``unsatisfied``, because
    nothing has looked at a cluster.
    """
    findings: list[RequirementFinding] = []

    # --- source templates: reviewed Proxmox templates, never a pull reference ------------------
    versions = ", ".join(component.image for component in template.components)
    findings.append(
        RequirementFinding(
            kind=RequirementKind.source_template,
            status=RequirementStatus.undetermined
            if observation is None
            else _observed_templates_status(observation, template),
            reason_id=None
            if observation is not None
            and _observed_templates_status(observation, template) is RequirementStatus.satisfied
            else "proxmox.reviewed_source_templates_unobserved",
            detail=(
                f"each guest is CLONED from a reviewed Proxmox template carrying its own "
                f"template_ref, image_digest and approval_reference; nothing is pulled. The "
                f"application versions that reviewed template must contain are pinned as "
                f"{versions}. Whether such templates exist on the cluster is a fact only a "
                f"discovery observation proves."
            ),
        )
    )

    # --- network / storage: from the recorded observation, per fact -----------------------------
    for field_name, kind, description in _PROXMOX_OBSERVED_FACTS:
        if kind is not RequirementKind.network:
            continue
        findings.append(_observed_fact_finding(observation, field_name, kind, description))

    findings.append(
        RequirementFinding(
            kind=RequirementKind.storage,
            status=RequirementStatus.undetermined
            if observation is None
            else _observed_storage_status(observation),
            reason_id=None
            if observation is not None
            and _observed_storage_status(observation) is RequirementStatus.satisfied
            else "proxmox.storage_unobserved",
            detail=(
                "every guest needs a storage id on its node that accepts guest images and has "
                "capacity. Storage is read from the observation's per-node storage list; it is "
                "never assumed, because a guessed storage id fails at clone time after the plan "
                "has already been approved."
            ),
        )
    )

    # --- team count: a floor the compiler enforces, checked against the actual request ----------
    findings.append(_team_count_finding(team_count))

    # --- scoring / telemetry / controlled egress -------------------------------------------------
    findings.append(
        RequirementFinding(
            kind=RequirementKind.scoring,
            status=RequirementStatus.satisfied,
            detail=(
                f"scoring is the native competition core; {len(template.challenges)} challenge(s) "
                "are seeded server-side. On this substrate a SHARED scoring segment is compiled, "
                "reachable from every team segment on the scoring port alone — it is the one "
                "cross-segment path the firewall permits."
            ),
        )
    )
    findings.append(
        RequirementFinding(
            kind=RequirementKind.telemetry,
            status=RequirementStatus.satisfied,
            detail=(
                "an optional per-team sensor guest is compiled when the team request asks for one; "
                "range events, allocations and the post-apply verification report are recorded "
                "either way."
            ),
        )
    )
    findings.append(
        RequirementFinding(
            kind=RequirementKind.controlled_egress,
            status=RequirementStatus.undetermined
            if observation is None
            else _observed_egress_status(observation),
            reason_id=None
            if observation is not None
            and _observed_egress_status(observation) is RequirementStatus.satisfied
            else "proxmox.control_plane_cidrs_unobserved",
            detail=(
                "egress is controlled by the compiled firewall: no team segment may reach another "
                "team, and no team segment may reach the Proxmox management plane. Proving the "
                "second needs the cluster's management CIDRs, which only a discovery observation "
                "supplies — a GUESSED management CIDR is how a team segment ends up bridged onto "
                "the management network, so it is never inferred."
            ),
        )
    )
    return tuple(findings)


def _observed_fact_finding(
    observation: object | None, field_name: str, kind: RequirementKind, description: str
) -> RequirementFinding:
    if observation is None:
        return _undetermined(
            kind,
            "proxmox.no_observation_of_record",
            f"{description} — no discovery observation has been recorded, so this is unknown. "
            "Unknown is not permission: the compiler refuses rather than assuming a value.",
        )
    value = getattr(observation, field_name, None)
    if value is None:
        return RequirementFinding(
            kind=kind,
            status=RequirementStatus.unsatisfied,
            reason_id=f"proxmox.{field_name}_unobserved",
            detail=(
                f"an observation was recorded but it does not carry {description}. A missing field "
                "is not an empty one: 'we never looked' and 'the cluster has none' are different "
                "facts and only the second permits an allocation."
            ),
        )
    return RequirementFinding(
        kind=kind,
        status=RequirementStatus.satisfied,
        detail=f"{description} was observed and recorded ({field_name}).",
    )


def _observed_templates_status(observation: object, template: CatalogTemplate) -> RequirementStatus:
    templates = getattr(observation, "templates", None) or ()
    return RequirementStatus.satisfied if templates else RequirementStatus.unsatisfied


def _observed_storage_status(observation: object) -> RequirementStatus:
    nodes = getattr(observation, "nodes", None) or ()
    has_storage = any(getattr(node, "storages", None) for node in nodes)
    return RequirementStatus.satisfied if has_storage else RequirementStatus.unsatisfied


def _observed_egress_status(observation: object) -> RequirementStatus:
    identity = getattr(observation, "identity", None)
    cidrs = getattr(identity, "management_cidrs", None) or ()
    return RequirementStatus.satisfied if cidrs else RequirementStatus.unsatisfied


def _team_count_finding(team_count: int | None) -> RequirementFinding:
    if team_count is None:
        return _undetermined(
            RequirementKind.team_count,
            "proxmox.team_count_undeclared",
            f"this substrate requires at least {PROXMOX_MIN_TEAMS} teams — with one team there is "
            "nothing to segregate and cross-team isolation cannot be exercised, let alone proved. "
            "No team request has been recorded for this range, so the count is unknown.",
        )
    if team_count < PROXMOX_MIN_TEAMS:
        return RequirementFinding(
            kind=RequirementKind.team_count,
            status=RequirementStatus.unsatisfied,
            reason_id="proxmox.team_count_below_floor",
            detail=(
                f"{team_count} team(s) requested; this substrate requires at least "
                f"{PROXMOX_MIN_TEAMS}. The segregated-network compiler refuses a single-team "
                "request outright rather than compiling a lab whose central property cannot hold."
            ),
        )
    return RequirementFinding(
        kind=RequirementKind.team_count,
        status=RequirementStatus.satisfied,
        detail=(
            f"{team_count} team(s) requested, at or above the {PROXMOX_MIN_TEAMS}-team floor. Each "
            "gets its own VNet, subnet, VLAN and copy of every target."
        ),
    )


_PROXMOX_TEAM_BOUNDS = (PROXMOX_MIN_TEAMS, None)


def _compatibility(
    provider: str,
    template: CatalogTemplate | None,
    *,
    observation: object | None,
    team_count: int | None,
) -> ProviderCompatibility:
    if template is None:
        return ProviderCompatibility(
            provider=provider,
            support=ProviderSupport.unsupported,
            template_slug=None,
            requirements=(
                RequirementFinding(
                    kind=RequirementKind.source_template,
                    status=RequirementStatus.unsatisfied,
                    reason_id="scenario.no_template_for_provider",
                    detail=(
                        f"no template in the shipped catalog builds this scenario on "
                        f"'{provider}'. This build cannot run it there. That is a definite answer, "
                        "not a missing check."
                    ),
                ),
            ),
            min_teams=None,
            max_teams=None,
        )
    if provider == "proxmox":
        return ProviderCompatibility(
            provider=provider,
            support=ProviderSupport.supported,
            template_slug=template.slug,
            requirements=_proxmox_requirements(
                template, observation=observation, team_count=team_count
            ),
            min_teams=_PROXMOX_TEAM_BOUNDS[0],
            max_teams=_PROXMOX_TEAM_BOUNDS[1],
        )
    return ProviderCompatibility(
        provider=provider,
        support=ProviderSupport.supported,
        template_slug=template.slug,
        requirements=_docker_requirements(template),
        min_teams=None,
        max_teams=None,
    )


def build_scenario(
    key: str,
    *,
    observation: object | None = None,
    team_count: int | None = None,
) -> Scenario | None:
    """Project one scenario, optionally against a recorded observation and team request.

    With no observation the Proxmox substrate-dependent requirements are ``undetermined``. With one,
    they are answered from what was actually recorded.
    """
    slugs = _SCENARIO_TEMPLATES.get(key)
    if slugs is None:
        return None
    templates = _templates(slugs)
    if not templates:
        return None
    _assert_shared_content(key, templates)
    by_provider = {template.provider: template for template in templates}
    canonical = templates[0]
    return Scenario(
        key=key,
        name=_scenario_name(canonical),
        summary=canonical.summary,
        providers=tuple(
            _compatibility(
                provider,
                by_provider.get(provider),
                observation=observation,
                team_count=team_count,
            )
            for provider in KNOWN_PROVIDERS
        ),
        challenge_keys=tuple(challenge.key for challenge in canonical.challenges),
        component_keys=tuple(component.key for component in canonical.components),
        total_points=canonical.total_points,
    )


def _scenario_name(template: CatalogTemplate) -> str:
    """The scenario's name, with any substrate qualifier stripped off the template name.

    ``proxmox-web-breach-lab`` is called "Web Breach Lab (Proxmox, two teams)" as a TEMPLATE, which
    is right — that string names a deployable definition. The scenario is just "Web Breach Lab", and
    the canonical template (the first listed) already carries that name, so nothing is parsed out of
    a display string here.
    """
    return template.name


def list_scenarios(
    *, observation: object | None = None, team_count: int | None = None
) -> tuple[Scenario, ...]:
    """Every scenario the catalog ships, blocked ones included and marked.

    A blocked scenario stays in this list. Filtering it out would leave an operator unable to ask
    why the lab they wanted is not offered, and "not listed" reads as "does not exist" rather than
    "cannot run here, for these named reasons".
    """
    built = (
        build_scenario(key, observation=observation, team_count=team_count)
        for key in _SCENARIO_TEMPLATES
    )
    return tuple(scenario for scenario in built if scenario is not None)


def scenario_key_for_template(slug: str) -> str | None:
    """Which scenario a concrete template realises, or ``None`` if it realises none."""
    for key, slugs in _SCENARIO_TEMPLATES.items():
        if slug in slugs:
            return key
    return None
