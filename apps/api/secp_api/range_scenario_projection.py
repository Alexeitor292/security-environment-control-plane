"""Scenario dataclasses -> published schemas.

Kept in its own module rather than appended to :mod:`secp_api.range_projection` because it projects
pure catalog values and touches no ORM row and no session — there is nothing here that has to be
materialised before a session closes, and mixing it into the ORM projections would suggest there is.

``blocked`` is computed from the requirement list on the way out, in one place, so a response can
never carry ``blocked: false`` beside a non-empty ``blockers``.
"""

from __future__ import annotations

from secp_api.range_scenarios import (
    ProviderCompatibility,
    RequirementFinding,
    Scenario,
)
from secp_api.schemas_range_scenarios import (
    ProviderCompatibilityOut,
    RequirementFindingOut,
    ScenarioOut,
)


def requirement_out(finding: RequirementFinding) -> RequirementFindingOut:
    return RequirementFindingOut(
        kind=finding.kind,
        status=finding.status,
        detail=finding.detail,
        reason_id=finding.reason_id,
    )


def compatibility_out(compatibility: ProviderCompatibility) -> ProviderCompatibilityOut:
    return ProviderCompatibilityOut(
        provider=compatibility.provider,
        support=compatibility.support,
        template_slug=compatibility.template_slug,
        blocked=compatibility.blocked,
        requirements=[requirement_out(item) for item in compatibility.requirements],
        blockers=[requirement_out(item) for item in compatibility.blockers],
        unmet_capabilities=[requirement_out(item) for item in compatibility.unmet_capabilities],
        min_teams=compatibility.min_teams,
        max_teams=compatibility.max_teams,
    )


def scenario_out(scenario: Scenario) -> ScenarioOut:
    providers = [compatibility_out(item) for item in scenario.providers]
    return ScenarioOut(
        key=scenario.key,
        name=scenario.name,
        summary=scenario.summary,
        providers=providers,
        component_keys=list(scenario.component_keys),
        challenge_keys=list(scenario.challenge_keys),
        total_points=scenario.total_points,
        # Derived from the projected providers, not recomputed from the dataclass, so the flag and
        # the list a client reads are the same data.
        blocked_everywhere=all(item.blocked for item in providers),
    )
