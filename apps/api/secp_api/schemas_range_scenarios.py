"""Published schemas for the scenario/provider-compatibility catalog.

The one property that matters here: **a blocked scenario is a normal, renderable response.** It
carries ``blocked: true`` and a non-empty ``blockers`` list, and it is returned by the list endpoint
alongside everything else. There is no shape in which a scenario that cannot run is either absent
from the catalog or marked eligible.

The second property: ``RequirementStatus`` has three members and ``undetermined`` is one of them. A
client that renders ``satisfied``/``not satisfied`` from a boolean would turn "no discovery
observation has been recorded" into "this requirement is met", which is the exact substitution the
Proxmox compiler refuses to make.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from secp_api.range_scenarios import (
    ProviderSupport,
    RequirementKind,
    RequirementStatus,
)


class RequirementFindingOut(BaseModel):
    """One requirement for one scenario on one provider."""

    kind: RequirementKind
    status: RequirementStatus
    detail: str
    #: A stable key a client may branch on. Present on ``unsatisfied`` and ``undetermined``;
    #: ``None`` on ``satisfied``, which has no reason to name.
    reason_id: str | None = None


class ProviderCompatibilityOut(BaseModel):
    """How one scenario stands on one provider — including when the answer is "it cannot run"."""

    provider: str
    support: ProviderSupport
    #: The concrete template slug ``POST /ranges`` takes to build this scenario here. ``None``
    #: exactly when ``support`` is ``unsupported``: there is no slug, so there is nothing a client
    #: could post by mistake.
    template_slug: str | None = None
    #: True when this scenario cannot be deployed on this provider right now. Derived from the
    #: requirements below, never declared alongside them, so the two can never disagree.
    blocked: bool
    requirements: list[RequirementFindingOut]
    #: Exactly the requirements that stop this scenario running here. An ``undetermined``
    #: requirement appears here: unchecked is not met. A ``not_provided`` one does not — it is a
    #: capability the substrate lacks, not a reason the lab cannot start.
    blockers: list[RequirementFindingOut]
    #: Properties this substrate will not give the scenario, though it will still run it. Reported
    #: separately from ``blockers`` because the two demand opposite decisions from an operator.
    unmet_capabilities: list[RequirementFindingOut]
    #: ``None`` for a bound this provider does not impose — distinct from a bound of zero.
    min_teams: int | None = None
    max_teams: int | None = None


class ScenarioOut(BaseModel):
    """One lab, listed ONCE, with every provider it can run on.

    The Web Breach Lab appears here a single time carrying two provider variants, not twice as two
    templates. The components and challenges are the shared catalog definitions both variants are
    built from, so the substrate changes and the content does not.
    """

    key: str
    name: str
    summary: str
    providers: list[ProviderCompatibilityOut]
    component_keys: list[str] = Field(default_factory=list)
    challenge_keys: list[str] = Field(default_factory=list)
    total_points: int
    #: True when NO provider can currently run this scenario. A scenario in this state is still
    #: listed and still names its blockers per provider.
    blocked_everywhere: bool
