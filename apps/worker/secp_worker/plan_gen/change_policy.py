"""The manifest-exact create-only plan-change policy (B1B-PR5B, ADR-022 §6).

The initial controlled-live scope is a SINGLE disposable LXC container (task §3). The first plan for
an operation must therefore contain EXACTLY ONE resource: the exact ``<type>.<name>`` address the
controlled-live renderer emits for THIS manifest, a MANAGED resource of the one supported
bpg/proxmox
container type, from the exact bpg/proxmox provider identity, with actions exactly ``["create"]``
and
no replacement. Anything else — a second or missing address, a duplicate, a different address/type/
provider, a data source, an update/delete/replace/read/no-op, or a
network/bridge/VLAN/host/HA/global
resource — fails closed. It contacts nothing and reveals no plan content in its refusal.

The evaluator receives an IMMUTABLE :class:`ExpectedPlanContext` derived SERVER-SIDE from the
immutable manifest + the controlled-live renderer identity; no caller may supply its own allowlist.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_worker.plan_gen.controlled_live import (
    CONTROLLED_LIVE_PROVIDER_SHOW_NAME,
    controlled_live_expected_address,
)

# The reviewed plan-change policy identity (stored on the durable result; bumped on any policy
# change,
# INDEPENDENTLY of the runner version).
PLAN_CHANGE_POLICY_VERSION = "secp-002b-1b-pr5b/plan-change-policy/v1"

_CONTAINER_TYPE = "proxmox_virtual_environment_container"
_CREATE_ONLY = ("create",)


class PlanChangePolicyError(Exception):
    """The canonical change set violates the manifest-exact create-only policy (bounded reason)."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class ExpectedPlanContext:
    """The immutable, server-derived expectation the plan must match EXACTLY."""

    expected_address: str
    expected_type: str
    expected_provider: str
    policy_version: str = PLAN_CHANGE_POLICY_VERSION


def expected_plan_context(manifest: dict) -> ExpectedPlanContext:
    """Derive the immutable expected-plan context server-side from the immutable manifest."""
    return ExpectedPlanContext(
        expected_address=controlled_live_expected_address(manifest),
        expected_type=_CONTAINER_TYPE,
        expected_provider=CONTROLLED_LIVE_PROVIDER_SHOW_NAME,
    )


@dataclass(frozen=True)
class PlanChangeDecision:
    """The accepted, create-only summary of a canonical change set (safe counts only)."""

    created: int
    resource_types: tuple[str, ...]
    policy_version: str
    outcome: str = "create_only"


class PlanChangePolicyEvaluator:
    """Evaluate a canonical change set against the manifest-EXACT create-only policy."""

    def __init__(self, *, expected: ExpectedPlanContext) -> None:
        self._expected = expected

    def evaluate(self, change_set: object) -> PlanChangeDecision:  # noqa: C901, PLR0912
        """Return a :class:`PlanChangeDecision`, or raise ``PlanChangePolicyError`` fail-closed."""
        exp = self._expected
        if not isinstance(change_set, dict):
            raise PlanChangePolicyError("change_policy_refused")
        resources = change_set.get("resources")
        if not isinstance(resources, list) or len(resources) != 1:
            # EXACTLY one resource — zero, more than one, or non-list all fail closed.
            raise PlanChangePolicyError("change_policy_refused")
        res = resources[0]
        if not isinstance(res, dict):
            raise PlanChangePolicyError("change_policy_refused")
        address = res.get("address")
        actions = res.get("actions")
        if res.get("mode") != "managed":
            raise PlanChangePolicyError("change_policy_refused")
        if not isinstance(address, str) or address != exp.expected_address:
            raise PlanChangePolicyError("change_policy_refused")
        if res.get("type") != exp.expected_type:
            raise PlanChangePolicyError("change_policy_refused")
        if res.get("provider") != exp.expected_provider:
            raise PlanChangePolicyError("change_policy_refused")
        if not isinstance(actions, list) or tuple(actions) != _CREATE_ONLY:
            raise PlanChangePolicyError("change_policy_refused")
        if res.get("replace") is True:
            raise PlanChangePolicyError("change_policy_refused")
        # Defense in depth: the canonical summary must also report exactly one create.
        summary = change_set.get("summary")
        if isinstance(summary, dict):
            if summary.get("count") != 1 or summary.get("by_action") != {"create": 1}:
                raise PlanChangePolicyError("change_policy_refused")
        return PlanChangeDecision(
            created=1,
            resource_types=(exp.expected_type,),
            policy_version=exp.policy_version,
        )
