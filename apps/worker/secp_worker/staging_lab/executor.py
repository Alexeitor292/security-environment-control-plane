"""Fake, provider-neutral staging-lab executor + ownership/blast-radius contract (SECP-002B-1B-9).

Fake-only. The executor reconciles a logical desired-state plan into logical *observed* resources
without touching any real infrastructure. It never constructs a transport, opens a socket, spawns
a subprocess, resolves a secret, or imports provider/network code. Every resource it may act on
must be positively identified as owned by the lab; unowned, production/shared, second
target-facing, production-reuse, or standing-authorization associations are refused fail-closed.

Idempotency: observed resources are keyed by a deterministic id derived from the lab ownership
label + resource kind, so re-running a simulation reconciles the same resources and never
produces duplicates on retry.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# Simulated lifecycle phases for a fake observed resource.
OBSERVED_PROVISIONED = "simulated_provisioned"
OBSERVED_DESTROYED = "simulated_destroyed"

# Attributes on a control-plane resource that must never indicate production reuse.
_PRODUCTION_REUSE_KEYS = ("uses_production_control_plane", "uses_production_database")


class StagingLabOwnershipError(Exception):
    """Raised when the fake adapter is asked to act outside the lab's owned blast radius."""

    def __init__(self, reason_code: str, message: str | None = None) -> None:
        super().__init__(message or reason_code)
        self.reason_code = reason_code


@runtime_checkable
class StagingLabExecutor(Protocol):
    """Worker-owned provider-neutral staging-lab execution seam.

    Only fake implementations exist in this PR. A future real adapter must preserve the ownership
    and blast-radius contract enforced here.
    """

    def simulate(self, *, plan: dict, prior_observed: dict | None) -> dict: ...

    def teardown(self, *, plan: dict, prior_observed: dict | None) -> dict: ...


def _resource_id(ownership_label: str, kind: str) -> str:
    digest = hashlib.sha256(f"{ownership_label}|{kind}".encode()).hexdigest()
    return f"sim:{digest[:24]}"


def assert_owned(resource: dict, ownership_label: str) -> None:
    """Fail closed unless ``resource`` is positively owned by ``ownership_label``.

    Also refuses production/shared network intent, a second target-facing connection policy,
    reuse of production control-plane components, and any standing-authorization association.
    """
    owner = resource.get("owner")
    if not owner or owner != ownership_label:
        raise StagingLabOwnershipError(
            "unowned_resource", "resource is not positively owned by this lab"
        )
    kind = resource.get("kind", "")
    if kind == "isolated_target_facing_network" and (
        resource.get("network_intent") != "host_only_no_uplink" or resource.get("uplink") != "none"
    ):
        raise StagingLabOwnershipError(
            "shared_or_production_network_rejected",
            "resource attaches to a shared/production network intent",
        )
    if kind == "target_facing_connection_policy" and resource.get("count") != 1:
        raise StagingLabOwnershipError(
            "second_target_facing_connection_rejected",
            "more than one target-facing connection is not permitted",
        )
    if kind == "self_contained_staging_control_plane":
        if any(bool(resource.get(k)) for k in _PRODUCTION_REUSE_KEYS):
            raise StagingLabOwnershipError(
                "production_control_plane_reuse_rejected",
                "resource reuses a production control-plane component",
            )
    if resource.get("standing_authorization"):
        raise StagingLabOwnershipError(
            "standing_authorization_rejected",
            "a standing authorization may not be associated with a lab resource",
        )


def assert_plan_blast_radius(plan: dict, ownership_label: str) -> None:
    """Validate the whole plan's blast radius before any (fake) action.

    Rejects unowned resources, more than one target-facing network, more than one nested target,
    more than one target-facing connection policy, and production reuse.
    """
    resources = plan.get("resources", [])
    counts: dict[str, int] = {}
    for resource in resources:
        assert_owned(resource, ownership_label)
        counts[resource.get("kind", "")] = counts.get(resource.get("kind", ""), 0) + 1
    if counts.get("isolated_target_facing_network", 0) > 1:
        raise StagingLabOwnershipError(
            "multiple_target_facing_networks_rejected",
            "more than one target-facing network is not permitted",
        )
    if counts.get("disposable_nested_proxmox_target", 0) > 1:
        raise StagingLabOwnershipError(
            "multiple_nested_targets_rejected", "more than one nested target is not permitted"
        )
    if counts.get("target_facing_connection_policy", 0) > 1:
        raise StagingLabOwnershipError(
            "second_target_facing_connection_rejected",
            "more than one target-facing connection is not permitted",
        )


@dataclass(frozen=True)
class FakeStagingLabExecutor:
    """Deterministic, idempotent fake executor. Produces logical observations only."""

    executor_identity: str = "fake-staging-lab-executor"

    def _observe(self, plan: dict, ownership_label: str, *, phase: str) -> dict:
        resources = []
        for resource in sorted(
            plan.get("resources", []), key=lambda r: (r.get("kind", ""), r.get("owner", ""))
        ):
            kind = resource.get("kind", "")
            resources.append(
                {
                    "resource_id": _resource_id(ownership_label, kind),
                    "kind": kind,
                    "owner": ownership_label,
                    "observed_phase": phase,
                    "simulated": True,
                }
            )
        return {
            "executor_identity": self.executor_identity,
            "simulated": True,
            "creates_infrastructure": False,
            "ownership_label": ownership_label,
            "resources": resources,
        }

    def simulate(self, *, plan: dict, prior_observed: dict | None) -> dict:
        """Reconcile the plan into simulated-provisioned observations (idempotent on retry)."""
        ownership_label = str(plan.get("ownership_label", ""))
        if not ownership_label:
            raise StagingLabOwnershipError("ownership_label_missing")
        assert_plan_blast_radius(plan, ownership_label)
        observed = self._observe(plan, ownership_label, phase=OBSERVED_PROVISIONED)
        # Idempotency: a retry with equivalent prior observed-state yields the identical set.
        if prior_observed is not None:
            prior_ids = {r.get("resource_id") for r in prior_observed.get("resources", [])}
            new_ids = {r.get("resource_id") for r in observed["resources"]}
            if prior_ids and prior_ids != new_ids:
                raise StagingLabOwnershipError(
                    "idempotency_violation",
                    "retry would change the owned resource set",
                )
        return observed

    def teardown(self, *, plan: dict, prior_observed: dict | None) -> dict:
        """Reconcile the plan into simulated-destroyed observations (idempotent, rollback-safe)."""
        ownership_label = str(plan.get("ownership_label", ""))
        if not ownership_label:
            raise StagingLabOwnershipError("ownership_label_missing")
        assert_plan_blast_radius(plan, ownership_label)
        return self._observe(plan, ownership_label, phase=OBSERVED_DESTROYED)
