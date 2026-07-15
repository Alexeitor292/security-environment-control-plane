"""The two-``SecretMaterial`` plan-only child-environment projection contract (B1B-PR5A, ADR-022
§10).

PR5B will inject two SEPARATE credentials into the plan child process: the provider plan-read
credential and the state-backend plan credential. This module defines their projection contract and
proves the discipline WITHOUT running any process (PR5A runs none):

* two DISTINCT builders — a combined ``SecretMaterial`` is never used;
* each produces a FRESH dict holding ONLY its own allowlisted variable;
* neither reads or mutates ``os.environ`` (this module does not import ``os`` at all), and inherits
  no ambient ``PATH``/``HOME``/proxy/cloud/SSH value;
* unknown keys, case collisions, newline/NUL/oversized values are refused;
* nothing is logged, persisted, or written into HCL, and neither value crosses into the other's var.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_api.plan_activation_contract import (
    PLAN_PROVIDER_ENV_ALLOWLIST,
    PLAN_SECRET_ENV_CONTRACT_VERSION,
    PLAN_STATE_ENV_ALLOWLIST,
)

from secp_worker.preflight.secret_resolution import SecretMaterial

_FORBIDDEN_VALUE_CHARS = ("\x00", "\n", "\r")
_MAX_ENV_VALUE_BYTES = 4096


class PlanEnvViolation(Exception):
    """Raised on any env-contract violation. It never echoes the rejected key or value."""


@dataclass(frozen=True)
class PlanEnvContract:
    """One credential's projection contract: its purpose label + its exact allowlisted variables."""

    purpose: str
    variable_names: tuple[str, ...]
    contract_version: str = PLAN_SECRET_ENV_CONTRACT_VERSION


PROVIDER_PLAN_ENV_CONTRACT = PlanEnvContract(
    purpose="provider_plan_read", variable_names=PLAN_PROVIDER_ENV_ALLOWLIST
)
STATE_PLAN_ENV_CONTRACT = PlanEnvContract(
    purpose="state_backend_plan", variable_names=PLAN_STATE_ENV_ALLOWLIST
)
# The union allowlist (defence in depth): no variable outside this set may ever be produced.
_ALL_ALLOWED = frozenset(PLAN_PROVIDER_ENV_ALLOWLIST) | frozenset(PLAN_STATE_ENV_ALLOWLIST)


def _project(material: SecretMaterial, *, contract: PlanEnvContract) -> dict[str, str]:
    if not isinstance(material, SecretMaterial):
        raise PlanEnvViolation("plan env requires opaque SecretMaterial")
    if contract.contract_version != PLAN_SECRET_ENV_CONTRACT_VERSION:
        raise PlanEnvViolation("plan env contract version mismatch")
    names = contract.variable_names
    if not names:
        raise PlanEnvViolation("plan env contract has no allowlisted variable")
    if len(names) != len(set(names)):
        raise PlanEnvViolation("duplicate plan env variable name")
    lowered = [n.lower() for n in names]
    if len(lowered) != len(set(lowered)):
        raise PlanEnvViolation("case-colliding plan env variable name")
    if not set(names) <= _ALL_ALLOWED:
        raise PlanEnvViolation("plan env variable is not in the allowlist")
    value = material.reveal_secret()
    if not isinstance(value, str) or not value:
        raise PlanEnvViolation("plan env value must be a non-empty string")
    if any(c in value for c in _FORBIDDEN_VALUE_CHARS):
        raise PlanEnvViolation("plan env value contains a forbidden control character")
    if len(value.encode("utf-8")) > _MAX_ENV_VALUE_BYTES:
        raise PlanEnvViolation("plan env value exceeds the maximum size")
    # A FRESH dict, no ambient inheritance. dict.fromkeys keeps the value out of any repr chain.
    return dict.fromkeys(names, value)


def build_provider_plan_env(material: SecretMaterial) -> dict[str, str]:
    """Project the PROVIDER plan-read credential into ONLY its allowlisted variable."""
    return _project(material, contract=PROVIDER_PLAN_ENV_CONTRACT)


def build_state_plan_env(material: SecretMaterial) -> dict[str, str]:
    """Project the STATE-BACKEND plan credential into ONLY its allowlisted variable."""
    return _project(material, contract=STATE_PLAN_ENV_CONTRACT)


def combined_plan_env(
    provider_material: SecretMaterial, state_material: SecretMaterial
) -> dict[str, str]:
    """The full plan child environment: the disjoint union of the two independent projections.

    The two projections are built SEPARATELY (never one combined ``SecretMaterial``), and their
    variable sets are disjoint, so neither value can ever land in the other's variable.
    """
    provider_env = build_provider_plan_env(provider_material)
    state_env = build_state_plan_env(state_material)
    # pragma below: the allowlists are disjoint by construction, so this never triggers.
    if set(provider_env) & set(state_env):  # pragma: no cover - disjoint by construction
        raise PlanEnvViolation("provider and state plan env variables must be disjoint")
    return {**provider_env, **state_env}
