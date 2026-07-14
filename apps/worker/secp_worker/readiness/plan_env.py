"""Explicit just-in-time child-process environment projection (B1B-PR4 / ADR-021 §K).

The ONE place opaque secret material may become a child-process environment variable for a FUTURE
plan-only execution. It is a pure projection: it builds a NEW dict and returns it. It

* accepts typed, opaque :class:`~secp_worker.preflight.secret_resolution.SecretMaterial` and an
  operation-specific contract — never a raw string from a caller and never a dict;
* NEVER reads ``os.environ`` and NEVER modifies ``os.environ`` (this module does not import ``os``
  at all, so there is no ambient environment to inherit and no global to mutate);
* includes ONLY the reviewed exact variable names in
  :data:`~secp_api.readiness_contract.PLAN_SECRET_ENV_ALLOWLIST` — never ``PATH``, ``HOME``,
  ``USERPROFILE``, a proxy variable, a cloud credential, an SSH-agent socket, a shell variable, a
  locale value, or any other ambient input;
* refuses an unknown key, a duplicate or case-colliding key, a NUL or newline character in a value,
  and an oversized value;
* contains no logging and no ``repr`` of a value, and builds no shell string;
* **executes no process** — B1B-PR4 runs nothing. The returned mapping is bounded in lifetime by
  the caller and is never persisted, audited, logged, hashed, or returned by the API.

**Zeroization limitation (documented honestly).** Python ``str`` is immutable and interned by the
runtime; a secret's bytes cannot be reliably scrubbed from memory. This module therefore does NOT
claim cryptographic zeroization. It minimizes LIFETIME and REFERENCES instead: the revealed value
exists only inside the returned dict, the caller is expected to drop it immediately (the readiness
path builds it from an INERT sentinel and discards it in the same function), and no copy is ever
taken by logging, ``repr``, serialization, hashing, or persistence.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_api.enums import PlanSecretPurpose
from secp_api.readiness_contract import (
    MAX_ENV_VALUE_BYTES,
    PLAN_SECRET_ENV_ALLOWLIST,
    PLAN_SECRET_ENV_CONTRACT_VERSION,
    assert_plan_only_purpose,
)

from secp_worker.preflight.secret_resolution import SecretMaterial

# Characters that must never appear in an environment value: NUL terminates a C string (truncation /
# smuggling) and a newline can forge a second variable in a naive consumer.
_FORBIDDEN_VALUE_CHARS = ("\x00", "\n", "\r")


class PlanSecretEnvViolation(Exception):
    """A fail-closed JIT-projection refusal. It NEVER echoes the rejected key or value."""


@dataclass(frozen=True)
class PlanSecretEnvContract:
    """The operation-specific projection contract.

    ``purpose`` must be ``plan_read``: an apply or destroy purpose is unrepresentable and refused,
    so this builder can never construct a mutation-capable environment.

    ``variable_names`` must be a non-empty subset of the reviewed allowlist with no duplicate and no
    case-colliding entry.
    """

    purpose: PlanSecretPurpose = PlanSecretPurpose.plan_read
    variable_names: tuple[str, ...] = PLAN_SECRET_ENV_ALLOWLIST
    contract_version: str = PLAN_SECRET_ENV_CONTRACT_VERSION


def build_plan_secret_env(
    material: SecretMaterial, *, contract: PlanSecretEnvContract
) -> dict[str, str]:
    """Project opaque secret material into the EXACT allowlisted plan-read environment.

    Returns a NEW dict containing only the contract's variable names. Refuses (``
    PlanSecretEnvViolation``) on any unknown / duplicate / case-colliding key, on a NUL or newline
    in
    the value, on an oversized value, and on any purpose other than ``plan_read``.

    It reads nothing from the ambient process environment and mutates nothing. It runs no process.
    """
    if not isinstance(material, SecretMaterial):
        raise PlanSecretEnvViolation("plan-secret env requires typed opaque SecretMaterial")
    if contract.contract_version != PLAN_SECRET_ENV_CONTRACT_VERSION:
        raise PlanSecretEnvViolation("plan-secret env contract version mismatch")
    try:
        assert_plan_only_purpose(contract.purpose)
    except Exception as exc:  # PurposeNotPermitted
        raise PlanSecretEnvViolation(
            "only the plan-read secret purpose may be projected into an environment"
        ) from exc

    names = tuple(contract.variable_names)
    if not names:
        raise PlanSecretEnvViolation("plan-secret env contract declares no variable")
    if len(names) != len(set(names)):
        raise PlanSecretEnvViolation("plan-secret env contract declares a duplicate variable")
    if len({n.upper() for n in names}) != len(names):
        raise PlanSecretEnvViolation(
            "plan-secret env contract declares case-colliding variable names"
        )
    allowed = set(PLAN_SECRET_ENV_ALLOWLIST)
    if not set(names) <= allowed:
        # The rejected key is NEVER echoed: an attacker-supplied key must not reach a log or an
        # exception message.
        raise PlanSecretEnvViolation("plan-secret env contract declares a non-allowlisted variable")

    value = material.reveal_secret()
    if not isinstance(value, str) or not value:
        raise PlanSecretEnvViolation("plan-secret material is empty")
    if any(ch in value for ch in _FORBIDDEN_VALUE_CHARS):
        raise PlanSecretEnvViolation("plan-secret value contains a forbidden control character")
    if len(value.encode("utf-8", "ignore")) > MAX_ENV_VALUE_BYTES:
        raise PlanSecretEnvViolation("plan-secret value exceeds the bounded size")

    # A NEW dict. Nothing is inherited; nothing global is touched.
    return dict.fromkeys(names, value)


def env_contract_is_satisfied(env: dict[str, str], *, contract: PlanSecretEnvContract) -> bool:
    """True iff ``env`` contains EXACTLY the contract's allowlisted keys and nothing else.

    Used as the ``jit_injection_contract`` facet check: it proves no ambient variable leaked in and
    no extra key was added.
    """
    return set(env) == set(contract.variable_names) <= set(PLAN_SECRET_ENV_ALLOWLIST)
