"""The mutation credential can never be the read-only one.

Before the dedicated column existed, the only reachable apply credential was the generic
``ExecutionTarget.secret_ref`` — the same column the legacy discovery and live-readonly paths
resolve. A read-only credential silently becoming the apply credential is the defect these tests
exist to keep closed.

Every case here asserts a REFUSAL for a specific way one purpose could be satisfied by another's
reference. The four purposes are deliberately non-substitutable in both directions.
"""

from __future__ import annotations

import pytest
from secp_api.credential_binding import (
    RealPlanCredentialError,
    dedicated_reference,
    purpose_reference,
    require_provider_execution_credential_reference,
    require_real_plan_credential_reference,
)
from secp_api.enums import CredentialPurposeClass as P

DISCOVERY_REF = "vault://discovery-readonly"
PLAN_REF = "vault://provider-plan-read"
STATE_REF = "vault://state-backend"
EXEC_REF = "vault://provider-execution"


class _Target:
    """A stand-in carrying exactly the four reference columns, so a test can set one at a time."""

    def __init__(self, **refs) -> None:
        self.secret_ref = refs.get("secret_ref")
        self.provider_plan_secret_ref = refs.get("provider_plan_secret_ref")
        self.state_backend_secret_ref = refs.get("state_backend_secret_ref")
        self.provider_execution_secret_ref = refs.get("provider_execution_secret_ref")


# === no other reference can satisfy provider execution ==========================================


@pytest.mark.parametrize(
    "column,value",
    [
        ("secret_ref", DISCOVERY_REF),
        ("provider_plan_secret_ref", PLAN_REF),
        ("state_backend_secret_ref", STATE_REF),
    ],
)
def test_no_other_reference_satisfies_provider_execution(column, value):
    """Including the GENERIC one, which is the specific hole this closes.

    A target may be fully configured for discovery, plan and state and still have no authority to
    mutate anything. That is the intended shape: mutation is a separate grant.
    """
    target = _Target(**{column: value})
    assert purpose_reference(target, P.provider_execution) is None
    assert dedicated_reference(target, P.provider_execution) is None
    with pytest.raises(RealPlanCredentialError):
        require_provider_execution_credential_reference(target)


def test_all_three_other_references_together_still_do_not_satisfy_it():
    """Not an accumulation problem — no combination substitutes for the dedicated grant."""
    target = _Target(
        secret_ref=DISCOVERY_REF,
        provider_plan_secret_ref=PLAN_REF,
        state_backend_secret_ref=STATE_REF,
    )
    with pytest.raises(RealPlanCredentialError):
        require_provider_execution_credential_reference(target)


def test_a_null_dedicated_reference_refuses():
    """Historical NULL is honest: the migration backfills nothing, and NULL cannot execute."""
    with pytest.raises(RealPlanCredentialError) as ei:
        require_provider_execution_credential_reference(_Target())
    assert "provider_execution" in str(ei.value)


def test_there_is_no_fallback_in_either_accessor():
    """Structural, over the source: `provider_plan_read` legitimately falls back to `secret_ref`,
    so the absence of a fallback for execution has to be asserted rather than assumed."""
    import ast
    import inspect

    from secp_api import credential_binding

    for fn in (credential_binding.purpose_reference, credential_binding.dedicated_reference):
        tree = ast.parse(inspect.getsource(fn).lstrip())
        for node in ast.walk(tree):
            # find the `provider_execution` branch and prove its return has no `or` fallback
            if (
                isinstance(node, ast.Compare)
                and getattr(getattr(node.comparators[0], "attr", None), "__str__", lambda: "")()
                == "provider_execution"
            ):
                pass
        src = inspect.getsource(fn)
        exec_branch = src.split("provider_execution", 1)[-1]
        assert " or " not in exec_branch.split("return None")[0], fn.__name__


# === and provider execution cannot satisfy the others ===========================================


@pytest.mark.parametrize("purpose", [P.provider_plan_read, P.state_backend_plan])
def test_the_execution_reference_does_not_satisfy_a_read_purpose(purpose):
    """The separation is symmetric. A mutation credential handed to a read path would be an
    over-privileged read, which is the same defect facing the other way."""
    target = _Target(provider_execution_secret_ref=EXEC_REF)
    assert dedicated_reference(target, purpose) is None
    with pytest.raises(RealPlanCredentialError):
        require_real_plan_credential_reference(target, purpose)


def test_each_purpose_reads_only_its_own_column():
    """All four set at once: each resolver must return its own value, never a neighbour's."""
    target = _Target(
        secret_ref=DISCOVERY_REF,
        provider_plan_secret_ref=PLAN_REF,
        state_backend_secret_ref=STATE_REF,
        provider_execution_secret_ref=EXEC_REF,
    )
    assert dedicated_reference(target, P.provider_plan_read) == PLAN_REF
    assert dedicated_reference(target, P.state_backend_plan) == STATE_REF
    assert dedicated_reference(target, P.provider_execution) == EXEC_REF
    assert require_provider_execution_credential_reference(target) == EXEC_REF


def test_the_purpose_is_not_a_generic_mutation_credential():
    """Narrow by construction: exactly one enum member, mapping to exactly one worker purpose.

    A generic "mutation credential" a caller could select is the escape hatch the authorization
    explicitly excluded.
    """
    from secp_worker.preflight.secret_resolution import ResolutionPurpose

    members = {m.value for m in P}
    assert members == {"provider_plan_read", "state_backend_plan", "provider_execution"}
    # and the worker-side purpose it maps to is the single Proxmox mutation purpose
    assert ResolutionPurpose.proxmox_provider_execution.value == "proxmox_provider_execution"
    for banned in ("mutation", "generic", "any", "write"):
        assert banned not in members
