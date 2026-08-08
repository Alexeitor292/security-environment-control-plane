"""The mutation credential path, end to end: authority first, purpose fixed, no fallback anywhere.

`_resolve_lab_secret_env` used to resolve `ExecutionTarget.secret_ref` through a duck-typed
`resolve(str)` protocol with no purpose at all — any object with a `.resolve` method satisfied it,
and the generic reference is the same column the legacy discovery and live-readonly paths use. These
tests pin the replacement, and each one asserts a REFUSAL for a specific way the old shape would
have said yes.
"""

from __future__ import annotations

import uuid

import pytest
from secp_worker.preflight.proxmox_secret_resolver import ProxmoxOperationSecretResolver
from secp_worker.preflight.secret_resolution import (
    ResolutionContractViolation,
    ResolutionPurpose,
    SecretResolutionUnavailable,
    TrustedCredentialReference,
    assert_proxmox_resolution_authorized,
    build_provider_execution_resolution_request,
)

ORG = uuid.UUID("11111111-1111-1111-1111-111111111111")
TARGET = uuid.UUID("22222222-2222-2222-2222-222222222222")
WORKER = "wk-selected-1"
OPERATION = "33333333-3333-3333-3333-333333333333"
REF = TrustedCredentialReference("vault://provider-execution")


def _pair(**over):
    base = dict(
        organization_id=ORG,
        execution_target_id=TARGET,
        worker_installation_id=WORKER,
        operation_identity=OPERATION,
        operation_generation=1,
        credential_reference=REF,
    )
    base.update(over)
    return build_provider_execution_resolution_request(**base)


# === the purpose is fixed at the call site, not chosen by a caller ==============================


def test_a_discovery_resolver_refuses_a_provider_execution_request():
    """The case that matters, and the one a self-consistency check alone would miss.

    The request and expectation agree with each other perfectly — they were built together. What
    stops them satisfying a DISCOVERY resolver is the second, independent comparison against the
    purpose the call site is actually for.
    """
    request, expectation = _pair()
    discovery = ProxmoxOperationSecretResolver(
        purpose=ResolutionPurpose.proxmox_readonly_discovery, client=None
    )
    with pytest.raises(ResolutionContractViolation) as ei:
        assert_proxmox_resolution_authorized(
            request, expectation, required_purpose=discovery.purpose
        )
    assert ei.value.reason_code == "proxmox_resolution_wrong_purpose"


def test_a_provider_execution_resolver_refuses_a_discovery_request():
    """Symmetric. A mutation credential handed to a read path is the same defect facing the other
    way, and a separation that only holds in one direction is not a separation."""
    from secp_worker.preflight.secret_resolution import (
        build_discovery_resolution_request,
    )

    request, expectation = build_discovery_resolution_request(
        organization_id=ORG,
        execution_target_id=TARGET,
        worker_installation_id=WORKER,
        operation_identity=OPERATION,
        operation_generation=1,
        credential_reference=TrustedCredentialReference("vault://discovery"),
    )
    with pytest.raises(ResolutionContractViolation) as ei:
        assert_proxmox_resolution_authorized(
            request,
            expectation,
            required_purpose=ResolutionPurpose.proxmox_provider_execution,
        )
    assert ei.value.reason_code == "proxmox_resolution_wrong_purpose"


def test_the_two_purposes_carry_different_contract_versions():
    """Two independent reasons to refuse the same mistake.

    A future edit that relaxed the purpose comparison would still meet the version comparison.
    """
    exec_request, _ = _pair()
    from secp_worker.preflight.secret_resolution import build_discovery_resolution_request

    disc_request, _ = build_discovery_resolution_request(
        organization_id=ORG,
        execution_target_id=TARGET,
        worker_installation_id=WORKER,
        operation_identity=OPERATION,
        operation_generation=1,
        credential_reference=REF,
    )
    assert exec_request.contract.contract_version != disc_request.contract.contract_version


# === every binding field refuses independently ==================================================


@pytest.mark.parametrize(
    "field,value,label",
    [
        ("organization_id", uuid.UUID("99999999-9999-9999-9999-999999999999"), "organization"),
        ("execution_target_id", uuid.UUID("88888888-8888-8888-8888-888888888888"), "target"),
        ("worker_installation_id", "wk-not-selected", "worker"),
        ("operation_identity", "44444444-4444-4444-4444-444444444444", "operation"),
        ("operation_generation", 7, "generation"),
        (
            "credential_reference",
            TrustedCredentialReference("vault://other"),
            "credential_reference",
        ),
    ],
)
def test_each_binding_field_refuses_and_names_itself(field, value, label):
    """Field by field, and the refusal NAMES which binding disagreed.

    An operator told only "contract violation" has to guess between a wrong organization, a wrong
    target and a wrong worker — three different things to go and fix.
    """
    request, _ = _pair()
    _, expectation = _pair(**{field: value})
    with pytest.raises(ResolutionContractViolation) as ei:
        assert_proxmox_resolution_authorized(
            request, expectation, required_purpose=ResolutionPurpose.proxmox_provider_execution
        )
    assert ei.value.reason_code == f"discovery_resolution_mismatch:{label}"


# === the shipped resolver fails closed ==========================================================


def test_the_shipped_resolver_has_no_backend_and_refuses_before_target_contact():
    """`client=None` is the SHIPPED state. It refuses rather than falling back to anything."""
    request, expectation = _pair()
    resolver = ProxmoxOperationSecretResolver(
        purpose=ResolutionPurpose.proxmox_provider_execution, client=None
    )
    from datetime import UTC, datetime

    with pytest.raises(SecretResolutionUnavailable) as ei:
        resolver.resolve(request, expectation=expectation, now=datetime.now(UTC))
    assert "proxmox_provider_execution" in str(ei.value)


def test_the_resolver_cannot_be_constructed_for_a_purpose_outside_the_proxmox_pair():
    """Not constructible, rather than constructible and refusing later."""
    with pytest.raises(ResolutionContractViolation):
        ProxmoxOperationSecretResolver(
            purpose=ResolutionPurpose.readonly_staging_preflight, client=None
        )


def test_the_resolver_cannot_be_serialized_or_pickled():
    """A picklable resolver is a file naming a backend, and a Temporal payload that carries one."""
    import copy
    import pickle

    resolver = ProxmoxOperationSecretResolver(
        purpose=ResolutionPurpose.proxmox_provider_execution, client=None
    )
    for attempt in (pickle.dumps, copy.deepcopy, copy.copy):
        with pytest.raises(TypeError):
            attempt(resolver)
    # and its repr names no backend, endpoint or reference
    assert "vault" not in repr(resolver)
    assert "client" not in repr(resolver).lower() or "redacted" in repr(resolver)


# === production reachability — a helper with test-only callers is not finished ===================


def test_the_production_path_fixes_the_purpose_at_construction():
    """Structural: the shipped factory names the purpose itself.

    A resolver whose purpose an argument could choose would let a discovery operation request an
    apply credential simply by naming one — which is precisely the caller-selectable escape hatch
    the authorization excluded.
    """
    import ast
    import inspect

    from secp_worker.provisioning import execution

    src = inspect.getsource(execution._default_provider_execution_resolver)
    tree = ast.parse(src.lstrip())
    kwargs = {
        kw.arg: kw.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        for kw in n.keywords
        if kw.arg
    }
    assert "purpose" in kwargs
    # the purpose is a literal attribute access, not a parameter of the factory
    assert isinstance(kwargs["purpose"], ast.Attribute)
    assert kwargs["purpose"].attr == "proxmox_provider_execution"
    assert (
        set(inspect.signature(execution._default_provider_execution_resolver).parameters) == set()
    )


def test_the_execution_path_calls_the_purpose_bound_builder_and_the_dedicated_accessor():
    """Reachability, asserted on the production function rather than a test double."""
    import ast
    import inspect

    from secp_worker.provisioning import execution

    tree = ast.parse(inspect.getsource(execution._resolve_lab_secret_env).lstrip())
    called = {
        (n.func.id if isinstance(n.func, ast.Name) else getattr(n.func, "attr", ""))
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
    }
    assert "build_provider_execution_resolution_request" in called
    assert "require_provider_execution_credential_reference" in called
    assert "build_provider_plan_env" in called  # the canonical, checked env projection
    # and it never reaches the retired generic path
    assert "build_lab_secret_env" not in called


def test_the_generic_reference_is_not_read_anywhere_on_the_mutation_path():
    """`target.secret_ref` must not appear in the resolution function at all.

    Not "is not preferred" — not present. It is the column the legacy discovery and live-readonly
    paths resolve, so any read of it here is the substitution this closes.
    """
    import ast
    import inspect

    from secp_worker.provisioning import execution

    tree = ast.parse(inspect.getsource(execution._resolve_lab_secret_env).lstrip())
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "secret_ref" not in attrs
    assert "provider_plan_secret_ref" not in attrs
    assert "state_backend_secret_ref" not in attrs


def test_authority_is_required_before_any_credential_work_happens():
    """Ordering, asserted structurally: the authority check precedes every resolution call.

    Possession of a credential is never permission to execute, so a live secret must not exist in
    the process for an execution that was not authorized first.
    """
    import inspect

    from secp_worker.provisioning import execution

    src = inspect.getsource(execution._resolve_lab_secret_env)
    authority_check = src.index("if authority is None:")
    for later in (
        "require_provider_execution_credential_reference(",
        "build_provider_execution_resolution_request(",
        ".resolve(",
    ):
        assert src.index(later) > authority_check, later


def test_the_authority_comes_from_the_executor_that_will_run():
    """Not threaded alongside it.

    Taking the authority from the executor guarantees the credential is bound to the same
    authorization that produced the thing about to execute; a separately-passed one could, after a
    refactor, describe a different operation.
    """
    import inspect

    from secp_worker.provisioning import execution

    src = inspect.getsource(execution.run_real_provisioning)
    assert 'getattr(process_executor, "authority", None)' in src


def test_no_live_secret_can_reach_a_durable_or_transported_surface():
    """The env projection returns SecretMaterial-derived values into a FRESH dict and nothing else.

    Asserted on the module: the mutation path may not import anything that persists, audits or
    transports, so a secret has nowhere to go even by accident.
    """
    import ast
    import inspect

    from secp_worker.provisioning import execution

    tree = ast.parse(inspect.getsource(execution._resolve_lab_secret_env).lstrip())
    imported = {
        a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names
    } | {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    for banned in ("audit", "logging", "logger", "temporalio", "requests", "httpx"):
        assert not any(banned in name.lower() for name in imported), banned
