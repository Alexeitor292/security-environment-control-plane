"""Two Proxmox credentials, and the property that keeps them two.

Discovery and provider execution authenticate the same API. Discovery holds four audit privileges;
execution must create an SDN object, a bridge, a VM. One shared token would mean every read-only
discovery run carried apply authority — so the separation is not a label, and these tests are what
make it structural.

The case that matters is NOT a malformed request. It is a perfectly well-formed
provider-execution request paired with its own matching expectation, offered to a discovery
resolver. Everything agrees with everything; it must still be refused.

No test opens a socket. The backend client is a fake, and the shipped default has no client at all.
"""

from __future__ import annotations

import pickle
import uuid
from datetime import UTC, datetime

import pytest
from secp_worker.plan_gen.openbao_plan_resolver import PlanSecretBackendError
from secp_worker.preflight.proxmox_secret_resolver import (
    PROXMOX_SECRET_RESOLVER_VERSION,
    ProxmoxOperationSecretResolver,
)
from secp_worker.preflight.secret_resolution import (
    SUPPORTED_PURPOSES,
    ResolutionContractViolation,
    ResolutionPurpose,
    SecretMaterial,
    SecretResolutionUnavailable,
    TrustedCredentialReference,
    build_discovery_resolution_request,
    build_provider_execution_resolution_request,
)

NOW = datetime(2026, 8, 7, 12, 0, 0, tzinfo=UTC)
ORG = uuid.uuid4()
TARGET = uuid.uuid4()
WORKER = "wk-1"
REF = "openbao:secp/proxmox/discovery"
TOKEN_VALUE = "secpdisc@pve!discovery=" + "0" * 8


class _FakeClient:
    """Records the read and returns material. Opens nothing."""

    def __init__(self, secret: str = TOKEN_VALUE, raises: Exception | None = None) -> None:
        self.secret = secret
        self.raises = raises
        self.reads: list[tuple[str, str]] = []

    def read_plan_secret(self, *, reference: str, scheme: str, now: datetime) -> str:
        self.reads.append((reference, scheme))
        if self.raises is not None:
            raise self.raises
        return self.secret


def _discovery(**kw):
    return build_discovery_resolution_request(
        organization_id=kw.get("org", ORG),
        execution_target_id=kw.get("target", TARGET),
        worker_installation_id=kw.get("worker", WORKER),
        operation_identity=kw.get("operation", "op-1"),
        operation_generation=kw.get("generation", 3),
        credential_reference=TrustedCredentialReference(kw.get("ref", REF)),
    )


def _execution(**kw):
    return build_provider_execution_resolution_request(
        organization_id=kw.get("org", ORG),
        execution_target_id=kw.get("target", TARGET),
        worker_installation_id=kw.get("worker", WORKER),
        operation_identity=kw.get("operation", "op-1"),
        operation_generation=kw.get("generation", 3),
        credential_reference=TrustedCredentialReference(kw.get("ref", REF)),
    )


# === the separation, which is the whole point ====================================================


def test_a_self_consistent_execution_request_cannot_satisfy_a_discovery_resolver():
    """THE test. Request and expectation agree with each other on every field — they were built
    together. A resolver that only compared them to each other would resolve this happily."""
    request, expectation = _execution()
    resolver = ProxmoxOperationSecretResolver(
        purpose=ResolutionPurpose.proxmox_readonly_discovery, client=_FakeClient()
    )
    with pytest.raises(ResolutionContractViolation) as exc:
        resolver.resolve(request, expectation=expectation, now=NOW)
    assert "wrong_purpose" in exc.value.reason_code


def test_a_self_consistent_discovery_request_cannot_satisfy_an_execution_resolver():
    """And the reverse, which is the direction that would grant apply authority to a read token."""
    request, expectation = _discovery()
    resolver = ProxmoxOperationSecretResolver(
        purpose=ResolutionPurpose.proxmox_provider_execution, client=_FakeClient()
    )
    with pytest.raises(ResolutionContractViolation) as exc:
        resolver.resolve(request, expectation=expectation, now=NOW)
    assert "wrong_purpose" in exc.value.reason_code


def test_the_two_purposes_also_differ_by_contract_version():
    """Two independent reasons to refuse the same mistake: a future edit that relaxed the purpose
    comparison still meets the version comparison."""
    _r1, discovery = _discovery()
    _r2, execution = _execution()
    assert discovery.purpose is not execution.purpose
    assert discovery.contract_version != execution.contract_version


def test_crossing_the_request_and_expectation_between_purposes_is_refused():
    """Not the same as the two tests above: here the PAIR is mismatched, and the field-by-field
    comparison names which binding disagreed."""
    request, _ = _discovery()
    _, expectation = _execution()
    resolver = ProxmoxOperationSecretResolver(
        purpose=ResolutionPurpose.proxmox_provider_execution, client=_FakeClient()
    )
    with pytest.raises(ResolutionContractViolation) as exc:
        resolver.resolve(request, expectation=expectation, now=NOW)
    assert "mismatch" in exc.value.reason_code


def test_both_purposes_are_in_the_supported_catalog_and_are_distinct():
    assert ResolutionPurpose.proxmox_readonly_discovery in SUPPORTED_PURPOSES
    assert ResolutionPurpose.proxmox_provider_execution in SUPPORTED_PURPOSES
    assert (
        ResolutionPurpose.proxmox_readonly_discovery
        is not ResolutionPurpose.proxmox_provider_execution
    )
    names = {p.value for p in ResolutionPurpose}
    for generic in ("proxmox", "proxmox_token", "proxmox_api", "http", "generic"):
        assert generic not in names, generic


def test_a_resolver_for_an_unsupported_purpose_is_not_constructible():
    """Not constructible, rather than constructible and refusing later."""
    with pytest.raises(ResolutionContractViolation, match="unsupported_purpose"):
        ProxmoxOperationSecretResolver(purpose=ResolutionPurpose.readonly_staging_preflight)


# === it resolves, and only from the authoritative reference ======================================


def test_it_resolves_the_matching_purpose_from_the_authoritative_reference():
    request, expectation = _discovery()
    client = _FakeClient()
    resolver = ProxmoxOperationSecretResolver(
        purpose=ResolutionPurpose.proxmox_readonly_discovery, client=client
    )
    material = resolver.resolve(request, expectation=expectation, now=NOW)
    assert isinstance(material, SecretMaterial)
    assert client.reads == [(REF, "openbao")]


def test_the_reference_read_is_the_EXPECTATION_s_not_the_request_s():
    """They were just proved equal; reading the expectation's is what keeps that true if the
    comparison is ever loosened."""
    import inspect
    import pathlib

    source = pathlib.Path(inspect.getfile(ProxmoxOperationSecretResolver)).read_text(
        encoding="utf-8"
    )
    assert "reference = expectation.credential_reference" in source
    assert "request.contract.credential_reference" not in source


@pytest.mark.parametrize("scheme_ref", ["secretref:secp/x", "file:///etc/x", "env:TOKEN", "plain"])
def test_a_reference_scheme_this_resolver_does_not_own_is_refused(scheme_ref):
    """``secretref:`` is valid for the CONTRACT and is not an OpenBao reference. Resolving it here
    would mean this resolver had quietly acquired a second backend."""
    request, expectation = _discovery(ref=scheme_ref)
    resolver = ProxmoxOperationSecretResolver(
        purpose=ResolutionPurpose.proxmox_readonly_discovery, client=_FakeClient()
    )
    with pytest.raises(ResolutionContractViolation, match="scheme_unsupported"):
        resolver.resolve(request, expectation=expectation, now=NOW)


# === fail closed, and leak nothing ===============================================================


def test_the_shipped_state_has_no_client_and_fails_closed():
    request, expectation = _discovery()
    resolver = ProxmoxOperationSecretResolver(purpose=ResolutionPurpose.proxmox_readonly_discovery)
    with pytest.raises(SecretResolutionUnavailable, match="sealed default"):
        resolver.resolve(request, expectation=expectation, now=NOW)


def test_the_binding_is_checked_BEFORE_the_client_is_touched():
    """A resolver that read the reference or the backend first would have acted on
    caller-influenced data before proving the caller was entitled to anything."""
    request, expectation = _execution()  # wrong purpose for this resolver
    client = _FakeClient()
    resolver = ProxmoxOperationSecretResolver(
        purpose=ResolutionPurpose.proxmox_readonly_discovery, client=client
    )
    with pytest.raises(ResolutionContractViolation):
        resolver.resolve(request, expectation=expectation, now=NOW)
    assert client.reads == [], "the backend was contacted for an unauthorized purpose"


def test_a_backend_failure_becomes_a_closed_reason_carrying_no_locator():
    request, expectation = _discovery()
    client = _FakeClient(raises=PlanSecretBackendError("backend_unreachable"))
    resolver = ProxmoxOperationSecretResolver(
        purpose=ResolutionPurpose.proxmox_readonly_discovery, client=client
    )
    with pytest.raises(SecretResolutionUnavailable) as exc:
        resolver.resolve(request, expectation=expectation, now=NOW)
    text = str(exc.value)
    assert REF not in text and TOKEN_VALUE not in text


def test_an_arbitrary_backend_exception_never_surfaces_raw():
    request, expectation = _discovery()
    client = _FakeClient(raises=RuntimeError("https://bao.internal.example/v1/secret/x failed"))
    resolver = ProxmoxOperationSecretResolver(
        purpose=ResolutionPurpose.proxmox_readonly_discovery, client=client
    )
    with pytest.raises(SecretResolutionUnavailable) as exc:
        resolver.resolve(request, expectation=expectation, now=NOW)
    assert "bao.internal.example" not in str(exc.value)


def test_an_empty_secret_is_a_failure_not_a_credential():
    request, expectation = _discovery()
    resolver = ProxmoxOperationSecretResolver(
        purpose=ResolutionPurpose.proxmox_readonly_discovery, client=_FakeClient(secret="")
    )
    with pytest.raises(SecretResolutionUnavailable, match="empty"):
        resolver.resolve(request, expectation=expectation, now=NOW)


def test_the_resolver_is_not_renderable_or_serializable():
    """A picklable resolver is a file naming a backend."""
    resolver = ProxmoxOperationSecretResolver(
        purpose=ResolutionPurpose.proxmox_readonly_discovery, client=_FakeClient()
    )
    assert "redacted" in repr(resolver)
    with pytest.raises(TypeError, match="cannot be serialized"):
        resolver.__getstate__()
    with pytest.raises(TypeError):
        pickle.dumps(resolver)
    assert resolver.__slots__ == ("_purpose", "_client")
    assert not hasattr(resolver, "__dict__")


# === it extends the canonical backend rather than starting a fourth family =======================


def test_it_reuses_the_openbao_client_rather_than_a_new_backend():
    """Three secret-resolver families already exist here; the fourth is the failure mode."""
    import ast
    import inspect
    import pathlib

    tree = ast.parse(
        pathlib.Path(inspect.getfile(ProxmoxOperationSecretResolver)).read_text(encoding="utf-8")
    )
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
    assert "secp_worker.plan_gen.openbao_plan_resolver" in imported
    for banned in ("httpx", "requests", "urllib", "urllib.request", "os", "subprocess", "socket"):
        assert banned not in imported, banned


def test_the_version_is_declared():
    assert PROXMOX_SECRET_RESOLVER_VERSION == "secp.proxmox-operation-secret-resolver/v1"
