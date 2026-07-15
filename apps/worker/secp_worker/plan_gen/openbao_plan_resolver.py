"""Concrete OpenBao plan-execution secret resolver (B1B-PR5B, ADR-022 §10) — DISABLED BY DEFAULT.

This is the reviewed, in-repository CONCRETE implementation of the
:class:`~secp_worker.plan_gen.plan_secret_resolution.WorkerPlanSecretResolver` seam. It is the
plan-execution analogue of the read-only-preflight
:class:`~secp_worker.preflight.backends.openbao_resolver.OpenBaoWorkerSecretResolver`, and it is
SEPARATE from it: a read-only-preflight resolver, a plan-secret readiness self-test, and this
plan-execution resolver never share authority.

Safety posture (identical to the read-only-preflight OpenBao adapter):

* It is never imported by the API or frontend, and never wired into the shipped runtime — the
shipped
  composition keeps :class:`SealedPlanSecretResolver`, so ordinary plan-only execution refuses at
  the
  seal before this class is even constructed.
* It constructs NO backend client and contacts NOTHING under default wiring: with no injected client
  (the default) it enforces the full plan-execution contract and then FAILS CLOSED.
* It re-enforces the plan-execution contract — the capability, the candidate request, and the
  capability's own contract are ALL verified against the authoritative expectation (per-fact) BEFORE
  any client is touched — exactly as the sealed resolver does.
* It resolves ONLY the AUTHORITATIVE opaque reference (from the expectation, never the candidate
  request), and only for the ``openbao`` / ``vault`` reference schemes; a ``secretref`` reference is
  refused (this adapter speaks only OpenBao). It returns a short-lived, opaque
  :class:`~secp_worker.preflight.secret_resolution.SecretMaterial` only when a client is EXPLICITLY
  injected (tests / a future out-of-band-granted activation).

No OpenBao instance, endpoint, host, port, token, policy, mount, unseal material, or credential is
present here or anywhere in the repository. A future activation must inject a production transport +
a production worker identity + an approved resolver activation out of band; nothing here enables
one.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from secp_worker.hardened_http import HardenedTransportError
from secp_worker.plan_gen.plan_secret_resolution import (
    PlanExecutionResolutionContract,
    PlanExecutionResolverCapability,
    PlanResolutionContractViolation,
    PlanSecretResolutionUnavailable,
    TrustedPlanResolutionRequest,
    assert_plan_resolution_authorized,
)
from secp_worker.preflight.secret_resolution import SecretMaterial
from secp_worker.reviewed_identity import (
    ReviewedIdentityError,
    assert_reviewed_object,
    declaration_digest,
    object_identity,
)

# The concrete OpenBao plan-execution resolver contract label. A plain, secret-free version marker —
# it carries no endpoint, mount, or backend detail. A future incompatible change bumps + re-reviews.
OPENBAO_PLAN_RESOLVER_CONTRACT_VERSION = "secp-002b-1b-pr5b/openbao-plan-resolver/v1"
# The reviewed concrete-implementation registration of the client layer.
OPENBAO_PLAN_CLIENT_REGISTRATION = "secp-002b-1b-pr5b/openbao-plan-client/v1"

# The exact reviewed identities the controlled-live composition is bound to (module.qualname — the
# un-forgeable anchor). The transport identity/registration are STRING-PINNED here (rather than
# imported) to keep this transport-free ``plan_gen`` module fully decoupled from the top-level
# ``httpx`` transport; ``test_concrete_transports`` cross-checks that they equal the transport's own
# constants, so drift is caught.
_RESOLVER_IDENTITY = "secp_worker.plan_gen.openbao_plan_resolver.OpenBaoPlanSecretResolver"
_CLIENT_IDENTITY = "secp_worker.plan_gen.openbao_plan_resolver.ConcreteOpenBaoPlanSecretClient"
_TRANSPORT_IDENTITY = "secp_worker.openbao_plan_http_transport.OpenBaoHttpTransport"
_TRANSPORT_REGISTRATION = "secp-002b-1b-pr5b/openbao-plan-http-transport/v1"


def openbao_plan_resolver_digest() -> str:
    """The stable digest of the reviewed concrete OpenBao plan resolver implementation identity."""
    return declaration_digest(OPENBAO_PLAN_RESOLVER_CONTRACT_VERSION)


def openbao_plan_client_digest() -> str:
    """The stable digest of the reviewed concrete OpenBao plan client implementation identity."""
    return declaration_digest(OPENBAO_PLAN_CLIENT_REGISTRATION)


# This OpenBao adapter speaks ONLY the ``openbao`` / ``vault`` reference schemes. The plan-execution
# contract additionally permits ``secretref``; a ``secretref`` reference is refused here (a
# different
# reviewed adapter would resolve it) so a mis-scoped reference can never be read through OpenBao.
_OPENBAO_SCHEMES = frozenset({"openbao", "vault"})

# The opaque logical-path grammar for a plan-secret locator: slash-delimited segments of safe
# characters, no leading slash, no empty segment, no host / scheme / port / query / whitespace. It
# names WHERE a secret lives, never a secret, endpoint, host, port, or token. It is validated, never
# normalized or rewritten — exact reference equality is part of the plan-execution binding contract.
_OPAQUE_LOCATOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9._-]+)*$")
_DOT_SEGMENTS = frozenset({".", ".."})


class PlanSecretBackendError(Exception):
    """Fail-closed client error. Carries ONLY a closed reason code (never a value or response)."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"plan-secret backend refused: {reason_code}")
        self.reason_code = reason_code


@runtime_checkable
class PlanSecretBackendClient(Protocol):
    """Narrow injected client seam for a FUTURE OpenBao plan-secret read.

    Only tests / a granted activation provide one; the shipped default is ``None`` (no client
    constructed, nothing contacted). ``read_plan_secret`` resolves the exact authoritative opaque
    reference and returns the backend secret string, or raises :class:`PlanSecretBackendError`.
    """

    def read_plan_secret(self, *, reference: str, scheme: str, now: datetime) -> str: ...


class OpenBaoPlanSecretResolver:
    """A ``WorkerPlanSecretResolver`` backed by OpenBao — sealed by default.

    Ordering (each step must pass before the next): capability type → per-fact contract gate on the
    request AND the capability's own contract against the authoritative expectation → OpenBao scheme
    boundary → backend-client boundary (no client → fail closed). It resolves the AUTHORITATIVE
    reference, never the candidate request reference.
    """

    IMPLEMENTATION_ID = OPENBAO_PLAN_RESOLVER_CONTRACT_VERSION

    def __init__(self, *, client: PlanSecretBackendClient | None = None) -> None:
        self._client = client
        # A resolver is "production bound" ONLY when it holds the EXACT concrete client over the
        # EXACT
        # concrete OpenBao HTTPS transport. A sealed/absent client, a fake client, or a client over
        # a
        # sealed/fake transport is not bound (the controlled-live composition verification refuses
        # it).
        self._production_bound = _client_is_production_bound(client)

    @property
    def contract_version(self) -> str:
        return OPENBAO_PLAN_RESOLVER_CONTRACT_VERSION

    def resolve(
        self,
        request: TrustedPlanResolutionRequest,
        *,
        expectation: PlanExecutionResolutionContract,
        capability: PlanExecutionResolverCapability,
        now: datetime,
    ) -> SecretMaterial:
        # 1. Capability type — a foreign object is never a capability (defence in depth).
        if not isinstance(capability, PlanExecutionResolverCapability):
            raise PlanResolutionContractViolation("resolver_capability_invalid")

        # 2. Per-fact contract gate. The request and the capability's OWN contract are INDEPENDENT
        # objects; both must agree with the authoritative expectation on every bound fact (purpose,
        #    org, target, manifest, dossier, credential binding, dedicated-operation source, worker
        # identity, resolver contract, fingerprint, lease/attempt, reference, expiry). Identical to
        #    the sealed resolver — enforced BEFORE any backend client is touched.
        assert_plan_resolution_authorized(request.contract, expectation, now=now)
        assert_plan_resolution_authorized(capability.contract, expectation, now=now)

        # 3. OpenBao scheme boundary. Resolve the AUTHORITATIVE reference (from the expectation,
        # never
        #    the candidate request). ``secretref`` — valid for the contract but not an OpenBao
        #    reference — is refused here with a closed reason code.
        reference = expectation.credential_reference
        scheme = reference.scheme
        if scheme not in _OPENBAO_SCHEMES:
            raise PlanResolutionContractViolation("reference_scheme_unsupported")

        # 4. Backend-client boundary. No client in shipped/default wiring → fail closed. This is the
        #    only point a real backend would ever be contacted, and only a test / granted activation
        #    injects a client.
        if self._client is None:
            raise PlanSecretResolutionUnavailable(
                "no production plan-execution OpenBao client is configured (sealed)"
            )

        # 5. Resolve just-in-time into opaque, short-lived material. Any backend failure maps to a
        #    closed, secret-free reason — the raw error, response body, and locator never surface.
        try:
            secret = self._client.read_plan_secret(
                reference=reference.reveal_reference(), scheme=scheme, now=now
            )
        except PlanSecretBackendError as exc:
            raise PlanSecretResolutionUnavailable(
                f"plan-execution OpenBao resolution refused: {exc.reason_code}"
            ) from exc
        except Exception as exc:  # defensive: never surface a raw backend error
            raise PlanSecretResolutionUnavailable(
                "plan-execution OpenBao resolution failed"
            ) from exc
        if not (isinstance(secret, str) and secret):
            raise PlanSecretResolutionUnavailable("plan-execution OpenBao resolution empty")
        return SecretMaterial(secret)


# --- the concrete client over an injected transport (the "concrete HTTP" layer) ------------------


@runtime_checkable
class PlanSecretBackendTransport(Protocol):
    """Injected, mockable OpenBao transport. A real implementation (deployment-only) enforces
    HTTPS/TLS verification, no redirects, ``trust_env=False``, and a bounded timeout; tests inject a
    fake. ``read`` returns the backend payload for the exact opaque locator (no secret logged)."""

    def read(self, *, locator: str, now: datetime) -> Mapping[str, Any]: ...


class SealedPlanSecretBackendTransport:
    """The shipped default: NO transport. ``read`` refuses — no network, no endpoint, no token."""

    def read(self, *, locator: str, now: datetime) -> Mapping[str, Any]:
        raise PlanSecretBackendError("plan_secret_transport_sealed")


def _valid_opaque_locator(locator: str) -> bool:
    """Structural charset/shape check + explicit rejection of any ``.``/``..`` path segment."""
    if not _OPAQUE_LOCATOR.match(locator):
        return False
    return all(segment not in _DOT_SEGMENTS for segment in locator.split("/"))


def _extract_locator(reference: str, scheme: str) -> str:
    """Return the opaque locator of a valid ``openbao`` / ``vault`` reference, else fail closed.

    The reference is split exactly as ``derive_reference_scheme`` splits it (on ``://`` or ``:``),
    the
    scheme prefix must equal the passed scheme, and the locator must satisfy the opaque grammar. No
    endpoint substitution, dynamic host, or uncontrolled path construction ever occurs.
    """
    if not (isinstance(reference, str) and reference.strip()):
        raise PlanSecretBackendError("blank_reference")
    if "://" in reference:
        head, locator = reference.split("://", 1)
    else:
        head, _, locator = reference.partition(":")
    if head.strip().lower() != scheme or scheme not in _OPENBAO_SCHEMES:
        raise PlanSecretBackendError("unsupported_reference_scheme")
    if not _valid_opaque_locator(locator):
        raise PlanSecretBackendError("malformed_reference")
    return locator


class ConcreteOpenBaoPlanSecretClient:
    """Implements the ``PlanSecretBackendClient`` seam (``read_plan_secret``) over an injected
    transport.

    NOT a shipped default — supplied only to a reviewed deployment-local plan-execution composition.
    It resolves ONLY the exact authoritative re-verified reference, maps errors to closed codes, and
    returns opaque secret text to the resolver (which wraps it as short-lived ``SecretMaterial``);
    it
    logs / persists / renders nothing.
    """

    IMPLEMENTATION_ID = OPENBAO_PLAN_CLIENT_REGISTRATION

    def __init__(self, *, transport: PlanSecretBackendTransport) -> None:
        self._transport = transport

    def read_plan_secret(self, *, reference: str, scheme: str, now: datetime) -> str:
        locator = _extract_locator(reference, scheme)
        try:
            response = self._transport.read(locator=locator, now=now)
        except PlanSecretBackendError:
            raise
        except HardenedTransportError as exc:
            # Preserve the transport's CLOSED reason code (never the raw error / host / body).
            raise PlanSecretBackendError(exc.reason_code) from None
        except Exception as exc:  # closed mapping — never the raw backend error
            raise PlanSecretBackendError("backend_unreachable") from exc
        secret = _extract_secret(response)
        if not secret:
            raise PlanSecretBackendError("reference_unknown")
        return secret


def _extract_secret(response: Mapping[str, Any]) -> str:
    """Extract the secret string from a closed backend response shape. Never logs the value or any
    other field; a missing/unknown shape yields no secret (fail closed upstream)."""
    if not isinstance(response, Mapping):
        return ""
    value = response.get("value")
    return value if isinstance(value, str) and value else ""


# --- reviewed concrete-chain binding (controlled-live composition verification) -------------------


def _client_is_production_bound(client: object) -> bool:
    """True only when ``client`` is the concrete client over the concrete OpenBao transport.

    Walks the reviewed chain by un-forgeable ``module.qualname`` identity + declared registration: a
    ``None``/sealed/fake client, or the concrete client over a sealed/fake/foreign transport, is not
    bound. No object is echoed; this performs no I/O.
    """
    if client is None:
        return False
    if object_identity(client) != _CLIENT_IDENTITY:
        return False
    if getattr(type(client), "IMPLEMENTATION_ID", None) != OPENBAO_PLAN_CLIENT_REGISTRATION:
        return False
    transport = getattr(client, "_transport", None)
    if transport is None:
        return False
    if object_identity(transport) != _TRANSPORT_IDENTITY:
        return False
    return getattr(type(transport), "IMPLEMENTATION_ID", None) == _TRANSPORT_REGISTRATION


def assert_concrete_openbao_plan_resolver(resolver: object) -> None:
    """Refuse unless ``resolver`` is the reviewed concrete OpenBao plan resolver, production-bound.

    A duck-typed resolver, a foreign subclass, a forged registration, the sealed resolver, or the
    concrete resolver holding a sealed/fake/foreign client or transport is refused with a closed
    reason
    code (:class:`~secp_worker.reviewed_identity.ReviewedIdentityError`). Used by the
    controlled-live
    plan-execution composition verification — it is never reached on the shipped sealed path.
    """
    assert_reviewed_object(
        resolver,
        expected_identity=_RESOLVER_IDENTITY,
        expected_registration=OPENBAO_PLAN_RESOLVER_CONTRACT_VERSION,
        reason_code="plan_resolver_not_concrete",
    )
    if not getattr(resolver, "_production_bound", False):
        raise ReviewedIdentityError("plan_resolver_not_production_bound")
