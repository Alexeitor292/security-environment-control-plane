"""Worker-only OpenBao secret-resolution adapter (SECP-B2-4) — DISABLED BY DEFAULT.

OpenBao is an implementation detail **behind** the existing ``WorkerSecretResolver`` seam. This
adapter:

* is never imported by the API or frontend (architecture guardrails enforce this);
* is never wired into shipped runtime (the shipped default stays ``SealedSecretResolver``);
* constructs **no** backend client and contacts nothing under default wiring — it fails closed;
* independently re-loads + re-verifies the authoritative records at resolution time (a
  ``TrustedResolutionRequest`` / passed ``expectation`` is never trusted as authorization proof);
* enforces the three-way credential-reference binding **before** any client is touched;
* returns an opaque, short-lived :class:`SecretMaterial` only when a client is explicitly injected
  (tests / a future out-of-band-granted activation). No successful resolution can occur in shipped
  runtime, and no secret/reference is ever logged, serialized, persisted, audited, or rendered.

No OpenBao instance, endpoint, host, port, token, policy, mount, unseal material, or worker
credential is present here or anywhere in the repository. A future activation must satisfy the full
SECP-B2-2 resolver activation evidence package and inject a production client + reverifier + a
production worker identity + an approved activation gate out of band.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from secp_api.secret_refs import InvalidSecretRefError, parse_secret_ref

from secp_worker.preflight.reverify import ReverifiedAuthority
from secp_worker.preflight.secret_resolution import (
    ResolutionContract,
    ResolutionContractViolation,
    SecretMaterial,
    SecretResolutionError,
    SecretResolutionUnavailable,
    TrustedCredentialReference,
    TrustedResolutionRequest,
    assert_resolution_authorized,
)

# Pinned resolver-adapter contract version. A future incompatible change must bump this and be
# re-reviewed. It is a plain label — it carries no endpoint, secret, or backend detail.
RESOLVER_ADAPTER_CONTRACT_VERSION = "secp-b2-4/openbao-worker-resolver/v1"


@dataclass(frozen=True)
class ResolverSelfTestResult:
    """A closed, secret-free self-test result. Carries no secret, reference, endpoint, or value."""

    ok: bool
    reason_code: str


@runtime_checkable
class ResolverSelfTest(Protocol):
    """Worker-only seam that a future live self-test implements to prove backend liveness + worker
    authentication WITHOUT resolving, returning, or revealing any secret or reference."""

    def run(self, *, now: datetime) -> ResolverSelfTestResult: ...


class SealedResolverSelfTest:
    """The shipped default self-test: sealed. Returns a closed, secret-free result and does no I/O.

    It constructs no client, reads no environment/host/network, and reveals nothing.
    """

    def run(self, *, now: datetime) -> ResolverSelfTestResult:
        return ResolverSelfTestResult(ok=False, reason_code="resolver_self_test_sealed")


@runtime_checkable
class AuthoritativeReverifier(Protocol):
    """Re-loads + re-verifies authoritative records at resolution time, returning the authoritative
    contract + references. Injected worker-only (a DB-backed reverifier); never caller-supplied."""

    def reverify(self, contract: ResolutionContract, *, now: datetime) -> ReverifiedAuthority: ...


@runtime_checkable
class OpenBaoHttpClient(Protocol):
    """Narrow injected client seam for a FUTURE OpenBao read. Only tests / a granted activation
    provide one; the shipped default is ``None`` (no client constructed, nothing contacted)."""

    def read_secret(self, *, reference: str, now: datetime) -> str: ...


def _references_bind_three_ways(
    request_ref: TrustedCredentialReference,
    target_ref: TrustedCredentialReference,
    binding_ref: TrustedCredentialReference,
) -> bool:
    """Constant-time three-way equality of the opaque reference (never logged/rendered)."""
    a = request_ref.reveal_reference()
    b = target_ref.reveal_reference()
    c = binding_ref.reveal_reference()
    if not (a and b and c):
        return False
    return hmac.compare_digest(a, b) and hmac.compare_digest(b, c)


def _is_supported_vault_reference(reference: str) -> bool:
    """True only for a syntactically valid ``vault:`` reference. Syntax-only; never resolves.

    Blank/malformed/non-``vault`` references (e.g. the dev ``env:`` scheme) return False. The
    reference value is never normalized, rewritten, or logged.
    """
    if not (isinstance(reference, str) and reference.strip()):
        return False
    try:
        scheme, _locator = parse_secret_ref(reference)
    except InvalidSecretRefError:
        return False
    return scheme == "vault"


class OpenBaoWorkerSecretResolver:
    """A ``WorkerSecretResolver`` backed by OpenBao — sealed by default.

    Ordering (each step must pass before the next): independent authoritative re-verification →
    per-field contract gate against the RE-DERIVED authoritative contract (not the passed
    ``expectation``) → three-way credential-reference binding → backend-client boundary. With no
    injected reverifier or client (the default), it fails closed before contacting anything.
    """

    def __init__(
        self,
        *,
        reverifier: AuthoritativeReverifier | None = None,
        http_client: OpenBaoHttpClient | None = None,
        self_test: ResolverSelfTest | None = None,
    ) -> None:
        self._reverifier = reverifier
        self._client = http_client
        self._self_test: ResolverSelfTest = self_test or SealedResolverSelfTest()

    @property
    def contract_version(self) -> str:
        return RESOLVER_ADAPTER_CONTRACT_VERSION

    def self_test(self, *, now: datetime) -> ResolverSelfTestResult:
        """Run the injected self-test (sealed by default). Reveals no secret or reference."""
        return self._self_test.run(now=now)

    def resolve(
        self,
        request: TrustedResolutionRequest,
        *,
        expectation: ResolutionContract,
        now: datetime,
    ) -> SecretMaterial:
        # 1. Independent authoritative re-verification. The request object and the passed
        #    `expectation` are NEVER trusted as authorization proof — authority is re-derived from
        #    the worker's authoritative records at resolution time. No reverifier -> fail closed.
        if self._reverifier is None:
            raise SecretResolutionUnavailable("authoritative re-verifier is not configured")
        try:
            authority = self._reverifier.reverify(request.contract, now=now)
        except SecretResolutionError:
            raise
        except Exception as exc:  # defensive: never surface internals; fail closed
            raise SecretResolutionUnavailable("authoritative re-verification failed") from exc

        # 2. Per-field contract gate against the RE-DERIVED authoritative contract.
        assert_resolution_authorized(request.contract, authority.contract, now=now)

        # 3. Three-way credential-reference binding BEFORE any backend client is touched.
        if not _references_bind_three_ways(
            request.contract.credential_reference,
            authority.target_credential_reference,
            authority.binding_credential_reference,
        ):
            raise ResolutionContractViolation("credential_reference_mismatch")

        # 4. Scheme boundary: this OpenBao adapter resolves ONLY `vault:` references. The
        #    AUTHORITATIVE target reference must be a valid vault reference; a non-vault (e.g. the
        #    dev `env:` scheme), malformed, or blank reference is refused with a closed, secret-free
        #    reason code BEFORE the client is invoked. The reference is never normalized or logged.
        authoritative_reference = authority.target_credential_reference.reveal_reference()
        if not _is_supported_vault_reference(authoritative_reference):
            raise ResolutionContractViolation("unsupported_reference_scheme")

        # 5. Backend-client boundary. No client in shipped/default wiring -> fail closed. This is
        #    the only point a real backend would ever be contacted, and only a test / granted
        #    activation injects a client. No successful resolution can occur in shipped runtime.
        if self._client is None:
            raise SecretResolutionUnavailable("openbao client is not configured (sealed)")

        # 6. Resolve just-in-time into opaque, short-lived material (test / granted activation),
        #    using the AUTHORITATIVE target reference (not the candidate request reference).
        secret = self._client.read_secret(reference=authoritative_reference, now=now)
        return SecretMaterial(secret)
