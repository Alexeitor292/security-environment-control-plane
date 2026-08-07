"""The production worker-only resolver for the two Proxmox operation credentials.

Until now the only implementation of ``ProxmoxCredentialResolver`` was the sealed default, which
always fails closed. That was correct while no backend existed; it is the reason an authorized
discovery run reaches the credential step and stops. This module is the real one.

IT EXTENDS THE CANONICAL BACKEND RATHER THAN STARTING A FOURTH FAMILY
----------------------------------------------------------------------
This repository already has three secret-resolver families and a standing rule that the fourth is
the failure mode. So the OpenBao read path is NOT re-implemented here: the concrete client, the
scheme boundary, the closed-reason mapping and the "no client means fail closed" default all come
from :mod:`secp_worker.plan_gen.openbao_plan_resolver`. What this adds is the part that is genuinely
different — the Proxmox operation contract, and the purpose separation over it.

WHY TWO PURPOSES AND NOT ONE TOKEN
-----------------------------------
Discovery and provider execution authenticate the SAME API and are nonetheless different
credentials. Discovery needs four audit privileges. Execution needs to create an SDN object, a
bridge, a VM. One shared token would mean every read-only discovery run carried apply authority —
the least-privileged half of the system would be the most privileged thing on the wire, and the
whole point of a privilege-separated discovery token would be gone.

So the resolver is constructed FOR a purpose and refuses anything else. It does not read the
purpose off the request and serve whatever it finds: a resolver that did would make purpose a
property of the caller's input rather than of the resolver, which is not a separation at all.

ORDER OF REFUSAL, AND WHY IT IS THIS ORDER
--------------------------------------------
1. the request/expectation binding, including purpose — before any reference is looked at;
2. the reference scheme — before any client is touched;
3. the client — absent means fail closed, never fall back;
4. the read itself, with every backend failure mapped to a closed, secret-free reason.

Nothing here logs, formats, or returns the secret except as :class:`SecretMaterial`, and no failure
path carries the reference, the locator, the endpoint or the raw backend error.
"""

from __future__ import annotations

from datetime import datetime

from secp_worker.plan_gen.openbao_plan_resolver import (
    PlanSecretBackendClient,
    PlanSecretBackendError,
)
from secp_worker.preflight.secret_resolution import (
    ProxmoxOperationResolutionContract,
    ResolutionContractViolation,
    ResolutionPurpose,
    SecretMaterial,
    SecretResolutionUnavailable,
    TrustedProxmoxResolutionRequest,
    assert_proxmox_resolution_authorized,
)

#: Bound into nothing and signed by nothing — an implementation id so a refusal can be attributed
#: to a known resolver rather than to "the credential path".
PROXMOX_SECRET_RESOLVER_VERSION = "secp.proxmox-operation-secret-resolver/v1"

#: Reference schemes this resolver will read. Deliberately the OpenBao ones only: a ``secretref:``
#: locator is valid for the CONTRACT and is not an OpenBao reference, and resolving it here would
#: mean this resolver had quietly acquired a second backend.
_SUPPORTED_SCHEMES: frozenset[str] = frozenset({"openbao", "vault"})


class ProxmoxOperationSecretResolver:
    """Resolves ONE purpose's credential, from the authoritative reference, just in time.

    ``purpose`` is fixed at construction. The resolver refuses a request for any other purpose even
    when that request is internally consistent — which is the case that matters, because a
    provider-execution request and a provider-execution expectation agree with each other perfectly
    and must still not satisfy a discovery resolver.
    """

    __slots__ = ("_purpose", "_client")

    def __init__(
        self, *, purpose: ResolutionPurpose, client: PlanSecretBackendClient | None = None
    ) -> None:
        if purpose not in {
            ResolutionPurpose.proxmox_readonly_discovery,
            ResolutionPurpose.proxmox_provider_execution,
        }:
            # A resolver for a purpose outside the Proxmox operation pair is not constructible,
            # rather than constructible and refusing later.
            raise ResolutionContractViolation("proxmox_resolver_unsupported_purpose")
        self._purpose = purpose
        self._client = client

    def __repr__(self) -> str:  # never the client, the endpoint or a reference
        return f"ProxmoxOperationSecretResolver(purpose={self._purpose.value!r}, <redacted>)"

    __str__ = __repr__

    def __getstate__(self):  # noqa: ANN201 - a picklable resolver is a file naming a backend
        raise TypeError("ProxmoxOperationSecretResolver cannot be serialized")

    def __reduce__(self):  # noqa: ANN201
        raise TypeError("ProxmoxOperationSecretResolver cannot be pickled")

    @property
    def purpose(self) -> ResolutionPurpose:
        return self._purpose

    def resolve(
        self,
        request: TrustedProxmoxResolutionRequest,
        *,
        expectation: ProxmoxOperationResolutionContract,
        now: datetime,
    ) -> SecretMaterial:
        # 1. Binding first, purpose included, BEFORE any reference is looked at. A resolver that
        #    read the reference first would have touched caller-influenced data before proving the
        #    caller was entitled to anything.
        assert_proxmox_resolution_authorized(request, expectation, required_purpose=self._purpose)

        # 2. The AUTHORITATIVE reference, from the expectation — never the candidate request's.
        #    They were just proved equal; taking the expectation's is what keeps that true if the
        #    comparison is ever loosened.
        reference = expectation.credential_reference
        scheme = _scheme_of(reference)
        if scheme not in _SUPPORTED_SCHEMES:
            raise ResolutionContractViolation("proxmox_reference_scheme_unsupported")

        # 3. No client is the SHIPPED state, and it fails closed rather than falling back.
        if self._client is None:
            raise SecretResolutionUnavailable(
                f"no {self._purpose.value} credential backend is configured (sealed default)"
            )

        # 4. Just-in-time read. Every backend failure becomes a closed, secret-free reason: the raw
        #    error, the response body and the locator never surface.
        try:
            secret = self._client.read_plan_secret(
                reference=reference.reveal_reference(), scheme=scheme, now=now
            )
        except PlanSecretBackendError as exc:
            raise SecretResolutionUnavailable(
                f"{self._purpose.value} resolution refused: {exc.reason_code}"
            ) from exc
        except Exception:  # defensive: never surface a raw backend error
            raise SecretResolutionUnavailable(f"{self._purpose.value} resolution failed") from None
        if not (isinstance(secret, str) and secret):
            raise SecretResolutionUnavailable(f"{self._purpose.value} resolution empty")
        return SecretMaterial(secret)


def _scheme_of(reference: object) -> str:
    """The reference's scheme, without revealing the locator.

    ``TrustedCredentialReference`` exposes the reference only through ``reveal_reference``; the
    scheme is the part before the first colon and is not sensitive on its own.
    """
    getter = getattr(reference, "scheme", None)
    if isinstance(getter, str):
        return getter
    try:
        raw = reference.reveal_reference()  # type: ignore[attr-defined]
    except Exception:
        return ""
    return raw.split(":", 1)[0] if ":" in raw else ""
