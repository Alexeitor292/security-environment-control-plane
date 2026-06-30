"""Discovery extension to the plugin contract (v1, non-breaking) — SECP-002A.

Adds an OPTIONAL discovery capability so a provider plugin can return a read-only
inventory snapshot, without forcing existing plugins (e.g. the Simulator) to
implement it. See ADR-003 (addendum) and ADR-010.

Secrets never appear in these models. A resolved credential is passed transiently
to ``discover`` via :class:`ProviderCredential`, whose repr is redacted, and is
never persisted or serialized into a snapshot/audit/response.
"""

from __future__ import annotations

from typing import NoReturn, Protocol, SupportsIndex, runtime_checkable

from pydantic import BaseModel, Field


class UnsupportedCapabilityError(Exception):
    """Raised by a plugin for a capability it exposes structurally but does not
    support. Must be raised BEFORE any provider request is attempted."""

    def __init__(self, plugin: str, capability: str):
        self.plugin = plugin
        self.capability = capability
        super().__init__(f"plugin '{plugin}' does not support capability '{capability}'")


class ProviderCredential:
    """Transient opaque credential passed to ``discover`` at call time only.

    This is intentionally not a Pydantic model and has no public secret field, no
    ``__dict__``, no iterator, and no pickle support. Worker/plugin code must use
    the narrow ``reveal_secret()`` accessor at the last possible moment.
    """

    __slots__ = ("__secret",)

    def __init__(self, secret: str) -> None:
        if not isinstance(secret, str) or not secret:
            raise ValueError("provider credential secret must be a non-empty string")
        self.__secret = secret

    @classmethod
    def from_secret(cls, secret: str) -> ProviderCredential:
        return cls(secret)

    def reveal_secret(self) -> str:
        """Return the secret for worker/plugin transport code only."""
        return self.__secret

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "ProviderCredential(secret='***redacted***')"

    __str__ = __repr__

    def __getstate__(self) -> NoReturn:
        raise TypeError("ProviderCredential cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError("ProviderCredential cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("ProviderCredential cannot be pickled")


class DiscoveryRequest(BaseModel):
    """A request to discover an execution target's inventory (read-only).

    Carries only non-secret configuration. The secret is resolved separately by
    the worker and handed to ``discover`` as a :class:`ProviderCredential`.
    """

    target_id: str
    plugin_name: str
    config: dict = Field(default_factory=dict)
    scope: dict | None = None
    correlation_id: str | None = None


class DiscoveredResource(BaseModel):
    """A normalized, provider-neutral inventory resource. No secrets."""

    resource_type: str  # e.g. node | vm | container | storage | network
    provider_external_id: str
    display_name: str
    parent_ref: str | None = None
    status: str = "unknown"
    attributes: dict = Field(default_factory=dict)


class DiscoveryResult(BaseModel):
    ok: bool
    resources: list[DiscoveredResource] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class TargetValidationResult(BaseModel):
    ok: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    # Non-secret, sanitized echo of how the target was understood (e.g. base_url).
    detail: dict = Field(default_factory=dict)


@runtime_checkable
class DiscoveryProtocol(Protocol):
    """Optional capability: provider inventory discovery (read-only).

    A plugin implementing this advertises ``Capability.discover``. The control
    plane checks capability support before dispatching discovery.
    """

    def validate_target(
        self, config: dict, scope_policy: dict | None = None
    ) -> TargetValidationResult: ...

    def discover(
        self, request: DiscoveryRequest, credential: ProviderCredential
    ) -> DiscoveryResult: ...
