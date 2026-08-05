"""Published schema for the derived provider-capability surface.

The old body was ``{milestone, provisioning_enabled, discovery, note}``, where every value was a
literal. Two properties of this replacement are load-bearing:

* **``provisioning_enabled`` does not exist.** It is not corrected to ``true`` — it is removed,
  because the question has three answers (not supported / supported but you are not authorized /
  supported and authorized) and a boolean can carry one. A test asserts the key is absent from the
  response so nothing can start reading it again.
* **``discovery`` may be ``undetermined``.** It is checked against the discovery plugin contract
  rather than asserted, so if that contract gains a mutating method this reports that it can no
  longer make the read-only claim, instead of continuing to make it.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from secp_api.provider_capabilities import CapabilityState


class OperationCapabilityOut(BaseModel):
    """One operator verb and whether this caller can use it."""

    operation: str
    state: CapabilityState
    #: The exact permission this operation requires, so an operator can request the right one
    #: instead of inferring it from the operation's name.
    required_permission: str
    detail: str


class ProviderCapabilityOut(BaseModel):
    """What one provider substrate can do in this build."""

    provider: str
    #: True when the shipped catalog has at least one deployable template for this provider.
    deployable: bool
    lifecycle_operations: list[str] = Field(default_factory=list)
    detail: str


class ProviderCapabilitiesOut(BaseModel):
    """Derived capability. No field here is a constant somebody chose."""

    operations: list[OperationCapabilityOut]
    providers: list[ProviderCapabilityOut]
    #: ``read-only`` only while the discovery plugin contract actually has no mutating method;
    #: ``undetermined`` when that can no longer be established. Never a carried-forward literal.
    discovery: str
    discovery_detail: str
    #: Convenience rollups, DERIVED from ``operations`` on the way out so they cannot disagree with
    #: it. Provided because a client that has to fold the list itself will eventually fold it
    #: differently from the next client.
    authorized_operations: list[str] = Field(default_factory=list)
    unauthorized_operations: list[str] = Field(default_factory=list)
    unsupported_operations: list[str] = Field(default_factory=list)
