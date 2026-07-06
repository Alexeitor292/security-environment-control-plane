"""Typed, provider-visible resource locators (SECP-B4 corrective).

A locator is the EXACT provider-visible identity of one deployment resource (e.g. an enrolled node
name + an allocated VMID, or an owned bridge interface name). Every locator field is a discovered or
generated value validated to a safe token — there is NO hardcoded ``pve``, VMID ``9000``,
``secpbr0``,
endpoint, or fallback here. Locator field values are supplied ONLY by the real provider discovery
backend (a sealed, fail-closed seam until integration-tested against the disposable staging target);
this module just gives them a typed, validated shape so a mutation route/body can be derived from an
exact object rather than a hardcoded string. It performs no I/O and contacts nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# A safe provider token: letters/digits/dot/underscore/hyphen only (no path, shell, or host char).
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# A safe Proxmox userid is ``name@realm`` where both parts are safe tokens.
_SAFE_USERID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}@[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")


class LocatorError(ValueError):
    """Raised for a malformed/unsafe locator field. Never echoes the raw offending value."""


def _token(value: object, field: str) -> str:
    if not (isinstance(value, str) and _SAFE_TOKEN.match(value)):
        raise LocatorError(f"unsafe_locator_field:{field}")
    return value


def _userid(value: object) -> str:
    if not (isinstance(value, str) and _SAFE_USERID.match(value)):
        raise LocatorError("unsafe_locator_field:userid")
    return value


def _vmid(value: object) -> int:
    # A discovered/allocated VMID within the bounded Proxmox range. Never a hardcoded default.
    if not isinstance(value, int) or isinstance(value, bool) or not (100 <= value <= 999_999_999):
        raise LocatorError("invalid_vmid")
    return value


@dataclass(frozen=True)
class BridgeLocator:
    """An owned Linux/SDN bridge on a discovered enrolled node."""

    node: str
    iface: str

    def __post_init__(self) -> None:
        _token(self.node, "node")
        _token(self.iface, "iface")

    def observe_key(self) -> str:
        return f"bridge:{self.node}:{self.iface}"


@dataclass(frozen=True)
class FirewallGroupLocator:
    """An exact SECP-owned cluster firewall GROUP (a new named object; never existing policy)."""

    group: str

    def __post_init__(self) -> None:
        _token(self.group, "group")

    def observe_key(self) -> str:
        return f"firewall-group:{self.group}"


@dataclass(frozen=True)
class GuestLocator:
    """A guest (VM) at a discovered/allocated VMID on a discovered enrolled node."""

    node: str
    vmid: int

    def __post_init__(self) -> None:
        _token(self.node, "node")
        _vmid(self.vmid)

    def observe_key(self) -> str:
        return f"guest:{self.node}:{self.vmid}"


@dataclass(frozen=True)
class ServiceIdentityLocator:
    """A Proxmox access user (the scoped service identity)."""

    userid: str

    def __post_init__(self) -> None:
        _userid(self.userid)

    def observe_key(self) -> str:
        return f"user:{self.userid}"


@dataclass(frozen=True)
class ScopedTokenLocator:
    """A Proxmox API token owned by the service identity."""

    userid: str
    tokenid: str

    def __post_init__(self) -> None:
        _userid(self.userid)
        _token(self.tokenid, "tokenid")

    def observe_key(self) -> str:
        return f"token:{self.userid}:{self.tokenid}"


@dataclass(frozen=True)
class ArtifactStageLocator:
    """An owned artifact-staging area on discovered storage."""

    node: str
    storage: str

    def __post_init__(self) -> None:
        _token(self.node, "node")
        _token(self.storage, "storage")

    def observe_key(self) -> str:
        return f"artifact-stage:{self.node}:{self.storage}"


@dataclass(frozen=True)
class OpenBaoCredentialLocator:
    """An owned scoped credential held in OpenBao (identified by its opaque path label)."""

    credential_ref: str

    def __post_init__(self) -> None:
        _token(self.credential_ref, "credential_ref")

    def observe_key(self) -> str:
        return f"openbao-credential:{self.credential_ref}"


ResourceLocator = (
    BridgeLocator
    | FirewallGroupLocator
    | GuestLocator
    | ServiceIdentityLocator
    | ScopedTokenLocator
    | ArtifactStageLocator
    | OpenBaoCredentialLocator
)

# Registry for durable (de)serialization of the exact observed locator (stored per resource record
# so
# rollback/teardown can fresh-read the same object). Keyed by a stable type discriminator.
_LOCATOR_TYPES: dict[str, type] = {
    "bridge": BridgeLocator,
    "firewall_group": FirewallGroupLocator,
    "guest": GuestLocator,
    "service_identity": ServiceIdentityLocator,
    "scoped_token": ScopedTokenLocator,
    "artifact_stage": ArtifactStageLocator,
    "openbao_credential": OpenBaoCredentialLocator,
}
_LOCATOR_DISCRIMINATOR: dict[type, str] = {v: k for k, v in _LOCATOR_TYPES.items()}


def locator_to_dict(locator: ResourceLocator) -> dict:
    """Serialize the exact observed locator (with a stable type discriminator) for durable
    storage."""
    disc = _LOCATOR_DISCRIMINATOR.get(type(locator))
    if disc is None:
        raise LocatorError("unknown_locator_type")
    return {"type": disc, **{k: getattr(locator, k) for k in locator.__dataclass_fields__}}


def locator_from_dict(data: object) -> ResourceLocator:
    """Rebuild the exact typed locator from durable storage. Fails closed on a malformed record."""
    if not isinstance(data, dict) or "type" not in data:
        raise LocatorError("malformed_locator_record")
    cls = _LOCATOR_TYPES.get(str(data["type"]))
    if cls is None:
        raise LocatorError("unknown_locator_type")
    field_names = cls.__dataclass_fields__  # type: ignore[attr-defined]
    fields = {k: data[k] for k in field_names if k in data}
    return cls(**fields)  # __post_init__ re-validates every field
