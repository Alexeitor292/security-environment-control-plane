"""What this build can actually do, DERIVED — never declared.

WHAT WAS HERE BEFORE, AND WHY IT HAD TO GO
--------------------------------------------
``GET /providers/capabilities`` returned a hardcoded module-level constant::

    PROVISIONING_ENABLED = False
    ...
    "provisioning_enabled": PROVISIONING_ENABLED,
    "discovery": "read-only",
    "note": "Proxmox provisioning is deferred to SECP-002B. Discovery is read-only."

with the docstring "Tells the UI that provisioning is NOT enabled". Provisioning is not
deferred: #105-#110 shipped desired-state compilation, plan generation, apply authorization,
observed verification, destroy authorization and the residue proof, and this slice added the
operator command surface on top. The endpoint had been reporting a false claim for six merges,
and its stated purpose was to make that claim to operators.

A capability endpoint that reads a constant is a RESTATEMENT. It cannot notice that the
capability changed, which is the only thing it exists to do. So every value below is derived from
the live modules that implement the capability, and the exhaustiveness test enumerates the
operation set from those same modules rather than from a list kept here.

THREE STATES, BECAUSE "DISABLED" WAS CONFLATING THREE
-------------------------------------------------------
``provisioning_enabled: false`` meant, indistinguishably: *this build cannot do it*, *it can but
you may not*, and *it can but not against this target*. Those lead to three different actions —
upgrade, get a permission, pick another target — so they are three values here, plus
``undetermined`` for anything this endpoint genuinely cannot settle.

Under-claiming is not the safe direction. An operator who is told a capability is absent when it is
present will not look for the authorization that is actually missing, and an operator told
something is "read-only" when it is not may run it against production.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from secp_api.auth import Principal
from secp_api.enums import Permission
from secp_api.range_enums import RangeOperationKind
from secp_api.range_scenarios import KNOWN_PROVIDERS
from secp_api.services import proxmox_commands, proxmox_lifecycle


class CapabilityState(str, Enum):
    """Whether this build can do something, and whether this caller may.

    ``supported_unauthorized`` and ``not_supported`` were the same value before, and they are the
    two an operator most needs to tell apart: one is fixed by granting a permission, the other
    cannot be fixed at all in this build.
    """

    #: No code path in this build implements it. A definite answer, not a missing check.
    not_supported = "not_supported"
    #: Implemented, but this principal does not hold the permission it requires.
    supported_unauthorized = "supported_unauthorized"
    #: Implemented, and this principal holds the required permission. NOT a statement that any
    #: particular target is ready — per-target readiness is answered by the range scenario and the
    #: authorization surfaces, which is where a target is actually in scope.
    supported_authorized = "supported_authorized"
    #: Cannot be settled here. Never rendered as a reassuring default: unknown is not permission.
    undetermined = "undetermined"


@dataclass(frozen=True)
class OperationCapability:
    """One operator verb, its state, and the permission that would grant it."""

    operation: str
    state: CapabilityState
    #: The exact permission required. Published so an operator can ask for the right one rather
    #: than guessing from the operation's name.
    required_permission: str
    detail: str


@dataclass(frozen=True)
class ProviderCapability:
    """What one provider substrate can do in this build."""

    provider: str
    #: True when the shipped catalog has at least one deployable template for this provider.
    deployable: bool
    #: The lifecycle operations this provider's ranges support, derived from the operation gates
    #: that exist for it — not from a per-provider constant.
    lifecycle_operations: tuple[str, ...]
    detail: str


@dataclass(frozen=True)
class CapabilityReport:
    operations: tuple[OperationCapability, ...]
    providers: tuple[ProviderCapability, ...]
    discovery: str
    discovery_detail: str


def _discovery_mode() -> tuple[str, str]:
    """Whether discovery is still read-only, checked against the plugin contract.

    The old endpoint asserted ``"discovery": "read-only"`` as a literal. That is a claim about what
    a discovery run may do to a target, and it is checkable: the capability a plugin advertises for
    discovery is backed by :class:`~secp_plugin_api.v1.discovery.DiscoveryProtocol`, whose entire
    surface is ``validate_target`` and ``discover``. If a mutating method is ever added to that
    protocol, the claim stops being true and this stops making it.
    """
    try:
        from secp_plugin_api.v1.discovery import DiscoveryProtocol
    except Exception:  # pragma: no cover - the contract package is a hard dependency
        return (
            CapabilityState.undetermined.value,
            "the discovery plugin contract could not be loaded, so nothing here can say what a "
            "discovery run is permitted to do. Unknown, not read-only.",
        )

    surface = {
        name
        for name in dir(DiscoveryProtocol)
        if not name.startswith("_") and callable(getattr(DiscoveryProtocol, name, None))
    }
    read_only_surface = {"validate_target", "discover"}
    if surface == read_only_surface:
        return (
            "read-only",
            "the discovery plugin contract exposes only validate_target and discover; it has no "
            "method that can change a target. Checked against the protocol, not asserted.",
        )
    return (
        CapabilityState.undetermined.value,
        f"the discovery plugin contract now exposes {sorted(surface)}, which is more than the "
        f"read-only surface {sorted(read_only_surface)}. Whether discovery still only reads is no "
        "longer something this endpoint can claim.",
    )


def _operation_state(principal: Principal, permission: Permission, implemented: bool):
    if not implemented:
        return CapabilityState.not_supported
    if principal.has(permission):
        return CapabilityState.supported_authorized
    return CapabilityState.supported_unauthorized


def _is_implemented(kind: proxmox_commands.CommandKind) -> bool:
    """Whether a handler for this command actually exists in the live module.

    Looked up by name on the module, so a command declared in the enum with no implementation
    reports ``not_supported`` rather than being advertised because it appears in a list.
    """
    return callable(getattr(proxmox_commands, kind.value, None))


def build_report(principal: Principal) -> CapabilityReport:
    """The capability report for this principal, derived from the live modules."""
    operations = tuple(
        OperationCapability(
            operation=kind.value,
            state=_operation_state(
                principal, proxmox_commands.COMMAND_PERMISSIONS[kind], _is_implemented(kind)
            ),
            required_permission=proxmox_commands.COMMAND_PERMISSIONS[kind].value,
            detail=_operation_detail(kind),
        )
        # Enumerated from the LIVE enum: a command added without a capability entry is impossible,
        # because there is no list here to forget to update.
        for kind in proxmox_commands.CommandKind
    )

    # Which lifecycle operations a Proxmox range supports is decided by which authorization gates
    # exist, and those are the RangeOperationKind members the gate matches — so this is derived from
    # the same enum the gate is exhaustive over.
    proxmox_lifecycle_ops = tuple(kind.value for kind in RangeOperationKind)

    providers = tuple(
        _provider_capability(provider, proxmox_lifecycle_ops) for provider in KNOWN_PROVIDERS
    )
    discovery, discovery_detail = _discovery_mode()
    return CapabilityReport(
        operations=operations,
        providers=providers,
        discovery=discovery,
        discovery_detail=discovery_detail,
    )


def _provider_capability(provider: str, lifecycle_ops: tuple[str, ...]) -> ProviderCapability:
    from secp_api.range_catalog import CATALOG

    templates = [template for template in CATALOG if template.provider == provider]
    if not templates:
        return ProviderCapability(
            provider=provider,
            deployable=False,
            lifecycle_operations=(),
            detail=(
                f"no template in the shipped catalog targets '{provider}', so this build stands up "
                "nothing on it. A definite answer, not a missing check."
            ),
        )
    if provider == proxmox_lifecycle.PROXMOX_PROVIDER:
        detail = (
            f"{len(templates)} template(s). Full lifecycle: the desired state is compiled in "
            "process, the plan and the destroy and reset scopes are each approved by their own "
            "hash, and execution is enqueued to the privileged worker. The API itself applies, "
            "destroys and resets nothing."
        )
    else:
        detail = (
            f"{len(templates)} template(s). The lifecycle is enqueued to the worker; this "
            "substrate has no approval gate, because a local container lab creates nothing on "
            "shared hardware."
        )
    return ProviderCapability(
        provider=provider,
        deployable=True,
        lifecycle_operations=lifecycle_ops,
        detail=detail,
    )


def _operation_detail(kind: proxmox_commands.CommandKind) -> str:
    if kind in proxmox_commands.COMMAND_OPERATION_KINDS:
        return (
            "persists intent and enqueues a durable operation for the privileged worker; the API "
            "executes nothing"
        )
    if kind is proxmox_commands.CommandKind.request_reconciliation:
        return (
            "persists intent only. No consumer takes it yet, and the response says so rather than "
            "implying work is in flight"
        )
    return "computes or records; starts nothing and enqueues nothing"
