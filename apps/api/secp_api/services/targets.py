"""Execution-target services (ADR-006, ADR-007).

Targets are organization-scoped, secret-free, and have immutable configuration.
The API validates secret-reference SYNTAX only and refuses any plaintext secret;
it never resolves a reference (worker-only).
"""

from __future__ import annotations

import re
import uuid
from ipaddress import ip_network
from urllib.parse import urlparse

from secp_scenario_schema import content_hash
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import AuditAction, Permission, TargetStatus
from secp_api.errors import NotFoundError, ValidationFailedError
from secp_api.models import AddressSpacePolicy, ExecutionTarget
from secp_api.secret_refs import (
    InvalidSecretRefError,
    looks_like_plaintext_secret,
    validate_secret_ref_syntax,
)

# Config keys that would indicate an attempt to persist a plaintext secret.
_SECRET_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|apikey|private[_-]?key|credential)",
    re.IGNORECASE,
)
_PROXMOX_CONFIG_KEYS = frozenset({"base_url", "verify_tls"})
# "provisioning" carries the SECP-002B-0 provisioning scope policy; its strict shape
# is validated at manifest generation (secp_api.provisioning_scope).
_PROXMOX_SCOPE_KEYS = frozenset({"resource_types", "nodes", "provisioning"})
_PROXMOX_RESOURCE_TYPES = frozenset({"node", "vm", "container", "storage", "network"})


def _assert_no_plaintext_secret(config: dict) -> None:
    """Reject configuration that appears to embed a plaintext secret (proof #1)."""

    def walk(value: object, path: str) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                if _SECRET_KEY_PATTERN.search(str(k)):
                    raise ValidationFailedError(
                        "execution-target config must not contain secret-like keys; "
                        f"found '{path}{k}'. Use an opaque secret_ref instead.",
                        errors=[f"plaintext secret key '{k}' is not allowed"],
                    )
                walk(v, f"{path}{k}.")
        elif isinstance(value, list):
            for i, v in enumerate(value):
                walk(v, f"{path}{i}.")

    walk(config, "")


def _validate_proxmox_target(config: dict, scope_policy: dict | None) -> None:
    """Validate Proxmox target shape without importing/invoking the plugin."""

    errors: list[str] = []
    unsupported = sorted(set(config) - _PROXMOX_CONFIG_KEYS)
    if unsupported:
        errors.append(f"unsupported Proxmox config keys: {', '.join(unsupported)}")

    base_url = config.get("base_url")
    if not isinstance(base_url, str):
        errors.append("config.base_url must be an https:// URL")
    else:
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or not parsed.netloc:
            errors.append("config.base_url must use https:// and include a host")

    verify_tls = config.get("verify_tls", True)
    if not isinstance(verify_tls, bool):
        errors.append("config.verify_tls must be a boolean")
    elif verify_tls is not True:
        errors.append("config.verify_tls=false is not allowed for Proxmox targets")

    errors.extend(_validate_proxmox_scope_policy(scope_policy or {}))
    if errors:
        raise ValidationFailedError("invalid Proxmox target configuration", errors=errors)


def _validate_proxmox_scope_policy(scope_policy: dict) -> list[str]:
    if not isinstance(scope_policy, dict):
        return ["scope_policy must be an object"]

    errors: list[str] = []
    unsupported = sorted(set(scope_policy) - _PROXMOX_SCOPE_KEYS)
    if unsupported:
        errors.append(f"unsupported Proxmox scope_policy keys: {', '.join(unsupported)}")

    resource_types = scope_policy.get("resource_types")
    if resource_types is not None:
        if not isinstance(resource_types, list) or not all(
            isinstance(v, str) for v in resource_types
        ):
            errors.append("scope_policy.resource_types must be a list of strings")
        else:
            unknown = sorted(set(resource_types) - _PROXMOX_RESOURCE_TYPES)
            if unknown:
                errors.append(
                    "scope_policy.resource_types contains unsupported values: " + ", ".join(unknown)
                )

    nodes = scope_policy.get("nodes")
    if nodes is not None and (
        not isinstance(nodes, list) or not all(isinstance(v, str) and v for v in nodes)
    ):
        errors.append("scope_policy.nodes must be a list of non-empty strings")

    provisioning = scope_policy.get("provisioning")
    if provisioning is not None and not isinstance(provisioning, dict):
        errors.append("scope_policy.provisioning must be an object")
    return errors


def _validate_address_spaces(address_spaces: list[dict] | None) -> list[tuple[str, int]]:
    normalized: list[tuple[str, int]] = []
    errors: list[str] = []

    for index, space in enumerate(address_spaces or []):
        try:
            block = ip_network(str(space["cidr_block"]), strict=True)
        except Exception:
            errors.append(f"address_spaces[{index}].cidr_block must be a valid CIDR block")
            continue
        try:
            subnet_prefix = int(space["subnet_prefix"])
        except Exception:
            errors.append(f"address_spaces[{index}].subnet_prefix must be an integer")
            continue
        if subnet_prefix < block.prefixlen or subnet_prefix > block.max_prefixlen:
            errors.append(
                f"address_spaces[{index}].subnet_prefix must be between "
                f"{block.prefixlen} and {block.max_prefixlen}"
            )
            continue
        overlaps_existing = False
        for existing_cidr, _existing_prefix in normalized:
            existing = ip_network(existing_cidr)
            if block.version == existing.version and block.overlaps(existing):
                errors.append(
                    f"address_spaces[{index}].cidr_block overlaps an existing "
                    "address-space policy on this target"
                )
                overlaps_existing = True
                break
        if overlaps_existing:
            continue
        normalized.append((str(block), subnet_prefix))

    if errors:
        raise ValidationFailedError("invalid address-space policy", errors=errors)
    return normalized


def register_target(
    session: Session,
    actor: Principal,
    *,
    display_name: str,
    plugin_name: str,
    config: dict,
    secret_ref: str | None = None,
    scope_policy: dict | None = None,
    address_spaces: list[dict] | None = None,
) -> ExecutionTarget:
    actor.require(Permission.target_manage)

    if not isinstance(config, dict):
        raise ValidationFailedError("config must be an object")
    _assert_no_plaintext_secret(config)
    scope_policy = scope_policy or {}
    if not isinstance(scope_policy, dict):
        raise ValidationFailedError("scope_policy must be an object")
    if plugin_name == "proxmox":
        _validate_proxmox_target(config, scope_policy)
    normalized_address_spaces = _validate_address_spaces(address_spaces)

    if secret_ref is not None:
        if looks_like_plaintext_secret(secret_ref):
            raise ValidationFailedError(
                "secret_ref must be an opaque reference (e.g. 'env:SECP_PROVIDER_SECRET__X'),"
                " never a plaintext secret"
            )
        try:
            validate_secret_ref_syntax(secret_ref)
        except InvalidSecretRefError as exc:
            raise ValidationFailedError("invalid secret_ref syntax", errors=[str(exc)]) from exc

    target = ExecutionTarget(
        organization_id=actor.organization_id,
        display_name=display_name,
        plugin_name=plugin_name,
        config=config,
        config_hash=content_hash(config),
        secret_ref=secret_ref,
        status=TargetStatus.active,
        scope_policy=scope_policy,
        created_by=actor.user_id,
    )
    session.add(target)
    session.flush()

    # B1B-PR4: give the target's credential SELECTION an opaque, versioned identity. It stores no
    # reference and no hash of one; changing ``secret_ref`` later ROTATES it (unavoidably), which
    # invalidates every prior readiness authorization/record through the operation fingerprint.
    from secp_api.credential_binding import ensure_credential_binding

    ensure_credential_binding(session, target, created_by=actor.user_id)

    for cidr_block, subnet_prefix in normalized_address_spaces:
        session.add(
            AddressSpacePolicy(
                organization_id=actor.organization_id,
                execution_target_id=target.id,
                cidr_block=cidr_block,
                subnet_prefix=subnet_prefix,
            )
        )
    session.flush()

    audit.record(
        session,
        action=AuditAction.target_created,
        resource_type="execution_target",
        resource_id=target.id,
        organization_id=actor.organization_id,
        actor=str(actor.user_id),
        data={
            "plugin_name": plugin_name,
            "config_hash": target.config_hash,
            "has_secret_ref": secret_ref is not None,
        },
    )
    return target


def get_target(session: Session, actor: Principal, target_id: uuid.UUID) -> ExecutionTarget:
    target = session.get(ExecutionTarget, target_id)
    if target is None:
        raise NotFoundError(f"execution target {target_id} not found")
    actor.require_org(target.organization_id)
    return target


def list_targets(session: Session, actor: Principal) -> list[ExecutionTarget]:
    return list(
        session.execute(
            select(ExecutionTarget)
            .where(ExecutionTarget.organization_id == actor.organization_id)
            .order_by(ExecutionTarget.created_at.desc())
        )
        .scalars()
        .all()
    )


def disable_target(session: Session, actor: Principal, target_id: uuid.UUID) -> ExecutionTarget:
    actor.require(Permission.target_manage)
    target = get_target(session, actor, target_id)
    target.status = TargetStatus.disabled
    audit.record(
        session,
        action=AuditAction.target_disabled,
        resource_type="execution_target",
        resource_id=target.id,
        organization_id=actor.organization_id,
        actor=str(actor.user_id),
    )
    return target


def list_address_spaces(
    session: Session, actor: Principal, target_id: uuid.UUID
) -> list[AddressSpacePolicy]:
    get_target(session, actor, target_id)
    return list(
        session.execute(
            select(AddressSpacePolicy)
            .where(AddressSpacePolicy.execution_target_id == target_id)
            .order_by(AddressSpacePolicy.cidr_block)
        )
        .scalars()
        .all()
    )


def rotate_target_credential(
    session: Session,
    actor: Principal,
    target_id: uuid.UUID,
    *,
    secret_ref: str | None,
) -> ExecutionTarget:
    """The SUPPORTED path for replacing a target's opaque credential reference (B1B-PR4 §2).

    It validates the new reference's syntax, writes it, and — through the ORM rotation hook —
    ROTATES the target's opaque credential binding to the next version. The reference itself is
    never persisted anywhere but ``ExecutionTarget.secret_ref`` (an opaque pointer, never a secret)
    and is never hashed.

    Rotating the binding invalidates every prior plan-secret authorization and readiness record
    (their operation fingerprints bind the old binding id + version) **without modifying any
    historical evidence**.
    """
    from secp_api.credential_binding import active_credential_binding

    actor.require(Permission.credential_binding_manage)
    target = get_target(session, actor, target_id)
    if secret_ref is not None:
        if looks_like_plaintext_secret(secret_ref):
            raise ValidationFailedError(
                "secret_ref must be an opaque reference (e.g. 'env:SECP_PROVIDER_SECRET__X'),"
                " never a plaintext secret"
            )
        try:
            validate_secret_ref_syntax(secret_ref)
        except InvalidSecretRefError as exc:
            raise ValidationFailedError("invalid secret_ref syntax", errors=[str(exc)]) from exc

    target.secret_ref = secret_ref
    session.flush()  # the ORM before_flush hook rotates the credential binding

    binding = active_credential_binding(session, target.id)
    audit.record(
        session,
        action=AuditAction.target_credential_rotated,
        resource_type="execution_target",
        resource_id=target.id,
        organization_id=target.organization_id,
        actor=str(actor.user_id),
        data={
            # OPAQUE ids only: never the reference, never a hash of it.
            "has_secret_ref": secret_ref is not None,
            "credential_binding_id": str(binding.id) if binding is not None else None,
            "credential_binding_version": binding.binding_version if binding is not None else None,
        },
    )
    return target
