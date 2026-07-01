"""Toolchain-profile services (SECP-002B-1A, ADR-013).

Control-plane only. Registers immutable, secret-free, provider-neutral toolchain
profiles that bind an execution target to a worker-side IaC runtime. This module NEVER
imports a runner, process executor, adapter, OpenTofu, provider client, or subprocess —
it validates the profile *shape/safety* and persists provenance for the worker to honor.
"""

from __future__ import annotations

import uuid
from typing import NoReturn

from secp_scenario_schema import content_hash
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import AuditAction, Permission, TargetStatus, ToolchainProfileStatus
from secp_api.errors import DomainError, NotFoundError, ValidationFailedError
from secp_api.models import ExecutionTarget, ToolchainProfile
from secp_api.toolchain_profile import validate_toolchain_profile

# The adapter type a profile declares must match the target's provider plugin, so a
# profile can never bind the wrong renderer to a target.
_ADAPTER_FOR_PLUGIN = {"proxmox": "proxmox"}


def _refuse(actor: Principal, target_id: uuid.UUID, org_id: uuid.UUID, reason: str) -> NoReturn:
    from secp_api.db import session_scope

    with session_scope() as s:
        audit.record(
            s,
            action=AuditAction.toolchain_profile_refused,
            resource_type="execution_target",
            resource_id=target_id,
            organization_id=org_id,
            actor=str(actor.user_id),
            outcome="denied",
            data={"reason": reason},
        )
    raise ValidationFailedError(reason)


def register_toolchain_profile(
    session: Session,
    actor: Principal,
    *,
    target_id: uuid.UUID,
    name: str,
    profile: dict,
) -> ToolchainProfile:
    """Validate and persist an immutable toolchain profile for a target."""
    actor.require(Permission.toolchain_manage)

    target = session.get(ExecutionTarget, target_id)
    if target is None:
        raise NotFoundError(f"execution target {target_id} not found")
    actor.require_org(target.organization_id)
    if target.status != TargetStatus.active:
        _refuse(
            actor,
            target_id,
            target.organization_id,
            f"execution target is '{target.status.value}', not active",
        )

    try:
        spec = validate_toolchain_profile(profile)
    except ValidationFailedError as exc:
        _refuse(
            actor, target_id, target.organization_id, f"invalid toolchain profile: {exc.message}"
        )

    expected_adapter = _ADAPTER_FOR_PLUGIN.get(target.plugin_name)
    if expected_adapter is None:
        _refuse(
            actor,
            target_id,
            target.organization_id,
            f"no toolchain adapter is defined for provider plugin '{target.plugin_name}'",
        )
    if spec.adapter_kind != expected_adapter:
        _refuse(
            actor,
            target_id,
            target.organization_id,
            f"adapter_kind '{spec.adapter_kind}' does not match the target provider "
            f"'{target.plugin_name}' (expected '{expected_adapter}')",
        )

    content = spec.model_dump(mode="json")
    next_version = (
        session.execute(
            select(func.coalesce(func.max(ToolchainProfile.version), 0)).where(
                ToolchainProfile.execution_target_id == target.id
            )
        ).scalar_one()
        + 1
    )

    tp = ToolchainProfile(
        organization_id=target.organization_id,
        execution_target_id=target.id,
        name=name,
        version=next_version,
        runner_kind=spec.runner_kind,
        activation_class=spec.activation_class,
        renderer_version=spec.renderer_version,
        content=content,
        content_hash=content_hash(content),
        status=ToolchainProfileStatus.active,
        created_by=actor.user_id,
    )
    session.add(tp)
    session.flush()

    audit.record(
        session,
        action=AuditAction.toolchain_profile_created,
        resource_type="toolchain_profile",
        resource_id=tp.id,
        organization_id=target.organization_id,
        actor=str(actor.user_id),
        data={
            "execution_target_id": str(target.id),
            "content_hash": tp.content_hash,
            "runner_kind": tp.runner_kind,
            "activation_class": tp.activation_class,
            "version": tp.version,
        },
    )
    return tp


def get_toolchain_profile(
    session: Session, actor: Principal, profile_id: uuid.UUID
) -> ToolchainProfile:
    tp = session.get(ToolchainProfile, profile_id)
    if tp is None:
        raise NotFoundError(f"toolchain profile {profile_id} not found")
    actor.require_org(tp.organization_id)
    return tp


def list_toolchain_profiles(
    session: Session, actor: Principal, target_id: uuid.UUID
) -> list[ToolchainProfile]:
    target = session.get(ExecutionTarget, target_id)
    if target is None:
        raise NotFoundError(f"execution target {target_id} not found")
    actor.require_org(target.organization_id)
    return list(
        session.execute(
            select(ToolchainProfile)
            .where(ToolchainProfile.execution_target_id == target_id)
            .order_by(ToolchainProfile.version.desc())
        )
        .scalars()
        .all()
    )


def active_profile_for_target(session: Session, target_id: uuid.UUID) -> ToolchainProfile | None:
    """The highest-version active toolchain profile for a target, or None."""
    return (
        session.execute(
            select(ToolchainProfile)
            .where(
                ToolchainProfile.execution_target_id == target_id,
                ToolchainProfile.status == ToolchainProfileStatus.active,
            )
            .order_by(ToolchainProfile.version.desc())
        )
        .scalars()
        .first()
    )


def disable_toolchain_profile(
    session: Session, actor: Principal, profile_id: uuid.UUID
) -> ToolchainProfile:
    actor.require(Permission.toolchain_manage)
    tp = get_toolchain_profile(session, actor, profile_id)
    if tp.status == ToolchainProfileStatus.disabled:
        raise DomainError("toolchain profile is already disabled")
    tp.status = ToolchainProfileStatus.disabled
    audit.record(
        session,
        action=AuditAction.toolchain_profile_disabled,
        resource_type="toolchain_profile",
        resource_id=tp.id,
        organization_id=tp.organization_id,
        actor=str(actor.user_id),
    )
    return tp
