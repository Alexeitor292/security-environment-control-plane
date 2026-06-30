"""Execution-target services (ADR-006, ADR-007).

Targets are organization-scoped, secret-free, and have immutable configuration.
The API validates secret-reference SYNTAX only and refuses any plaintext secret;
it never resolves a reference (worker-only).
"""

from __future__ import annotations

import re
import uuid

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
        scope_policy=scope_policy or {},
        created_by=actor.user_id,
    )
    session.add(target)
    session.flush()

    for space in address_spaces or []:
        session.add(
            AddressSpacePolicy(
                organization_id=actor.organization_id,
                execution_target_id=target.id,
                cidr_block=str(space["cidr_block"]),
                subnet_prefix=int(space["subnet_prefix"]),
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
