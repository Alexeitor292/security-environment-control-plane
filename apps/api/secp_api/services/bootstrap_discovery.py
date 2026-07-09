"""SECP-B7 — Proxmox read-only discovery bootstrap automation service.

Replaces the manual SECP-B6 canary steps (hand-writing manifest.json / binding.json / known_hosts /
endpoint-binding hashes / authorization ids) with a safe, wizard-driven flow. The API produces ONLY
secret-free desired state: an idempotent Proxmox bootstrap script (from the public SSH key), the
opaque endpoint-binding digest (computed by backend code, never shell), a separately-approved
live-read authorization, and the worker's secret-free ``binding.json`` descriptor.

Every SECP-B6 fail-closed invariant is preserved:
  * the API never stores/reads an SSH private key (only the PUBLIC key is accepted, private-key
    material is rejected);
  * live discovery still requires an active onboarding + a separately-approved live-read
    authorization for the exact endpoint digest;
  * the endpoint-binding digest is deterministic backend code over the authoritative target host +
    the operator-supplied public host-key fingerprint;
  * binding generation fails closed on any target/onboarding/enrollment mismatch;
  * the API contacts nothing and runs no probe.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.discovery_bootstrap_contract import (
    DEFAULT_ACCOUNT,
    DEFAULT_PVE_ROLE,
    BootstrapContractError,
    render_bootstrap_script,
    validate_public_ssh_key,
)
from secp_api.enums import (
    AuditAction,
    OnboardingStatus,
    Permission,
    ProxmoxBootstrapStatus,
    TargetStatus,
)
from secp_api.errors import DomainError, NotFoundError
from secp_api.live_read_contract import (
    LIVE_READ_PLUGIN_NAME,
    normalize_target_host,
    ssh_endpoint_binding_hash,
)
from secp_api.models import (
    ExecutionTarget,
    ProxmoxReadOnlyBootstrapSession,
    TargetDiscoveryEnrollment,
    TargetOnboarding,
)
from secp_api.services import readonly_preflight

_SESSION_TTL = timedelta(hours=24)
_AUTHORIZATION_TTL_SECONDS = 3600
# A public SSH host-key fingerprint the operator reads off the Proxmox host (never a secret).
_FINGERPRINT_MAX = 200


class BootstrapDiscoveryError(DomainError):
    """A bootstrap-flow failure. Message is safe (closed reason / non-secret)."""

    http_status = 422
    code = "invalid_bootstrap_input"


def _fail(message: str) -> BootstrapDiscoveryError:
    return BootstrapDiscoveryError(message)


def _now() -> datetime:
    return datetime.now(UTC)


def _load_target(session: Session, actor: Principal, target_id: uuid.UUID) -> ExecutionTarget:
    target = session.get(ExecutionTarget, target_id)
    if target is None:
        raise NotFoundError("execution_target_not_found")
    actor.require_org(target.organization_id)
    return target


def _active_onboarding(session: Session, target_id: uuid.UUID) -> TargetOnboarding:
    onboarding = session.execute(
        select(TargetOnboarding).where(
            TargetOnboarding.execution_target_id == target_id,
            TargetOnboarding.status == OnboardingStatus.active,
        )
    ).scalar_one_or_none()
    if onboarding is None:
        raise _fail("no active onboarding for target; complete + activate onboarding first")
    return onboarding


def _get_session(
    session: Session, actor: Principal, session_id: uuid.UUID
) -> ProxmoxReadOnlyBootstrapSession:
    row = session.get(ProxmoxReadOnlyBootstrapSession, session_id)
    if row is None:
        raise NotFoundError("bootstrap_session_not_found")
    actor.require_org(row.organization_id)
    return row


def _audit(
    session: Session, row: ProxmoxReadOnlyBootstrapSession, action: AuditAction, outcome: str
) -> None:
    audit.record(
        session,
        action=action,
        resource_type="proxmox_readonly_bootstrap_session",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor="operator",
        outcome=outcome,
        data={
            "status": row.status.value,
            "execution_target_id": str(row.execution_target_id),
            "onboarding_id": str(row.onboarding_id),
        },
    )


def create_bootstrap_session(
    session: Session,
    actor: Principal,
    *,
    execution_target_id: uuid.UUID,
    worker_ssh_public_key: str,
    ssh_port: int = 22,
) -> ProxmoxReadOnlyBootstrapSession:
    """Create a bootstrap session for an active-onboarded Proxmox target from the worker's PUBLIC
    key. Fails closed on a private key, a non-proxmox/inactive target, or a missing onboarding."""
    actor.require(Permission.target_discovery_manage)
    target = _load_target(session, actor, execution_target_id)
    if target.plugin_name != LIVE_READ_PLUGIN_NAME:
        raise _fail("read-only discovery bootstrap is only supported for proxmox targets")
    if target.status != TargetStatus.active:
        raise _fail("target is not active")
    onboarding = _active_onboarding(session, execution_target_id)
    if not (isinstance(ssh_port, int) and 1 <= ssh_port <= 65535):
        raise _fail("ssh_port must be an integer in 1..65535")
    try:
        normalized_key, fingerprint = validate_public_ssh_key(worker_ssh_public_key)
    except BootstrapContractError as exc:
        # Never echo the raw key; surface only the closed reason code.
        raise _fail(f"worker_ssh_public_key rejected: {exc.reason_code}") from None

    row = ProxmoxReadOnlyBootstrapSession(
        organization_id=target.organization_id,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        account=DEFAULT_ACCOUNT,
        pve_role=DEFAULT_PVE_ROLE,
        worker_ssh_public_key=normalized_key,
        worker_ssh_public_key_fingerprint=fingerprint,
        status=ProxmoxBootstrapStatus.pending,
        ssh_port=ssh_port,
        expires_at=_now() + _SESSION_TTL,
        created_by=actor.user_id,
    )
    session.add(row)
    session.flush()
    _audit(session, row, AuditAction.readonly_bootstrap_session_created, "success")
    return row


def render_session_script(session: Session, actor: Principal, session_id: uuid.UUID) -> str:
    """Render the idempotent Proxmox bootstrap script for a session (secret-free; public key)."""
    row = _get_session(session, actor, session_id)
    return render_bootstrap_script(
        public_ssh_key=row.worker_ssh_public_key,
        account=row.account,
        pve_role=row.pve_role,
        session_id=str(row.id),
    )


def complete_bootstrap_session(
    session: Session,
    actor: Principal,
    session_id: uuid.UUID,
    *,
    host_key_fingerprint: str,
    proof_text: str | None = None,
) -> ProxmoxReadOnlyBootstrapSession:
    """Accept the operator's bounded, secret-free proof + the public host-key fingerprint, compute
    the endpoint-binding digest (backend code) and transition ``pending`` → ``completed``."""
    actor.require(Permission.target_discovery_manage)
    row = _get_session(session, actor, session_id)
    if row.status != ProxmoxBootstrapStatus.pending:
        raise _fail(f"bootstrap session is not pending (status={row.status.value})")
    if _aware(row.expires_at) <= _now():
        raise _fail("bootstrap session expired; create a new one")
    fp = (host_key_fingerprint or "").strip()
    if not (fp.startswith("SHA256:") and 8 < len(fp) <= _FINGERPRINT_MAX and "\n" not in fp):
        raise _fail("host_key_fingerprint must be an SSH 'SHA256:...' fingerprint")
    proof_summary = _parse_proof(proof_text) if proof_text else {"submitted": True}

    target = _load_target(session, actor, row.execution_target_id)
    try:
        normalized_host = normalize_target_host(target.config or {})
    except ValueError:
        raise _fail("target host is unresolvable from its config") from None
    endpoint_binding_hash = ssh_endpoint_binding_hash(
        normalized_target_host=normalized_host,
        ssh_host=normalized_host,  # SECP-B6 MB-2: the SSH host MUST equal the authoritative target
        ssh_port=int(row.ssh_port),
        host_key_fingerprint=fp,
    )
    row.host_key_fingerprint = fp
    row.endpoint_binding_hash = endpoint_binding_hash
    row.proof_summary = proof_summary
    row.status = ProxmoxBootstrapStatus.completed
    row.revision = row.revision + 1
    session.flush()
    _audit(session, row, AuditAction.readonly_bootstrap_session_completed, "success")
    return row


def bind_bootstrap_session(
    session: Session, actor: Principal, session_id: uuid.UUID
) -> ProxmoxReadOnlyBootstrapSession:
    """Bind a completed session to a separately-approved live-read authorization for the exact
    endpoint digest. Requires ``onboarding_approve`` (the explicit, auditable authorization
    permission). Fails closed if the target is not substrate-eligible."""
    actor.require(Permission.onboarding_approve)
    row = _get_session(session, actor, session_id)
    if row.status not in (ProxmoxBootstrapStatus.completed, ProxmoxBootstrapStatus.bound):
        raise _fail(
            f"bootstrap session must be completed before binding (status={row.status.value})"
        )
    if not row.endpoint_binding_hash:
        raise _fail("bootstrap session has no endpoint binding digest; complete it first")
    # Create + approve the live-read authorization bound to the exact endpoint digest. This reuses
    # the SECP-002B-1B-6 authorization pipeline (substrate-eligibility gated, endpoint-bound).
    authorization = readonly_preflight.create_preflight_authorization(
        session,
        actor,
        execution_target_id=row.execution_target_id,
        ttl_seconds=_AUTHORIZATION_TTL_SECONDS,
        endpoint_binding_hash=row.endpoint_binding_hash,
    )
    approved = readonly_preflight.approve_preflight_authorization(session, actor, authorization.id)
    row.live_read_authorization_id = approved.id
    row.authorization_version = approved.authorization_version
    row.status = ProxmoxBootstrapStatus.bound
    row.revision = row.revision + 1
    session.flush()
    _audit(session, row, AuditAction.readonly_bootstrap_session_bound, "success")
    return row


def get_binding_descriptor(session: Session, actor: Principal, enrollment_id: uuid.UUID) -> dict:
    """Return the worker's SECRET-FREE ``binding.json`` descriptor for an enrollment — the exact
    non-secret fields the mounted bundle requires. Fails closed unless a bound bootstrap session
    exists for the enrollment's exact target + onboarding."""
    enrollment = session.get(TargetDiscoveryEnrollment, enrollment_id)
    if enrollment is None:
        raise NotFoundError("enrollment_not_found")
    actor.require_org(enrollment.organization_id)
    row = session.execute(
        select(ProxmoxReadOnlyBootstrapSession).where(
            ProxmoxReadOnlyBootstrapSession.execution_target_id == enrollment.execution_target_id,
            ProxmoxReadOnlyBootstrapSession.onboarding_id == enrollment.onboarding_id,
            ProxmoxReadOnlyBootstrapSession.status == ProxmoxBootstrapStatus.bound,
        )
    ).scalar_one_or_none()
    if row is None:
        raise _fail("no bound bootstrap session for this enrollment's target + onboarding")
    if not (
        row.organization_id == enrollment.organization_id
        and row.endpoint_binding_hash
        and row.live_read_authorization_id
        and row.authorization_version
    ):
        raise _fail("bootstrap session binding is incomplete")
    # Exactly the fields the worker mounted-bundle contract requires (all non-secret IDs + digest).
    return {
        "organization_id": str(enrollment.organization_id),
        "execution_target_id": str(enrollment.execution_target_id),
        "onboarding_id": str(enrollment.onboarding_id),
        "enrollment_id": str(enrollment.id),
        "authorization_id": str(row.live_read_authorization_id),
        "authorization_version": int(row.authorization_version),
        "endpoint_binding_hash": row.endpoint_binding_hash,
    }


def get_bootstrap_session(
    session: Session, actor: Principal, session_id: uuid.UUID
) -> ProxmoxReadOnlyBootstrapSession:
    return _get_session(session, actor, session_id)


def list_bootstrap_sessions(
    session: Session, actor: Principal, *, execution_target_id: uuid.UUID | None = None
) -> list[ProxmoxReadOnlyBootstrapSession]:
    stmt = select(ProxmoxReadOnlyBootstrapSession).where(
        ProxmoxReadOnlyBootstrapSession.organization_id == actor.organization_id
    )
    if execution_target_id is not None:
        stmt = stmt.where(
            ProxmoxReadOnlyBootstrapSession.execution_target_id == execution_target_id
        )
    stmt = stmt.order_by(ProxmoxReadOnlyBootstrapSession.created_at)
    return list(session.execute(stmt).scalars())


# --- helpers -----------------------------------------------------------------


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _parse_proof(proof_text: str) -> dict:
    """Extract ONLY closed, bounded keys from a pasted SECPDISC-PROOF block. Reject any private-key
    material; never retain arbitrary free text."""
    if not isinstance(proof_text, str) or len(proof_text) > 8192:
        raise _fail("proof text is too large")
    if "PRIVATE KEY" in proof_text.upper():
        raise _fail("proof must not contain private key material")
    allowed = {
        "session_id",
        "account",
        "pve_role",
        "pve_privs",
        "force_command",
        "authorized_key_fingerprint",
        "host_key_fingerprint",
        "selftest_ok",
    }
    facts: dict[str, str] = {}
    for line in proof_text.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key in allowed and len(value) <= 200 and "\x00" not in value:
            facts[key] = value.strip()
    if facts.get("selftest_ok") not in (None, "1"):
        raise _fail("bootstrap self-test did not pass on the host")
    return facts or {"submitted": True}
