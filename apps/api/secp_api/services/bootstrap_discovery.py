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
    LiveReadAuthorizationStatus,
    OnboardingStatus,
    Permission,
    ProxmoxBootstrapStatus,
    StagingSubstrateEligibilityStatus,
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
    LiveReadAuthorization,
    ProxmoxReadOnlyBootstrapSession,
    StagingSubstrateEligibility,
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
    host_public_key: str | None = None,
) -> ProxmoxReadOnlyBootstrapSession:
    """Accept the operator's bounded, secret-free proof + the public host-key fingerprint, compute
    the endpoint-binding digest (backend code) and transition ``pending`` → ``completed``.

    SECP-B8: if the proof (or an explicit arg) carries the host's PUBLIC key line, it is validated,
    cross-checked against ``host_key_fingerprint`` (fail closed on mismatch) and stored so the
    worker can synthesize an authoritative ``known_hosts`` entry without contacting Proxmox."""
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

    # SECP-B8: capture the host PUBLIC key (explicit arg wins over the parsed proof fact). It is
    # validated as a public key (private-key material rejected) and its derived fingerprint MUST
    # equal the operator-supplied host_key_fingerprint, or completion fails closed.
    host_key_line = str(host_public_key or proof_summary.get("host_public_key") or "").strip()
    normalized_host_public_key: str | None = None
    if host_key_line and host_key_line.lower() != "unknown":
        try:
            normalized_host_public_key, derived_fp = validate_public_ssh_key(host_key_line)
        except BootstrapContractError:
            raise _fail("host_public_key is not a valid SSH public key") from None
        if derived_fp != fp:
            raise _fail("host_public_key does not match host_key_fingerprint")

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
    if normalized_host_public_key is not None:
        row.host_public_key = normalized_host_public_key
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
    if row.status == ProxmoxBootstrapStatus.bound:
        # A retry is idempotent. Never mint a second authorization for the same session.
        if row.live_read_authorization_id and row.authorization_version:
            return row
        raise _fail("bound bootstrap session has incomplete authorization metadata")

    # A fresh post-activation worker key is adopted through THIS existing bootstrap contract. Lock
    # and supersede any prior binding for the same target/onboarding, revoking its still-approved
    # authorization before the replacement can become bound. The partial unique index is the
    # concurrent-writer backstop; no caller ever selects an unordered stale binding.
    prior_rows = list(
        session.execute(
            select(ProxmoxReadOnlyBootstrapSession)
            .where(
                ProxmoxReadOnlyBootstrapSession.execution_target_id == row.execution_target_id,
                ProxmoxReadOnlyBootstrapSession.onboarding_id == row.onboarding_id,
                ProxmoxReadOnlyBootstrapSession.status == ProxmoxBootstrapStatus.bound,
                ProxmoxReadOnlyBootstrapSession.id != row.id,
            )
            .with_for_update()
        ).scalars()
    )
    for prior in prior_rows:
        if prior.live_read_authorization_id is not None:
            authorization = session.get(LiveReadAuthorization, prior.live_read_authorization_id)
            if (
                authorization is not None
                and authorization.status == LiveReadAuthorizationStatus.approved
            ):
                readonly_preflight.revoke_preflight_authorization(
                    session,
                    actor,
                    authorization.id,
                    reason_code="worker_key_rotated",
                )
        prior.status = ProxmoxBootstrapStatus.refused
        prior.revision = prior.revision + 1
        _audit(session, prior, AuditAction.readonly_bootstrap_session_refused, "worker_key_rotated")
    session.flush()
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


def get_bundle_descriptor(session: Session, actor: Principal, enrollment_id: uuid.UUID) -> dict:
    """SECP-B8: the SECRET-FREE superset the worker's bundle manager needs to assemble the mounted
    discovery bundle without contacting Proxmox — the ``binding.json`` fields PLUS the SSH endpoint
    facts (host/port/account), the public host-key fingerprint, and the host PUBLIC key line the
    worker writes into ``known_hosts``. Fails closed unless a fully-bound session exists AND the
    host public key was captured at completion. No secret is ever returned."""
    enrollment = session.get(TargetDiscoveryEnrollment, enrollment_id)
    if enrollment is None:
        raise NotFoundError("enrollment_not_found")
    actor.require_org(enrollment.organization_id)
    row = _bound_session_for_enrollment(session, enrollment)
    if not (
        row.endpoint_binding_hash and row.live_read_authorization_id and row.authorization_version
    ):
        raise _fail("bootstrap session binding is incomplete")
    if not row.host_public_key:
        raise _fail("bootstrap session has no captured host public key; re-run completion")
    if not row.host_key_fingerprint:
        raise _fail("bootstrap session has no host key fingerprint")
    target = _load_target(session, actor, row.execution_target_id)
    try:
        ssh_host = normalize_target_host(target.config or {})
    except ValueError:
        raise _fail("target host is unresolvable from its config") from None
    descriptor = {
        "organization_id": str(enrollment.organization_id),
        "execution_target_id": str(enrollment.execution_target_id),
        "onboarding_id": str(enrollment.onboarding_id),
        "enrollment_id": str(enrollment.id),
        "authorization_id": str(row.live_read_authorization_id),
        "authorization_version": int(row.authorization_version),
        "endpoint_binding_hash": row.endpoint_binding_hash,
        # SSH endpoint facts + host key material (all non-secret) for manifest.json + known_hosts.
        "ssh_host": ssh_host,
        "ssh_port": int(row.ssh_port),
        "account": row.account.split("@", 1)[0],
        "host_key_fingerprint": row.host_key_fingerprint,
        "host_public_key": row.host_public_key,
    }
    return descriptor


def resolve_ready_bundle_descriptors(session: Session, organization_id: uuid.UUID) -> list[dict]:
    """SECP-B8 worker/system-facing: build the SECRET-FREE bundle descriptor for EVERY enrollment
    whose bootstrap session is fully bound AND has the host public key captured. No principal — the
    worker process resolves its own bundle prep from the shared control-plane store, and every field
    is non-secret (IDs, endpoint digest, SSH host/port/account, host public key). Returns [] when
    nothing is ready. It contacts nothing and reads no private key."""
    if not isinstance(organization_id, uuid.UUID):
        return []
    rows = (
        session.execute(
            select(ProxmoxReadOnlyBootstrapSession).where(
                ProxmoxReadOnlyBootstrapSession.organization_id == organization_id,
                ProxmoxReadOnlyBootstrapSession.status == ProxmoxBootstrapStatus.bound,
                ProxmoxReadOnlyBootstrapSession.host_public_key.is_not(None),
            )
        )
        .scalars()
        .all()
    )
    descriptors: list[dict] = []
    for row in rows:
        if not (
            row.endpoint_binding_hash
            and row.live_read_authorization_id
            and row.authorization_version
            and row.host_key_fingerprint
            and row.host_public_key
        ):
            continue
        enrollment = (
            session.execute(
                select(TargetDiscoveryEnrollment)
                .where(
                    TargetDiscoveryEnrollment.execution_target_id == row.execution_target_id,
                    TargetDiscoveryEnrollment.onboarding_id == row.onboarding_id,
                    TargetDiscoveryEnrollment.organization_id == organization_id,
                )
                .order_by(TargetDiscoveryEnrollment.created_at.desc())
            )
            .scalars()
            .first()
        )
        if enrollment is None:
            continue
        target = session.execute(
            select(ExecutionTarget).where(
                ExecutionTarget.id == row.execution_target_id,
                ExecutionTarget.organization_id == organization_id,
            )
        ).scalar_one_or_none()
        if target is None:
            continue
        try:
            ssh_host = normalize_target_host(target.config or {})
        except ValueError:
            continue
        descriptors.append(
            {
                "organization_id": str(row.organization_id),
                "execution_target_id": str(row.execution_target_id),
                "onboarding_id": str(row.onboarding_id),
                "enrollment_id": str(enrollment.id),
                # Public binding proof used by the worker to refuse a bootstrap session that
                # authorized a prior worker SSH key.  The private key never enters this descriptor.
                "worker_ssh_public_key_fingerprint": row.worker_ssh_public_key_fingerprint,
                "authorization_id": str(row.live_read_authorization_id),
                "authorization_version": int(row.authorization_version),
                "endpoint_binding_hash": row.endpoint_binding_hash,
                "ssh_host": ssh_host,
                "ssh_port": int(row.ssh_port),
                "account": row.account.split("@", 1)[0],
                "host_key_fingerprint": row.host_key_fingerprint,
                "host_public_key": row.host_public_key,
            }
        )
    return descriptors


def discovery_readiness(session: Session, actor: Principal, enrollment_id: uuid.UUID) -> dict:
    """SECP-B8: a precise, secret-free readiness diagnostic for an enrollment's live discovery path.

    Instead of the worker failing opaquely with ``probe_source_sealed``, this reports EXACTLY which
    prerequisite is missing (Proxmox script not run / bootstrap not completed / not bound / host key
    not captured / substrate ineligible). It reads state only — it grants nothing and contacts
    nothing."""
    enrollment = session.get(TargetDiscoveryEnrollment, enrollment_id)
    if enrollment is None:
        raise NotFoundError("enrollment_not_found")
    actor.require_org(enrollment.organization_id)

    onboarding = session.get(TargetOnboarding, enrollment.onboarding_id)
    target = session.get(ExecutionTarget, enrollment.execution_target_id)
    row = (
        session.execute(
            select(ProxmoxReadOnlyBootstrapSession)
            .where(
                ProxmoxReadOnlyBootstrapSession.execution_target_id
                == enrollment.execution_target_id,
                ProxmoxReadOnlyBootstrapSession.onboarding_id == enrollment.onboarding_id,
            )
            .order_by(ProxmoxReadOnlyBootstrapSession.created_at.desc())
        )
        .scalars()
        .first()
    )

    onboarding_active = bool(onboarding and onboarding.status == OnboardingStatus.active)
    substrate_eligible = bool(
        target
        and target.status == TargetStatus.active
        and _active_substrate_eligibility(session, target.id) is not None
    )
    status_value = row.status.value if row else None
    bootstrap_completed = bool(
        row and row.status in (ProxmoxBootstrapStatus.completed, ProxmoxBootstrapStatus.bound)
    )
    bootstrap_bound = bool(row and row.status == ProxmoxBootstrapStatus.bound)
    host_key_captured = bool(row and row.host_public_key)
    live_read_authorized = bool(
        row and row.live_read_authorization_id and row.authorization_version
    )

    checks = [
        ("onboarding_active", onboarding_active),
        ("substrate_eligible", substrate_eligible),
        ("bootstrap_session_present", bool(row)),
        ("bootstrap_completed", bootstrap_completed),
        ("host_public_key_captured", host_key_captured),
        ("live_read_authorized", live_read_authorized),
        ("bootstrap_bound", bootstrap_bound),
    ]
    missing = [name for name, ok in checks if not ok]
    ready = not missing
    return {
        "enrollment_id": str(enrollment.id),
        "execution_target_id": str(enrollment.execution_target_id),
        "onboarding_id": str(enrollment.onboarding_id),
        "bootstrap_session_id": str(row.id) if row else None,
        "bootstrap_status": status_value,
        "ready": ready,
        "missing_prerequisites": missing,
        "checks": {name: ok for name, ok in checks},
    }


def _active_substrate_eligibility(
    session: Session, target_id: uuid.UUID
) -> StagingSubstrateEligibility | None:
    return (
        session.execute(
            select(StagingSubstrateEligibility).where(
                StagingSubstrateEligibility.execution_target_id == target_id,
                StagingSubstrateEligibility.status == StagingSubstrateEligibilityStatus.active,
            )
        )
        .scalars()
        .first()
    )


def _bound_session_for_enrollment(
    session: Session, enrollment: TargetDiscoveryEnrollment
) -> ProxmoxReadOnlyBootstrapSession:
    row = session.execute(
        select(ProxmoxReadOnlyBootstrapSession).where(
            ProxmoxReadOnlyBootstrapSession.execution_target_id == enrollment.execution_target_id,
            ProxmoxReadOnlyBootstrapSession.onboarding_id == enrollment.onboarding_id,
            ProxmoxReadOnlyBootstrapSession.status == ProxmoxBootstrapStatus.bound,
        )
    ).scalar_one_or_none()
    if row is None:
        raise _fail("no bound bootstrap session for this enrollment's target + onboarding")
    if row.organization_id != enrollment.organization_id:
        raise _fail("bootstrap session organization mismatch")
    return row


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
        "host_public_key",
        "selftest_ok",
    }
    facts: dict[str, str] = {}
    for line in proof_text.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key in allowed and len(value) <= 400 and "\x00" not in value:
            facts[key] = value.strip()
    if facts.get("selftest_ok") not in (None, "1"):
        raise _fail("bootstrap self-test did not pass on the host")
    return facts or {"submitted": True}
