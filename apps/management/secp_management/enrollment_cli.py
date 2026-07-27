"""secpctl enrollment command engine (SECP-PR5H-B1, Phase 4).

The controller-side ``secpctl enrollment invite create|status|revoke`` engine. It composes ONLY the
hardened management-plane controller HTTPS client (which itself pins to the bootstrap-recorded
locator + protected operator token) — never ``secp_api``, an ORM, a service, a database session, or
an internal Principal. Human-readable and ``--json`` output call THIS same engine; the CLI only
formats. Every result is a bounded ``(exit_code, report)`` pair with a stable exit category and a
deterministic, secret-free report — never a bearer token, token-file path, CA path, controller
origin, private key, raw attestation, raw HTTP response, or exception chain.
"""

from __future__ import annotations

import datetime as _dt
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import NoReturn, Protocol

from secp_management import ManagementError
from secp_management.enrollment_controller_client import (
    ControllerInvitation,
    EnrollmentControllerClient,
    SealedEnrollmentControllerClient,
)
from secp_management.transaction import EXIT_OK, EXIT_REFUSED, WriteGate

# --- stable exit categories (0 success, 2 refused; 3..9 are the enrollment-specific categories) ---
EXIT_AUTH_UNAVAILABLE = 3
EXIT_CONTROLLER_UNAVAILABLE = 4
EXIT_TRANSPORT = 5
EXIT_REVISION_CONFLICT = 6
EXIT_MALFORMED = 7
EXIT_ENROLLMENT_TERMINAL = 8
EXIT_WORKER_HEALTH = 9

_EXIT_BY_REASON: dict[str, int] = {
    # authorization / refused
    "secpctl_controller_forbidden": EXIT_REFUSED,
    "secpctl_controller_conflict": EXIT_REFUSED,
    # authentication unavailable / expired
    "secpctl_operator_auth_unavailable": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_auth_expired": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_token_invalid": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_token_unsafe": EXIT_AUTH_UNAVAILABLE,
    # controller unreachable / not activated
    "secpctl_controller_client_unavailable": EXIT_CONTROLLER_UNAVAILABLE,
    "secpctl_controller_locator_unavailable": EXIT_CONTROLLER_UNAVAILABLE,
    "secpctl_controller_locator_invalid": EXIT_CONTROLLER_UNAVAILABLE,
    "secpctl_controller_unavailable": EXIT_CONTROLLER_UNAVAILABLE,
    # transport / TLS
    "secpctl_controller_transport_failed": EXIT_TRANSPORT,
    # revision conflict
    "secpctl_controller_revision_conflict": EXIT_REVISION_CONFLICT,
    # malformed request / response / id / not-found
    "secpctl_controller_request_invalid": EXIT_MALFORMED,
    "secpctl_controller_response_invalid": EXIT_MALFORMED,
    "secpctl_enrollment_id_invalid": EXIT_MALFORMED,
    "secpctl_controller_not_found": EXIT_MALFORMED,
    # --- worker exchange (PoP-authenticated; no operator token) ---
    "secpctl_worker_enroller_unavailable": EXIT_CONTROLLER_UNAVAILABLE,
    "enrollment_worker_key_sealed": EXIT_CONTROLLER_UNAVAILABLE,
    "enrollment_transport_not_activated": EXIT_CONTROLLER_UNAVAILABLE,
    "enrollment_transport_failed": EXIT_TRANSPORT,
    "secpctl_invitation_file_invalid": EXIT_MALFORMED,
    "secpctl_invitation_file_unreadable": EXIT_MALFORMED,
    "enrollment_invitation_origin_invalid": EXIT_MALFORMED,
    "enrollment_invitation_release_invalid": EXIT_MALFORMED,
    "enrollment_invitation_expired": EXIT_MALFORMED,
    "enrollment_offer_signature_invalid": EXIT_MALFORMED,
    "enrollment_offer_binding_mismatch": EXIT_MALFORMED,
    "enrollment_offer_malformed": EXIT_MALFORMED,
    "enrollment_offer_missing": EXIT_MALFORMED,
    "enrollment_pop_invalid": EXIT_MALFORMED,
    "enrollment_health_incomplete": EXIT_WORKER_HEALTH,
    "enrollment_invitation_revoked": EXIT_ENROLLMENT_TERMINAL,
    "enrollment_invitation_consumed": EXIT_ENROLLMENT_TERMINAL,
    "enrollment_wrong_state": EXIT_ENROLLMENT_TERMINAL,
}

# the non-secret invitation fields the worker requires (from `enrollment invite create`)
_REQUIRED_INVITATION_KEYS = (
    "enrollment_id",
    "invitation_id",
    "controller_installation_id",
    "controller_key_id",
    "controller_origin",
    "transaction_id",
    "release_digest",
    "expires_at",
)
_MAX_INVITATION_BYTES = 8192

_MAX_RETRY = 3  # bounded lost-response retries with the SAME idempotency key
# reason codes that are safe to retry with the identical request (transient controller/transport)
_RETRYABLE = {"secpctl_controller_transport_failed", "secpctl_controller_unavailable"}


def exit_for(reason_code: str) -> int:
    return _EXIT_BY_REASON.get(reason_code, EXIT_REFUSED)


class WorkerCliError(ManagementError):
    """A bounded worker-command refusal (the sealed enroller or a malformed invitation file)."""


def _worker_reject(reason_code: str) -> NoReturn:
    raise WorkerCliError(reason_code)


class WorkerEnroller(Protocol):
    """Drives the worker side of the exchange from a validated non-secret invitation. It
    authenticates via worker proof-of-possession + the signed controller offer (NOT the operator
    OIDC token). Returns a bounded, secret-free outcome dict; refuses with a bounded reason code."""

    def enroll(self, invitation: dict, *, now: str) -> dict: ...
    def status(self, invitation: dict) -> dict: ...
    def retry(self, invitation: dict, *, now: str) -> dict: ...


class SealedWorkerEnroller:
    """The shipped default: no worker enrollment driver is wired; every attempt fails closed."""

    def enroll(self, invitation: dict, *, now: str) -> dict:
        _worker_reject("secpctl_worker_enroller_unavailable")

    def status(self, invitation: dict) -> dict:
        _worker_reject("secpctl_worker_enroller_unavailable")

    def retry(self, invitation: dict, *, now: str) -> dict:
        _worker_reject("secpctl_worker_enroller_unavailable")


def _new_idempotency_key() -> str:
    # a cryptographically strong url-safe key (>= 128 bits) matching the API's 22..128 grammar
    return secrets.token_urlsafe(24)


def _utc_now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


@dataclass
class EnrollmentCliDeps:
    """Injected collaborators for the enrollment commands. Shipped defaults are SEALED; tests inject
    fakes. No API/ORM/DB/Principal is reachable from here."""

    controller_client: EnrollmentControllerClient = field(
        default_factory=SealedEnrollmentControllerClient
    )
    worker_enroller: WorkerEnroller = field(default_factory=SealedWorkerEnroller)
    idempotency_key: Callable[[], str] = _new_idempotency_key
    now: Callable[[], str] = _utc_now


def _invitation_report(inv: ControllerInvitation) -> dict:
    """The full NON-SECRET invitation the operator hands the worker — every field the worker needs,
    none redacted, and never the idempotency key."""
    return {
        "enrollment_id": inv.enrollment_id,
        "invitation_id": inv.invitation_id,
        "controller_installation_id": inv.controller_installation_id,
        "controller_key_id": inv.controller_key_id,
        "controller_trust_anchor_hex": inv.controller_trust_anchor_hex,
        "controller_origin": inv.controller_origin,
        "release_digest": inv.release_digest,
        "transaction_id": inv.transaction_id,
        "deployment_site_label": inv.deployment_site_label,
        "created_at": inv.created_at,
        "expires_at": inv.expires_at,
        "state": inv.state,
        "revision": inv.revision,
    }


def _status_report(status) -> dict:
    return {
        "enrollment_id": status.enrollment_id,
        "state": status.state,
        "revision": status.revision,
        "controller_installation_id": status.controller_installation_id,
        "controller_key_fingerprint": status.controller_key_fingerprint,
        "worker_installation_id": status.worker_installation_id,
        "worker_key_fingerprint": status.worker_key_fingerprint,
        "release_fingerprint": status.release_fingerprint,
        "offer_fingerprint": status.offer_fingerprint,
        "result_fingerprint": status.result_fingerprint,
        "expires_at": status.expires_at,
        "updated_at": status.updated_at,
        "refusal_reason": status.refusal_reason,
    }


def _refused(command: str, reason_code: str) -> tuple[int, dict]:
    return exit_for(reason_code), {"command": command, "reason_code": reason_code}


def invite_create(
    deps: EnrollmentCliDeps, *, deployment_site_label: str, ttl_seconds: int, gate: WriteGate
) -> tuple[int, dict]:
    """``secpctl enrollment invite create`` — mutation; dry-run unless --write --confirm. Generates
    a strong idempotency key automatically and reuses the SAME key across a bounded lost-response
    retry, so a retried create returns the byte-equivalent original invitation; the raw key is never
    printed or persisted after the command completes."""
    command = "enrollment invite create"
    if not gate.is_write:
        return EXIT_OK, {
            "command": command,
            "mode": "dry_run",
            "deployment_site_label": deployment_site_label,
            "ttl_seconds": ttl_seconds,
        }
    key = deps.idempotency_key()  # generated ONCE; identical across the internal retry
    last_reason = "secpctl_controller_unavailable"
    for _attempt in range(_MAX_RETRY):
        try:
            inv = deps.controller_client.create_invitation(
                deployment_site_label=deployment_site_label,
                ttl_seconds=ttl_seconds,
                idempotency_key=key,
            )
        except ManagementError as exc:
            last_reason = exc.reason_code
            if exc.reason_code in _RETRYABLE:
                continue  # re-send the IDENTICAL request (same key) — the create is idempotent
            return _refused(command, exc.reason_code)
        return EXIT_OK, {"command": command, "mode": "written", **_invitation_report(inv)}
    return _refused(command, last_reason)


def enrollment_status(deps: EnrollmentCliDeps, *, enrollment_id: str) -> tuple[int, dict]:
    """``secpctl enrollment status`` — read-only bounded status; makes no mutation."""
    command = "enrollment status"
    try:
        status = deps.controller_client.get_enrollment_status(enrollment_id=enrollment_id)
    except ManagementError as exc:
        return _refused(command, exc.reason_code)
    return EXIT_OK, {"command": command, "mode": "read", **_status_report(status)}


def enrollment_revoke(
    deps: EnrollmentCliDeps, *, enrollment_id: str, expected_revision: int, gate: WriteGate
) -> tuple[int, dict]:
    """``secpctl enrollment revoke`` — mutation; dry-run unless --write --confirm. Requires the last
    observed public revision; exact-retry safe (the controller treats a repeat as idempotent)."""
    command = "enrollment revoke"
    if not gate.is_write:
        return EXIT_OK, {
            "command": command,
            "mode": "dry_run",
            "enrollment_id": enrollment_id,
            "expected_revision": expected_revision,
        }
    try:
        status = deps.controller_client.revoke_enrollment(
            enrollment_id=enrollment_id, expected_revision=expected_revision
        )
    except ManagementError as exc:
        return _refused(command, exc.reason_code)
    return EXIT_OK, {"command": command, "mode": "written", **_status_report(status)}


# --- worker commands (PoP-authenticated; never the operator OIDC token) --------------------------


def load_invitation_file(path: str) -> dict:
    """Read + validate the non-secret invitation file the operator handed the worker. Bounded read,
    strict JSON, every required field present and a string; a malformed/oversized/unreadable file is
    a bounded closed refusal. The invitation is public — no ownership/mode hardening is required,
    but the content is strictly shaped before use."""
    if not isinstance(path, str) or not path:
        _worker_reject("secpctl_invitation_file_invalid")
    try:
        with open(path, "rb") as handle:  # noqa: PTH123 - a bounded read of a public invitation
            raw = handle.read(_MAX_INVITATION_BYTES + 1)
    except OSError:
        _worker_reject("secpctl_invitation_file_unreadable")
    if not raw or len(raw) > _MAX_INVITATION_BYTES:
        _worker_reject("secpctl_invitation_file_invalid")
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        _worker_reject("secpctl_invitation_file_invalid")
    if not isinstance(data, dict) or any(
        not isinstance(data.get(key), str) or not data[key] for key in _REQUIRED_INVITATION_KEYS
    ):
        _worker_reject("secpctl_invitation_file_invalid")
    return {key: data[key] for key in _REQUIRED_INVITATION_KEYS}


def _worker_outcome(command: str, mode: str, outcome: dict) -> tuple[int, dict]:
    report = {"command": command, "mode": mode}
    for key in ("enrollment_id", "state", "revision", "already_healthy"):
        if key in outcome:
            report[key] = outcome[key]
    return EXIT_OK, report


def _drive_worker(
    command: str, invitation_file: str, action: Callable[[dict], tuple[int, dict]]
) -> tuple[int, dict]:
    try:
        invitation = load_invitation_file(invitation_file)
        return action(invitation)
    except ManagementError as exc:
        return _refused(command, exc.reason_code)
    except Exception as exc:  # noqa: BLE001 - a driver refusal carries a bounded reason_code
        reason = getattr(exc, "reason_code", None)
        if isinstance(reason, str):
            return _refused(command, reason)
        raise


def worker_enroll(
    deps: EnrollmentCliDeps, *, invitation_file: str, gate: WriteGate
) -> tuple[int, dict]:
    """``secpctl worker enroll`` — drive the worker exchange to healthy; dry-run unless
    --write --confirm. Uses ONLY worker PoP + the signed controller offer, never the operator
    token."""
    command = "worker enroll"
    if not gate.is_write:
        return _drive_worker(
            command,
            invitation_file,
            lambda inv: (EXIT_OK, {"command": command, "mode": "dry_run"}),
        )
    return _drive_worker(
        command,
        invitation_file,
        lambda inv: _worker_outcome(
            command, "written", deps.worker_enroller.enroll(inv, now=deps.now())
        ),
    )


def worker_status(deps: EnrollmentCliDeps, *, invitation_file: str) -> tuple[int, dict]:
    """``secpctl worker enrollment status`` — read-only local reconciliation; makes no mutation and
    contacts no controller with a mutating request."""
    command = "worker enrollment status"
    return _drive_worker(
        command,
        invitation_file,
        lambda inv: _worker_outcome(command, "read", deps.worker_enroller.status(inv)),
    )


def worker_retry(
    deps: EnrollmentCliDeps, *, invitation_file: str, gate: WriteGate
) -> tuple[int, dict]:
    """``secpctl worker enrollment retry`` — resume-safe re-drive; dry-run unless --write --confirm.
    The controller treats an exact retry as idempotent."""
    command = "worker enrollment retry"
    if not gate.is_write:
        return _drive_worker(
            command,
            invitation_file,
            lambda inv: (EXIT_OK, {"command": command, "mode": "dry_run"}),
        )
    return _drive_worker(
        command,
        invitation_file,
        lambda inv: _worker_outcome(
            command, "written", deps.worker_enroller.retry(inv, now=deps.now())
        ),
    )


__all__ = [
    "EXIT_AUTH_UNAVAILABLE",
    "EXIT_CONTROLLER_UNAVAILABLE",
    "EXIT_ENROLLMENT_TERMINAL",
    "EXIT_MALFORMED",
    "EXIT_REVISION_CONFLICT",
    "EXIT_TRANSPORT",
    "EXIT_WORKER_HEALTH",
    "EnrollmentCliDeps",
    "SealedWorkerEnroller",
    "WorkerCliError",
    "WorkerEnroller",
    "enrollment_revoke",
    "enrollment_status",
    "exit_for",
    "invite_create",
    "load_invitation_file",
    "worker_enroll",
    "worker_retry",
    "worker_status",
]
