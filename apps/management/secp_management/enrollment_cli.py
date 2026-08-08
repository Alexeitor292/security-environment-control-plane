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
    "secpctl_invitation_field_too_large": EXIT_MALFORMED,
    "secpctl_invitation_ca_too_large": EXIT_MALFORMED,
    "secpctl_invitation_ca_invalid": EXIT_MALFORMED,
    "secpctl_controller_ca_unavailable": EXIT_CONTROLLER_UNAVAILABLE,
    "secpctl_controller_ca_invalid": EXIT_CONTROLLER_UNAVAILABLE,
    "enrollment_invitation_ca_missing": EXIT_MALFORMED,
    "enrollment_transport_invitation_mismatch": EXIT_TRANSPORT,
    "enrollment_ca_required": EXIT_MALFORMED,
    "enrollment_ca_invalid": EXIT_MALFORMED,
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
    # The controller CA chain travels IN the invitation (it is not in the signed release bundle and
    # not read from a deployment-local path). It MUST be required here: `load_invitation_file`
    # projects exactly `_REQUIRED_INVITATION_KEYS` and performs no unknown-key rejection, so a CA
    # that is not on this tuple parses fine and is then silently DISCARDED — surfacing much later as
    # an opaque TLS failure with nothing pointing back at the truncation.
    "controller_ca_bundle_pem",
)

# Whole-file cap. Raised from 8192 for the CA: an ordinary enterprise root+intermediate chain is
# 2.4-3.2 KB of PEM, which is exactly the `TLS_MODE_IMPORTED_ENTERPRISE` case the bound exists to
# serve, and the remaining fields already consume most of the old budget.
_MAX_INVITATION_BYTES = 16384
#: Per-field cap for every field EXCEPT the CA chain. Without a per-field bound only the whole-file
#: cap applies, so one oversized field can crowd a required field out of the budget and the failure
#: reads as a malformed file rather than as the oversized field it is.
_MAX_INVITATION_FIELD_BYTES = 1024
#: The CA chain's own bound — deliberately larger than the per-field cap, and its own reason code so
#: an oversized chain is distinguishable from an oversized identifier.
_MAX_CA_BUNDLE_BYTES = 8192

_PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
_PEM_END = "-----END CERTIFICATE-----"
#: base64 body + PEM armour + whitespace; deliberately closed (no control characters)
_PEM_BODY_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=- \r\n\t"
)

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

    def enroll(
        self, invitation: dict, *, now: str, expected_controller_key_id: str | None = None
    ) -> dict: ...
    def status(self, invitation: dict) -> dict: ...
    def retry(
        self, invitation: dict, *, now: str, expected_controller_key_id: str | None = None
    ) -> dict: ...


class SealedWorkerEnroller:
    """The shipped default: no worker enrollment driver is wired; every attempt fails closed."""

    def enroll(
        self, invitation: dict, *, now: str, expected_controller_key_id: str | None = None
    ) -> dict:
        _worker_reject("secpctl_worker_enroller_unavailable")

    def status(self, invitation: dict) -> dict:
        _worker_reject("secpctl_worker_enroller_unavailable")

    def retry(
        self, invitation: dict, *, now: str, expected_controller_key_id: str | None = None
    ) -> dict:
        _worker_reject("secpctl_worker_enroller_unavailable")


def _new_idempotency_key() -> str:
    # a cryptographically strong url-safe key (>= 128 bits) matching the API's 22..128 grammar
    return secrets.token_urlsafe(24)


def _utc_now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


class ControllerCaBundleProvider(Protocol):
    """Supplies the controller CA chain that goes INTO the invitation, as PEM text."""

    def read_pem(self) -> str: ...


class SealedControllerCaBundleProvider:
    """The shipped default: no CA source is wired, so invitation creation fails closed rather than
    emitting an invitation the worker cannot use."""

    def __repr__(self) -> str:
        return "SealedControllerCaBundleProvider(<sealed>)"

    def read_pem(self) -> str:
        _worker_reject("secpctl_controller_ca_unavailable")


class LocatorControllerCaBundleProvider:
    """Reads the controller CA chain from the BOOTSTRAP-RECORDED locator's CA path.

    This is the security-relevant choice of source. The locator is written root-gated at controller
    bootstrap with its CA path PINNED to the installer-produced bundle (never caller-supplied), and
    it is the same bundle this operator's own controller client already pins its TLS to. Sourcing
    the invitation's CA here means the chain handed to the worker is the one established
    out-of-band at install time.

    It is deliberately NOT sourced from the controller API's own response: a controller serving its
    own CA is circular — anyone able to impersonate the origin would serve their own CA with it, and
    the field would authenticate nothing.

    The read is bounded and goes through the hardened filesystem seam; the CA path never appears in
    a report, error, or repr."""

    __slots__ = ("_fs", "_locator_provider")

    def __init__(self, fs, locator_provider) -> None:
        self._fs = fs
        self._locator_provider = locator_provider

    def __repr__(self) -> str:  # never the CA path
        return "LocatorControllerCaBundleProvider(<redacted>)"

    def read_pem(self) -> str:
        try:
            locator = self._locator_provider.locate()
        except ManagementError:
            raise
        except Exception:  # noqa: BLE001 - an unavailable locator is a bounded closed refusal
            _worker_reject("secpctl_controller_ca_unavailable")
        try:
            raw = self._fs.safe_read(
                locator.ca_bundle_path, max_bytes=_MAX_CA_BUNDLE_BYTES, expected_uid=0
            )
        except Exception:  # noqa: BLE001 - never surfaces the CA path or the raw error
            _worker_reject("secpctl_controller_ca_unavailable")
        try:
            pem = raw.decode("utf-8")
        except UnicodeDecodeError:
            _worker_reject("secpctl_controller_ca_invalid")
        _validate_ca_bundle_pem(pem)  # the same grammar the worker will re-apply on load
        return pem


@dataclass
class EnrollmentCliDeps:
    """Injected collaborators for the enrollment commands. Shipped defaults are SEALED; tests inject
    fakes. No API/ORM/DB/Principal is reachable from here."""

    controller_client: EnrollmentControllerClient = field(
        default_factory=SealedEnrollmentControllerClient
    )
    worker_enroller: WorkerEnroller = field(default_factory=SealedWorkerEnroller)
    ca_bundle: ControllerCaBundleProvider = field(default_factory=SealedControllerCaBundleProvider)
    idempotency_key: Callable[[], str] = _new_idempotency_key
    now: Callable[[], str] = _utc_now


def _invitation_report(inv: ControllerInvitation, ca_bundle_pem: str) -> dict:
    """The full NON-SECRET invitation the operator hands the worker — every field the worker needs,
    none redacted, and never the idempotency key.

    ``controller_ca_bundle_pem`` is added HERE rather than coming from the controller API response:
    it is sourced from the operator's own bootstrap-recorded locator, so it is not something the
    controller asserts about itself. See :class:`LocatorControllerCaBundleProvider`. Certificates
    are public material; nothing secret is added to this report."""
    return {
        "enrollment_id": inv.enrollment_id,
        "invitation_id": inv.invitation_id,
        "controller_installation_id": inv.controller_installation_id,
        "controller_key_id": inv.controller_key_id,
        "controller_trust_anchor_hex": inv.controller_trust_anchor_hex,
        "controller_origin": inv.controller_origin,
        "controller_ca_bundle_pem": ca_bundle_pem,
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
    # Resolve the CA chain BEFORE creating anything: an invitation without it is unusable by the
    # worker, so failing here avoids burning a single-use invitation that could never be redeemed.
    try:
        ca_bundle_pem = deps.ca_bundle.read_pem()
    except ManagementError as exc:
        return _refused(command, exc.reason_code)
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
        return EXIT_OK, {
            "command": command,
            "mode": "written",
            **_invitation_report(inv, ca_bundle_pem),
        }
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


def _validate_ca_bundle_pem(value: str) -> None:
    """Bounded grammar check for the controller CA chain: a PEM CERTIFICATE chain and nothing else.

    Validating here means a malformed or wrong-kind value refuses in THIS layer, with a reason code
    naming the field, rather than reaching ``ssl.create_default_context`` and surfacing as an opaque
    TLS error at connect time. Only certificate blocks are accepted, so a private key pasted into
    the invitation is a refusal rather than material this process loads. This is a grammar gate, not
    a cryptographic validation — ``ssl`` still parses and validates the chain."""
    if len(value.encode("utf-8")) > _MAX_CA_BUNDLE_BYTES:
        _worker_reject("secpctl_invitation_ca_too_large")
    text = value.strip()
    if not text.startswith(_PEM_BEGIN) or _PEM_END not in text:
        _worker_reject("secpctl_invitation_ca_invalid")
    if text.count(_PEM_BEGIN) != text.count(_PEM_END):
        _worker_reject("secpctl_invitation_ca_invalid")
    begins = [line for line in text.splitlines() if line.strip().startswith("-----BEGIN")]
    if not begins or any(line.strip() != _PEM_BEGIN for line in begins):
        _worker_reject("secpctl_invitation_ca_invalid")  # a key or unknown block type
    if set(text) - _PEM_BODY_CHARS:
        _worker_reject("secpctl_invitation_ca_invalid")  # control characters / non-base64 body


def load_invitation_file(path: str) -> dict:
    """Read + validate the non-secret invitation file the operator handed the worker. Bounded read,
    strict JSON, every required field present and a string; a malformed/oversized/unreadable file is
    a bounded closed refusal. The invitation is public — no ownership/mode hardening is required,
    but the content is strictly shaped before use.

    Bounds are applied at THREE levels: the whole file, each ordinary field, and the CA chain (which
    has its own larger bound and its own reason codes). The per-field bound matters because the
    whole-file cap alone lets one oversized field crowd a required field out of the budget."""
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
    for key in _REQUIRED_INVITATION_KEYS:
        if key == "controller_ca_bundle_pem":
            continue  # its own larger bound + grammar, with distinguishable reason codes
        if len(data[key].encode("utf-8")) > _MAX_INVITATION_FIELD_BYTES:
            _worker_reject("secpctl_invitation_field_too_large")
    _validate_ca_bundle_pem(data["controller_ca_bundle_pem"])
    return {key: data[key] for key in _REQUIRED_INVITATION_KEYS}


def controller_key_fingerprint(controller_key_id: str) -> str:
    """A short, human-comparable rendering of the pinned controller key id.

    Displayed on first use so an operator whose invitation hand-off channel is weak can confirm the
    controller identity OUT OF BAND before the worker commits to it. Since the CA now travels in the
    invitation, this fingerprint is the value worth comparing against an independently-obtained
    copy: it is what the worker pins the controller's signed offer to."""
    body = controller_key_id.split(":", 1)[-1]
    return " ".join(body[i : i + 8] for i in range(0, min(len(body), 32), 8))


#: The controller-authoritative state a completed drive must reach.
_STATE_HEALTHY = "healthy"
#: Terminal controller states: no retry can fix these, an operator must intervene.
_TERMINAL_STATES = ("refused", "recovery_required")


def _exit_for_drive(state: object) -> int:
    """The exit code for a COMPLETED drive, from the controller's authoritative reported state.

    A drive that ends anywhere other than ``healthy`` is not a success, and must not exit 0 — an
    operator scripting ``secpctl worker enroll`` would otherwise treat a refused or
    recovery-required enrollment as a successful one. A terminal state gets the terminal category
    (no retry can fix it); an active state means the exchange stopped short, which is the
    worker-health category."""
    if state == _STATE_HEALTHY:
        return EXIT_OK
    if state in _TERMINAL_STATES:
        return EXIT_ENROLLMENT_TERMINAL
    return EXIT_WORKER_HEALTH


def _worker_outcome(
    command: str,
    mode: str,
    outcome: dict,
    *,
    controller_key_id: str | None = None,
    exit_on_state: bool = False,
) -> tuple[int, dict]:
    """Project a bounded worker outcome.

    ``exit_on_state`` is set by the DRIVING commands (enroll/retry), whose ``state`` is the
    controller's authoritative enrollment state. It is NOT set by ``status``, whose ``state`` is the
    local restart marker (``unknown``/``offer_verified``/``healthy``) — a read that reports an
    in-progress marker is a successful read, not a failed enrollment."""
    report = {"command": command, "mode": mode}
    if controller_key_id is not None:
        report["controller_key_id"] = controller_key_id
        report["controller_key_fingerprint"] = controller_key_fingerprint(controller_key_id)
    for key in ("enrollment_id", "state", "revision", "already_healthy"):
        if key in outcome:
            report[key] = outcome[key]
    if not exit_on_state:
        return EXIT_OK, report
    code = _exit_for_drive(outcome.get("state"))
    if code != EXIT_OK:
        # name the terminal/incomplete outcome so the report is actionable, not just a bare state
        report["reason_code"] = (
            f"enrollment_{outcome.get('state')}"
            if outcome.get("state") in _TERMINAL_STATES
            else "enrollment_health_incomplete"
        )
    return code, report


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


def _expected_controller_key_id(controller_trust_anchor_hex: str | None) -> str | None:
    """Derive the operator-channel controller SIGNING key id, or ``None`` if none was supplied.

    ``--controller-trust-anchor`` is a raw Ed25519 PUBLIC SIGNING key, not a TLS CA fingerprint —
    the same value ``secpctl worker install`` already requires, derived with the same primitive so
    the two paths cannot disagree about what a key id is. A malformed value yields ``None`` rather
    than a fabricated id, and the driver then refuses an unowned worker for the honest reason.
    """
    if not controller_trust_anchor_hex or not controller_trust_anchor_hex.strip():
        return None
    from secp_commissioning.enrollment_attestation import key_id_for

    try:
        return key_id_for(controller_trust_anchor_hex.strip())
    except Exception:  # noqa: BLE001 - a malformed anchor is "no independent identity supplied"
        return None


def worker_enroll(
    deps: EnrollmentCliDeps,
    *,
    invitation_file: str,
    gate: WriteGate,
    controller_trust_anchor_hex: str | None = None,
) -> tuple[int, dict]:
    """``secpctl worker enroll`` — drive the worker exchange to healthy; dry-run unless
    --write --confirm. Uses ONLY worker PoP + the signed controller offer, never the operator
    token."""
    command = "worker enroll"
    if not gate.is_write:
        # the dry run is where an operator verifies the controller identity out of band, BEFORE
        # committing the worker to it — so the fingerprint is shown here too
        return _drive_worker(
            command,
            invitation_file,
            lambda inv: (
                EXIT_OK,
                {
                    "command": command,
                    "mode": "dry_run",
                    "controller_key_id": inv["controller_key_id"],
                    "controller_key_fingerprint": controller_key_fingerprint(
                        inv["controller_key_id"]
                    ),
                },
            ),
        )
    return _drive_worker(
        command,
        invitation_file,
        lambda inv: _worker_outcome(
            command,
            "written",
            deps.worker_enroller.enroll(
                inv,
                now=deps.now(),
                expected_controller_key_id=_expected_controller_key_id(controller_trust_anchor_hex),
            ),
            controller_key_id=inv["controller_key_id"],
            exit_on_state=True,
        ),
    )


def worker_ownership_reset(deps: EnrollmentCliDeps, *, gate: WriteGate) -> tuple[int, dict]:
    """``secpctl worker ownership reset`` — release this worker so another plane may claim it.

    LOCAL and privileged. It takes no invitation, no origin and no controller-supplied argument, and
    it makes no network request: the only transfer mechanism for an owned worker is a person with
    root on the worker deciding so. A controller able to release a worker it does not own would be
    the hijack the ownership binding exists to prevent.

    Destructive, so it is dry-run unless ``--write --confirm``. It removes the binding, clears the
    retry hints and rotates the dedicated enrollment key — and deliberately touches NO Proxmox
    resource, because worker ownership and infrastructure ownership are different authority domains.
    """
    command = "worker ownership reset"
    from secp_commissioning.runtime import RealFilesystem
    from secp_worker.worker_ownership import load_worker_ownership, reset_worker_ownership

    fs = RealFilesystem()
    try:
        if not gate.is_write:
            owner = load_worker_ownership(fs)
            return EXIT_OK, {
                "command": command,
                "mode": "dry_run",
                "owned": owner is not None,
                "controller_installation_id": (
                    owner.controller_installation_id if owner is not None else ""
                ),
            }
        # `gate.is_write` is already `write AND confirm`, so both gates are proven set here.
        outcome = reset_worker_ownership(fs, write=True, confirm=True)
    except Exception as exc:  # noqa: BLE001 - bounded reason codes only
        reason = getattr(exc, "reason_code", None)
        if isinstance(reason, str):
            return _refused(command, reason)
        raise
    return EXIT_OK, {
        "command": command,
        "mode": "written",
        "ownership_removed": outcome.ownership_removed,
        "retry_hints_cleared": outcome.retry_hints_cleared,
        "enrollment_key_rotated": outcome.enrollment_key_rotated,
    }


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
    deps: EnrollmentCliDeps,
    *,
    invitation_file: str,
    gate: WriteGate,
    controller_trust_anchor_hex: str | None = None,
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
            command,
            "written",
            deps.worker_enroller.retry(
                inv,
                now=deps.now(),
                expected_controller_key_id=_expected_controller_key_id(controller_trust_anchor_hex),
            ),
            exit_on_state=True,
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
