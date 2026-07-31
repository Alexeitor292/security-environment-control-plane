"""``secpctl auth login|status|refresh|logout`` engine — SECP-PR5H-B2, Workstream C.

The operator-authentication command engine. It composes ONLY management-plane collaborators — the
bootstrap-recorded controller locator, the hardened device-auth client, the pure RFC 8628 scheduler,
the pure token verifier, and the credential store — never ``secp_api``, an ORM, a service, a
database session, or an internal ``Principal``. Human-readable and ``--json`` output call THIS same
engine; the CLI only formats.

Every result is a bounded ``(exit_code, report)`` pair with a stable exit category and a
deterministic, SECRET-FREE report. A report never carries an access token, a device code, a bearer
header, a CA path, a controller origin, an issuer, a provider response body, or an exception chain.
The ``user_code`` and ``verification_uri`` ARE emitted — they are the operator-facing values the
grant exists to display, and the flow cannot work without them — but they are short-lived and
useless to anyone who cannot also authenticate to the identity provider as that operator. The
credential ACCOUNT (a controller's canonical origin) is emitted only as a non-reversing fingerprint,
so ``--json`` output pasted into a ticket does not carry a deployment's address.

Three properties are worth stating because they are easy to lose in a later edit:

* **The account is derived, never chosen.** It comes from the reviewed controller locator, so a
  credential minted against one controller can never be selected for another, and there is no
  ``--account`` / ``--controller`` flag to smuggle an identity in through.
* **Polling is bounded three ways** — the provider's ``interval`` (with the permanent ``slow_down``
  increase), a LOCAL deadline from ``expires_in``, and an attempt budget — and is additionally
  cancellable, so neither a hostile provider nor an inattentive operator can pin the CLI.
* **Persistence is the last step and has no alternative.** The token is verified before it is
  offered to the store, and a store that refuses ends the command. There is deliberately no
  ``except`` around the persist call that writes the token somewhere else instead.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from secp_management import ManagementError
from secp_management.controller_api_locator import (
    ControllerApiLocator,
    ControllerApiLocatorProvider,
    SealedControllerApiLocatorProvider,
)
from secp_management.device_grant import (
    ACTION_STOP,
    DeviceAuthorization,
    DevicePollScheduler,
)
from secp_management.operator_auth import OperatorAccessToken
from secp_management.operator_credential_store import (
    OperatorCredentialStore,
    SealedOperatorCredentialStore,
    StoredCredentialStatus,
    account_fingerprint,
    account_for_controller,
    subject_fingerprint,
)
from secp_management.operator_device_auth import DeviceAuthorizationClient
from secp_management.operator_token_verify import jwks_by_kid, verify_operator_token
from secp_management.transaction import EXIT_OK, EXIT_REFUSED, WriteGate

# Stable exit categories. These MIRROR ``enrollment_cli``'s categories by value so a single operator
# script can interpret every secpctl exit uniformly. They are restated rather than imported so this
# module does not couple to a file under concurrent change; ``test_auth_cli`` asserts the two
# definitions agree, the same "same literal, no import, agreement asserted by test" idiom the
# repository already uses for the Alembic head across planes.
EXIT_AUTH_UNAVAILABLE = 3
EXIT_CONTROLLER_UNAVAILABLE = 4
EXIT_TRANSPORT = 5
EXIT_MALFORMED = 7

_EXIT_BY_REASON: dict[str, int] = {
    # --- credential storage ---
    "secpctl_credential_store_unavailable": EXIT_AUTH_UNAVAILABLE,
    "secpctl_credential_store_locked": EXIT_AUTH_UNAVAILABLE,
    "secpctl_credential_account_invalid": EXIT_AUTH_UNAVAILABLE,
    "secpctl_credential_store_not_serializable": EXIT_AUTH_UNAVAILABLE,
    "secpctl_credential_absent": EXIT_AUTH_UNAVAILABLE,
    "secpctl_credential_expired": EXIT_AUTH_UNAVAILABLE,
    "secpctl_credential_account_mismatch": EXIT_AUTH_UNAVAILABLE,
    "secpctl_credential_backend_failed": EXIT_AUTH_UNAVAILABLE,
    "secpctl_credential_too_large": EXIT_AUTH_UNAVAILABLE,
    "secpctl_credential_subject_changed": EXIT_REFUSED,
    "secpctl_credential_record_invalid": EXIT_MALFORMED,
    # --- device grant outcomes ---
    "secpctl_device_authorization_denied": EXIT_REFUSED,
    "secpctl_device_authorization_cancelled": EXIT_REFUSED,
    "secpctl_device_code_expired": EXIT_AUTH_UNAVAILABLE,
    "secpctl_device_poll_exhausted": EXIT_AUTH_UNAVAILABLE,
    "secpctl_device_grant_unsupported": EXIT_AUTH_UNAVAILABLE,
    "secpctl_device_authorization_refused": EXIT_AUTH_UNAVAILABLE,
    "secpctl_device_authority_not_oidc": EXIT_AUTH_UNAVAILABLE,
    # --- token verification ---
    "secpctl_operator_token_expired": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_token_invalid": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_token_signature_invalid": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_token_algorithm_refused": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_token_claims_invalid": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_token_key_unknown": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_token_jwks_invalid": EXIT_MALFORMED,
    # --- controller / provider reachability ---
    "secpctl_controller_locator_unavailable": EXIT_CONTROLLER_UNAVAILABLE,
    "secpctl_controller_locator_invalid": EXIT_CONTROLLER_UNAVAILABLE,
    "secpctl_controller_unavailable": EXIT_CONTROLLER_UNAVAILABLE,
    "secpctl_device_provider_unavailable": EXIT_CONTROLLER_UNAVAILABLE,
    "secpctl_controller_transport_failed": EXIT_TRANSPORT,
    # --- malformed ---
    "secpctl_controller_response_invalid": EXIT_MALFORMED,
    "secpctl_device_authority_invalid": EXIT_MALFORMED,
    "secpctl_device_discovery_invalid": EXIT_MALFORMED,
    "secpctl_device_authorization_invalid": EXIT_MALFORMED,
    "secpctl_device_token_refused": EXIT_MALFORMED,
    "secpctl_device_code_not_serializable": EXIT_MALFORMED,
    "secpctl_device_client_not_serializable": EXIT_MALFORMED,
}


def exit_for(reason_code: str) -> int:
    return _EXIT_BY_REASON.get(reason_code, EXIT_REFUSED)


def _refused(command: str, reason_code: str) -> tuple[int, dict]:
    return exit_for(reason_code), {"command": command, "reason_code": reason_code}


def present_device_prompt(prompt: dict) -> None:
    """The default operator-facing presenter for the device grant.

    RFC 8628 §5.4 recommends telling the operator they are authorizing a DEVICE and confirming it is
    the one in front of them. §5.5 notes the code is displayed in whatever environment the tool runs
    in — on a shared or recorded terminal it is observable, so the wording says so plainly rather
    than implying the channel is private. It also tells the operator how to abandon the grant, which
    is the cancellation path ``_poll_for_token`` honours.
    """
    import sys

    lines = [
        "",
        "secpctl is requesting operator authorization for THIS machine.",
        "Approve it only if you started this command yourself.",
        "",
        f"  1. Open: {prompt['verification_uri']}",
        f"  2. Enter code: {prompt['user_code']}",
    ]
    complete = prompt.get("verification_uri_complete")
    if complete:
        lines.append(f"     (or open directly: {complete})")
    lines += [
        "",
        f"  This code expires in {prompt['expires_in']}s. Anyone who can see this terminal",
        "  can see the code, so do not share your screen while it is displayed.",
        "",
        "Waiting for approval... (press Ctrl-C to cancel; nothing is stored until you approve)",
        "",
    ]
    sys.stderr.write("\n".join(lines) + "\n")
    sys.stderr.flush()


def _build_device_client(locator: ControllerApiLocator) -> DeviceAuthorizationClient:
    return DeviceAuthorizationClient(locator=locator)


def _never_cancelled() -> bool:
    """The default cooperative-cancellation probe: nothing cancels a grant on its own."""
    return False


@dataclass
class AuthCliDeps:
    """Injected collaborators for the auth commands. Shipped defaults are SEALED; tests inject
    fakes. No API/ORM/DB/Principal is reachable from here."""

    credential_store: OperatorCredentialStore = field(default_factory=SealedOperatorCredentialStore)
    locator_provider: ControllerApiLocatorProvider = field(
        default_factory=SealedControllerApiLocatorProvider
    )
    device_client: Callable[[ControllerApiLocator], DeviceAuthorizationClient] = (
        _build_device_client
    )
    present: Callable[[dict], None] = present_device_prompt
    sleep: Callable[[float], None] = time.sleep
    monotonic: Callable[[], float] = time.monotonic
    now_epoch: Callable[[], float] = time.time
    cancelled: Callable[[], bool] = _never_cancelled


@dataclass(frozen=True)
class _Selection:
    """The controller this invocation acts on and the credential store bound to its account."""

    locator: ControllerApiLocator
    account: str
    store: OperatorCredentialStore


def _select(deps: AuthCliDeps) -> _Selection:
    """Resolve the reviewed controller and bind the credential store to ITS account.

    This is the multi-controller selection point, and it is the ONLY one: the account comes from the
    bootstrap-recorded locator, so no flag, environment variable or provider response can steer a
    command at a different controller's credential.
    """
    locator = deps.locator_provider.locate()
    account = account_for_controller(locator)
    return _Selection(
        locator=locator, account=account, store=deps.credential_store.for_account(account)
    )


def _prompt_payload(authorization: DeviceAuthorization) -> dict:
    """The operator-facing prompt. It carries the user code and verification URI (the grant's whole
    purpose) and NEVER the device code, which is the bearer half of the exchange."""
    payload = {
        "user_code": authorization.user_code,
        "verification_uri": authorization.verification_uri,
        "expires_in": authorization.expires_in,
        "interval": authorization.interval,
    }
    if authorization.verification_uri_complete:
        payload["verification_uri_complete"] = authorization.verification_uri_complete
    return payload


def _credential_report(account: str, status: StoredCredentialStatus) -> dict:
    """The bounded credential facts every auth report carries. The account appears ONLY as a
    non-reversing fingerprint, never as the controller's origin."""
    return {
        "account": account_fingerprint(account) if account else "",
        "account_selected": bool(account),
        "credential_subject": status.subject_fingerprint,
        **status.to_report(),
    }


def _discover(deps: AuthCliDeps, locator: ControllerApiLocator) -> tuple[Any, Any, Any]:
    """The READ-ONLY half of the grant: the reviewed authority and the issuer's endpoints."""
    client = deps.device_client(locator)
    authority = client.reviewed_authority()
    return client, authority, client.discover(authority)


def _authenticate(
    deps: AuthCliDeps, client: Any, endpoints: Any, authority: Any
) -> tuple[str, Any]:
    """Run the interactive grant and VERIFY the issued token. Returns ``(token, verified)``.

    Verification happens here, before the caller can reach a store, so no caller can persist an
    unverified token by forgetting a step (ADR-028 §3).
    """
    authorization = client.request_device_authorization(endpoints)
    deps.present(_prompt_payload(authorization))
    token = _poll_for_token(deps, client, endpoints, authorization)
    return token, _verify(deps, client, endpoints, authority, token)


def auth_login(deps: AuthCliDeps, *, gate: WriteGate) -> tuple[int, dict]:
    """``secpctl auth login`` — obtain an operator access token by OAuth 2.0 Device Authorization
    Grant (RFC 8628) and persist it in the OS credential store for THIS controller's account.

    Dry-run (the default) performs the READ-ONLY half only: it resolves the reviewed authority and
    discovers the issuer's endpoints, then reports whether the provider actually advertises the
    device grant. It never starts a grant, so it never produces a user code.

    ``--write --confirm`` runs the full grant, verifies the token, and offers it to the store. When
    no OS keystore is available the store refuses and the token is discarded — there is deliberately
    no fallback location.
    """
    command = "auth login"
    try:
        selection = _select(deps)
        client, authority, endpoints = _discover(deps, selection.locator)

        if not gate.is_write:
            return EXIT_OK, {
                "command": command,
                "mode": "dry_run",
                "device_grant_supported": bool(endpoints.device_authorization_endpoint),
                **_credential_report(selection.account, selection.store.describe()),
            }

        token, verified = _authenticate(deps, client, endpoints, authority)

        # The one place the token is persisted. There is deliberately no `except` here that writes
        # it somewhere else instead: a store that refuses ends the command.
        selection.store.store(
            OperatorAccessToken(token),
            expires_at_epoch=verified.expires_at_epoch,
            subject_fingerprint=subject_fingerprint(verified.subject),
        )
        return EXIT_OK, {
            "command": command,
            "mode": "written",
            "authenticated": True,
            **_credential_report(selection.account, selection.store.describe()),
        }
    except ManagementError as exc:
        return _refused(command, exc.reason_code)


def auth_refresh(deps: AuthCliDeps, *, gate: WriteGate) -> tuple[int, dict]:
    """``secpctl auth refresh`` — renew THIS controller's stored operator credential.

    Renewal re-runs the device grant rather than redeeming an OAuth refresh token, and that is a
    deliberate posture, not an omission: ``secp-cli`` is a PUBLIC client with ``use.refresh.tokens``
    explicitly off and the CLI never requests ``offline_access``, mirroring the browser posture
    ADR-018 established. A long-lived renewal credential sitting in an operator's keystore is a much
    larger blast radius than a short-lived access token that expires on its own.

    It refuses when there is nothing to renew, and it refuses when the renewed token belongs to a
    DIFFERENT operator than the stored one — a refresh must never silently switch identity.
    """
    command = "auth refresh"
    try:
        selection = _select(deps)
        current = selection.store.describe()
        if not current.has_credential:
            return _refused(command, "secpctl_credential_absent")

        if not gate.is_write:
            return EXIT_OK, {
                "command": command,
                "mode": "dry_run",
                "renewal_required": current.expired,
                **_credential_report(selection.account, current),
            }

        client, authority, endpoints = _discover(deps, selection.locator)
        token, verified = _authenticate(deps, client, endpoints, authority)
        fingerprint = subject_fingerprint(verified.subject)
        if current.subject_fingerprint and fingerprint != current.subject_fingerprint:
            return _refused(command, "secpctl_credential_subject_changed")

        selection.store.store(
            OperatorAccessToken(token),
            expires_at_epoch=verified.expires_at_epoch,
            subject_fingerprint=fingerprint,
        )
        return EXIT_OK, {
            "command": command,
            "mode": "written",
            "authenticated": True,
            **_credential_report(selection.account, selection.store.describe()),
        }
    except ManagementError as exc:
        return _refused(command, exc.reason_code)


def _poll_for_token(
    deps: AuthCliDeps,
    client: DeviceAuthorizationClient,
    endpoints: Any,
    authorization: DeviceAuthorization,
) -> str:
    """Drive the RFC 8628 §3.5 poll loop. Every scheduling decision comes from the PURE scheduler;
    this function only sleeps, posts, and honours cancellation.

    The authoritative wait is ``next_attempt``'s, which re-reads the CURRENT interval including
    every permanent ``slow_down`` increase. ``record_error`` reports the same number for the same
    schedule — ``test_device_grant`` pins that they never diverge — so reading one and not the
    other cannot silently poll faster than the provider licensed.

    Cancellation is honoured in TWO forms: a cooperative probe checked before every attempt, and a
    ``KeyboardInterrupt`` from the operator's terminal. Both end the grant with a bounded reason and
    leave nothing persisted, because persistence is the caller's next step and is never reached.
    """
    scheduler = DevicePollScheduler.for_authorization(authorization)
    started = deps.monotonic()
    try:
        while True:
            if deps.cancelled():
                raise ManagementError("secpctl_device_authorization_cancelled")
            decision = scheduler.next_attempt(elapsed_seconds=deps.monotonic() - started)
            if decision.action == ACTION_STOP:
                raise ManagementError(decision.reason_code)
            deps.sleep(decision.wait_seconds)
            token, error = client.request_token(endpoints, authorization.device_code)
            if not error:
                return token
            decision = scheduler.record_error(error)
            if decision.action == ACTION_STOP:
                raise ManagementError(decision.reason_code)
    except KeyboardInterrupt:
        # `from None` so there is no traceback chain: a Ctrl-C is a bounded outcome, not a crash.
        raise ManagementError("secpctl_device_authorization_cancelled") from None


def _verify(
    deps: AuthCliDeps,
    client: DeviceAuthorizationClient,
    endpoints: Any,
    authority: Any,
    token: str,
) -> Any:
    """Verify the issued token against the reviewed issuer's JWKS BEFORE it is offered for storage
    (ADR-028 §3). An unverifiable token is never persisted and never returned."""
    jwks = jwks_by_kid(client.fetch_jwks(endpoints))
    return verify_operator_token(
        token,
        jwks=jwks,
        issuer=authority.issuer,
        audience=authority.audience,
        now_epoch=deps.now_epoch(),
    )


def auth_status(deps: AuthCliDeps) -> tuple[int, dict]:
    """``secpctl auth status`` — read-only. Reports the credential store's bounded, secret-free
    state for the selected controller; it makes no mutation, starts no grant, opens no socket, and
    never prints a token.

    An UNRECORDED locator is not an error here: the backend is still reportable, and "a keystore is
    available but no controller is selected" is exactly what an operator needs to see on a host that
    has not been bootstrapped yet.

    Resolving the authoritative operator principal from ``/api/v1/me`` remains out of scope: the DB
    is the sole authority for organization, role and permission, and a token claim never determines
    them. This command reports LOCAL credential state only.
    """
    command = "auth status"
    try:
        selection = _select(deps)
    except ManagementError:
        backend = _describe_unbound(deps)
        return EXIT_OK, {"command": command, "mode": "read", **_credential_report("", backend)}
    try:
        status = selection.store.describe()
    except ManagementError as exc:
        return _refused(command, exc.reason_code)
    return EXIT_OK, {
        "command": command,
        "mode": "read",
        **_credential_report(selection.account, status),
    }


def _describe_unbound(deps: AuthCliDeps) -> StoredCredentialStatus:
    """The backend's own state, with no controller selected. ``describe`` is specified never to
    raise, but a third-party store is not this module's to trust, so a refusal degrades to the
    sealed projection rather than escaping as an unbounded failure."""
    try:
        return deps.credential_store.describe()
    except ManagementError:
        return StoredCredentialStatus(backend="sealed", available=False)


def auth_logout(deps: AuthCliDeps, *, gate: WriteGate) -> tuple[int, dict]:
    """``secpctl auth logout`` — delete ONLY the credential material this store owns for THIS
    controller's account. Dry-run unless ``--write --confirm``. It never touches an unrelated OS
    keyring entry, never touches another controller's account, and never revokes anything
    server-side (revocation is the identity provider's surface, not secpctl's)."""
    command = "auth logout"
    try:
        selection = _select(deps)
        if not gate.is_write:
            return EXIT_OK, {
                "command": command,
                "mode": "dry_run",
                **_credential_report(selection.account, selection.store.describe()),
            }
        removed = selection.store.delete()
        return EXIT_OK, {
            "command": command,
            "mode": "written",
            "removed": bool(removed),
            "account": account_fingerprint(selection.account),
        }
    except ManagementError as exc:
        return _refused(command, exc.reason_code)


__all__ = [
    "EXIT_AUTH_UNAVAILABLE",
    "EXIT_CONTROLLER_UNAVAILABLE",
    "EXIT_MALFORMED",
    "EXIT_TRANSPORT",
    "AuthCliDeps",
    "auth_login",
    "auth_logout",
    "auth_refresh",
    "auth_status",
    "exit_for",
    "present_device_prompt",
]
