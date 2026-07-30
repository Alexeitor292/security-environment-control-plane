"""``secpctl auth login|status|logout`` engine — SECP-PR5H-B2, Workstream C.

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
useless to anyone who cannot also authenticate to the identity provider as that operator.

**This slice cannot complete a login.** ``auth login`` runs the entire grant and verifies the
resulting token, then refuses to PERSIST it because no OS credential backend is wired
(:mod:`secp_management.operator_credential_store` ships only the sealed default). That refusal is
the designed behaviour, not a defect: there is deliberately no fallback to a file, an environment
variable, or a process-lifetime cache. See the credential-store module docstring for why the backend
is deferred to its own reviewed slice.
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
    # --- credential storage (this slice's expected terminal state) ---
    "secpctl_credential_store_unavailable": EXIT_AUTH_UNAVAILABLE,
    "secpctl_credential_account_invalid": EXIT_AUTH_UNAVAILABLE,
    "secpctl_credential_store_not_serializable": EXIT_AUTH_UNAVAILABLE,
    # --- device grant outcomes ---
    "secpctl_device_authorization_denied": EXIT_REFUSED,
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
    than implying the channel is private.
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
        "Waiting for approval...",
        "",
    ]
    sys.stderr.write("\n".join(lines) + "\n")
    sys.stderr.flush()


def _build_device_client(locator: ControllerApiLocator) -> DeviceAuthorizationClient:
    return DeviceAuthorizationClient(locator=locator)


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


def auth_login(deps: AuthCliDeps, *, gate: WriteGate) -> tuple[int, dict]:
    """``secpctl auth login`` — obtain an operator access token by OAuth 2.0 Device Authorization
    Grant (RFC 8628) and persist it in the OS credential store.

    Dry-run (the default) performs the READ-ONLY half only: it resolves the reviewed authority and
    discovers the issuer's endpoints, then reports whether the provider actually advertises the
    device grant. It never starts a grant, so it never produces a user code.

    ``--write --confirm`` runs the full grant. In THIS slice the final persist step refuses, because
    no OS credential backend is wired; the token is verified and then discarded rather than written
    to any consolation location.
    """
    command = "auth login"
    try:
        locator = deps.locator_provider.locate()
        client = deps.device_client(locator)
        authority = client.reviewed_authority()
        endpoints = client.discover(authority)

        if not gate.is_write:
            return EXIT_OK, {
                "command": command,
                "mode": "dry_run",
                "device_grant_supported": True,
                "credential_store": deps.credential_store.describe().to_report(),
            }

        authorization = client.request_device_authorization(endpoints)
        deps.present(_prompt_payload(authorization))

        token = _poll_for_token(deps, client, endpoints, authorization)
        verified = _verify(deps, client, endpoints, authority, token)

        # The one place a real backend would persist. It refuses in this slice — and there is
        # deliberately no `except` here that writes the token somewhere else instead.
        deps.credential_store.store(
            OperatorAccessToken(token), expires_at_epoch=verified.expires_at_epoch
        )
        return EXIT_OK, {
            "command": command,
            "mode": "written",
            "authenticated": True,
            "credential_store": deps.credential_store.describe().to_report(),
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
    this function only sleeps and posts."""
    scheduler = DevicePollScheduler.for_authorization(authorization)
    started = deps.monotonic()
    while True:
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
    state; it makes no mutation, starts no grant, and never prints a token.

    Resolving the authoritative operator principal from ``/api/v1/me`` lands with the credential
    backend: with the sealed store no credential can exist, so that path would be unreachable code
    in this slice. The DB remains the sole authority for organization, role and permission — a token
    claim never determines them.
    """
    command = "auth status"
    try:
        status = deps.credential_store.describe()
    except ManagementError as exc:
        return _refused(command, exc.reason_code)
    return EXIT_OK, {"command": command, "mode": "read", **status.to_report()}


def auth_logout(deps: AuthCliDeps, *, gate: WriteGate) -> tuple[int, dict]:
    """``secpctl auth logout`` — delete ONLY credential material this store owns. Dry-run unless
    ``--write --confirm``. It never touches an unrelated OS keyring entry and never revokes anything
    server-side (revocation is the identity provider's surface, not secpctl's)."""
    command = "auth logout"
    if not gate.is_write:
        try:
            status = deps.credential_store.describe()
        except ManagementError as exc:
            return _refused(command, exc.reason_code)
        return EXIT_OK, {"command": command, "mode": "dry_run", **status.to_report()}
    try:
        removed = deps.credential_store.delete()
    except ManagementError as exc:
        return _refused(command, exc.reason_code)
    return EXIT_OK, {"command": command, "mode": "written", "removed": bool(removed)}


__all__ = [
    "EXIT_AUTH_UNAVAILABLE",
    "EXIT_CONTROLLER_UNAVAILABLE",
    "EXIT_MALFORMED",
    "EXIT_TRANSPORT",
    "AuthCliDeps",
    "auth_login",
    "auth_logout",
    "auth_status",
    "exit_for",
    "present_device_prompt",
]
