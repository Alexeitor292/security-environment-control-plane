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
* **Persistence is the last step and has no alternative.** The token is verified and resolved by
  the controller's authoritative ``/api/v1/me`` before it is offered to the store. An unavailable
  store refuses before issuance; a post-issuance refusal best-effort revokes only the new token.
  There is deliberately no fallback location.
* **Logout covers every known source.** It reads an explicitly configured protected token file and
  the selected OS-store generation independently, deduplicates an identical token, and asks the
  issuer to revoke every unique readable token before deleting only the exact OS generation it
  owns. The user-managed file and any concurrent OS replacement are retained.
"""

from __future__ import annotations

import secrets
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
from secp_management.operator_auth import (
    OperatorAccessToken,
    OperatorAccessTokenProvider,
    SealedOperatorAccessTokenProvider,
)
from secp_management.operator_credential_store import (
    CredentialMutationResult,
    CredentialSnapshot,
    OperatorCredentialStore,
    SealedOperatorCredentialStore,
    StoredCredentialStatus,
    account_fingerprint,
    account_for_controller,
    subject_fingerprint,
)
from secp_management.operator_device_auth import (
    OPERATOR_CLI_CLIENT_ID,
    DeviceAuthorizationClient,
    ResolvedOperatorPrincipal,
)
from secp_management.operator_token_revoke import (
    OUTCOME_CONCURRENT_REPLACEMENT,
    OUTCOME_PARTIAL,
    OUTCOME_REFUSED,
    OUTCOME_REVOKED,
    OUTCOME_UNAVAILABLE,
    OUTCOME_UNSUPPORTED,
    RevocationOutcome,
    revocation_credential_unreadable,
    revocation_not_required,
)
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
    "secpctl_credential_generation_changed": EXIT_REFUSED,
    "secpctl_credential_lock_unavailable": EXIT_AUTH_UNAVAILABLE,
    "secpctl_credential_record_invalid": EXIT_MALFORMED,
    # --- device grant outcomes ---
    "secpctl_device_authorization_denied": EXIT_REFUSED,
    "secpctl_device_authorization_cancelled": EXIT_REFUSED,
    "secpctl_device_code_expired": EXIT_AUTH_UNAVAILABLE,
    "secpctl_device_poll_exhausted": EXIT_AUTH_UNAVAILABLE,
    "secpctl_device_grant_unsupported": EXIT_AUTH_UNAVAILABLE,
    "secpctl_device_authorization_refused": EXIT_AUTH_UNAVAILABLE,
    "secpctl_device_authority_not_oidc": EXIT_AUTH_UNAVAILABLE,
    "secpctl_device_refresh_token_unexpected": EXIT_REFUSED,
    # --- granted scope (a provider that widened or narrowed the grant) ---
    "secpctl_device_scope_refused": EXIT_REFUSED,
    "secpctl_device_scope_insufficient": EXIT_AUTH_UNAVAILABLE,
    "secpctl_device_scope_invalid": EXIT_MALFORMED,
    # --- token verification ---
    "secpctl_operator_token_expired": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_token_invalid": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_token_unsafe": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_auth_unavailable": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_token_signature_invalid": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_token_algorithm_refused": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_token_claims_invalid": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_token_client_invalid": EXIT_REFUSED,
    "secpctl_operator_token_key_unknown": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_token_jwks_invalid": EXIT_MALFORMED,
    # --- authoritative controller principal resolution ---
    "secpctl_operator_principal_unavailable": EXIT_AUTH_UNAVAILABLE,
    "secpctl_operator_principal_invalid": EXIT_MALFORMED,
    # --- revocation (RFC 7009). These never fail the command — logout deletes locally regardless —
    # but they are categorised so a reason code that DOES surface has a stable exit.
    "secpctl_revocation_provider_unavailable": EXIT_CONTROLLER_UNAVAILABLE,
    "secpctl_revocation_unsupported_token_type": EXIT_AUTH_UNAVAILABLE,
    "secpctl_revocation_endpoint_absent": EXIT_AUTH_UNAVAILABLE,
    "secpctl_revocation_refused": EXIT_REFUSED,
    "secpctl_revocation_token_invalid": EXIT_MALFORMED,
    "secpctl_revocation_request_invalid": EXIT_MALFORMED,
    "secpctl_revocation_response_invalid": EXIT_MALFORMED,
    # NOTE: there is deliberately NO `secpctl_revocation_credential_unreadable` entry.
    # `revocation_credential_unreadable()` carries the STORE's own reason code through unchanged
    # (`secpctl_credential_record_invalid`, `..._account_mismatch`, `..._store_locked`,
    # `..._backend_failed`), each of which is already mapped above and is strictly more informative
    # than a generic one would be. A dedicated code here would never fire, and a code that never
    # fires is worse than absent: a later reader could map or match on it and never know why.
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


#: Stable, secret-free remedies for the refusals an operator can actually DO something about. A
#: bounded reason code says what failed; without this it never says what to do next — and these are
#: reached after an interactive approval, where "exit 3" alone strands the operator.
_REMEDY_BY_REASON: dict[str, str] = {
    "secpctl_credential_too_large": (
        "the issued token is larger than an OS keystore record can hold; disable the 'roles' "
        "client scope on the secp-cli client (or trim realm/resource role claims) and retry"
    ),
    "secpctl_credential_store_unavailable": (
        "no OS keystore is reachable; enable one (Windows Credential Manager, macOS Keychain, or a "
        "freedesktop Secret Service) and retry — secpctl will not store a token anywhere else"
    ),
    "secpctl_credential_store_locked": ("the OS keyring is locked; unlock it and retry"),
    "secpctl_revocation_endpoint_absent": (
        "the identity provider advertises no RFC 7009 revocation endpoint; this token stays valid "
        "until it expires and cannot be revoked from here"
    ),
    "secpctl_credential_record_invalid": (
        "the credential record is invalid and secpctl cannot verify a generation it owns; remove "
        "the secp-secpctl-operator entry with the OS keystore's own tooling, then run "
        "'secpctl auth login' again"
    ),
    "secpctl_credential_account_mismatch": (
        "the keystore entry belongs to a different controller and was not used; run "
        "'secpctl auth login' again for this controller"
    ),
    "secpctl_credential_generation_changed": (
        "the credential changed in another secpctl process; inspect auth status and retry"
    ),
}


def exit_for(reason_code: str) -> int:
    return _EXIT_BY_REASON.get(reason_code, EXIT_REFUSED)


def _bounded_reason(reason_code: object, fallback: str) -> str:
    """Accept only this module's closed reason vocabulary at a report boundary."""
    return (
        reason_code if isinstance(reason_code, str) and reason_code in _EXIT_BY_REASON else fallback
    )


def _with_remedy(report: dict, reason_code: str) -> dict:
    """Attach the actionable remedy for ``reason_code``, when one exists.

    The remedy is a fixed, code-owned string keyed by the bounded reason code — it never embeds a
    value from the environment, the provider, or the failure itself, so it cannot leak.
    """
    remedy = _REMEDY_BY_REASON.get(reason_code)
    if remedy:
        report["remedy"] = remedy
    return report


def _refused(command: str, reason_code: str) -> tuple[int, dict]:
    return exit_for(reason_code), _with_remedy(
        {"command": command, "reason_code": reason_code}, reason_code
    )


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


def _token_file_unknown() -> bool | None:
    """The shipped default: it is NOT KNOWN which provider authenticated commands will use.

    Deliberately not ``False``. ``False`` is the reassuring answer — "the keystore is live" — and
    the sealed default is reached exactly when deps composition FAILED, which is when that claim is
    least justified. Reporting the comfortable value for an unknown is the same defect as reporting
    "nothing to revoke" for a credential that merely could not be read.
    """
    return None


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
    #: Whether the protected token FILE seam is currently selected for AUTHENTICATED commands.
    #: Injected rather than read here: this module must never touch the environment (the credential
    #: surface is scanned for that), and the env read already lives in ``cli.py`` where the token
    #: provider is composed. See :func:`auth_status` for why it is reported.
    token_file_active: Callable[[], bool | None] = _token_file_unknown
    #: The exact token-file provider selected by production composition. It is consulted only when
    #: the probe above says that provider is selected; the sealed default exposes no credential.
    token_file_provider: OperatorAccessTokenProvider = field(
        default_factory=SealedOperatorAccessTokenProvider
    )


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


#: The provider an AUTHENTICATED command will use, as reported by ``auth status``.
PROVIDER_OS_KEYSTORE = "os_keystore"
PROVIDER_TOKEN_FILE = "token_file"
PROVIDER_UNAVAILABLE = "unavailable"
#: The probe did not run, or the deps did not compose — so which provider is live is NOT KNOWN.
PROVIDER_UNKNOWN = "unknown"


def _active_provider_report(deps: AuthCliDeps, status: StoredCredentialStatus) -> dict:
    """Name the provider authenticated commands will actually use, and flag a silent override.

    ``token_file_override_active`` is the operator-facing warning: when it is true, ``auth login``
    can succeed and store a perfectly good credential that NOTHING will use, because the explicitly
    selected token file wins. Without this the two facts never appear together.

    A failed probe means UNKNOWN; a validated absent override plus an unavailable store means
    UNAVAILABLE. Neither may report ``os_keystore`` — the reassuring answer — because that is a
    positive claim made precisely when no usable keystore exists. ``token_file_override_active`` is
    omitted when unknown so no boolean can be read as a settled answer.
    """
    try:
        file_active = deps.token_file_active()
    except Exception:  # noqa: BLE001 - a broken probe must not break a read-only status
        file_active = None
    if file_active is None:
        return {"active_token_provider": PROVIDER_UNKNOWN}
    if not file_active and not status.available:
        return {
            "active_token_provider": PROVIDER_UNAVAILABLE,
            "token_file_override_active": False,
        }
    return {
        "active_token_provider": PROVIDER_TOKEN_FILE if file_active else PROVIDER_OS_KEYSTORE,
        "token_file_override_active": bool(file_active),
    }


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


def _issue_token(deps: AuthCliDeps, client: Any, endpoints: Any) -> str:
    """Run the interactive grant and return its newly issued raw bearer to the immediate caller."""
    authorization = client.request_device_authorization(endpoints)
    deps.present(_prompt_payload(authorization))
    return _poll_for_token(deps, client, endpoints, authorization)


def _verify_and_resolve_issued_token(
    deps: AuthCliDeps,
    client: Any,
    endpoints: Any,
    authority: Any,
    raw_token: str,
) -> tuple[OperatorAccessToken, Any, ResolvedOperatorPrincipal]:
    """Verify an issued token and resolve its authoritative controller principal.

    The raw token remains with the caller so ANY refusal here can compensate by revoking that exact
    newly issued credential. Token claims never supply organization or permissions.
    """
    verified = _verify(deps, client, endpoints, authority, raw_token)
    token = OperatorAccessToken(raw_token)
    principal = client.resolve_principal(token)
    return token, verified, principal


def _compensate_issued_refusal(
    command: str,
    reason_code: str,
    *,
    client: Any,
    endpoints: Any,
    raw_token: str,
) -> tuple[int, dict]:
    """Best-effort revoke a newly issued token that the command cannot safely retain.

    This never deletes or overwrites an existing local credential. If revocation cannot be
    established, the outstanding live-token reason becomes primary while the original bounded
    refusal is retained separately.
    """
    try:
        outcome = client.revoke_token(endpoints, raw_token)
    except ManagementError as exc:
        outcome = RevocationOutcome(OUTCOME_UNAVAILABLE, reason_code=exc.reason_code)
    except Exception:  # noqa: BLE001 - compensation never leaks token/provider/exception detail
        outcome = RevocationOutcome(
            OUTCOME_UNAVAILABLE,
            reason_code="secpctl_revocation_provider_unavailable",
        )

    primary_reason = reason_code
    report = {
        "command": command,
        "credential_stored": False,
        **outcome.to_report(),
    }
    if outcome.token_still_live:
        report["credential_refusal_reason_code"] = reason_code
        primary_reason = outcome.reason_code or "secpctl_revocation_refused"
    report["reason_code"] = primary_reason
    return exit_for(primary_reason), _with_remedy(report, primary_reason)


def auth_login(deps: AuthCliDeps, *, gate: WriteGate) -> tuple[int, dict]:
    """``secpctl auth login`` — obtain an operator access token by OAuth 2.0 Device Authorization
    Grant (RFC 8628) and persist it in the OS credential store for THIS controller's account.

    Dry-run (the default) performs the READ-ONLY half only: it resolves the reviewed authority and
    discovers the issuer's endpoints, then reports whether the provider actually advertises the
    device grant. It never starts a grant, so it never produces a user code.

    ``--write --confirm`` first requires an available store, then runs the full grant, verifies the
    token, resolves its controller principal, and offers it to the store. A refusal after issuance
    best-effort revokes that new token; there is deliberately no fallback location.
    """
    command = "auth login"
    try:
        selection = _select(deps)
        status = selection.store.describe()
        if gate.is_write and not status.available:
            # Do not mint a live provider credential when there is nowhere safe to retain it.
            return _refused(
                command,
                status.unavailable_reason or "secpctl_credential_store_unavailable",
            )
        expected_generation: str | None = None
        if gate.is_write:
            before_grant = selection.store.snapshot()
            expected_generation = None if before_grant is None else before_grant.generation
        client, authority, endpoints = _discover(deps, selection.locator)

        if not gate.is_write:
            return EXIT_OK, {
                "command": command,
                "mode": "dry_run",
                "device_grant_supported": bool(endpoints.device_authorization_endpoint),
                **_credential_report(selection.account, status),
            }

        raw_token = _issue_token(deps, client, endpoints)
        try:
            token, verified, principal = _verify_and_resolve_issued_token(
                deps, client, endpoints, authority, raw_token
            )

            # The one place the token is persisted. There is deliberately no fallback location.
            persist_result = selection.store.compare_and_store(
                expected_generation,
                token,
                expires_at_epoch=verified.expires_at_epoch,
                subject_fingerprint=subject_fingerprint(verified.subject),
            )
            if persist_result is not CredentialMutationResult.STORED:
                return _compensate_issued_refusal(
                    command,
                    "secpctl_credential_generation_changed",
                    client=client,
                    endpoints=endpoints,
                    raw_token=raw_token,
                )
        except ManagementError as exc:
            return _compensate_issued_refusal(
                command,
                exc.reason_code,
                client=client,
                endpoints=endpoints,
                raw_token=raw_token,
            )
        return EXIT_OK, {
            "command": command,
            "mode": "written",
            "authenticated": True,
            **principal.to_report(),
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
        if not current.available:
            # ``describe`` is intentionally non-raising, but refresh must not turn "could not read
            # the keyring" into "no credential exists". Preserve the exact bounded store refusal
            # captured by the status projection; third-party stores without one fail closed to the
            # generic unavailable reason.
            return _refused(
                command,
                current.unavailable_reason or "secpctl_credential_store_unavailable",
            )
        if not current.has_credential:
            return _refused(command, "secpctl_credential_absent")

        if not gate.is_write:
            return EXIT_OK, {
                "command": command,
                "mode": "dry_run",
                "renewal_required": current.expired,
                **_credential_report(selection.account, current),
            }

        before_grant = selection.store.snapshot()
        if before_grant is None:
            return _refused(command, "secpctl_credential_absent")
        if not before_grant.subject_fingerprint:
            # Refresh is an identity-preserving replacement, so a legacy/corrupt record without the
            # only stored identity binding cannot safely authorize an overwrite.
            return _refused(command, "secpctl_credential_record_invalid")

        client, authority, endpoints = _discover(deps, selection.locator)
        raw_token = _issue_token(deps, client, endpoints)
        try:
            token, verified, principal = _verify_and_resolve_issued_token(
                deps, client, endpoints, authority, raw_token
            )
            fingerprint = subject_fingerprint(verified.subject)
        except ManagementError as exc:
            return _compensate_issued_refusal(
                command,
                exc.reason_code,
                client=client,
                endpoints=endpoints,
                raw_token=raw_token,
            )
        if fingerprint != before_grant.subject_fingerprint:
            return _compensate_issued_refusal(
                command,
                "secpctl_credential_subject_changed",
                client=client,
                endpoints=endpoints,
                raw_token=raw_token,
            )

        try:
            persist_result = selection.store.compare_and_store(
                before_grant.generation,
                token,
                expires_at_epoch=verified.expires_at_epoch,
                subject_fingerprint=fingerprint,
            )
            if persist_result is not CredentialMutationResult.STORED:
                return _compensate_issued_refusal(
                    command,
                    "secpctl_credential_generation_changed",
                    client=client,
                    endpoints=endpoints,
                    raw_token=raw_token,
                )
        except ManagementError as exc:
            return _compensate_issued_refusal(
                command,
                exc.reason_code,
                client=client,
                endpoints=endpoints,
                raw_token=raw_token,
            )
        return EXIT_OK, {
            "command": command,
            "mode": "written",
            "authenticated": True,
            **principal.to_report(),
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
            # Cancellation can arrive while the scheduler-directed sleep is in progress. Recheck
            # at the actual network boundary so a cancelled grant cannot post one final token
            # request and persist its answer.
            if deps.cancelled():
                raise ManagementError("secpctl_device_authorization_cancelled")
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
        # CLIENT validation: a present `azp` must name the client secpctl actually presented, so a
        # token minted for a different client at the same issuer and audience is refused here rather
        # than stored and rejected later by the controller.
        client_id=OPERATOR_CLI_CLIENT_ID,
    )


def auth_status(deps: AuthCliDeps) -> tuple[int, dict]:
    """``secpctl auth status`` — read-only. Reports the credential store's bounded, secret-free
    state for the selected controller and, for a readable live credential, resolves the controller's
    authoritative database-backed principal. It makes no mutation, starts no grant, and never
    prints a token.

    An UNRECORDED locator is not an error here: the backend is still reportable, and "a keystore is
    available but no controller is selected" is exactly what an operator needs to see on a host that
    has not been bootstrapped yet.

    It also names the provider AUTHENTICATED commands will actually use. That matters because the
    two can disagree silently: an operator who set ``SECP_OPERATOR_TOKEN_FILE`` during rollout, then
    ran ``auth login`` successfully, keeps using the file's token — so a stale or revoked file token
    produces an auth failure immediately after an apparently successful login, and a status command
    that reported only keystore state would show nothing wrong. The precedence itself is deliberate
    (the file is an explicit opt-in recovery seam); what was missing was saying which one is live.

    The ``/api/v1/me`` request uses only the bootstrap-pinned controller transport. Its result, not
    token claims, supplies user, organization and permissions. When the protected token-file seam is
    selected, that exact provider is resolved; otherwise the selected OS-keystore credential is.
    """
    command = "auth status"
    try:
        selection = _select(deps)
    except ManagementError as exc:
        if exc.reason_code != "secpctl_controller_locator_unavailable":
            # Only a genuinely UNRECORDED locator is a healthy pre-bootstrap status. A present but
            # corrupt/unsafe locator is a trust-input failure and must never be projected as
            # ``account_selected: false`` with exit 0.
            return _refused(command, exc.reason_code)
        backend = _describe_unbound(deps)
        return EXIT_OK, {
            "command": command,
            "mode": "read",
            "active_principal_resolved": False,
            **_active_provider_report(deps, backend),
            **_credential_report("", backend),
        }
    try:
        status = selection.store.describe()
    except ManagementError as exc:
        return _refused(command, exc.reason_code)
    provider_report = _active_provider_report(deps, status)
    report = {
        "command": command,
        "mode": "read",
        "active_principal_resolved": False,
        **provider_report,
        **_credential_report(selection.account, status),
    }
    active_provider = provider_report["active_token_provider"]
    token: OperatorAccessToken | None = None
    if active_provider == PROVIDER_TOKEN_FILE:
        try:
            token = deps.token_file_provider.access_token()
        except ManagementError as exc:
            return _refused(command, exc.reason_code)
    elif (
        active_provider == PROVIDER_OS_KEYSTORE
        and status.available
        and status.has_credential
        and not status.expired
    ):
        try:
            token = selection.store.access_token()
        except ManagementError as exc:
            return _refused(command, exc.reason_code)
    if token is not None:
        try:
            principal = deps.device_client(selection.locator).resolve_principal(token)
        except ManagementError as exc:
            return _refused(command, exc.reason_code)
        report["active_principal_resolved"] = True
        report.update(principal.to_report(active=True))
    return EXIT_OK, report


def _describe_unbound(deps: AuthCliDeps) -> StoredCredentialStatus:
    """The backend's own state, with no controller selected. ``describe`` is specified never to
    raise, but a third-party store is not this module's to trust, so a refusal degrades to the
    sealed projection rather than escaping as an unbounded failure."""
    try:
        return deps.credential_store.describe()
    except ManagementError:
        return StoredCredentialStatus(
            backend="sealed",
            available=False,
            unavailable_reason="secpctl_credential_store_unavailable",
        )


def _revoke_stored_token(
    deps: AuthCliDeps,
    selection: _Selection,
    tokens: tuple[OperatorAccessToken, ...],
) -> tuple[RevocationOutcome, ...]:
    """Revoke every unique readable token after one shared discovery operation."""
    if not tokens:
        return ()
    try:
        client, _authority, endpoints = _discover(deps, selection.locator)
    except ManagementError as exc:
        unavailable = RevocationOutcome(
            OUTCOME_UNAVAILABLE,
            reason_code=_bounded_reason(exc.reason_code, "secpctl_revocation_provider_unavailable"),
        )
        return tuple(unavailable for _token in tokens)
    except Exception:  # noqa: BLE001 - discovery detail must never escape into output
        unavailable = RevocationOutcome(
            OUTCOME_UNAVAILABLE, reason_code="secpctl_revocation_provider_unavailable"
        )
        return tuple(unavailable for _token in tokens)

    outcomes: list[RevocationOutcome] = []
    for token in tokens:
        try:
            outcome = client.revoke_token(endpoints, token.revocation_request_value())
        except ManagementError as exc:
            outcome = RevocationOutcome(
                OUTCOME_UNAVAILABLE,
                reason_code=_bounded_reason(
                    exc.reason_code, "secpctl_revocation_provider_unavailable"
                ),
            )
        except Exception:  # noqa: BLE001 - never reflect provider/transport exception detail
            outcome = RevocationOutcome(
                OUTCOME_UNAVAILABLE,
                reason_code="secpctl_revocation_provider_unavailable",
            )
        if (
            not isinstance(outcome, RevocationOutcome)
            or outcome.outcome
            not in {OUTCOME_REFUSED, OUTCOME_REVOKED, OUTCOME_UNAVAILABLE, OUTCOME_UNSUPPORTED}
            or (
                outcome.reason_code
                and _bounded_reason(outcome.reason_code, "") != outcome.reason_code
            )
        ):
            outcome = RevocationOutcome(
                OUTCOME_REFUSED, reason_code="secpctl_revocation_response_invalid"
            )
        outcomes.append(outcome)
    return tuple(outcomes)


@dataclass(frozen=True, repr=False)
class _LogoutSources:
    """Secret-redacted snapshot of every source known to this invocation."""

    tokens: tuple[OperatorAccessToken, ...]
    os_snapshot: CredentialSnapshot | None
    read_failures: tuple[str, ...]

    def __repr__(self) -> str:
        return "_LogoutSources(<redacted>)"


def _read_logout_sources(deps: AuthCliDeps, selection: _Selection) -> _LogoutSources:
    """Read token-file and OS-store sources independently, then deduplicate identical tokens."""
    tokens: list[OperatorAccessToken] = []
    failures: list[str] = []

    try:
        token_file_active = deps.token_file_active()
    except Exception:  # noqa: BLE001 - a broken probe is unreadable, not absence
        token_file_active = None
    if type(token_file_active) is not bool:
        failures.append("secpctl_operator_auth_unavailable")
    elif token_file_active:
        try:
            file_token = deps.token_file_provider.access_token()
            if not isinstance(file_token, OperatorAccessToken):
                raise ManagementError("secpctl_operator_token_invalid")
            tokens.append(file_token)
        except ManagementError as exc:
            failures.append(_bounded_reason(exc.reason_code, "secpctl_operator_auth_unavailable"))
        except Exception:  # noqa: BLE001 - never expose a token-file path or exception
            failures.append("secpctl_operator_auth_unavailable")

    os_snapshot: CredentialSnapshot | None = None
    try:
        candidate = selection.store.snapshot()
        if candidate is not None and not isinstance(candidate, CredentialSnapshot):
            raise ManagementError("secpctl_credential_record_invalid")
        os_snapshot = candidate
        if os_snapshot is not None:
            tokens.append(os_snapshot.token)
    except ManagementError as exc:
        failures.append(_bounded_reason(exc.reason_code, "secpctl_credential_store_unavailable"))
    except Exception:  # noqa: BLE001 - never expose backend/path/exception detail
        failures.append("secpctl_credential_store_unavailable")

    unique: list[OperatorAccessToken] = []
    for token in tokens:
        raw = token.revocation_request_value()
        if not any(
            secrets.compare_digest(raw, prior.revocation_request_value()) for prior in unique
        ):
            unique.append(token)
    return _LogoutSources(tuple(unique), os_snapshot, tuple(failures))


def _aggregate_logout_outcome(
    tokens: tuple[OperatorAccessToken, ...],
    read_failures: tuple[str, ...],
    outcomes: tuple[RevocationOutcome, ...],
) -> RevocationOutcome:
    """Project many source/outcome facts into one conservative, deterministic result."""
    dead_count = sum(not outcome.token_still_live for outcome in outcomes)
    if read_failures:
        if dead_count:
            return RevocationOutcome(OUTCOME_PARTIAL, reason_code=read_failures[0])
        return revocation_credential_unreadable(read_failures[0])
    live = tuple(outcome for outcome in outcomes if outcome.token_still_live)
    if live:
        if dead_count:
            return RevocationOutcome(
                OUTCOME_PARTIAL,
                reason_code=live[0].reason_code or "secpctl_revocation_refused",
            )
        return live[0]
    if tokens and len(outcomes) == len(tokens):
        return RevocationOutcome(OUTCOME_REVOKED)
    if not tokens:
        return revocation_not_required()
    return RevocationOutcome(OUTCOME_REFUSED, reason_code="secpctl_revocation_response_invalid")


def auth_logout(deps: AuthCliDeps, *, gate: WriteGate) -> tuple[int, dict]:
    """``secpctl auth logout`` — revoke every readable token known for this controller/account,
    then delete ONLY the OS-store generation this invocation owns. A configured user-managed token
    file is read and revoked but never deleted or rewritten. Dry-run unless ``--write --confirm``.

    The ORDER is deliberate: snapshot first, revoke second, generation-checked deletion last.
    Revocation needs the token, so deleting first would throw away the only thing that can end the
    session at the provider. The compare-and-delete step never removes a concurrent replacement.

    Local deletion alone was never a real logout. Until the token is revoked it remains valid at the
    provider until its own expiry, so anyone who captured it still holds a working credential; that
    is precisely the window RFC 7009 exists to close.

    When any known source is unreadable or any token cannot be proven revoked, the command reports
    ``token_still_live`` and exits non-zero. ``removed`` describes only owned OS-store cleanup; it
    never claims that a configured token file was removed.

    It never touches an unrelated OS keyring entry and never touches another controller's account.
    """
    command = "auth logout"
    try:
        selection = _select(deps)
        if not gate.is_write:
            sources = _read_logout_sources(deps, selection)
            if sources.read_failures:
                return _refused(command, sources.read_failures[0])
            status = selection.store.describe()
            if not status.available:
                # An unreadable credential is not an absent credential. A dry run cannot truthfully
                # say no revocation is planned when a live token may be hidden behind a locked,
                # failed, or corrupt store.
                return _refused(
                    command,
                    status.unavailable_reason or "secpctl_credential_store_unavailable",
                )
            return EXIT_OK, {
                "command": command,
                "mode": "dry_run",
                # Stated WITHOUT a network call: a dry run opens no socket, so it reports what the
                # write path would attempt rather than what the provider would answer. Local expiry
                # does not suppress the attempt because the issuer's clock is authoritative.
                "revocation_planned": bool(sources.tokens),
                **_credential_report(selection.account, status),
            }
        sources = _read_logout_sources(deps, selection)
        outcomes = _revoke_stored_token(deps, selection, sources.tokens)
        outcome = _aggregate_logout_outcome(sources.tokens, sources.read_failures, outcomes)

        cleanup_reason = ""
        mutation = CredentialMutationResult.ABSENT
        if sources.os_snapshot is not None:
            try:
                mutation = selection.store.delete_if_generation(sources.os_snapshot.generation)
                if not isinstance(mutation, CredentialMutationResult):
                    cleanup_reason = "secpctl_credential_backend_failed"
            except ManagementError as exc:
                cleanup_reason = _bounded_reason(
                    exc.reason_code, "secpctl_credential_backend_failed"
                )
            except Exception:  # noqa: BLE001 - never expose backend/path/exception detail
                cleanup_reason = "secpctl_credential_backend_failed"
        removed = mutation is CredentialMutationResult.DELETED
        report = {
            "command": command,
            "mode": "written",
            "removed": bool(removed),
            "account": account_fingerprint(selection.account),
            **outcome.to_report(),
        }
        if mutation is CredentialMutationResult.GENERATION_MISMATCH:
            # The old token may have been revoked, but a newer generation is now known to exist.
            # This operation neither owns nor deletes it and therefore cannot call logout complete.
            outcome = RevocationOutcome(
                OUTCOME_CONCURRENT_REPLACEMENT,
                reason_code="secpctl_credential_generation_changed",
            )
            report.update(outcome.to_report())
            reason_code = outcome.reason_code
            report.update(
                {
                    "concurrent_credential_present": True,
                    "token_still_live": True,
                    "reason_code": reason_code,
                }
            )
            return exit_for(reason_code), _with_remedy(report, reason_code)
        if cleanup_reason:
            report["credential_cleanup_reason_code"] = cleanup_reason
        if not outcome.token_still_live:
            if cleanup_reason:
                report["reason_code"] = cleanup_reason
                return exit_for(cleanup_reason), _with_remedy(report, cleanup_reason)
            return EXIT_OK, report
        # At least one known source may still carry a live provider token. Exiting 0 here would make
        # `secpctl auth logout && echo revoked` print a falsehood.
        report["reason_code"] = outcome.reason_code or "secpctl_revocation_refused"
        return exit_for(report["reason_code"]), _with_remedy(report, report["reason_code"])
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
