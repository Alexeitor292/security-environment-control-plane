#!/usr/bin/env python3
"""Deterministic deployment of the public ``secp-cli`` device-grant client — SECP-PR5H-B2 WS-C.

``secpctl auth login`` (ADR-028 §3) needs ONE public OAuth 2.0 client on the reviewed issuer. Before
this module, that client was described only as prose in ``infra/production/oidc.env.example`` — an
operator followed it by clicking through an admin console, and nothing could tell them afterwards
whether what they clicked matched what the CLI needs. This module replaces the click-path with a
committed artifact plus an idempotent reconciler, so the same bytes produce the same client in
development, in the disposable test realm, and on a production identity provider.

The artifact is ``infra/keycloak/secp-cli-client.json``. It is environment-independent by
construction: the device grant has no browser redirect, so the representation carries no hostname,
no origin, and no secret — there is nothing in it to vary per deployment, and therefore nothing to
get wrong per deployment.

WHAT THIS TOOL RECONCILES, AND WHY IT IS NOT JUST A ``PUT``
-----------------------------------------------------------
Keycloak's Admin REST API ignores three parts of a ``ClientRepresentation`` on UPDATE, and they are
exactly the three that carry this client's security posture:

* ``defaultClientScopes`` / ``optionalClientScopes`` — assigned through dedicated sub-resources.
  A ``PUT`` that carries them silently changes nothing, so a client created once with the console
  defaults keeps the ``roles`` scope forever no matter how often the representation is re-applied.
* ``protocolMappers`` — likewise a sub-resource. Without the audience mapper the API refuses every
  token the CLI ever obtains.

So this tool reconciles each of them explicitly, to an EXACT set rather than a superset: a scope or
mapper that is present and not desired is REMOVED. "Ensure present" alone would let the one setting
that matters most survive every re-run.

THE ``roles`` SCOPE IS A SIZE CONTROL, NOT A POLICY ONE
--------------------------------------------------------
The ``roles`` client scope adds ``realm_access`` / ``resource_access`` claims. On a deployment with
many roles the issued access token grows past what an OS keystore record holds
(``CRED_MAX_CREDENTIAL_BLOB_SIZE`` is 2560 bytes on Windows, and secpctl applies that bound on every
platform so a credential that stores on one workstation stores on all of them). The grant then
COMPLETES, the token VERIFIES, and ``secpctl auth login`` refuses with
``secpctl_credential_too_large`` — after the operator has already approved interactively, which is
the worst possible place to fail. ``fullScopeAllowed: false`` is the second, independent control on
the same failure: it stops the client's own role scope-mappings from inflating the token even if the
``roles`` scope were ever reattached.

secpctl needs no role claims at all: the database is the sole authority for organization, role and
permission, and a token claim never determines them.

SAFETY POSTURE
--------------
* The default action is ``plan`` and it opens NO socket at all.
* ``apply`` is DRY-RUN unless BOTH ``--write`` and ``--confirm`` are given; a dry run issues only
  ``GET`` requests, and :func:`Reconciler.actions` reports exactly what a write would do.
* A plaintext ``http://`` base URL is REFUSED unless ``--insecure-http`` is passed explicitly, which
  exists for a disposable containerised realm and is named so it cannot be mistaken for a default.
* Administrator credentials are read from the environment only; there is no ``--password`` flag, so
  a credential cannot land in a shell history or a process listing.
* Nothing here prints the administrator password, the admin access token, or a client secret. The
  ``secp-cli`` client HAS no secret; if the provider ever returns one, that is reported as a failure
  rather than echoed.

USAGE
-----
    # offline: what would be deployed (no network)
    python scripts/keycloak/secp_cli_client.py plan

    # read-only conformance of a deployed realm (RFC 8414 discovery + RFC 7009 revocation)
    export SECP_KEYCLOAK_ADMIN=... SECP_KEYCLOAK_ADMIN_PASSWORD=...
    python scripts/keycloak/secp_cli_client.py verify \\
        --base-url https://idp.example.com --realm secp

    # reconcile (dry run first, then for real)
    python scripts/keycloak/secp_cli_client.py apply \\
        --base-url https://idp.example.com --realm secp
    python scripts/keycloak/secp_cli_client.py apply \\
        --base-url https://idp.example.com --realm secp --write --confirm
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The single committed source of truth for the client. Development, test and production all deploy
#: THIS file; there is no per-environment variant to drift.
ARTIFACT_PATH = REPO_ROOT / "infra" / "keycloak" / "secp-cli-client.json"

#: The code-owned public client id. It matches ``secp_management.operator_device_auth
#: .OPERATOR_CLI_CLIENT_ID``; ``tests/test_keycloak_secp_cli_deployment.py`` pins that they agree
#: without this script importing the management plane (which it must not: this is deployment
#: tooling, runnable on a host that has no SECP packages installed).
CLIENT_ID = "secp-cli"

#: Keycloak's per-client switch for RFC 8628. A STRING "true" — Keycloak stores client attributes as
#: strings, and a JSON boolean here is silently not enabled.
DEVICE_GRANT_ATTRIBUTE = "oauth2.device.authorization.grant.enabled"

#: RFC 8628 §3.4 grant type, as advertised in ``grant_types_supported``.
DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

#: Client scopes that must NEVER be attached to this client, with the reason each is refused.
REFUSED_DEFAULT_SCOPES: dict[str, str] = {
    "roles": (
        "adds realm_access/resource_access claims; on a deployment with many roles the issued "
        "token "
        "exceeds the 2560-byte OS keystore record and `secpctl auth login` refuses with "
        "secpctl_credential_too_large AFTER the operator has approved"
    ),
    "offline_access": (
        "mints a long-lived refresh credential; ADR-018 is that no such credential ever exists on "
        "an operator workstation, and the CLI refuses a grant that carries it"
    ),
}

#: Flags that must be OFF. The device grant is the client's only way in.
REFUSED_FLOWS: tuple[str, ...] = (
    "standardFlowEnabled",
    "implicitFlowEnabled",
    "directAccessGrantsEnabled",
    "serviceAccountsEnabled",
)

#: Environment variables the administrator credential is read from. No CLI flag carries a password.
ENV_ADMIN_USER = "SECP_KEYCLOAK_ADMIN"
ENV_ADMIN_PASSWORD = "SECP_KEYCLOAK_ADMIN_PASSWORD"
ENV_ADMIN_REALM = "SECP_KEYCLOAK_ADMIN_REALM"
ENV_ADMIN_CLIENT_ID = "SECP_KEYCLOAK_ADMIN_CLIENT_ID"

_DEFAULT_ADMIN_REALM = "master"
_DEFAULT_ADMIN_CLIENT_ID = "admin-cli"
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_DEFAULT_TIMEOUT = 30.0

#: Keycloak stores ``client.description`` in a ``VARCHAR(255)`` column. A longer one does not
#: fail validation — the realm import fails with an opaque "Database operation failed", which is a
#: miserable thing to debug. Bound it here so the artifact check catches it offline.
MAX_DESCRIPTION_CHARS = 255

#: ``(method, url, headers, body) -> (status, headers, body)``. Injected so the reconciler is
#: exercisable without a socket; the shipped default is :func:`urllib_transport`.
Transport = Callable[[str, str, dict, "bytes | None"], "tuple[int, dict, bytes]"]


class DeploymentError(Exception):
    """A bounded deployment refusal. Carries a message safe to print: never a password, an admin
    token, a client secret, or a raw provider body."""


# --- the committed artifact -----------------------------------------------------------------------


def load_artifact(path: Path = ARTIFACT_PATH) -> dict[str, Any]:
    """Read the committed representation. A malformed artifact is a refusal, not a default."""
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DeploymentError(f"client artifact not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise DeploymentError(f"client artifact is not valid JSON: {path}") from exc
    if not isinstance(parsed, dict):
        raise DeploymentError(f"client artifact must be a JSON object: {path}")
    return parsed


def desired_default_scopes(client: dict[str, Any]) -> list[str]:
    scopes = client.get("defaultClientScopes")
    if not isinstance(scopes, list):
        raise DeploymentError("artifact does not pin `defaultClientScopes`")
    return [str(s) for s in scopes]


def check_artifact(client: dict[str, Any]) -> list[str]:
    """Offline conformance of the committed representation.

    Returns a list of problems; an EMPTY list is the only pass.

    Every set-sized assertion is COUNT-based rather than membership-based: "roles is absent" is true
    of an empty list too, and an empty default-scope list would break the grant in a way that reads
    as passing. The exact expected members and the exact expected size are both checked.
    """
    problems: list[str] = []

    if client.get("clientId") != CLIENT_ID:
        problems.append(f"clientId must be {CLIENT_ID!r}, found {client.get('clientId')!r}")
    if client.get("protocol") != "openid-connect":
        problems.append(f"protocol must be 'openid-connect', found {client.get('protocol')!r}")
    if client.get("enabled") is not True:
        problems.append("client must be enabled")

    # --- public client, no secret -----------------------------------------------------------------
    if client.get("publicClient") is not True:
        problems.append("publicClient must be true (the CLI cannot hold a secret)")
    if "secret" in client:
        problems.append("a public client must carry NO `secret`")
    if client.get("bearerOnly") is True:
        problems.append("bearerOnly must be false (this client obtains tokens)")

    # --- exactly one way in -----------------------------------------------------------------------
    attributes = client.get("attributes")
    if not isinstance(attributes, dict):
        problems.append("client must declare an `attributes` object")
        attributes = {}
    if attributes.get(DEVICE_GRANT_ATTRIBUTE) != "true":
        problems.append(
            f"{DEVICE_GRANT_ATTRIBUTE} must be the STRING 'true', "
            f"found {attributes.get(DEVICE_GRANT_ATTRIBUTE)!r}"
        )
    for flag in REFUSED_FLOWS:
        if client.get(flag) is not False:
            problems.append(f"{flag} must be false")
    if attributes.get("use.refresh.tokens") != "false":
        problems.append("use.refresh.tokens must be the STRING 'false'")

    # --- no browser surface -----------------------------------------------------------------------
    if client.get("redirectUris"):
        problems.append("the device grant has no browser redirect: redirectUris must be empty")
    if client.get("webOrigins"):
        problems.append("the device grant has no browser origin: webOrigins must be empty")

    # --- token size -------------------------------------------------------------------------------
    problems.extend(check_scope_policy(client.get("defaultClientScopes"), "defaultClientScopes"))
    optional = client.get("optionalClientScopes")
    # An OPTIONAL scope is not a dormant one: it is granted the moment something requests it, so the
    # refused-scope policy applies to this list exactly as it does to the default list. The
    # exact-empty check is separate and additional — the CLI requests nothing beyond its defaults,
    # so any optional scope is surface with no caller.
    problems.extend(check_scope_policy(optional, "optionalClientScopes"))
    if not isinstance(optional, list) or len(optional) != 0:
        problems.append(f"optionalClientScopes must be exactly [], found {optional!r}")
    if client.get("fullScopeAllowed") is not False:
        problems.append(
            "fullScopeAllowed must be false — it is the second, independent control on token size "
            "(Keycloak's own default is true)"
        )

    # --- the audience the API requires ------------------------------------------------------------
    problems.extend(check_audience_mappers(client.get("protocolMappers")))

    # --- portability ------------------------------------------------------------------------------
    description = client.get("description")
    if isinstance(description, str) and len(description) > MAX_DESCRIPTION_CHARS:
        problems.append(
            f"description is {len(description)} characters; Keycloak's column holds "
            f"{MAX_DESCRIPTION_CHARS} and a longer one fails realm import with an opaque "
            "'Database operation failed'"
        )
    blob = json.dumps(client)
    for marker in ("http://", "https://"):
        if marker in blob:
            problems.append(
                f"the artifact must stay environment-independent, but it contains {marker!r}"
            )
    return problems


def check_scope_policy(scopes: object, field: str) -> list[str]:
    """Refuse any scope the CLI must never hold. Shared by the artifact check and the live check."""
    problems: list[str] = []
    if not isinstance(scopes, list):
        return [f"{field} must be a list, found {type(scopes).__name__}"]
    names = [str(s) for s in scopes]
    if len(set(names)) != len(names):
        problems.append(f"{field} contains a duplicate")
    for refused, why in REFUSED_DEFAULT_SCOPES.items():
        if refused in names:
            problems.append(f"{field} must not contain {refused!r}: {why}")
    return problems


def check_audience_mappers(mappers: object) -> list[str]:
    """EXACTLY one audience mapper, targeting ``secp-api``, landing in the ACCESS token."""
    problems: list[str] = []
    if not isinstance(mappers, list):
        return ["protocolMappers must be a list"]
    audience = [
        m
        for m in mappers
        if isinstance(m, dict) and m.get("protocolMapper") == "oidc-audience-mapper"
    ]
    if len(audience) != 1:
        problems.append(
            f"expected exactly 1 audience mapper, found {len(audience)} — the CLI client does not "
            "inherit the browser client's mapper, and without it the API refuses every CLI token"
        )
        return problems
    config = audience[0].get("config")
    if not isinstance(config, dict):
        return ["the audience mapper carries no `config`"]
    if config.get("included.custom.audience") != "secp-api":
        problems.append(
            f"audience mapper must target 'secp-api', found "
            f"{config.get('included.custom.audience')!r}"
        )
    if config.get("access.token.claim") != "true":
        problems.append("the audience must land in the ACCESS token (access.token.claim='true')")
    return problems


# --- RFC 8414 discovery + RFC 7009 revocation ---------------------------------------------------


def check_discovery(document: object, *, issuer: str, require_https: bool) -> list[str]:
    """Validate an RFC 8414 authorization-server metadata document for THIS deployment.

    Two members get treated more strictly than RFC 8414 alone requires, and deliberately:

    * ``device_authorization_endpoint`` — RFC 8414 §2 makes it optional, but a deployment without it
      cannot run ``secpctl auth login`` at all, so its absence is a deployment failure here even
      though the CLI reports it as a provider limitation at runtime.
    * ``revocation_endpoint`` — also optional in RFC 8414 §2, and the CLI tolerates its absence
      (``auth logout`` then reports that the token stays live rather than claiming a revocation).
      A SECP deployment must still advertise one, because "logout leaves the credential valid at the
      provider" is not an acceptable steady state for an operator workstation.
    """
    problems: list[str] = []
    if not isinstance(document, dict):
        return ["discovery document is not a JSON object"]

    if document.get("issuer") != issuer:
        problems.append(
            f"discovery `issuer` must EXACTLY equal {issuer!r}, found {document.get('issuer')!r} — "
            "the CLI refuses any mismatch, including a trailing-slash difference"
        )

    for member in ("token_endpoint", "jwks_uri", "device_authorization_endpoint"):
        value = document.get(member)
        if not isinstance(value, str) or not value:
            problems.append(f"discovery document does not advertise `{member}` (RFC 8414 §2)")
            continue
        problems.extend(_check_endpoint_url(value, member, require_https=require_https))

    grant_types = document.get("grant_types_supported")
    if isinstance(grant_types, list) and DEVICE_CODE_GRANT_TYPE not in grant_types:
        problems.append(
            f"`grant_types_supported` does not include {DEVICE_CODE_GRANT_TYPE!r}; the CLI refuses "
            "the deployment as not supporting the device grant"
        )

    revocation = document.get("revocation_endpoint")
    if not isinstance(revocation, str) or not revocation:
        problems.append(
            "discovery document does not advertise `revocation_endpoint` (RFC 7009). The CLI "
            "tolerates this and reports the token as still live after `auth logout`; a SECP "
            "deployment must not leave an operator credential live at the provider"
        )
    else:
        # RFC 7009 §2: "URLs for token revocation endpoints MUST be HTTPS URLs."
        problems.extend(
            _check_endpoint_url(revocation, "revocation_endpoint", require_https=require_https)
        )
    return problems


def _check_endpoint_url(value: str, member: str, *, require_https: bool) -> list[str]:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ("http", "https"):
        return [f"`{member}` is not an http(s) URL"]
    if require_https and parsed.scheme != "https":
        return [f"`{member}` is plaintext http; the CLI refuses a non-HTTPS endpoint"]
    if not parsed.hostname:
        return [f"`{member}` has no host"]
    if parsed.username or parsed.password or "@" in parsed.netloc:
        return [f"`{member}` carries userinfo"]
    return []


def check_public_revocation_probe(status: int) -> list[str]:
    """Interpret an unauthenticated revocation probe (RFC 7009 §2.2).

    §2.2 requires 200 both when the token was revoked AND when the client submitted an invalid one —
    precisely so a client cannot probe token validity here. Sending a syntactically valid but
    meaningless token therefore proves the endpoint is USABLE BY A PUBLIC CLIENT without putting any
    real credential at risk. That check is worth making: Keycloak's own
    ``revocation_endpoint_auth_methods_supported`` does not list ``none``, so reading the metadata
    alone would suggest a public client cannot revoke, while in practice it can.
    """
    if status // 100 == 2:
        return []
    if status in (400, 401, 403):
        return [
            f"the revocation endpoint answered {status} to a PUBLIC client presenting only "
            "client_id. RFC 7009 §2.2 requires 200 even for an invalid token, so `secpctl auth "
            "logout` cannot revoke against this deployment and will report the token as still live"
        ]
    return [f"the revocation endpoint answered an unexpected {status} to a public-client probe"]


# --- transport ---------------------------------------------------------------------------------


def urllib_transport(
    method: str, url: str, headers: dict, body: bytes | None
) -> tuple[int, dict, bytes]:
    """The shipped transport: stdlib only, no redirects followed, bounded read.

    Redirects are refused rather than followed because this request carries an administrator bearer
    token, and a redirect would forward it to whatever host the response named.
    """

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: Any, **kwargs: Any) -> None:
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(request, timeout=_DEFAULT_TIMEOUT) as response:
            return response.status, dict(response.headers), response.read(_MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:  # a 4xx/5xx is an ANSWER, not a transport failure
        return exc.code, dict(exc.headers or {}), exc.read(_MAX_RESPONSE_BYTES)
    except urllib.error.URLError as exc:
        raise DeploymentError(
            f"cannot reach {urllib.parse.urlsplit(url).netloc}: {exc.reason}"
        ) from None


class KeycloakAdmin:
    """A minimal Keycloak Admin REST client.

    It counts its own MUTATING requests. That count is what makes "a dry run writes nothing" a
    measurable post-condition rather than a claim in a docstring: a dry run must finish with
    :attr:`mutations` == 0, and a test asserts exactly that.
    """

    def __init__(
        self,
        base_url: str,
        *,
        transport: Transport = urllib_transport,
        admin_realm: str = _DEFAULT_ADMIN_REALM,
        admin_client_id: str = _DEFAULT_ADMIN_CLIENT_ID,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._transport = transport
        self._admin_realm = admin_realm
        self._admin_client_id = admin_client_id
        self._token: str | None = None
        self.mutations = 0

    # --- authentication ---------------------------------------------------------------------------

    def authenticate(self, username: str, password: str) -> None:
        """Obtain an administrator access token. The password is never stored or echoed."""
        form = urllib.parse.urlencode(
            {
                "client_id": self._admin_client_id,
                "username": username,
                "password": password,
                "grant_type": "password",
            }
        ).encode("utf-8")
        status, _headers, body = self._transport(
            "POST",
            f"{self.base_url}/realms/{self._admin_realm}/protocol/openid-connect/token",
            {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            form,
        )
        if status // 100 != 2:
            raise DeploymentError(
                f"administrator authentication failed with HTTP {status} "
                f"(realm {self._admin_realm!r}, client {self._admin_client_id!r})"
            )
        try:
            token = json.loads(body.decode("utf-8"))["access_token"]
        except Exception as exc:  # noqa: BLE001 - never echo the body of a token response
            raise DeploymentError("administrator token response was not usable") from exc
        self._token = str(token)

    def _authorized(self) -> dict:
        if not self._token:
            raise DeploymentError("not authenticated: call authenticate() first")
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    # --- verbs ------------------------------------------------------------------------------------

    def get(self, path: str) -> Any:
        status, _headers, body = self._transport(
            "GET", f"{self.base_url}{path}", self._authorized(), None
        )
        if status // 100 != 2:
            raise DeploymentError(f"GET {path} failed with HTTP {status}")
        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise DeploymentError(f"GET {path} did not return JSON") from exc

    def mutate(self, method: str, path: str, payload: Any = None) -> int:
        """Issue a MUTATING request. Every call increments :attr:`mutations`."""
        if method == "GET":
            raise DeploymentError("mutate() is for mutating verbs only")
        headers = self._authorized()
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode("utf-8")
        self.mutations += 1
        status, _headers, response = self._transport(
            method, f"{self.base_url}{path}", headers, body
        )
        if status // 100 != 2:
            raise DeploymentError(
                f"{method} {path} failed with HTTP {status}: {_bounded_error(response)}"
            )
        return status


def _bounded_error(body: bytes) -> str:
    """A short, bounded excerpt of an error body — enough to debug, never a whole page."""
    try:
        parsed = json.loads(body.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return f"<{len(body)} bytes>"
    if isinstance(parsed, dict):
        for key in ("errorMessage", "error_description", "error"):
            value = parsed.get(key)
            if isinstance(value, str):
                return value[:200]
    return f"<{len(body)} bytes>"


# --- reconciliation ------------------------------------------------------------------------------


class Reconciler:
    """Bring one realm's ``secp-cli`` client to the committed representation, idempotently.

    ``write=False`` computes the same action list and issues no mutating request, so an operator can
    read exactly what would change before anything does.
    """

    def __init__(self, admin: KeycloakAdmin, realm: str, desired: dict[str, Any], *, write: bool):
        self.admin = admin
        self.realm = realm
        self.desired = desired
        self.write = write
        self.actions: list[str] = []

    def _act(self, description: str, method: str, path: str, payload: Any = None) -> None:
        self.actions.append(description)
        if self.write:
            self.admin.mutate(method, path, payload)

    def find_client(self) -> dict[str, Any] | None:
        query = urllib.parse.urlencode({"clientId": CLIENT_ID})
        found = self.admin.get(f"/admin/realms/{self.realm}/clients?{query}")
        if not isinstance(found, list):
            raise DeploymentError("client lookup did not return a list")
        for client in found:
            if isinstance(client, dict) and client.get("clientId") == CLIENT_ID:
                return client
        return None

    def run(self) -> list[str]:
        existing = self.find_client()
        core = {k: v for k, v in self.desired.items() if k not in ("protocolMappers",)}
        if existing is None:
            self._act(
                f"create client {CLIENT_ID!r} in realm {self.realm!r}",
                "POST",
                f"/admin/realms/{self.realm}/clients",
                core,
            )
            if not self.write:
                # Nothing exists to reconcile against; the create carries the whole representation.
                self.actions.append(
                    "(dry run) sub-resource reconciliation is reported after the client exists"
                )
                return self.actions
            created = self.find_client()
            if created is None:
                raise DeploymentError("client was created but cannot be read back")
            existing = created
        elif not core_matches(existing, core):
            self._act(
                f"update client {CLIENT_ID!r} (uuid {existing['id']})",
                "PUT",
                f"/admin/realms/{self.realm}/clients/{existing['id']}",
                {**core, "id": existing["id"]},
            )

        self.reconcile_scopes(existing["id"], "default")
        self.reconcile_scopes(existing["id"], "optional")
        self.reconcile_mappers(existing["id"])
        return self.actions

    # Keycloak IGNORES defaultClientScopes/optionalClientScopes on a client UPDATE, so a `PUT` alone
    # can never remove the `roles` scope from a client that was first created through the console.
    def reconcile_scopes(self, uuid: str, kind: str) -> None:
        field = "defaultClientScopes" if kind == "default" else "optionalClientScopes"
        resource = "default-client-scopes" if kind == "default" else "optional-client-scopes"
        desired = {str(s) for s in (self.desired.get(field) or [])}
        assigned = self.admin.get(f"/admin/realms/{self.realm}/clients/{uuid}/{resource}") or []
        assigned_names = {str(s.get("name")) for s in assigned if isinstance(s, dict)}
        by_name = {str(s.get("name")): str(s.get("id")) for s in assigned if isinstance(s, dict)}

        for surplus in sorted(assigned_names - desired):
            reason = REFUSED_DEFAULT_SCOPES.get(surplus, "not in the committed representation")
            self._act(
                f"remove {kind} client scope {surplus!r} ({reason})",
                "DELETE",
                f"/admin/realms/{self.realm}/clients/{uuid}/{resource}/{by_name[surplus]}",
            )

        missing = sorted(desired - assigned_names)
        if missing:
            catalogue = self.admin.get(f"/admin/realms/{self.realm}/client-scopes") or []
            ids = {str(s.get("name")): str(s.get("id")) for s in catalogue if isinstance(s, dict)}
            for name in missing:
                if name not in ids:
                    raise DeploymentError(
                        f"realm {self.realm!r} has no client scope named {name!r}; the committed "
                        "representation cannot be satisfied"
                    )
                self._act(
                    f"attach {kind} client scope {name!r}",
                    "PUT",
                    f"/admin/realms/{self.realm}/clients/{uuid}/{resource}/{ids[name]}",
                )

    # Protocol mappers are a sub-resource too: a `PUT` carrying `protocolMappers` changes nothing.
    def reconcile_mappers(self, uuid: str) -> None:
        desired = {
            str(m.get("name")): m
            for m in (self.desired.get("protocolMappers") or [])
            if isinstance(m, dict)
        }
        base = f"/admin/realms/{self.realm}/clients/{uuid}/protocol-mappers/models"
        existing = self.admin.get(base) or []
        existing_by_name = {str(m.get("name")): m for m in existing if isinstance(m, dict)}

        for surplus in sorted(set(existing_by_name) - set(desired)):
            self._act(
                f"remove protocol mapper {surplus!r} (not in the committed representation)",
                "DELETE",
                f"{base}/{existing_by_name[surplus]['id']}",
            )
        for name, mapper in sorted(desired.items()):
            current = existing_by_name.get(name)
            if current is None:
                self._act(f"create protocol mapper {name!r}", "POST", base, mapper)
            elif not _mapper_matches(current, mapper):
                self._act(
                    f"update protocol mapper {name!r}",
                    "PUT",
                    f"{base}/{current['id']}",
                    {**mapper, "id": current["id"]},
                )


#: Sub-resources Keycloak ignores on a client UPDATE. They are reconciled by their own endpoints, so
#: comparing them here would report a difference this ``PUT`` could never close.
_SUBRESOURCE_KEYS = frozenset({"protocolMappers", "defaultClientScopes", "optionalClientScopes"})


def core_matches(deployed: dict[str, Any], desired_core: dict[str, Any]) -> bool:
    """Whether the deployed client already carries every desired core field.

    Convergence has to be OBSERVABLE, not assumed: without this an ``apply`` would issue its ``PUT``
    on every run, ``mutations`` would never reach zero, and "the realm is already correct" would be
    indistinguishable from "the realm was just corrected". With it, a second ``apply`` against a
    converged realm produces an EMPTY action list, which is what the integration test asserts.

    ``attributes`` is compared key-by-key because Keycloak adds its own
    (``post.logout.redirect.uris`` among them); a whole-object comparison would never match.
    """
    for key, value in desired_core.items():
        if key in _SUBRESOURCE_KEYS:
            continue
        if key == "attributes":
            current = deployed.get("attributes") or {}
            if any(str(current.get(k)) != str(v) for k, v in (value or {}).items()):
                return False
            continue
        if deployed.get(key) != value:
            return False
    return True


def _mapper_matches(current: dict[str, Any], desired: dict[str, Any]) -> bool:
    """Whether a deployed mapper already carries every desired key.

    Keycloak adds its own defaults to a mapper's ``config`` (``introspection.token.claim`` and
    friends), so this compares the DESIRED keys rather than the whole object — otherwise the tool
    would rewrite an already-correct mapper on every run and never converge.
    """
    if current.get("protocolMapper") != desired.get("protocolMapper"):
        return False
    current_config = current.get("config") or {}
    for key, value in (desired.get("config") or {}).items():
        if str(current_config.get(key)) != str(value):
            return False
    return True


# --- live verification ---------------------------------------------------------------------------


def check_deployed_client(client: dict[str, Any], assigned_default_scopes: list[str]) -> list[str]:
    """Assert a DEPLOYED client (as the Admin REST API returns it) matches the committed posture.

    ``assigned_default_scopes`` comes from the ``default-client-scopes`` sub-resource, not from the
    client representation: the representation's copy is what a ``PUT`` ignores, so trusting it would
    verify the wrong thing.
    """
    problems: list[str] = []
    if client.get("publicClient") is not True:
        problems.append("deployed client is not a public client")
    if client.get("secret"):
        problems.append("deployed client carries a client SECRET; a public client must have none")
    if (client.get("attributes") or {}).get(DEVICE_GRANT_ATTRIBUTE) != "true":
        problems.append("deployed client does not have the device authorization grant enabled")
    for flag in REFUSED_FLOWS:
        if client.get(flag) is not False:
            problems.append(f"deployed client has {flag} enabled")
    if client.get("fullScopeAllowed") is not False:
        problems.append("deployed client has fullScopeAllowed enabled (token-size control)")
    if client.get("redirectUris"):
        problems.append("deployed client declares a redirect URI")
    problems.extend(check_scope_policy(assigned_default_scopes, "assigned default client scopes"))
    return problems


def verify_deployment(
    admin: KeycloakAdmin,
    realm: str,
    desired: dict[str, Any],
    *,
    discovery_document: object,
    issuer: str,
    require_https: bool,
    revocation_probe_status: int | None,
) -> list[str]:
    """Every read-only assertion, in one list. An empty list is the only pass."""
    problems = list(check_discovery(discovery_document, issuer=issuer, require_https=require_https))
    if revocation_probe_status is not None:
        problems.extend(check_public_revocation_probe(revocation_probe_status))

    query = urllib.parse.urlencode({"clientId": CLIENT_ID})
    found = admin.get(f"/admin/realms/{realm}/clients?{query}")
    matches = [c for c in (found or []) if isinstance(c, dict) and c.get("clientId") == CLIENT_ID]
    if len(matches) != 1:
        problems.append(f"expected exactly 1 client named {CLIENT_ID!r}, found {len(matches)}")
        return problems

    client = matches[0]
    uuid = client["id"]
    assigned = admin.get(f"/admin/realms/{realm}/clients/{uuid}/default-client-scopes") or []
    names = sorted(str(s.get("name")) for s in assigned if isinstance(s, dict))
    expected = sorted(desired_default_scopes(desired))
    if names != expected:
        problems.append(
            f"assigned default client scopes are {names} but the committed representation pins "
            f"{expected} (exactly {len(expected)}, not a superset)"
        )
    problems.extend(check_deployed_client(client, names))

    mappers = admin.get(f"/admin/realms/{realm}/clients/{uuid}/protocol-mappers/models") or []
    problems.extend(check_audience_mappers(mappers))
    return problems


# --- command line --------------------------------------------------------------------------------


def _require_admin_credentials(env: dict) -> tuple[str, str]:
    username = env.get(ENV_ADMIN_USER)
    password = env.get(ENV_ADMIN_PASSWORD)
    if not username or not password:
        raise DeploymentError(
            f"set {ENV_ADMIN_USER} and {ENV_ADMIN_PASSWORD} in the environment "
            "(there is deliberately no --password flag)"
        )
    return username, password


def _require_base_url(base_url: str | None, *, insecure_http: bool) -> str:
    if not base_url:
        raise DeploymentError("--base-url is required for this action")
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise DeploymentError("--base-url must be an http(s) URL with a host")
    if parsed.scheme != "https" and not insecure_http:
        raise DeploymentError(
            "--base-url is plaintext http. Pass --insecure-http to allow it; it exists for a "
            "disposable containerised realm and never for a real deployment"
        )
    return base_url.rstrip("/")


def issuer_for(base_url: str, realm: str) -> str:
    return f"{base_url.rstrip('/')}/realms/{realm}"


def fetch_discovery(base_url: str, realm: str, transport: Transport) -> object:
    status, _headers, body = transport(
        "GET",
        f"{issuer_for(base_url, realm)}/.well-known/openid-configuration",
        {"Accept": "application/json"},
        None,
    )
    if status // 100 != 2:
        raise DeploymentError(f"discovery document request failed with HTTP {status}")
    try:
        return json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise DeploymentError("discovery document is not JSON") from exc


#: A syntactically valid, structurally meaningless token used ONLY to prove the revocation endpoint
#: accepts a public client. It is not a credential and never was one.
_REVOCATION_PROBE_TOKEN = "secp-cli-deployment-probe-not-a-token"


def probe_revocation(base_url: str, realm: str, transport: Transport) -> int:
    form = urllib.parse.urlencode(
        {
            "token": _REVOCATION_PROBE_TOKEN,
            "token_type_hint": "access_token",
            "client_id": CLIENT_ID,
        }
    ).encode("utf-8")
    status, _headers, _body = transport(
        "POST",
        f"{issuer_for(base_url, realm)}/protocol/openid-connect/revoke",
        {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        form,
    )
    return status


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secp_cli_client.py",
        description="Deploy and verify the public secp-cli device-grant client.",
    )
    parser.add_argument(
        "action",
        nargs="?",
        default="plan",
        choices=("plan", "apply", "verify"),
        help="plan (offline default), apply (dry run unless --write --confirm), verify (read-only)",
    )
    parser.add_argument("--base-url", help="Keycloak base URL, e.g. https://idp.example.com")
    parser.add_argument("--realm", default="secp", help="target realm (default: secp)")
    parser.add_argument("--write", action="store_true", help="perform mutations (apply only)")
    parser.add_argument("--confirm", action="store_true", help="required alongside --write")
    parser.add_argument(
        "--insecure-http",
        action="store_true",
        help="allow a plaintext base URL (disposable containerised realm only)",
    )
    parser.add_argument(
        "--discovery-only",
        action="store_true",
        help="verify: skip every check that needs administrator credentials",
    )
    parser.add_argument("--json", action="store_true", help="emit a machine-readable report")
    return parser


def main(argv: list[str] | None = None, *, transport: Transport = urllib_transport) -> int:
    args = build_parser().parse_args(argv)
    env = dict(os.environ)
    report: dict[str, Any] = {"action": args.action, "client_id": CLIENT_ID}

    try:
        desired = load_artifact()
        artifact_problems = check_artifact(desired)
        report["artifact_problems"] = artifact_problems

        if args.action == "plan":
            report["default_client_scopes"] = desired_default_scopes(desired)
            report["refused_scopes"] = sorted(REFUSED_DEFAULT_SCOPES)
            report["ok"] = not artifact_problems
            _emit(report, args.json, plan=desired)
            return 0 if not artifact_problems else 1

        if artifact_problems:
            report["ok"] = False
            _emit(report, args.json)
            return 1

        base_url = _require_base_url(args.base_url, insecure_http=args.insecure_http)
        admin = KeycloakAdmin(
            base_url,
            transport=transport,
            admin_realm=env.get(ENV_ADMIN_REALM, _DEFAULT_ADMIN_REALM),
            admin_client_id=env.get(ENV_ADMIN_CLIENT_ID, _DEFAULT_ADMIN_CLIENT_ID),
        )

        if args.action == "apply":
            if args.write and not args.confirm:
                raise DeploymentError("--write requires --confirm")
            admin.authenticate(*_require_admin_credentials(env))
            actions = Reconciler(admin, args.realm, desired, write=args.write).run()
            report["mode"] = "write" if args.write else "dry_run"
            report["actions"] = actions
            report["mutations"] = admin.mutations
            report["ok"] = True
            _emit(report, args.json)
            return 0

        # verify
        document = fetch_discovery(base_url, args.realm, transport)
        probe = probe_revocation(base_url, args.realm, transport)
        issuer = issuer_for(base_url, args.realm)
        if args.discovery_only:
            problems = check_discovery(
                document, issuer=issuer, require_https=not args.insecure_http
            )
            problems.extend(check_public_revocation_probe(probe))
        else:
            admin.authenticate(*_require_admin_credentials(env))
            problems = verify_deployment(
                admin,
                args.realm,
                desired,
                discovery_document=document,
                issuer=issuer,
                require_https=not args.insecure_http,
                revocation_probe_status=probe,
            )
        report["problems"] = problems
        report["ok"] = not problems
        report["mutations"] = admin.mutations
        _emit(report, args.json)
        return 0 if not problems else 1

    except DeploymentError as exc:
        report["ok"] = False
        report["error"] = str(exc)
        _emit(report, args.json)
        return 2


def _emit(report: dict[str, Any], as_json: bool, *, plan: dict[str, Any] | None = None) -> None:
    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return
    print(f"action: {report['action']}  client: {report['client_id']}")
    if plan is not None:
        print(json.dumps(plan, indent=2, sort_keys=True))
    for key in ("actions", "problems", "artifact_problems"):
        for line in report.get(key) or []:
            print(f"  [{key.rstrip('s')}] {line}")
    if "mutations" in report:
        print(f"  mutating requests issued: {report['mutations']}")
    if "error" in report:
        print(f"  ERROR: {report['error']}")
    print(f"  ok: {report.get('ok')}")


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    sys.exit(main())
