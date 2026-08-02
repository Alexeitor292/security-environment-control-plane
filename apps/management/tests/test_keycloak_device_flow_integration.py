"""Real RFC 8628 device flow against a DISPOSABLE containerised Keycloak — SECP-PR5H-B2, WS-C.

This is the live half of the deployment slice; ``tests/test_keycloak_secp_cli_deployment.py`` is the
hermetic half. Nothing here is stubbed on the identity-provider side: a Keycloak container is
created by this module, configured from the COMMITTED ``infra/keycloak/secp-cli-client.json``,
driven through a genuine device-authorization grant with a genuine interactive approval, and
destroyed again. The token that gets stored is one a real provider actually minted.

Only the CONTROLLER half is stubbed (bounded ``GET /api/v1/auth/config`` and ``GET /api/v1/me``
responses) and only the OS keystore is faked (an in-memory binding behind the real
``OsKeystoreCredentialStore``, so the real record encoding and the real ``require_storable`` bound
are still in the path). Everything between those two edges — discovery, the device-authorization
request, the poll schedule, the token request, the JWKS fetch, token verification, record encoding,
revocation — is shipped code talking to a real provider.

WHAT THIS PROVES THAT A STUBBED TOKEN ENDPOINT CANNOT
------------------------------------------------------
The size control. ``secpctl auth login`` fails at the WORST possible moment when the ``roles``
client scope is attached: the grant completes, the operator approves interactively, the token
verifies — and only then does the credential store refuse it as too large for an OS keystore record.
A stub can assert that a big string is refused; it cannot tell you whether a REAL Keycloak, on a
realistic realm, actually issues a token that big. So two realms are created from the same
skeleton and the same operator carrying the same roles, differing ONLY in the two settings the
artifact pins, and the flow is run for real against both:

* ``artifact``        — the committed representation                    -> login SUCCEEDS
* ``console-default`` — Keycloak's own console defaults restored -> refused, too large

Both realms are built by mutating the LOADED artifact object, and the number of differing fields is
asserted, so the negative result is attributable to those fields and to nothing else.

RUNNING IT
----------
Requires Docker. Opt in explicitly::

    SECP_TEST_KEYCLOAK_DEVICE_FLOW=1 pytest \
        apps/management/tests/test_keycloak_device_flow_integration.py

CI runs it in the ``backend-keycloak-device-flow`` job, which additionally refuses a skipped or
under-collected result — a skipped body proves nothing about itself.
"""

from __future__ import annotations

import base64
import copy
import html as htmllib
import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urljoin

import httpx
import pytest
import yaml
from secp_management.auth_cli import AuthCliDeps, auth_login, auth_logout
from secp_management.controller_api_locator import ControllerApiLocator
from secp_management.device_grant import DEVICE_CODE_GRANT_TYPE
from secp_management.operator_credential_backends import MAX_SECRET_BYTES
from secp_management.operator_credential_store import (
    CREDENTIAL_SERVICE_NAME,
    CredentialRecord,
    OsKeystoreCredentialStore,
)
from secp_management.operator_device_auth import (
    OPERATOR_CLI_CLIENT_ID,
    OPERATOR_CLI_SCOPE,
    DeviceAuthorizationClient,
)
from secp_management.transaction import EXIT_OK, WriteGate

REPO = Path(__file__).resolve().parents[3]
ARTIFACT_PATH = REPO / "infra" / "keycloak" / "secp-cli-client.json"
SKELETON_PATH = REPO / "infra" / "keycloak" / "test-realm-skeleton.json"
DEV_COMPOSE_PATH = REPO / "infra" / "dev" / "docker-compose.yml"
TOOL_PATH = REPO / "scripts" / "keycloak" / "secp_cli_client.py"

ENABLE_ENV = "SECP_TEST_KEYCLOAK_DEVICE_FLOW"

pytestmark = pytest.mark.skipif(
    os.environ.get(ENABLE_ENV) != "1",
    reason=f"set {ENABLE_ENV}=1 (and have Docker) to run the real device-flow proof",
)

#: The disposable realm's operator carries this many realm roles. It is the "deployment with many
#: roles" the size control exists for, and it is an EXACT count that the fixture verifies landed —
#: an empty role load would make the negative result meaningless.
OPERATOR_ROLE_COUNT = 48

OPERATOR_USERNAME = "test-operator"
OPERATOR_PASSWORD = "dev-only-disposable-operator-password-change-me"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "dev-only-disposable-admin-password-change-me"

#: The controller the CLI believes it is acting for. Never contacted: the controller transport is a
#: one-route stub, because the controller is not what this module is testing.
CONTROLLER_ORIGIN = "https://controller.disposable.invalid"
LOCATOR = ControllerApiLocator(
    canonical_origin=CONTROLLER_ORIGIN, ca_bundle_path="/etc/secp/controller/ca.pem"
)

_STARTUP_TIMEOUT_SECONDS = 240.0
_HTTP_TIMEOUT = 30.0

#: Keycloak 25 serves ``/health/*`` on a separate MANAGEMENT interface (port 9000), not on the HTTP
#: port. Gating readiness on the provider's own health endpoint rather than on a sleep is what keeps
#: this job from going flaky for every stream once it is a required check.
_MANAGEMENT_PORT = 9000

#: Sub-budget for the health port to answer AT ALL. Distinguishing "the management interface never
#: appeared" from "the provider was slow" matters: the first means the image moved the port (a
#: version bump) and the second means a loaded runner. Reported as different failures.
_HEALTH_PORT_BUDGET_SECONDS = 90.0

#: RFC 8628 §3.5: on ``slow_down`` the client MUST increase its polling interval by 5 seconds.
_SLOW_DOWN_INCREMENT_SECONDS = 5

#: Ceiling for a device-grant poll after the approval has been submitted. Generous, because it is a
#: failure bound and not an expected duration — the loop exits as soon as the provider answers.
_TOKEN_POLL_BUDGET_SECONDS = 120.0


def _load_tool():
    spec = importlib.util.spec_from_file_location("secp_cli_client_tool_live", TOOL_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["secp_cli_client_tool_live"] = module
    spec.loader.exec_module(module)
    return module


tool = _load_tool()


# --- disposable provider --------------------------------------------------------------------------


def _keycloak_image() -> str:
    """The image the DEV STACK runs, read from its compose file.

    One pin, not two. A test that ran a different Keycloak version than the deployment would be
    proving something about a provider nobody deploys.
    """
    compose = yaml.safe_load(DEV_COMPOSE_PATH.read_text(encoding="utf-8"))
    return str(compose["services"]["keycloak"]["image"])


def _free_ports(count: int) -> list[int]:
    """``count`` DISTINCT free ports.

    Every socket is held open until all of them are bound, then all are closed. Calling a
    single-port helper twice can return the SAME port — the first socket is closed before the
    second binds, so the kernel is free to hand it back — and the container would then fail to
    publish with a message about the port, not about the race that caused it.
    """
    held: list[socket.socket] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            held.append(sock)
        ports = [int(sock.getsockname()[1]) for sock in held]
    finally:
        for sock in held:
            sock.close()
    assert len(set(ports)) == count, f"port allocation collided: {ports}"
    return ports


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run one ``docker`` command. A failure fails the TEST with the daemon's own words.

    ``check=True`` would raise a ``CalledProcessError`` whose repr omits stderr, and "the container
    could not start" is exactly the message worth reading.
    """
    completed = subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=False, timeout=300
    )
    if check and completed.returncode != 0:
        pytest.fail(
            f"`docker {' '.join(args[:2])}` failed with exit {completed.returncode}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    return completed


class Provider:
    """A disposable Keycloak, plus the Admin REST calls the fixtures need."""

    def __init__(self, base_url: str, container: str) -> None:
        self.base_url = base_url
        self.container = container
        self._token: str | None = None

    # --- admin ---------------------------------------------------------------------------------

    def admin_token(self) -> str:
        response = httpx.post(
            f"{self.base_url}/realms/master/protocol/openid-connect/token",
            data={
                "client_id": "admin-cli",
                "username": ADMIN_USERNAME,
                "password": ADMIN_PASSWORD,
                "grant_type": "password",
            },
            timeout=_HTTP_TIMEOUT,
        )
        response.raise_for_status()
        return str(response.json()["access_token"])

    def _headers(self) -> dict:
        if self._token is None:
            self._token = self.admin_token()
        return {"Authorization": f"Bearer {self._token}"}

    def admin_get(self, path: str):
        response = httpx.get(
            f"{self.base_url}{path}", headers=self._headers(), timeout=_HTTP_TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    def create_realm(self, realm: dict) -> None:
        response = httpx.post(
            f"{self.base_url}/admin/realms",
            json=realm,
            headers=self._headers(),
            timeout=120.0,
        )
        assert response.status_code == 201, (
            f"realm import failed: {response.status_code} {response.text[:400]}"
        )

    def issuer(self, realm: str) -> str:
        return f"{self.base_url}/realms/{realm}"


@pytest.fixture(scope="module")
def provider():
    """Create a Keycloak container for this module and destroy it afterwards, always."""
    probe = _docker("version", "--format", "{{.Server.Version}}", check=False)
    if probe.returncode != 0:
        # Deliberately a FAILURE, not a skip. This module is opted into explicitly; once it has
        # been asked to run, "Docker was missing" must not read as "the proof passed".
        pytest.fail(f"Docker is required and did not answer: {probe.stderr.strip()}")

    port, management_port = _free_ports(2)
    name = f"secp-cli-device-flow-{uuid.uuid4().hex[:12]}"
    _docker(
        "run",
        "-d",
        "--name",
        name,
        "-p",
        f"127.0.0.1:{port}:8080",
        # The management interface, published so readiness can be gated on the provider's OWN
        # health endpoint rather than on a sleep or on a guess about when it is up.
        "-p",
        f"127.0.0.1:{management_port}:{_MANAGEMENT_PORT}",
        "-e",
        f"KEYCLOAK_ADMIN={ADMIN_USERNAME}",
        "-e",
        f"KEYCLOAK_ADMIN_PASSWORD={ADMIN_PASSWORD}",
        "-e",
        "KC_HTTP_PORT=8080",
        _keycloak_image(),
        "start-dev",
        # Off by default. The dev compose service enables it; this container is started by this
        # module and would not have it otherwise.
        "--health-enabled=true",
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        _await_ready(base_url, f"http://127.0.0.1:{management_port}", name)
        yield Provider(base_url, name)
    finally:
        _docker("rm", "-f", name, check=False)


def _poll_until(probe: Callable[[], str | None], *, budget: float, interval: float = 2.0) -> str:
    """Call ``probe`` until it returns ``None`` (ready) or the budget expires.

    ``probe`` returns a short string describing why it is not ready yet, so the caller can report
    the LAST reason rather than only that time ran out. Returns "" on success, else that reason.
    """
    deadline = time.monotonic() + budget
    last = "never answered"
    while time.monotonic() < deadline:
        reason = probe()
        if reason is None:
            return ""
        last = reason
        time.sleep(interval)
    return last


def _await_ready(base_url: str, management_url: str, container: str) -> None:
    """Gate on the provider's OWN readiness signal, in two phases with distinguishable failures.

    Never a fixed sleep. This job is a required check for every stream once it lands, so a flaky
    readiness gate would turn every unrelated PR red with a cause that looks like their change.

    The two phases fail differently ON PURPOSE. "The management interface never answered" means the
    image moved the health port (Keycloak 24 and earlier served it on the HTTP port; 25 moved it to
    the management interface), which is a version-bump defect. "Health answered but OIDC did not"
    means a slow or wedged realm subsystem. Collapsing them into one timeout message would make a
    version bump read as runner slowness, which is the diagnosis that costs the most time.
    """

    def health_probe() -> str | None:
        try:
            response = httpx.get(f"{management_url}/health/ready", timeout=5.0)
        except httpx.HTTPError as exc:
            return type(exc).__name__
        return None if response.status_code == 200 else f"HTTP {response.status_code}"

    started = time.monotonic()
    reason = _poll_until(health_probe, budget=_HEALTH_PORT_BUDGET_SECONDS)
    if reason:
        logs = _docker("logs", "--tail", "40", container, check=False)
        pytest.fail(
            f"the Keycloak management interface at {management_url}/health/ready did not answer "
            f"within {_HEALTH_PORT_BUDGET_SECONDS:.0f}s (last: {reason}). This is NOT ordinary "
            f"runner slowness: --health-enabled=true was passed, so either the image moved the "
            f"health endpoint off port {_MANAGEMENT_PORT} (check the image pin in "
            f"{DEV_COMPOSE_PATH.name}) or the container never started. "
            f"Container logs:\n{logs.stdout}{logs.stderr}"
        )

    # Health-ready is necessary but not sufficient: it says the server is up, not that this realm's
    # OIDC endpoints are serving. The flow needs the second thing, so both are gated.
    def oidc_probe() -> str | None:
        try:
            response = httpx.get(
                f"{base_url}/realms/master/.well-known/openid-configuration", timeout=5.0
            )
        except httpx.HTTPError as exc:
            return type(exc).__name__
        return None if response.status_code == 200 else f"HTTP {response.status_code}"

    remaining = max(10.0, _STARTUP_TIMEOUT_SECONDS - (time.monotonic() - started))
    reason = _poll_until(oidc_probe, budget=remaining)
    if reason:
        logs = _docker("logs", "--tail", "40", container, check=False)
        pytest.fail(
            f"Keycloak reported health-ready but its OIDC discovery endpoint did not answer within "
            f"{remaining:.0f}s (last: {reason}) — the realm subsystem is slow or wedged, not the "
            f"container. Container logs:\n{logs.stdout}{logs.stderr}"
        )


# --- realms built from the committed artifact -----------------------------------------------------


def _role_names() -> list[str]:
    return [f"secp-exercise-operator-{index:03d}" for index in range(OPERATOR_ROLE_COUNT)]


def _artifact_client() -> dict:
    return json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))


def _console_default_client() -> dict:
    """The artifact with Keycloak's OWN console defaults put back.

    These are not invented failure modes: ``roles`` is attached to every client the admin console
    creates, and ``fullScopeAllowed`` defaults to ``true`` there. This object is what an operator
    ends up with by following a click-path, which is exactly what the artifact replaces.
    """
    client = _artifact_client()
    client["defaultClientScopes"] = [*client["defaultClientScopes"], "roles"]
    client["fullScopeAllowed"] = True
    return client


def _realm_document(name: str, client: dict) -> dict:
    realm = json.loads(SKELETON_PATH.read_text(encoding="utf-8"))
    realm["realm"] = name
    realm["clients"] = [client]
    roles = _role_names()
    realm["roles"]["realm"] = [{"name": role} for role in roles]
    realm["users"][0]["realmRoles"] = roles
    return realm


def _provision(provider: Provider, name: str, client: dict) -> str:
    provider.create_realm(_realm_document(name, client))
    users = provider.admin_get(f"/admin/realms/{name}/users?username={OPERATOR_USERNAME}")
    assert len(users) == 1, f"expected exactly 1 operator in {name}, found {len(users)}"
    mapped = provider.admin_get(f"/admin/realms/{name}/users/{users[0]['id']}/role-mappings/realm")
    granted = {role["name"] for role in mapped} & set(_role_names())
    assert len(granted) == OPERATOR_ROLE_COUNT, (
        f"the role load did not land in {name}: {len(granted)} of {OPERATOR_ROLE_COUNT}"
    )
    return name


@pytest.fixture(scope="module")
def artifact_realm(provider) -> str:
    return _provision(provider, "secp-artifact", _artifact_client())


@pytest.fixture(scope="module")
def console_default_realm(provider) -> str:
    return _provision(provider, "secp-console-default", _console_default_client())


@pytest.fixture(scope="module")
def drifted_realm(provider) -> str:
    """A private realm for the reconciler to REPAIR, so repairing it cannot disturb the
    console-default realm the negative proof depends on."""
    return _provision(provider, "secp-drifted", _console_default_client())


@pytest.fixture(scope="module")
def repaired_realm(provider) -> str:
    """A console-default realm that HAS been repaired by the reconciler.

    Its own realm rather than a reuse of ``drifted_realm``, so "the repair fixes the actual failure"
    and "the reconciler converges" are independent facts. Depending on the other test having run
    first would make one of them silently conditional on pytest's collection order.
    """
    name = _provision(provider, "secp-repaired", _console_default_client())
    admin = tool.KeycloakAdmin(provider.base_url)
    admin.authenticate(ADMIN_USERNAME, ADMIN_PASSWORD)
    actions = tool.Reconciler(admin, name, _artifact_client(), write=True).run()
    assert admin.mutations == len(actions) >= 2, actions
    return name


# --- the operator, approving for real -------------------------------------------------------------

_FORM = re.compile(r"<form[^>]*>.*?</form>", re.DOTALL | re.IGNORECASE)
_ACTION = re.compile(r'action="([^"]*)"', re.IGNORECASE)
_INPUT = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_ATTR = re.compile(r'(\w+)="([^"]*)"')
_MAX_APPROVAL_PAGES = 6


def _first_form(page_html: str) -> dict | None:
    match = _FORM.search(page_html)
    if match is None:
        return None
    raw = match.group(0)
    action = _ACTION.search(raw)
    return {
        "action": htmllib.unescape(action.group(1)) if action else "",
        "fields": [dict(_ATTR.findall(tag)) for tag in _INPUT.findall(raw)],
    }


class OperatorApproval:
    """Approves the grant the way an operator does: through the provider's OWN pages.

    Keycloak serves two of them for a device grant — sign-in, then the ``OAUTH_GRANT``
    confirmation —
    and this walks both by submitting the forms it is given. It never guesses a URL and never calls
    an admin API to shortcut the consent, because the point is that the operator-facing half of RFC
    8628 works, not just the machine-facing half.

    ``cancel`` is explicitly never submitted: it is the button that DENIES the grant, and a driver
    that pressed whichever submit came first would silently test the denial path.
    """

    def __init__(self) -> None:
        self.prompts: list[dict] = []
        self.submissions = 0

    def __call__(self, prompt: dict) -> None:
        self.prompts.append(prompt)
        uri = prompt.get("verification_uri_complete") or prompt["verification_uri"]
        browser = httpx.Client(follow_redirects=True, timeout=_HTTP_TIMEOUT)
        try:
            page = browser.get(uri)
            for _ in range(_MAX_APPROVAL_PAGES):
                form = _first_form(page.text)
                if form is None:
                    return
                data: dict[str, str] = {}
                chosen = False
                for field in form["fields"]:
                    name = field.get("name")
                    if not name:
                        continue
                    kind = field.get("type", "text")
                    if kind == "password":
                        data[name] = OPERATOR_PASSWORD
                    elif name == "username":
                        data[name] = OPERATOR_USERNAME
                    elif name == "user_code":
                        data[name] = prompt["user_code"]
                    elif kind == "submit":
                        if name == "cancel" or chosen:
                            continue
                        data[name] = field.get("value", "")
                        chosen = True
                    else:
                        data[name] = field.get("value", "")
                target = urljoin(str(page.url), form["action"]) if form["action"] else str(page.url)
                page = browser.post(target, data=data)
                self.submissions += 1
            raise AssertionError("the approval pages did not terminate")
        finally:
            browser.close()


# --- the CLI, composed against the disposable provider ------------------------------------------


class _Headers:
    def __init__(self, values: list[str]) -> None:
        self._values = values

    def get_list(self, _name: str) -> list[str]:
        return self._values


class _StubResponse:
    def __init__(self, payload: dict) -> None:
        self.status_code = 200
        self.content = json.dumps(payload).encode("utf-8")
        self.headers = _Headers([])
        self.is_redirect = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_bytes(self):
        yield self.content


class _ControllerStub:
    """The controller's public auth config and authoritative principal routes, and nothing else.

    The controller is CA-pinned in the shipped composition and is not what this module tests, so it
    is the single seam replaced on that side. Login nevertheless must resolve the database-backed
    principal before its first credential write, so the double serves that second bounded response
    and proves the request carried a bearer without retaining its value. The issuer side has no seam
    replaced at all.
    """

    def __init__(self, issuer: str) -> None:
        self._auth_config = {
            "mode": "oidc",
            "issuer": issuer,
            "client_id": "secp-web",
            "audience": "secp-api",
            "scope": OPERATOR_CLI_SCOPE,
            "redirect_path": "/auth/callback",
            "post_logout_redirect_path": "/login",
        }
        self._principal = {
            "user_id": "5ec9ad00-0000-4000-8000-000000000001",
            "organization_id": "6ec9ad00-0000-4000-8000-000000000001",
            "email": "operator@example.invalid",
            "permissions": ["enrollment:manage", "enrollment:read"],
            "is_dev_fallback": False,
        }
        self.requested: list[str] = []
        self.bearer_requests = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def stream(self, method: str, url: str, *, headers: dict[str, str] | None = None):
        assert method == "GET"
        self.requested.append(url)
        if url.endswith("/api/v1/auth/config"):
            assert headers is None
            return _StubResponse(self._auth_config)
        if url.endswith("/api/v1/me"):
            authorization = "" if headers is None else headers.get("Authorization", "")
            assert authorization.startswith("Bearer ") and len(authorization) > len("Bearer ")
            self.bearer_requests += 1
            return _StubResponse(self._principal)
        raise AssertionError("the auth client requested an unexpected controller route")


class FakeKeystore:
    """In-memory stand-in for ONE OS keystore. The real ``OsKeystoreCredentialStore`` sits in front
    of it, so the real record encoding and the real ``require_storable`` bound still apply."""

    backend_id = "fake_os_keystore"

    def __init__(self) -> None:
        self.entries: dict[tuple[str, str], bytes] = {}

    def set_secret(self, *, service, account, secret) -> None:
        self.entries[(service, account)] = bytes(secret)

    def get_secret(self, *, service, account):
        return self.entries.get((service, account))

    def delete_secret(self, *, service, account) -> bool:
        return self.entries.pop((service, account), None) is not None


class _Composition:
    """One fully composed ``secpctl auth`` invocation against one realm."""

    def __init__(self, provider: Provider, realm: str) -> None:
        self.issuer = provider.issuer(realm)
        self.keystore = FakeKeystore()
        self.approval = OperatorApproval()
        self.controller = _ControllerStub(self.issuer)

        def device_client(locator):
            return DeviceAuthorizationClient(
                locator=locator,
                # The disposable provider speaks plain HTTP on loopback. This is the SAME seam the
                # module's own unit tests use, and it is the only relaxation made here.
                require_https=False,
                pinned_client_factory=lambda: self.controller,
            )

        self.deps = AuthCliDeps(
            credential_store=OsKeystoreCredentialStore(self.keystore),
            locator_provider=_FixedLocator(),
            device_client=device_client,
            present=self.approval,
            # This proof composes the OS store only. Make the absence of the independently
            # configurable protected token file explicit so multi-source logout does not have to
            # treat an unknown source as an unreadable, potentially-live credential.
            token_file_active=lambda: False,
        )

    @property
    def account(self) -> str:
        return CONTROLLER_ORIGIN

    def stored_record(self) -> CredentialRecord:
        raw = self.keystore.get_secret(service=CREDENTIAL_SERVICE_NAME, account=self.account)
        assert raw is not None, "no credential was stored"
        return CredentialRecord.from_bytes(raw)


class _FixedLocator:
    def locate(self) -> ControllerApiLocator:
        return LOCATOR


def _poll_for_token(client, endpoints, authorization) -> str:
    """Poll the token endpoint the way RFC 8628 §3.5 says to, and return the access token.

    The three tests that drive the transport directly (rather than through ``auth_login``, which
    has the shipped scheduler) previously slept ``interval + 1`` once and asserted the very next
    response was the token. That is a wall-clock assumption in two ways, and both are the shape
    that goes flaky under CI load once this job is a required check for every stream:

    * it assumes the approval has propagated by the time the single request goes out, so a slow
      provider reads as a device-flow defect;
    * it ignores ``slow_down``. §3.5 says a client that polls too fast gets ``slow_down`` and MUST
      add 5 seconds to its interval. A single-shot assertion turns that CORRECT provider behaviour
      into a test failure.

    So this honours the server's own numbers: the interval it licensed in the authorization
    response, increased by 5 whenever the server says to. The budget is a failure bound, not an
    expected duration — the loop returns as soon as the provider answers.
    """
    interval = float(authorization.interval)
    deadline = time.monotonic() + _TOKEN_POLL_BUDGET_SECONDS
    attempts = 0
    while time.monotonic() < deadline:
        time.sleep(interval)
        attempts += 1
        token, error = client.request_token(endpoints, authorization.device_code)
        if not error:
            return token
        if error == "slow_down":
            interval += _SLOW_DOWN_INCREMENT_SECONDS
            continue
        if error == "authorization_pending":
            continue
        # expired_token, access_denied, invalid_grant: terminal, and worth naming exactly.
        pytest.fail(
            f"the provider refused the device grant with {error!r} after {attempts} poll(s). "
            "This is a provider answer, not a timeout."
        )
    pytest.fail(
        f"no token after {attempts} poll(s) over {_TOKEN_POLL_BUDGET_SECONDS:.0f}s at a final "
        f"interval of {interval:.0f}s. The provider kept answering authorization_pending, so the "
        "approval submission did not take effect."
    )


def _poll_raw_token(token_endpoint: str, authorization) -> dict:
    """:func:`_poll_for_token`'s semantics against the provider's RAW token response.

    Kept separate rather than parameterised because the caller needs the response BODY, including
    members (``refresh_token``) the shipped client refuses outright — routing it through the client
    would hide exactly the misconfiguration that caller is checking for.
    """
    interval = float(authorization.interval)
    deadline = time.monotonic() + _TOKEN_POLL_BUDGET_SECONDS
    attempts = 0
    while time.monotonic() < deadline:
        time.sleep(interval)
        attempts += 1
        body = httpx.post(
            token_endpoint,
            data={
                "grant_type": DEVICE_CODE_GRANT_TYPE,
                "device_code": authorization.device_code.token_request_value(),
                "client_id": OPERATOR_CLI_CLIENT_ID,
            },
            timeout=_HTTP_TIMEOUT,
        ).json()
        error = body.get("error")
        if not error:
            return body
        if error == "slow_down":
            interval += _SLOW_DOWN_INCREMENT_SECONDS
            continue
        if error == "authorization_pending":
            continue
        pytest.fail(f"the provider refused the grant with {error!r} after {attempts} poll(s)")
    pytest.fail(
        f"no raw token response after {attempts} poll(s) over {_TOKEN_POLL_BUDGET_SECONDS:.0f}s"
    )


def _claims(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


WRITE = WriteGate(write=True, confirm=True)


# --- the deployed realm matches the committed artifact --------------------------------------------


def test_the_disposable_realm_deploys_the_committed_artifact(provider, artifact_realm):
    """The provider's own view of the client must satisfy every deployment check.

    This runs the SHIPPED verifier (``scripts/keycloak/secp_cli_client.py``) against a real realm,
    so the tool that an operator points at production is the tool exercised here.
    """
    admin = tool.KeycloakAdmin(provider.base_url)
    admin.authenticate(ADMIN_USERNAME, ADMIN_PASSWORD)
    document = tool.fetch_discovery(provider.base_url, artifact_realm, tool.urllib_transport)
    probe = tool.probe_revocation(
        document["revocation_endpoint"], tool.urllib_transport, require_https=False
    )
    problems = tool.verify_deployment(
        admin,
        artifact_realm,
        _artifact_client(),
        discovery_document=document,
        issuer=provider.issuer(artifact_realm),
        require_https=False,
        revocation_probe_status=probe,
    )
    assert problems == []
    assert admin.mutations == 0  # verification is READ-ONLY, and says so with a count


def test_the_verifier_refuses_the_console_default_realm(provider, console_default_realm):
    """The paired refusal. Without it, ``problems == []`` above would be satisfied by a verifier
    that always returns an empty list."""
    admin = tool.KeycloakAdmin(provider.base_url)
    admin.authenticate(ADMIN_USERNAME, ADMIN_PASSWORD)
    document = tool.fetch_discovery(provider.base_url, console_default_realm, tool.urllib_transport)
    problems = tool.verify_deployment(
        admin,
        console_default_realm,
        _artifact_client(),
        discovery_document=document,
        issuer=provider.issuer(console_default_realm),
        require_https=False,
        revocation_probe_status=tool.probe_revocation(
            document["revocation_endpoint"], tool.urllib_transport, require_https=False
        ),
    )
    # Exactly four: the assigned scope set is not the pinned set, `roles` is attached, and
    # fullScopeAllowed is detected both as a core-representation difference and by its dedicated
    # safety check. An exact count means fewer findings — or an unrelated new one — fails here.
    assert len(problems) == 4, problems
    assert admin.mutations == 0


def test_the_two_realms_differ_in_exactly_the_documented_fields():
    """The negative result must be ATTRIBUTABLE. Count the differing fields, never describe."""
    artifact = _artifact_client()
    console = _console_default_client()
    differing = {k for k in set(artifact) | set(console) if artifact.get(k) != console.get(k)}
    assert differing == {"defaultClientScopes", "fullScopeAllowed"}
    assert len(differing) == 2
    assert set(console["defaultClientScopes"]) - set(artifact["defaultClientScopes"]) == {"roles"}


def test_the_deployed_default_scopes_are_the_pinned_set_exactly(provider, artifact_realm):
    """Read from the SUB-RESOURCE, which is the authority, not from the client representation."""
    clients = provider.admin_get(
        f"/admin/realms/{artifact_realm}/clients?clientId={OPERATOR_CLI_CLIENT_ID}"
    )
    assert len(clients) == 1
    assigned = provider.admin_get(
        f"/admin/realms/{artifact_realm}/clients/{clients[0]['id']}/default-client-scopes"
    )
    names = {scope["name"] for scope in assigned}
    assert names == set(_artifact_client()["defaultClientScopes"])
    assert len(assigned) == 3
    assert "roles" not in names


# --- RFC 8414 discovery, read by the shipped client ---------------------------------------------


def test_the_shipped_client_discovers_the_device_and_revocation_endpoints(provider, artifact_realm):
    composition = _Composition(provider, artifact_realm)
    client = composition.deps.device_client(LOCATOR)
    authority = client.reviewed_authority()
    assert authority.issuer == provider.issuer(artifact_realm)

    endpoints = client.discover(authority)
    # READ from the document, never constructed: both must be the provider's own advertised values.
    document = json.loads(
        httpx.get(
            f"{authority.issuer}/.well-known/openid-configuration", timeout=_HTTP_TIMEOUT
        ).text
    )
    assert endpoints.device_authorization_endpoint == document["device_authorization_endpoint"]
    assert endpoints.revocation_endpoint == document["revocation_endpoint"]
    assert endpoints.token_endpoint == document["token_endpoint"]
    assert endpoints.jwks_uri == document["jwks_uri"]
    assert DEVICE_CODE_GRANT_TYPE in document["grant_types_supported"]
    # The controller's public auth-config route was consumed exactly once, unchanged.
    assert len(composition.controller.requested) == 1
    assert composition.controller.requested[0].endswith("/api/v1/auth/config")


def test_the_provider_answers_authorization_pending_before_the_operator_approves(
    provider, artifact_realm
):
    """The RFC 8628 §3.5 pending->granted transition, from a REAL provider.

    A stub can be told to answer ``authorization_pending``; only a real one proves the shipped
    parser reads what Keycloak actually sends, and that the scheduler's interval is the one the
    provider licensed.
    """
    composition = _Composition(provider, artifact_realm)
    client = composition.deps.device_client(LOCATOR)
    endpoints = client.discover(client.reviewed_authority())
    authorization = client.request_device_authorization(endpoints)

    assert authorization.interval == 5  # pinned by the artifact's oauth2.device.polling.interval
    assert authorization.verification_uri_complete  # the one-paste URI the operator is given

    token, error = client.request_token(endpoints, authorization.device_code)
    assert (token, error) == ("", "authorization_pending")

    composition.approval(
        {
            "user_code": authorization.user_code,
            "verification_uri": authorization.verification_uri,
            "verification_uri_complete": authorization.verification_uri_complete,
        }
    )
    assert composition.approval.submissions >= 2  # sign-in, then the grant confirmation

    token = _poll_for_token(client, endpoints, authorization)
    assert len(token.split(".")) == 3  # a real signed JWT, not a stub string


# --- the whole customer path --------------------------------------------------------------------


def test_a_real_device_flow_stores_an_operator_credential(provider, artifact_realm):
    composition = _Composition(provider, artifact_realm)
    code, report = auth_login(composition.deps, gate=WRITE)

    assert code == EXIT_OK, report
    assert report["mode"] == "written"
    assert report["authenticated"] is True
    # The operator really was prompted, and really did approve through the provider's pages.
    assert len(composition.approval.prompts) == 1
    assert composition.approval.submissions >= 2
    assert composition.controller.requested[-1].endswith("/api/v1/me")
    assert composition.controller.bearer_requests == 1

    assert len(composition.keystore.entries) == 1  # exactly one entry, for exactly this controller
    record = composition.stored_record()
    assert record.account == CONTROLLER_ORIGIN
    assert len(record.token.split(".")) == 3
    assert record.expires_at_epoch > int(time.time())


def test_the_issued_token_carries_no_role_claims_and_fits_the_keystore(provider, artifact_realm):
    """The size control, measured on a real token from a realm with a real role load."""
    composition = _Composition(provider, artifact_realm)
    code, report = auth_login(composition.deps, gate=WRITE)
    assert code == EXIT_OK, report

    record = composition.stored_record()
    claims = _claims(record.token)
    # The realm HAS 48 roles on this operator (the fixture asserted the mapping landed), so their
    # absence here is caused by the client's scope configuration and by nothing else.
    assert "realm_access" not in claims
    assert "resource_access" not in claims
    assert claims["azp"] == OPERATOR_CLI_CLIENT_ID
    assert claims["iss"] == provider.issuer(artifact_realm)

    encoded = record.to_bytes()
    assert len(encoded) < MAX_SECRET_BYTES
    # Headroom, not a coin flip: schema v2 deliberately adds an immutable generation, but the
    # resulting record must still reserve at least 1 KiB for normal provider/key variation.
    assert MAX_SECRET_BYTES - len(encoded) >= 1024


def test_the_console_default_posture_refuses_after_the_operator_approved(
    provider, console_default_realm
):
    """THE proof this module exists for.

    Same skeleton, same operator, same 48 roles, same committed artifact — with Keycloak's console
    defaults restored. The grant completes and the operator approves; only then is the credential
    refused, which is precisely the failure the artifact prevents and precisely why a paper review
    of the client would not have caught it.
    """
    composition = _Composition(provider, console_default_realm)
    code, report = auth_login(composition.deps, gate=WRITE)

    assert report["reason_code"] == "secpctl_credential_too_large", report
    assert code != EXIT_OK
    # The failure happened AFTER the interactive approval, not before it: the operator was prompted
    # and did approve, and only the persist step refused.
    assert len(composition.approval.prompts) == 1
    assert composition.approval.submissions >= 2
    # Nothing was written anywhere on the way out.
    assert len(composition.keystore.entries) == 0
    # ...and the operator is told what to do about it, not just that it failed.
    assert "roles" in report["remedy"]


def test_the_console_default_token_really_is_the_thing_that_is_too_large(
    provider, console_default_realm
):
    """Attribute the refusal to the TOKEN, not to anything else in the record.

    The same grant is run through the transport directly, and the token is measured. Without this,
    ``secpctl_credential_too_large`` above could in principle come from any other oversized field.
    """
    composition = _Composition(provider, console_default_realm)
    client = composition.deps.device_client(LOCATOR)
    endpoints = client.discover(client.reviewed_authority())
    authorization = client.request_device_authorization(endpoints)
    composition.approval(
        {
            "user_code": authorization.user_code,
            "verification_uri": authorization.verification_uri,
            "verification_uri_complete": authorization.verification_uri_complete,
        }
    )
    token = _poll_for_token(client, endpoints, authorization)

    claims = _claims(token)
    assert len(claims["realm_access"]["roles"]) >= OPERATOR_ROLE_COUNT
    assert len(token) > MAX_SECRET_BYTES  # the TOKEN alone already exceeds the record bound


# --- RFC 7009 revocation, end to end ------------------------------------------------------------


def _userinfo_status(issuer: str, token: str) -> int:
    return httpx.get(
        f"{issuer}/protocol/openid-connect/userinfo",
        headers={"Authorization": f"Bearer {token}"},
        timeout=_HTTP_TIMEOUT,
    ).status_code


def test_logout_revokes_the_token_at_the_provider_not_only_locally(provider, artifact_realm):
    """Local deletion alone was never a logout. Prove the token STOPS WORKING at the provider.

    The proof is the provider's own answer to the token before and after: a credential that still
    authenticates after ``auth logout`` is exactly the window RFC 7009 exists to close, and only a
    real provider can tell you which side of it you are on.
    """
    composition = _Composition(provider, artifact_realm)
    code, report = auth_login(composition.deps, gate=WRITE)
    assert code == EXIT_OK, report
    token = composition.stored_record().token
    issuer = provider.issuer(artifact_realm)

    assert _userinfo_status(issuer, token) == 200  # live before

    code, report = auth_logout(composition.deps, gate=WRITE)
    assert code == EXIT_OK, report
    assert report["revoked"] is True
    assert report["token_still_live"] is False
    assert report["removed"] is True

    assert _userinfo_status(issuer, token) == 401  # dead after, at the PROVIDER
    assert len(composition.keystore.entries) == 0  # and gone locally


def test_the_revocation_endpoint_accepts_this_public_client(provider, artifact_realm):
    """Keycloak does not advertise ``none`` in ``revocation_endpoint_auth_methods_supported``, so a
    metadata-only review would conclude a public client cannot revoke here. It can, and that is the
    behaviour ``secpctl auth logout`` depends on — so it is probed rather than assumed."""
    document = tool.fetch_discovery(provider.base_url, artifact_realm, tool.urllib_transport)
    status = tool.probe_revocation(
        document["revocation_endpoint"], tool.urllib_transport, require_https=False
    )
    assert tool.check_public_revocation_probe(status) == []
    assert status == 200


# --- the reconciler repairs a drifted realm on a live provider ----------------------------------


def test_the_reconciler_repairs_a_console_default_realm_and_then_converges(provider, drifted_realm):
    """A ``PUT`` of the representation cannot remove the ``roles`` scope — Keycloak ignores that
    field on update — so this is the check that the reconciler drives the right sub-resources.

    Three post-conditions, in order: a dry run changes NOTHING (count), a write repairs the realm
    (the verifier then reports zero problems), and a second write finds nothing left to do (an empty
    action list). Without the third, "repaired" and "rewritten every time" look the same.
    """
    desired = _artifact_client()

    dry = tool.KeycloakAdmin(provider.base_url)
    dry.authenticate(ADMIN_USERNAME, ADMIN_PASSWORD)
    planned = tool.Reconciler(dry, drifted_realm, desired, write=False).run()
    assert dry.mutations == 0
    assert len([a for a in planned if a.startswith("remove default client scope 'roles'")]) == 1

    admin = tool.KeycloakAdmin(provider.base_url)
    admin.authenticate(ADMIN_USERNAME, ADMIN_PASSWORD)
    applied = tool.Reconciler(admin, drifted_realm, desired, write=True).run()
    assert admin.mutations == len(applied) >= 2

    verifier = tool.KeycloakAdmin(provider.base_url)
    verifier.authenticate(ADMIN_USERNAME, ADMIN_PASSWORD)
    document = tool.fetch_discovery(provider.base_url, drifted_realm, tool.urllib_transport)
    problems = tool.verify_deployment(
        verifier,
        drifted_realm,
        desired,
        discovery_document=document,
        issuer=provider.issuer(drifted_realm),
        require_https=False,
        revocation_probe_status=tool.probe_revocation(
            document["revocation_endpoint"],
            tool.urllib_transport,
            require_https=False,
        ),
    )
    assert problems == []

    again = tool.KeycloakAdmin(provider.base_url)
    again.authenticate(ADMIN_USERNAME, ADMIN_PASSWORD)
    assert tool.Reconciler(again, drifted_realm, desired, write=True).run() == []
    assert again.mutations == 0


def test_a_repaired_realm_issues_a_token_that_fits(provider, repaired_realm):
    """The repair has to fix the actual FAILURE, not just the configuration read-back.

    ``test_the_console_default_posture_refuses_after_the_operator_approved`` establishes that this
    realm's starting posture genuinely refuses; a successful login here is therefore attributable to
    the reconciler's removal and to nothing else. The realm is repaired by its own fixture, so this
    does not depend on another test having run first.
    """
    composition = _Composition(provider, repaired_realm)
    code, report = auth_login(composition.deps, gate=WRITE)
    assert code == EXIT_OK, report
    record = composition.stored_record()
    assert "realm_access" not in _claims(record.token)
    assert len(record.to_bytes()) < MAX_SECRET_BYTES


# --- posture the flow must never acquire --------------------------------------------------------


def test_the_grant_never_yields_a_refresh_token(provider, artifact_realm):
    """``use.refresh.tokens: false`` plus never requesting ``offline_access``. Checked against the
    provider's RAW token response, because the CLI refuses one if it arrives and would therefore
    hide the misconfiguration behind a bounded reason code."""
    composition = _Composition(provider, artifact_realm)
    client = composition.deps.device_client(LOCATOR)
    endpoints = client.discover(client.reviewed_authority())
    authorization = client.request_device_authorization(endpoints)
    composition.approval(
        {
            "user_code": authorization.user_code,
            "verification_uri": authorization.verification_uri,
            "verification_uri_complete": authorization.verification_uri_complete,
        }
    )
    # Polled RAW rather than through `_poll_for_token`: the shipped client REFUSES a response
    # carrying a refresh token, so routing this through it would turn the misconfiguration this
    # test looks for into a bounded reason code and hide it. Same RFC 8628 §3.5 semantics as the
    # helper — honour the licensed interval, add 5s on slow_down, never a bare sleep-and-assert.
    raw = _poll_raw_token(endpoints.token_endpoint, authorization)
    assert "access_token" in raw
    assert "refresh_token" not in raw
    assert set(raw["scope"].split()) == {"openid", "profile", "email"}


def test_the_client_is_deployed_without_a_secret(provider, artifact_realm):
    clients = provider.admin_get(
        f"/admin/realms/{artifact_realm}/clients?clientId={OPERATOR_CLI_CLIENT_ID}"
    )
    assert len(clients) == 1
    assert clients[0]["publicClient"] is True
    assert not clients[0].get("secret")
    # And the provider agrees the browser flows are off, whatever the artifact said.
    for flag in ("standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled"):
        assert clients[0][flag] is False


def test_the_artifact_realm_document_is_the_committed_artifact_verbatim():
    """The realm this module imports must carry the artifact UNCHANGED — otherwise every result
    above is about a client nobody deploys."""
    document = _realm_document("secp-artifact", _artifact_client())
    assert document["clients"] == [json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))]
    assert len(document["clients"]) == 1
    assert len(document["roles"]["realm"]) == OPERATOR_ROLE_COUNT
    assert len(document["users"][0]["realmRoles"]) == OPERATOR_ROLE_COUNT
    # ...and the console-default document differs from it in exactly one client field pair.
    console = _realm_document("secp-console-default", _console_default_client())
    assert console["roles"] == document["roles"]
    assert console["users"] == document["users"]
    assert copy.deepcopy(console["clients"][0]) != document["clients"][0]
