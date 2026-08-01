"""Deployment contract for the public ``secp-cli`` device-grant client — SECP-PR5H-B2, WS-C.

Hermetic: no Keycloak, no container, no socket. These pin the parts of the deployment that a
running provider cannot tell you about — that the committed artifact says what it must, that the
development realm deploys THAT artifact and not a hand-maintained copy of it, that the reconciler
refuses to write without being asked twice, and that the checker actually refuses each thing it
claims to. The live half (a real device flow against a disposable Keycloak) is
``apps/management/tests/test_keycloak_device_flow_integration.py``.

Every checker assertion here is exercised in BOTH directions. A checker that returns "no problems"
for a correct artifact proves nothing on its own: the same function would return "no problems" if
its body were ``return []``. So each guard is paired with a mutation of the LOADED artifact object
that must make it report an EXACT number of problems, against a baseline that reports zero.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest
import yaml
from secp_management.device_grant import REFUSED_SCOPES
from secp_management.operator_credential_backends import MAX_SECRET_BYTES
from secp_management.operator_device_auth import OPERATOR_CLI_CLIENT_ID, OPERATOR_CLI_SCOPE

REPO = Path(__file__).resolve().parents[1]
ARTIFACT_PATH = REPO / "infra" / "keycloak" / "secp-cli-client.json"
SKELETON_PATH = REPO / "infra" / "keycloak" / "test-realm-skeleton.json"
DEV_REALM_PATH = REPO / "infra" / "dev" / "keycloak" / "realm-secp.json"
DEV_COMPOSE_PATH = REPO / "infra" / "dev" / "docker-compose.yml"
PROD_OIDC_PATH = REPO / "infra" / "production" / "oidc.env.example"
TOOL_PATH = REPO / "scripts" / "keycloak" / "secp_cli_client.py"

#: The exact default client scopes the artifact pins. An EXACT set, not a floor: an extra scope is
#: exactly the defect this file exists to catch, so "at least these three" would be the wrong shape.
EXPECTED_DEFAULT_SCOPES = frozenset({"basic", "email", "profile"})


def _load_tool():
    spec = importlib.util.spec_from_file_location("secp_cli_client_tool", TOOL_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["secp_cli_client_tool"] = module
    spec.loader.exec_module(module)
    return module


tool = _load_tool()


@pytest.fixture
def artifact() -> dict:
    return json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))


def _dev_realm_client() -> dict:
    realm = json.loads(DEV_REALM_PATH.read_text(encoding="utf-8"))
    return next(c for c in realm["clients"] if c["clientId"] == "secp-cli")


# --- one artifact, deployed everywhere ----------------------------------------------------------


def test_dev_realm_deploys_the_committed_artifact_verbatim(artifact):
    """The development realm must EMBED the artifact, not a copy that drifts from it.

    Deep equality, both directions: a missing key and an extra key are both drift. Without this the
    dev stack could keep working while the artifact an operator applies to production says something
    different — which is the failure mode the artifact exists to remove.
    """
    assert _dev_realm_client() == artifact


def test_the_artifact_is_the_only_secp_cli_client_in_the_dev_realm():
    realm = json.loads(DEV_REALM_PATH.read_text(encoding="utf-8"))
    matching = [c for c in realm["clients"] if c.get("clientId") == "secp-cli"]
    assert len(matching) == 1


def test_the_artifact_carries_no_environment_specific_value(artifact):
    # The device grant has no browser redirect, so a correct representation has nothing in it that
    # varies per deployment. If a URL appears here, the "one artifact everywhere" claim is dead.
    blob = json.dumps(artifact)
    assert "http://" not in blob
    assert "https://" not in blob
    assert artifact.get("redirectUris") == []
    assert artifact.get("webOrigins") == []


def test_the_client_id_agrees_across_every_plane(artifact):
    """The CLI, the artifact, the dev realm and the deployment tool must name the SAME client.

    The tool deliberately does not import ``secp_management`` — it has to run on an operator's host
    where no SECP package is installed — so the literal is stated twice and pinned here, the same
    documented non-import pair pattern as ``worker_enrollment_schema`` / ``migration_heads``.
    """
    assert OPERATOR_CLI_CLIENT_ID == "secp-cli"
    assert artifact["clientId"] == OPERATOR_CLI_CLIENT_ID
    assert _dev_realm_client()["clientId"] == OPERATOR_CLI_CLIENT_ID
    assert tool.CLIENT_ID == OPERATOR_CLI_CLIENT_ID


# --- token size: the control that fails AFTER the operator has approved --------------------------


def test_default_client_scopes_are_exactly_the_three_the_cli_needs(artifact):
    scopes = artifact["defaultClientScopes"]
    assert len(scopes) == len(set(scopes)) == 3  # exact size, no duplicates
    assert set(scopes) == EXPECTED_DEFAULT_SCOPES


def test_the_roles_scope_is_absent_and_full_scope_is_off(artifact):
    """The two INDEPENDENT controls on token size, pinned separately because either one alone can
    let the token grow past the keystore record.

    ``roles`` adds ``realm_access``/``resource_access``; ``fullScopeAllowed`` (whose Keycloak
    default
    is ``true``) lets the client's own role scope-mappings inflate the token even without it.
    """
    assert "roles" not in artifact["defaultClientScopes"]
    assert artifact["optionalClientScopes"] == []
    assert artifact["fullScopeAllowed"] is False


def test_the_cli_requests_only_scopes_the_client_actually_carries(artifact):
    """Every scope ``secpctl`` asks for must be attached to the client (or be ``openid``).

    A requested scope the client does not carry is not a token that quietly lacks a claim — Keycloak
    refuses the device-authorization request outright — so this catches "the scope was trimmed
    on the
    provider but the CLI still asks for it" at review time rather than at an operator's first login.
    """
    requested = set(OPERATOR_CLI_SCOPE.split())
    assert requested == {"openid", "profile", "email"}
    assert requested - {"openid"} <= set(artifact["defaultClientScopes"])


def test_the_refused_scope_policy_agrees_across_the_boundary():
    # `offline_access` is refused by the CLI at runtime and by the deployment tool at configuration
    # time. Two enforcement points, one policy; this pins that they have not drifted apart.
    assert REFUSED_SCOPES <= frozenset(tool.REFUSED_DEFAULT_SCOPES)


def test_the_keystore_bound_the_size_control_is_measured_against():
    """The bound itself. NOT the token sizes — nothing hermetic can know those.

    This file cannot measure a token: that needs a real provider issuing against a real role load,
    which is ``test_keycloak_device_flow_integration.py``'s job. So this pins only the thing that IS
    knowable here — the bound the control is measured against — and the test below pins that the
    measurements themselves still exist to do the measuring.
    """
    assert MAX_SECRET_BYTES == 2560  # CRED_MAX_CREDENTIAL_BLOB_SIZE, applied on every platform


def test_the_size_control_has_a_real_measurer_in_both_directions():
    """The size control is only load-bearing if something actually measures a REAL token on each
    side of the bound. Neither direction can be established here, so what this guards is that both
    measurements still exist to be run — a deletion of either is the failure this catches.

    Keyed on the assertion text rather than on test names, so renaming a test does not silently
    drop the coverage while leaving this green.
    """
    source = (
        REPO / "apps" / "management" / "tests" / "test_keycloak_device_flow_integration.py"
    ).read_text(encoding="utf-8")
    # The artifact posture FITS, with headroom rather than by a margin of one claim...
    assert "assert len(encoded) < MAX_SECRET_BYTES // 2" in source
    # ...and the console-default posture genuinely does NOT, measured on the token alone.
    assert "assert len(token) > MAX_SECRET_BYTES" in source
    # ...and the refusal lands AFTER the operator approved, which is the whole point.
    assert 'assert report["reason_code"] == "secpctl_credential_too_large", report' in source


# --- the required job must be deterministic, not merely passing ----------------------------------

#: Read once; several guards below key on its text.
_LIVE_MODULE = (
    REPO / "apps" / "management" / "tests" / "test_keycloak_device_flow_integration.py"
).read_text(encoding="utf-8")


def test_the_device_flow_proof_gates_readiness_on_the_provider_health_endpoint():
    """Once `backend-keycloak-device-flow` is required, a flaky readiness gate turns EVERY stream's
    PR red with a cause that looks like their change. So readiness is gated on Keycloak's own
    health endpoint, and the container is started with the flag that serves it.

    Keycloak 25 moved `/health/*` to the management interface, so the flag alone is not enough —
    the port has to be published too, and this pins both.
    """
    assert '"--health-enabled=true",' in _LIVE_MODULE
    assert "/health/ready" in _LIVE_MODULE
    assert "_MANAGEMENT_PORT = 9000" in _LIVE_MODULE
    assert 'f"127.0.0.1:{management_port}:{_MANAGEMENT_PORT}",' in _LIVE_MODULE


def test_the_device_flow_proof_has_no_bare_sleep_before_an_assertion():
    """Every `time.sleep` in the live module must be a poll interval, never a "wait and hope".

    A fixed sleep followed by a single assertion is the canonical CI flake: it passes on a quiet
    runner and fails on a loaded one, and the failure reads as a device-flow defect. This asserts
    the shape structurally — the only sleeps are on a variable named `interval`.
    """
    sleeps = re.findall(r"time\.sleep\(([^)]*)\)", _LIVE_MODULE)
    assert sleeps, "the live module has no sleeps at all — this guard is measuring nothing"
    assert set(sleeps) == {"interval"}, f"a sleep on something other than a poll interval: {sleeps}"


def test_the_device_flow_proof_honours_rfc8628_slow_down():
    """RFC 8628 §3.5: a client polled too fast gets `slow_down` and MUST add 5 seconds.

    Both poll loops (through the shipped client, and raw) must handle it, or CORRECT provider
    behaviour under load becomes a test failure. Counted, not merely present: there are two loops
    and both need it.
    """
    assert _LIVE_MODULE.count('if error == "slow_down":') == 2
    assert _LIVE_MODULE.count("interval += _SLOW_DOWN_INCREMENT_SECONDS") == 2
    assert "_SLOW_DOWN_INCREMENT_SECONDS = 5" in _LIVE_MODULE
    assert _LIVE_MODULE.count('if error == "authorization_pending":') == 2


def test_the_device_flow_proof_distinguishes_runner_slowness_from_a_real_defect():
    """A bounded timeout is not enough; the message has to say WHICH failure it is.

    "The management interface never answered" means the image moved the health port (a version
    bump). "Health answered but OIDC did not" means a slow realm subsystem. One collapsed timeout
    message would make a version bump read as runner slowness.
    """
    assert "This is NOT ordinary " in _LIVE_MODULE
    assert "reported health-ready but its OIDC discovery endpoint did not answer" in _LIVE_MODULE
    assert "_HEALTH_PORT_BUDGET_SECONDS" in _LIVE_MODULE
    assert "_TOKEN_POLL_BUDGET_SECONDS" in _LIVE_MODULE


def test_the_device_flow_proof_allocates_distinct_ports_atomically():
    """Two calls to a single-port helper can return the SAME port — the first socket is closed
    before the second binds. The container would then fail to publish, with a message about the
    port rather than about the race. All sockets are held until every port is bound."""
    assert "def _free_ports(count: int) -> list[int]:" in _LIVE_MODULE
    assert "assert len(set(ports)) == count" in _LIVE_MODULE
    assert "def _free_port()" not in _LIVE_MODULE  # the racy single-port helper is gone


# --- the artifact checker refuses what it claims to ----------------------------------------------


def test_the_committed_artifact_passes_its_own_checker(artifact):
    assert tool.check_artifact(artifact) == []


#: ``(label, mutate, expected_problem_count)``. Each mutation is applied to the LOADED object, and
#: the baseline above reports ZERO problems — so every problem counted here was caused by the
#: mutation and by nothing else. Counts are exact: a mutation that starts reporting a different
#: number of problems has changed what the checker means, and that must be a visible edit.
_MUTATIONS: list[tuple[str, object, int]] = [
    (
        "device grant disabled",
        lambda c: c["attributes"].pop("oauth2.device.authorization.grant.enabled"),
        1,
    ),
    (
        "device grant as a JSON boolean",
        lambda c: c["attributes"].__setitem__("oauth2.device.authorization.grant.enabled", True),
        1,
    ),
    ("a client secret appears", lambda c: c.__setitem__("secret", "not-a-public-client"), 1),
    ("made confidential", lambda c: c.__setitem__("publicClient", False), 1),
    ("browser flow switched on", lambda c: c.__setitem__("standardFlowEnabled", True), 1),
    ("implicit flow switched on", lambda c: c.__setitem__("implicitFlowEnabled", True), 1),
    ("password grant switched on", lambda c: c.__setitem__("directAccessGrantsEnabled", True), 1),
    ("service account switched on", lambda c: c.__setitem__("serviceAccountsEnabled", True), 1),
    (
        "refresh tokens re-enabled",
        lambda c: c["attributes"].__setitem__("use.refresh.tokens", "true"),
        1,
    ),
    ("roles scope restored", lambda c: c["defaultClientScopes"].append("roles"), 1),
    (
        "offline_access scope attached",
        lambda c: c["defaultClientScopes"].append("offline_access"),
        1,
    ),
    ("full scope allowed", lambda c: c.__setitem__("fullScopeAllowed", True), 1),
    ("an optional scope attached", lambda c: c["optionalClientScopes"].append("roles"), 2),
    ("audience mapper removed", lambda c: c["protocolMappers"].clear(), 1),
    (
        "audience mapper duplicated",
        lambda c: c["protocolMappers"].append(copy.deepcopy(c["protocolMappers"][0])),
        1,
    ),
    (
        "audience retargeted",
        lambda c: c["protocolMappers"][0]["config"].__setitem__(
            "included.custom.audience", "somewhere-else"
        ),
        1,
    ),
    (
        "audience moved out of the access token",
        lambda c: c["protocolMappers"][0]["config"].__setitem__("access.token.claim", "false"),
        1,
    ),
    ("a redirect URI added", lambda c: c["redirectUris"].append("/callback"), 1),
    ("a web origin added", lambda c: c["webOrigins"].append("*"), 1),
    (
        "a hostname baked in",
        lambda c: c.__setitem__("description", "see https://idp.example.com"),
        1,
    ),
    ("description past the Keycloak column", lambda c: c.__setitem__("description", "x" * 256), 1),
    ("renamed", lambda c: c.__setitem__("clientId", "secp-cli-2"), 1),
    ("disabled", lambda c: c.__setitem__("enabled", False), 1),
]


@pytest.mark.parametrize(
    ("label", "mutate", "expected"), _MUTATIONS, ids=[m[0] for m in _MUTATIONS]
)
def test_each_artifact_guard_refuses_its_own_mutation(artifact, label, mutate, expected):
    baseline = copy.deepcopy(artifact)
    assert tool.check_artifact(baseline) == [], "baseline must be clean or the count is meaningless"
    mutated = copy.deepcopy(artifact)
    mutate(mutated)
    assert mutated != baseline, f"{label}: the mutation did not land on the loaded object"
    problems = tool.check_artifact(mutated)
    assert len(problems) == expected, f"{label}: {problems}"


def test_the_mutation_battery_covers_every_field_the_artifact_pins(artifact):
    # A battery that silently stops covering a field is the failure mode a battery has. Every
    # top-level key the artifact declares must be touched by at least one mutation.
    touched: set[str] = set()
    for _label, mutate, _expected in _MUTATIONS:
        mutated = copy.deepcopy(artifact)
        mutate(mutated)
        touched |= {k for k in set(artifact) | set(mutated) if artifact.get(k) != mutated.get(k)}
    uncovered = set(artifact) - touched
    assert uncovered <= {
        "name",
        "protocol",
        "bearerOnly",
        "consentRequired",
        "frontchannelLogout",
    }, f"artifact fields with no mutation coverage: {sorted(uncovered)}"


# --- RFC 8414 discovery + RFC 7009 revocation checks ---------------------------------------------

ISSUER = "https://idp.invalid/realms/secp"
GOOD_DISCOVERY = {
    "issuer": ISSUER,
    "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
    "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
    "device_authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth/device",
    "revocation_endpoint": f"{ISSUER}/protocol/openid-connect/revoke",
    "grant_types_supported": ["authorization_code", tool.DEVICE_CODE_GRANT_TYPE],
}


def test_a_conforming_discovery_document_passes():
    assert tool.check_discovery(GOOD_DISCOVERY, issuer=ISSUER, require_https=True) == []


_DISCOVERY_MUTATIONS: list[tuple[str, object, int]] = [
    ("device endpoint absent", lambda d: d.pop("device_authorization_endpoint"), 1),
    ("grant types absent", lambda d: d.pop("grant_types_supported"), 1),
    ("revocation endpoint absent", lambda d: d.pop("revocation_endpoint"), 1),
    ("token endpoint absent", lambda d: d.pop("token_endpoint"), 1),
    ("jwks absent", lambda d: d.pop("jwks_uri"), 1),
    ("issuer differs by a trailing slash", lambda d: d.__setitem__("issuer", ISSUER + "/"), 1),
    (
        "device grant not advertised",
        lambda d: d.__setitem__("grant_types_supported", ["authorization_code"]),
        1,
    ),
    (
        "revocation over plaintext",
        lambda d: d.__setitem__("revocation_endpoint", "http://idp.invalid/revoke"),
        1,
    ),
    (
        "device endpoint over plaintext",
        lambda d: d.__setitem__("device_authorization_endpoint", "http://idp.invalid/device"),
        1,
    ),
    (
        "device endpoint carries userinfo",
        lambda d: d.__setitem__(
            "device_authorization_endpoint", "https://user:pw@idp.invalid/device"
        ),
        1,
    ),
]


@pytest.mark.parametrize(
    ("label", "mutate", "expected"),
    _DISCOVERY_MUTATIONS,
    ids=[m[0] for m in _DISCOVERY_MUTATIONS],
)
def test_each_discovery_guard_refuses_its_own_mutation(label, mutate, expected):
    baseline = copy.deepcopy(GOOD_DISCOVERY)
    assert tool.check_discovery(baseline, issuer=ISSUER, require_https=True) == []
    mutated = copy.deepcopy(GOOD_DISCOVERY)
    mutate(mutated)
    assert mutated != baseline, f"{label}: the mutation did not land"
    problems = tool.check_discovery(mutated, issuer=ISSUER, require_https=True)
    assert len(problems) == expected, f"{label}: {problems}"


def test_a_non_object_discovery_document_is_one_refusal():
    assert len(tool.check_discovery("not-a-document", issuer=ISSUER, require_https=True)) == 1


@pytest.mark.parametrize("status", [201, 202, 204, 299])
def test_discovery_fetch_requires_exactly_http_200(status):
    def transport(_method, _url, _headers, _body):
        return status, {}, json.dumps(GOOD_DISCOVERY).encode()

    with pytest.raises(tool.DeploymentError, match=f"failed with HTTP {status}"):
        tool.fetch_discovery("https://idp.invalid", "secp", transport)


def test_absent_grant_types_is_the_exact_unsupported_limitation():
    discovery = copy.deepcopy(GOOD_DISCOVERY)
    discovery.pop("grant_types_supported")
    expected = (
        f"`grant_types_supported` does not include {tool.DEVICE_CODE_GRANT_TYPE!r}; "
        "the CLI refuses "
        "the deployment as not supporting the device grant"
    )
    assert tool.check_discovery(discovery, issuer=ISSUER, require_https=True) == [expected]


@pytest.mark.parametrize(
    "grant_types",
    [
        None,
        tool.DEVICE_CODE_GRANT_TYPE,
        {"device_code": True},
        [tool.DEVICE_CODE_GRANT_TYPE, 7],
        [tool.DEVICE_CODE_GRANT_TYPE, ""],
        [tool.DEVICE_CODE_GRANT_TYPE, "authorization code"],
    ],
)
def test_malformed_grant_types_is_one_bounded_configuration_problem(grant_types):
    discovery = {**GOOD_DISCOVERY, "grant_types_supported": grant_types}
    assert tool.check_discovery(discovery, issuer=ISSUER, require_https=True) == [
        "`grant_types_supported` is malformed; expected a JSON array of non-empty printable "
        "grant-type strings"
    ]


def test_the_revocation_probe_reads_rfc7009_status_semantics():
    # §2.2: 200 for a revoked token AND for an invalid one. A 401 means a public client cannot
    # revoke here at all, which is a deployment defect the CLI would surface only at logout.
    assert tool.check_public_revocation_probe(200) == []
    for undefined_success in (201, 202, 204, 299):
        assert len(tool.check_public_revocation_probe(undefined_success)) == 1
    assert len(tool.check_public_revocation_probe(401)) == 1
    assert len(tool.check_public_revocation_probe(400)) == 1
    assert len(tool.check_public_revocation_probe(503)) == 1


def test_the_revocation_probe_posts_to_the_exact_advertised_endpoint():
    calls: list[tuple[str, str]] = []

    def transport(method, url, _headers, _body):
        calls.append((method, url))
        return 200, {}, b""

    endpoint = "https://revocation.identity.invalid/custom/revoke"
    assert tool.probe_revocation(endpoint, transport) == 200
    assert calls == [("POST", endpoint)]


def test_the_revocation_probe_refuses_an_unsafe_endpoint_before_contact():
    calls: list[str] = []

    def transport(_method, url, _headers, _body):  # pragma: no cover - must remain unreachable
        calls.append(url)
        raise AssertionError("an unsafe advertised endpoint must not be contacted")

    with pytest.raises(tool.DeploymentError, match="invalid advertised revocation endpoint"):
        tool.probe_revocation("https://user:password@identity.invalid/revoke", transport)
    assert calls == []


@pytest.mark.parametrize(
    "hostile_url",
    (
        "https://[2001:db8::1/revoke",
        "https://idp.invalid:0/revoke",
        "https://idp.invalid:65536/revoke",
        "https://idp.invalid:not-a-port/revoke",
        "https://idp.invalid/revoke#fragment",
        "https://idp.invalid/revoke#",
        " https://idp.invalid/revoke",
        "https://idp.invalid/revoke\x7f",
    ),
)
def test_hostile_ipv6_ports_and_fragments_are_bounded_before_network_contact(hostile_url):
    discovery = {**GOOD_DISCOVERY, "token_endpoint": hostile_url}
    problems = tool.check_discovery(discovery, issuer=ISSUER, require_https=True)
    assert len(problems) == 1
    assert hostile_url not in problems[0]

    with pytest.raises(tool.DeploymentError) as base_error:
        tool._require_base_url(hostile_url, insecure_http=False)
    assert hostile_url not in str(base_error.value)

    calls: list[str] = []

    def transport(_method, url, _headers, _body):  # pragma: no cover - must remain unreachable
        calls.append(url)
        raise AssertionError("a malformed endpoint must not be contacted")

    with pytest.raises(tool.DeploymentError, match="invalid advertised revocation endpoint"):
        tool.probe_revocation(hostile_url, transport)
    assert calls == []


def test_a_well_formed_ipv6_endpoint_and_nonzero_port_remain_supported():
    endpoint = "https://[2001:db8::1]:8443/revoke"
    assert tool._check_endpoint_url(endpoint, "revocation_endpoint", require_https=True) == []
    assert tool._require_base_url("https://[2001:db8::1]:8443", insecure_http=False) == (
        "https://[2001:db8::1]:8443"
    )


def test_base_url_query_is_refused_while_an_endpoint_query_remains_supported():
    base_url = "https://idp.invalid?tenant=secp"
    with pytest.raises(tool.DeploymentError, match="must not carry a URL query"):
        tool._require_base_url(base_url, insecure_http=False)
    assert (
        tool._check_endpoint_url(
            "https://idp.invalid/token?tenant=secp", "token_endpoint", require_https=True
        )
        == []
    )


@pytest.mark.parametrize(
    "base_url",
    ("https://user:password@idp.invalid/keycloak", "https://@idp.invalid/keycloak"),
)
def test_base_url_userinfo_and_raw_at_are_refused_without_echo(base_url):
    with pytest.raises(tool.DeploymentError, match="must not carry userinfo") as exc_info:
        tool._require_base_url(base_url, insecure_http=False)
    assert base_url not in str(exc_info.value)


def test_keycloak_base_url_path_prefix_remains_supported():
    base_url = "https://idp.invalid/keycloak"
    assert tool._require_base_url(base_url, insecure_http=False) == base_url


# --- the shipped urllib transport enforces its response cap while reading -----------------------


class _BoundedBody:
    def __init__(self, body: bytes, *, status: int = 200) -> None:
        self.body = body
        self.status = status
        self.headers: dict[str, str] = {}
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return self.body if size < 0 else self.body[:size]

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def _install_urllib_response(monkeypatch, body: bytes, *, as_http_error: bool) -> _BoundedBody:
    response = _BoundedBody(body, status=400 if as_http_error else 200)

    class _Opener:
        def open(self, request, *, timeout):
            assert timeout == tool._DEFAULT_TIMEOUT
            if as_http_error:
                raise tool.urllib.error.HTTPError(
                    request.full_url, response.status, "provider refusal", {}, response
                )
            return response

    monkeypatch.setattr(tool.urllib.request, "build_opener", lambda *_handlers: _Opener())
    return response


@pytest.mark.parametrize("as_http_error", (False, True), ids=("success", "http-error"))
def test_urllib_transport_accepts_an_exact_bound_body(monkeypatch, as_http_error):
    exact_json = b'{"ok":1}'
    monkeypatch.setattr(tool, "_MAX_RESPONSE_BYTES", len(exact_json))
    response = _install_urllib_response(monkeypatch, exact_json, as_http_error=as_http_error)

    status, _headers, body = tool.urllib_transport("GET", "https://idp.invalid/admin", {}, None)

    assert status == (400 if as_http_error else 200)
    assert body == exact_json
    assert response.read_sizes == [len(exact_json) + 1]


@pytest.mark.parametrize("as_http_error", (False, True), ids=("success", "http-error"))
def test_urllib_transport_refuses_one_byte_over_the_bound_without_disclosure(
    monkeypatch, as_http_error
):
    accepted_json_prefix = b'{"ok":1}'
    provider_secret = b"provider-secret-must-not-escape"
    oversized = accepted_json_prefix + provider_secret
    url = "https://idp.invalid/admin?credential=url-secret-must-not-escape"
    monkeypatch.setattr(tool, "_MAX_RESPONSE_BYTES", len(accepted_json_prefix))
    response = _install_urllib_response(monkeypatch, oversized, as_http_error=as_http_error)

    with pytest.raises(tool.DeploymentError) as exc_info:
        tool.urllib_transport("GET", url, {}, None)

    refusal = str(exc_info.value)
    assert refusal == "provider response exceeded the bounded size limit"
    assert url not in refusal and "idp.invalid" not in refusal
    assert provider_secret.decode() not in refusal and "url-secret-must-not-escape" not in refusal
    assert response.read_sizes == [len(accepted_json_prefix) + 1]


# --- the reconciler does not write unless asked twice --------------------------------------------


class _RecordingTransport:
    """Records every request and answers from a scripted realm. Counts are the post-condition."""

    def __init__(self, responses: dict | None = None):
        self.calls: list[tuple[str, str]] = []
        self._responses = responses or {}

    @property
    def mutating(self) -> list[tuple[str, str]]:
        """Every request that could CHANGE the provider, excluding the admin token request.

        The token request is a POST by protocol and changes nothing, so counting raw POSTs would
        make "a dry run mutates nothing" impossible to state. It is excluded by its exact path, not
        by a substring, so a POST to any other endpoint still counts.
        """
        return [
            (method, url)
            for method, url in self.calls
            if method != "GET" and not url.endswith("/protocol/openid-connect/token")
        ]

    def __call__(self, method: str, url: str, headers: dict, body: bytes | None):
        self.calls.append((method, url))
        if url.endswith("/protocol/openid-connect/token"):
            return 200, {}, json.dumps({"access_token": "admin-token-value"}).encode()
        for suffix, payload in self._responses.items():
            if url.endswith(suffix):
                return 200, {}, json.dumps(payload).encode()
        return 200, {}, b"[]"


@pytest.mark.parametrize("status", (201, 204))
def test_administrator_token_document_requires_exact_http_200(status):
    def transport(_method, _url, _headers, _body):
        return status, {}, json.dumps({"access_token": "admin-token-value"}).encode()

    admin = tool.KeycloakAdmin("https://idp.invalid", transport=transport)
    with pytest.raises(tool.DeploymentError, match=f"failed with HTTP {status}"):
        admin.authenticate("admin", "placeholder-not-a-real-password")


@pytest.mark.parametrize("status", (201, 204))
def test_admin_get_document_requires_exact_http_200(status):
    def transport(_method, url, _headers, _body):
        if url.endswith("/protocol/openid-connect/token"):
            return 200, {}, json.dumps({"access_token": "admin-token-value"}).encode()
        return status, {}, b"{}"

    admin = tool.KeycloakAdmin("https://idp.invalid", transport=transport)
    admin.authenticate("admin", "placeholder-not-a-real-password")
    with pytest.raises(tool.DeploymentError, match=f"failed with HTTP {status}"):
        admin.get("/admin/realms/secp/clients")


@pytest.mark.parametrize("document", ("admin-token", "admin-get", "discovery"))
def test_network_json_documents_turn_invalid_utf8_into_bounded_refusals(document):
    def transport(_method, url, _headers, _body):
        if url.endswith("/protocol/openid-connect/token"):
            body = b"\xff" if document == "admin-token" else b'{"access_token":"admin-token"}'
            return 200, {}, body
        return 200, {}, b"\xff"

    if document == "discovery":
        with pytest.raises(tool.DeploymentError, match="discovery document is not JSON"):
            tool.fetch_discovery("https://idp.invalid", "secp", transport)
        return

    admin = tool.KeycloakAdmin("https://idp.invalid", transport=transport)
    if document == "admin-token":
        expected = "administrator token response was not usable"
        with pytest.raises(tool.DeploymentError, match=expected):
            admin.authenticate("admin", "placeholder-not-a-real-password")
    else:
        admin.authenticate("admin", "placeholder-not-a-real-password")
        with pytest.raises(tool.DeploymentError, match="did not return JSON"):
            admin.get("/admin/realms/secp/clients")


def test_discovery_only_cannot_pass_by_probing_a_reconstructed_revocation_path(capsys):
    """The runtime consumes metadata, so verification must probe the same bytes.

    The conventional Keycloak path answers 200 while the advertised endpoint answers 503. The old
    verifier probed the former and returned success; the fixed verifier reaches the latter and
    reports the deployment failure.
    """
    advertised = "https://wrong-provider.invalid/custom/revoke"
    document = {**GOOD_DISCOVERY, "revocation_endpoint": advertised}
    calls: list[tuple[str, str]] = []

    def transport(method, url, _headers, _body):
        calls.append((method, url))
        if method == "GET":
            return 200, {}, json.dumps(document).encode()
        if url == advertised:
            return 503, {}, b""
        if url == f"{ISSUER}/protocol/openid-connect/revoke":
            return 200, {}, b""  # the reconstructed path is a deliberate false-positive trap
        raise AssertionError(url)

    code = tool.main(
        [
            "verify",
            "--base-url",
            "https://idp.invalid",
            "--realm",
            "secp",
            "--discovery-only",
            "--json",
        ],
        transport=transport,
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert report["ok"] is False
    assert len(report["problems"]) == 1
    assert calls == [
        ("GET", f"{ISSUER}/.well-known/openid-configuration"),
        ("POST", advertised),
    ]


def test_an_invalid_advertised_revocation_endpoint_is_not_contacted(capsys):
    document = {
        **GOOD_DISCOVERY,
        "revocation_endpoint": "https://user:password@wrong-provider.invalid/revoke",
    }
    calls: list[tuple[str, str]] = []

    def transport(method, url, _headers, _body):
        calls.append((method, url))
        assert method == "GET", "discovery failed validation, so no probe is safe"
        return 200, {}, json.dumps(document).encode()

    code = tool.main(
        [
            "verify",
            "--base-url",
            "https://idp.invalid",
            "--realm",
            "secp",
            "--discovery-only",
            "--json",
        ],
        transport=transport,
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 1 and report["ok"] is False
    assert len(calls) == 1 and calls[0][0] == "GET"


class _StaticDeploymentAdmin:
    def __init__(
        self,
        client: dict,
        default_scopes: list[str],
        optional_scopes: list[str],
        mappers: list[dict],
    ) -> None:
        self.client = client
        self.default_scopes = default_scopes
        self.optional_scopes = optional_scopes
        self.mappers = mappers

    def get(self, path: str):
        if "/clients?" in path:
            return [self.client]
        if path.endswith("/default-client-scopes"):
            return [
                {"id": f"default-{i}", "name": name} for i, name in enumerate(self.default_scopes)
            ]
        if path.endswith("/optional-client-scopes"):
            return [
                {"id": f"optional-{i}", "name": name} for i, name in enumerate(self.optional_scopes)
            ]
        if path.endswith("/protocol-mappers/models"):
            return self.mappers
        raise AssertionError(path)


def _live_deployment_state(artifact: dict) -> dict:
    client = copy.deepcopy(artifact)
    client["id"] = "uuid-1"
    return {
        "client": client,
        "default_scopes": list(artifact["defaultClientScopes"]),
        "optional_scopes": list(artifact["optionalClientScopes"]),
        "mappers": copy.deepcopy(artifact["protocolMappers"]),
    }


def _verify_live_state(artifact: dict, state: dict) -> list[str]:
    return tool.verify_deployment(
        _StaticDeploymentAdmin(
            state["client"],
            state["default_scopes"],
            state["optional_scopes"],
            state["mappers"],
        ),
        "secp",
        artifact,
        discovery_document=GOOD_DISCOVERY,
        issuer=ISSUER,
        require_https=True,
        revocation_probe_status=200,
    )


def test_a_live_client_matching_the_artifact_passes_every_authoritative_read(artifact):
    assert _verify_live_state(artifact, _live_deployment_state(artifact)) == []


_LIVE_DEPLOYMENT_DRIFTS = (
    (
        "disabled client",
        lambda state: state["client"].__setitem__("enabled", False),
        "not enabled",
    ),
    (
        "wrong client protocol",
        lambda state: state["client"].__setitem__("protocol", "saml"),
        "client protocol",
    ),
    (
        "client consent enabled",
        lambda state: state["client"].__setitem__("consentRequired", True),
        "client core differs",
    ),
    (
        "front-channel logout enabled",
        lambda state: state["client"].__setitem__("frontchannelLogout", True),
        "client core differs",
    ),
    (
        "bearer-only client",
        lambda state: state["client"].__setitem__("bearerOnly", True),
        "bearerOnly",
    ),
    (
        "refresh tokens enabled",
        lambda state: state["client"]["attributes"].__setitem__("use.refresh.tokens", "true"),
        "refresh-token issuance",
    ),
    (
        "device polling interval drifted",
        lambda state: state["client"]["attributes"].__setitem__(
            "oauth2.device.polling.interval", "30"
        ),
        "client core differs",
    ),
    (
        "browser origin added",
        lambda state: state["client"]["webOrigins"].append("https://browser.invalid"),
        "browser origin",
    ),
    (
        "default scope added",
        lambda state: state["default_scopes"].append("roles"),
        "assigned default client scopes",
    ),
    (
        "optional scope added",
        lambda state: state["optional_scopes"].append("offline_access"),
        "assigned optional client scopes",
    ),
    (
        "extra non-audience mapper added",
        lambda state: state["mappers"].append(
            {
                "name": "unexpected-claims",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-attribute-mapper",
                "consentRequired": False,
                "config": {"claim.name": "unexpected"},
            }
        ),
        "protocol mapper set",
    ),
    (
        "wrong mapper protocol",
        lambda state: state["mappers"][0].__setitem__("protocol", "saml"),
        "differs from the committed mapper",
    ),
    (
        "mapper consent enabled",
        lambda state: state["mappers"][0].__setitem__("consentRequired", True),
        "differs from the committed mapper",
    ),
    (
        "malformed live mapper config",
        lambda state: state["mappers"][0].__setitem__("config", ["not", "an", "object"]),
        "differs from the committed mapper",
    ),
)


@pytest.mark.parametrize(
    ("label", "mutate", "expected_fragment"),
    _LIVE_DEPLOYMENT_DRIFTS,
    ids=[case[0] for case in _LIVE_DEPLOYMENT_DRIFTS],
)
def test_live_verification_refuses_each_security_posture_drift(
    artifact, label, mutate, expected_fragment
):
    state = _live_deployment_state(artifact)
    assert _verify_live_state(artifact, state) == []
    mutate(state)
    problems = _verify_live_state(artifact, state)
    assert problems, f"{label}: live verification silently accepted the drift"
    assert any(expected_fragment in problem for problem in problems), (label, problems)


@pytest.mark.parametrize("bad_id", (None, "", 7, "../hostile\npath"))
def test_malformed_live_client_id_refuses_before_any_subresource_path(artifact, bad_id):
    client = copy.deepcopy(artifact)
    if bad_id is not None:
        client["id"] = bad_id
    calls: list[str] = []

    class _LookupOnlyAdmin:
        def get(self, path: str):
            calls.append(path)
            if "/clients?" in path:
                return [client]
            raise AssertionError("a malformed id must never reach a client sub-resource")

    problems = tool.verify_deployment(
        _LookupOnlyAdmin(),
        "secp",
        artifact,
        discovery_document=GOOD_DISCOVERY,
        issuer=ISSUER,
        require_https=True,
        revocation_probe_status=200,
    )
    assert problems == ["deployed client id is missing or malformed"]
    assert calls == ["/admin/realms/secp/clients?clientId=secp-cli"]


def _admin_env(monkeypatch) -> None:
    monkeypatch.setenv(tool.ENV_ADMIN_USER, "admin")
    monkeypatch.setenv(tool.ENV_ADMIN_PASSWORD, "placeholder-not-a-real-password")


def test_hostile_administrator_token_is_refused_before_header_use_or_output(monkeypatch, capsys):
    _admin_env(monkeypatch)
    hostile_token = "admin-secret\r\nX-Forged: yes"
    calls: list[tuple[str, dict]] = []

    def transport(_method, _url, headers, _body):
        calls.append((_url, dict(headers)))
        return 200, {}, json.dumps({"access_token": hostile_token}).encode()

    code = tool.main(
        ["apply", "--base-url", "https://idp.invalid", "--realm", "secp"],
        transport=transport,
    )
    rendered = capsys.readouterr().out
    assert code == 2
    assert len(calls) == 1 and "Authorization" not in calls[0][1]
    assert hostile_token not in rendered
    assert "admin-secret" not in rendered and "X-Forged" not in rendered
    assert "administrator token response was not usable" in rendered


def test_provider_error_cannot_reflect_admin_bearer_or_terminal_controls(monkeypatch, capsys):
    _admin_env(monkeypatch)
    admin_token = "admin-bearer-secret"
    injected = f"Bearer {admin_token}\n[forged] ok: True\r\x1b[2J\u202e"
    provider_body = json.dumps({"errorMessage": injected}).encode()

    def transport(method, url, headers, _body):
        if url.endswith("/protocol/openid-connect/token"):
            return 200, {}, json.dumps({"access_token": admin_token}).encode()
        assert headers["Authorization"] == f"Bearer {admin_token}"
        if method == "GET":
            return 200, {}, b"[]"
        return 400, {}, provider_body

    code = tool.main(
        [
            "apply",
            "--base-url",
            "https://idp.invalid",
            "--realm",
            "secp",
            "--write",
            "--confirm",
        ],
        transport=transport,
    )
    rendered = capsys.readouterr().out
    assert code == 2
    assert tool._bounded_error(provider_body) == f"<{len(provider_body)} bytes>"
    assert admin_token not in rendered and "[forged]" not in rendered
    assert "\r" not in rendered and "\x1b" not in rendered and "\u202e" not in rendered
    assert f"<{len(provider_body)} bytes>" in rendered


def test_human_emitter_escapes_every_dynamic_string_to_its_code_owned_line(capsys):
    injected = 'visible\n[forged] ok: True\r\x1b[31mred\x1b[0m\u202e"\\tail'
    tool._emit(
        {
            "action": injected,
            "client_id": injected,
            "actions": [injected],
            "problems": [injected],
            "artifact_problems": [injected],
            "mutations": 0,
            "error": injected,
            "ok": injected,
        },
        False,
    )
    rendered = capsys.readouterr().out
    assert len(rendered.splitlines()) == 7
    assert "\n[forged]" not in rendered
    assert "\r" not in rendered and "\x1b" not in rendered and "\u202e" not in rendered
    assert r"\n[forged] ok: True\r" in rendered
    assert r"\u001b[31m" in rendered and r"\u202e" in rendered
    assert r"\"\\tail" in rendered


def test_apply_without_write_issues_no_mutating_request(monkeypatch, capsys):
    _admin_env(monkeypatch)
    transport = _RecordingTransport()
    code = tool.main(
        ["apply", "--base-url", "https://idp.invalid", "--realm", "secp", "--json"],
        transport=transport,
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["mode"] == "dry_run"
    assert report["mutations"] == 0
    assert len(transport.mutating) == 0
    # ...and it still SAID what it would do, or a dry run would be worthless.
    assert len(report["actions"]) >= 1


def test_write_without_confirm_refuses_and_writes_nothing(monkeypatch, capsys):
    _admin_env(monkeypatch)
    transport = _RecordingTransport()
    code = tool.main(
        ["apply", "--base-url", "https://idp.invalid", "--realm", "secp", "--write", "--json"],
        transport=transport,
    )
    capsys.readouterr()
    assert code == 2
    assert len(transport.mutating) == 0


def test_a_plaintext_base_url_refuses_before_any_request(monkeypatch, capsys):
    _admin_env(monkeypatch)
    transport = _RecordingTransport()
    code = tool.main(
        ["apply", "--base-url", "http://idp.invalid", "--realm", "secp", "--json"],
        transport=transport,
    )
    capsys.readouterr()
    assert code == 2
    # Not merely "no mutation": no request at all, so no administrator credential left the host.
    assert len(transport.calls) == 0


def test_the_insecure_http_escape_hatch_must_be_named_explicitly(monkeypatch, capsys):
    _admin_env(monkeypatch)
    transport = _RecordingTransport()
    code = tool.main(
        [
            "apply",
            "--base-url",
            "http://idp.invalid",
            "--realm",
            "secp",
            "--insecure-http",
            "--json",
        ],
        transport=transport,
    )
    capsys.readouterr()
    assert code == 0
    assert len(transport.calls) >= 1


def test_missing_administrator_credentials_refuse_rather_than_default(monkeypatch, capsys):
    monkeypatch.delenv(tool.ENV_ADMIN_USER, raising=False)
    monkeypatch.delenv(tool.ENV_ADMIN_PASSWORD, raising=False)
    transport = _RecordingTransport()
    code = tool.main(
        ["apply", "--base-url", "https://idp.invalid", "--realm", "secp", "--json"],
        transport=transport,
    )
    capsys.readouterr()
    assert code == 2
    assert len(transport.mutating) == 0


def test_plan_is_offline(capsys):
    transport = _RecordingTransport()
    code = tool.main(["plan", "--json"], transport=transport)
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["ok"] is True
    assert len(transport.calls) == 0  # the default action opens no socket at all
    assert sorted(report["default_client_scopes"]) == sorted(EXPECTED_DEFAULT_SCOPES)


def test_the_reconciler_removes_a_surplus_scope_rather_than_only_adding(monkeypatch, capsys):
    """The whole point of reconciling to an EXACT set.

    A client created through the admin console carries ``roles``; an "ensure present" reconciler
    would report success forever while leaving it attached. The dry run must name the REMOVAL.
    """
    _admin_env(monkeypatch)
    transport = _RecordingTransport(
        {
            "/clients?clientId=secp-cli": [{"id": "uuid-1", "clientId": "secp-cli"}],
            "/default-client-scopes": [
                {"id": "s1", "name": "basic"},
                {"id": "s2", "name": "email"},
                {"id": "s3", "name": "profile"},
                {"id": "s4", "name": "roles"},
            ],
        }
    )
    code = tool.main(
        ["apply", "--base-url", "https://idp.invalid", "--realm", "secp", "--json"],
        transport=transport,
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    removals = [a for a in report["actions"] if a.startswith("remove default client scope 'roles'")]
    assert len(removals) == 1
    assert len(transport.mutating) == 0


def test_a_converged_realm_produces_an_empty_action_list(monkeypatch, capsys, artifact):
    """Convergence must be observable, or "already correct" and "just corrected" look alike."""
    _admin_env(monkeypatch)
    deployed = {k: v for k, v in artifact.items() if k != "protocolMappers"}
    deployed["id"] = "uuid-1"
    transport = _RecordingTransport(
        {
            "/clients?clientId=secp-cli": [deployed],
            "/default-client-scopes": [
                {"id": "s1", "name": "basic"},
                {"id": "s2", "name": "email"},
                {"id": "s3", "name": "profile"},
            ],
            "/protocol-mappers/models": [
                {
                    "id": "m1",
                    "name": "secp-api-audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "consentRequired": False,
                    "config": {
                        "included.custom.audience": "secp-api",
                        "id.token.claim": "false",
                        "access.token.claim": "true",
                    },
                }
            ],
        }
    )
    code = tool.main(
        [
            "apply",
            "--base-url",
            "https://idp.invalid",
            "--realm",
            "secp",
            "--write",
            "--confirm",
            "--json",
        ],
        transport=transport,
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["actions"] == []
    assert report["mutations"] == 0
    assert len(transport.mutating) == 0


# --- the disposable test realm --------------------------------------------------------------------


def test_the_test_realm_skeleton_declares_no_client():
    """The disposable realm must get its client from the artifact and from nowhere else.

    A client baked into the skeleton would let the integration test pass against configuration the
    artifact does not describe — which is precisely the drift the whole slice removes.
    """
    skeleton = json.loads(SKELETON_PATH.read_text(encoding="utf-8"))
    assert skeleton["clients"] == []
    assert skeleton["roles"]["realm"] == []
    assert len(skeleton["users"]) == 1
    assert skeleton["users"][0]["realmRoles"] == []


def test_the_test_realm_carries_only_obvious_placeholder_credentials():
    blob = SKELETON_PATH.read_text(encoding="utf-8")
    skeleton = json.loads(blob)
    for user in skeleton["users"]:
        for credential in user["credentials"]:
            assert "dev-only" in credential["value"] and "change-me" in credential["value"]
    assert "disposable" in skeleton["displayName"].lower()
    assert "UNSAFE FOR PRODUCTION" in skeleton["displayName"]
    assert skeleton["sslRequired"] == "none"  # plaintext, so it can never be a real deployment


def test_the_test_realm_pins_the_device_grant_timings_it_relies_on():
    skeleton = json.loads(SKELETON_PATH.read_text(encoding="utf-8"))
    # The integration test waits real seconds between polls; both numbers must be the provider's,
    # not a default that could change under the test and turn it flaky.
    assert skeleton["oauth2DevicePollingInterval"] == 5
    assert skeleton["oauth2DeviceCodeLifespan"] == 600


def test_the_integration_test_and_the_dev_stack_share_one_provider_pin():
    """The disposable provider must be the version the dev stack actually runs.

    The integration test reads its image from this same compose file, so this pins that the value is
    a real, immutable-looking tag rather than ``latest`` — a floating tag would make the device-flow
    proof mean something different on every run.
    """
    compose = yaml.safe_load(DEV_COMPOSE_PATH.read_text(encoding="utf-8"))
    image = compose["services"]["keycloak"]["image"]
    assert image.startswith("quay.io/keycloak/keycloak:")
    assert not image.endswith(":latest")


# --- the production reference points at the artifact, not at prose --------------------------------


def test_the_production_reference_names_the_reproducible_artifact():
    text = PROD_OIDC_PATH.read_text(encoding="utf-8")
    assert "infra/keycloak/secp-cli-client.json" in text
    assert "scripts/keycloak/secp_cli_client.py" in text


def test_the_production_reference_still_carries_no_secret():
    text = PROD_OIDC_PATH.read_text(encoding="utf-8")
    for line in text.splitlines():
        if "PASSWORD" in line and "=" in line and not line.strip().startswith("#"):
            value = line.split("=", 1)[1].strip()
            assert value == "" or "change-me" in value
