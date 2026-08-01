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


def test_the_measured_token_sizes_straddle_the_keystore_bound():
    """The numbers behind the size control, as MEASURED against a real Keycloak 25 realm carrying 48
    realm roles on the operator (``test_keycloak_device_flow_integration.py`` re-measures both).

    They are recorded here so the non-container shards still fail if the bound ever moves under
    them: the artifact's token must fit with room to spare, and the console-default posture must
    genuinely NOT fit — a control that is not actually load-bearing is worse than no control.
    """
    artifact_record_bytes = 1226
    console_default_record_bytes = 3116
    assert MAX_SECRET_BYTES == 2560
    assert artifact_record_bytes < MAX_SECRET_BYTES
    assert console_default_record_bytes > MAX_SECRET_BYTES


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


def test_the_revocation_probe_reads_rfc7009_status_semantics():
    # §2.2: 200 for a revoked token AND for an invalid one. A 401 means a public client cannot
    # revoke here at all, which is a deployment defect the CLI would surface only at logout.
    assert tool.check_public_revocation_probe(200) == []
    assert tool.check_public_revocation_probe(204) == []
    assert len(tool.check_public_revocation_probe(401)) == 1
    assert len(tool.check_public_revocation_probe(400)) == 1
    assert len(tool.check_public_revocation_probe(503)) == 1


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


def _admin_env(monkeypatch) -> None:
    monkeypatch.setenv(tool.ENV_ADMIN_USER, "admin")
    monkeypatch.setenv(tool.ENV_ADMIN_PASSWORD, "placeholder-not-a-real-password")


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
                    "protocolMapper": "oidc-audience-mapper",
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
