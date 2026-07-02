"""SECP-002B-1B-3 — offline fake Proxmox read-only transport + closed allowlist contract.

Test-first, fakes only. Proves the GET-only closed policy, allowlist accept/deny, mutation and
redirect/cross-host refusal (before any response lookup), the offline transport has no
network-capable imports, the provider-neutral normalizer redacts and never infers, missing/
malformed/incomplete observations become ``unverifiable`` through the EXISTING comparison, the
``fully_segregated`` guardrail (generic inventory can never pass), the API import boundary, and
the unchanged live-evidence seal. Nothing real is contacted; no evidence is persisted.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest
from secp_api.enums import EvidenceStatus, VerificationLevel
from secp_api.target_evidence import (
    CHECK_ISOLATION,
    SIMULATED_EVIDENCE_SOURCE,
    TARGET_EVIDENCE_SCHEMA_VERSION,
    compare_boundary_to_evidence,
    findings_pass,
    summarize_findings,
)
from secp_plugin_api.v1 import DiscoveryRequest, ProviderCredential, UnsupportedCapabilityError
from secp_plugin_proxmox import (
    ALLOWED_PATH_TEMPLATES,
    PROXMOX_READONLY_POLICY_VERSION,
    CrossHostRequestRefused,
    FakeProxmoxReadOnlyTransport,
    MutatingRequestRefused,
    NonCanonicalPathRefused,
    ProxmoxPlugin,
    RedirectRefused,
    RedirectResponse,
    UnknownPathRefused,
    assert_request_allowed,
    canonical_path_violation,
    fake_transport_factory,
    normalize_proxmox_observations,
    path_is_allowed,
)
from tests.conftest import VALID_ONBOARDING_BOUNDARY  # type: ignore

GOOD_CONFIG = {"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True}

# Canned inventory that satisfies the declared nodes/storage/segments/cidrs (fake values only).
FULL_INVENTORY = {
    "/nodes": [
        # Deliberately noisy: descriptions/secrets must be stripped by the normalizer.
        {"node": "pve-node-1", "status": "online", "description": "lab", "password": "hunter2"},
        {"node": "pve-node-2", "status": "online", "notes": "n", "token": "PVEAPIToken=abc"},
    ],
    "/nodes/pve-node-1/storage": [{"storage": "local-lvm", "type": "lvmthin", "comment": "x"}],
    "/nodes/pve-node-2/storage": [{"storage": "local-lvm"}],
    "/cluster/sdn/vnets": [{"vnet": "vmbr0", "cidr": "10.60.0.0/16", "tags": "t", "ticket": "T"}],
}

# Discovery-path inventory (what ProxmoxPlugin.discover requests).
DISCOVER_INVENTORY = {
    "/nodes": [{"node": "pve-node-1", "status": "online"}],
    "/nodes/pve-node-1/qemu": [{"vmid": 9000, "name": "vm-a", "status": "running"}],
    "/nodes/pve-node-1/lxc": [],
    "/nodes/pve-node-1/storage": [{"storage": "local-lvm", "type": "lvmthin"}],
}


def _payload(observed: dict) -> dict:
    """TEST-ONLY: wrap normalized observations in the simulated-only evidence schema so the
    existing comparison can be exercised. This is never a runtime collection path."""
    return {
        "schema_version": TARGET_EVIDENCE_SCHEMA_VERSION,
        "evidence_source": SIMULATED_EVIDENCE_SOURCE,
        "verification_level": VerificationLevel.simulated.value,
        "observed": observed,
    }


# --- closed policy: GET-only, allowlist accept/deny -------------------------------


def test_allowlist_accepts_expected_get_paths():
    for path in ("/nodes", "/nodes/pve-node-1/storage", "/cluster/sdn/vnets", "/cluster/resources"):
        assert path_is_allowed(path), path
    # every template resolves for a concrete instantiation
    assert "/nodes" in ALLOWED_PATH_TEMPLATES
    assert PROXMOX_READONLY_POLICY_VERSION.startswith("secp-002b-1b-3/")


def test_unknown_paths_are_denied():
    for path in ("/", "/access", "/nodes/pve-node-1/unknown", "/version", "/foo/bar"):
        assert not path_is_allowed(path), path
        with pytest.raises(UnknownPathRefused):
            assert_request_allowed("GET", path)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def test_non_get_methods_refused_before_lookup(method):
    with pytest.raises(MutatingRequestRefused):
        assert_request_allowed(method, "/nodes")


def test_transport_get_only_and_records_calls():
    t = FakeProxmoxReadOnlyTransport(FULL_INVENTORY)
    assert t.get("/nodes")  # allowed GET
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(MutatingRequestRefused):
            t.request(method, "/nodes")
    assert {m for (m, _p) in t.calls} == {"GET"}  # only the GET was ever recorded


def test_mutation_refused_before_response_lookup():
    """A refused method/path must never consult the canned response map."""
    t = FakeProxmoxReadOnlyTransport({"/nodes": [{"node": "pve-node-1"}]})
    with pytest.raises(MutatingRequestRefused):
        t.request("DELETE", "/nodes")
    with pytest.raises(UnknownPathRefused):
        t.request("GET", "/nodes/pve-node-1/qemu/9000/config")
    assert t.calls == []  # nothing was looked up


# --- forbidden endpoint families are denied --------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/nodes/pve-node-1/tasks",  # tasks
        "/nodes/pve-node-1/qemu/9000/status/start",  # power action
        "/nodes/pve-node-1/qemu/9000/vncproxy",  # console
        "/nodes/pve-node-1/qemu/9000/agent/exec",  # guest agent
        "/nodes/pve-node-1/vzdump",  # backup
        "/nodes/pve-node-1/storage/local-lvm/upload",  # upload
        "/nodes/pve-node-1/storage/local-lvm/content/vm-9000-disk-0",  # download
        "/nodes/pve-node-1/qemu/9000/config",  # config mutation surface
        "/cluster/firewall/rules",  # firewall
        "/nodes/pve-node-1/network/vmbr0",  # network mutation surface
        "/access/acl",  # ACL
        "/access/users/root@pam/token/mytoken",  # token
    ],
)
def test_forbidden_endpoints_are_refused(path):
    assert not path_is_allowed(path), path
    t = FakeProxmoxReadOnlyTransport()
    with pytest.raises(UnknownPathRefused):
        t.get(path)


# --- redirect / cross-host refusal -----------------------------------------------


def test_cross_host_and_absolute_urls_refused():
    t = FakeProxmoxReadOnlyTransport()
    for path in ("https://evil.example/nodes", "//other-host/nodes", "http://x/nodes"):
        assert not path_is_allowed(path)
        with pytest.raises(CrossHostRequestRefused):
            t.get(path)


def test_redirect_responses_are_refused():
    t = FakeProxmoxReadOnlyTransport({"/nodes": RedirectResponse("https://elsewhere/nodes")})
    with pytest.raises(RedirectRefused):
        t.get("/nodes")
    with pytest.raises(RedirectRefused):
        t.follow("https://elsewhere/nodes")


# --- canonical path validation (encoded-delimiter smuggling) ---------------------

# Each of these could decode to a DIFFERENT endpoint path and must be refused before matching.
NON_CANONICAL_PATHS = [
    "/nodes/node-a%2Fqemu%2F9000%2Fconfig",  # encoded '/' smuggling a deeper path
    "/nodes/node-a%2fqemu",  # lowercase encoded '/'
    "/nodes/%2e%2e%2fcluster",  # encoded traversal ../
    "/nodes/%2E%2E/cluster",  # encoded dot-segment (uppercase)
    "/nodes/..%2fcluster",  # mixed raw + encoded traversal
    "/nodes/node-a%5Cqemu",  # encoded backslash (uppercase)
    "/nodes/node-a%5cqemu",  # encoded backslash (lowercase)
    "/nodes/node-a\\qemu",  # raw backslash
    "\\nodes",  # raw backslash at start
    "/nodes//qemu",  # repeated internal slash
    "/nodes///status",  # repeated internal slash (triple)
    "/nodes/..",  # raw dot-segment traversal
    "/nodes/./status",  # raw single-dot segment
    "/nodes/%00",  # encoded NUL control
    "/nodes/%0a/status",  # encoded newline control
    "/nodes/node%2",  # malformed percent-encoding (truncated)
    "/nodes/node%zz",  # malformed percent-encoding (non-hex)
    "/nodes/node%",  # malformed percent-encoding (bare percent)
]


@pytest.mark.parametrize("path", NON_CANONICAL_PATHS)
def test_non_canonical_paths_refused_before_lookup(path):
    assert canonical_path_violation(path) is not None, path
    assert not path_is_allowed(path), path
    # Refused by the policy (either canonical or, for backslash-prefixed, cross-host first).
    with pytest.raises((NonCanonicalPathRefused, CrossHostRequestRefused)):
        assert_request_allowed("GET", path)
    # Refused by the transport BEFORE any canned-response lookup.
    t = FakeProxmoxReadOnlyTransport({path: [{"node": "x"}]})
    with pytest.raises((NonCanonicalPathRefused, CrossHostRequestRefused)):
        t.get(path)
    assert t.calls == []


def test_encoded_slash_smuggling_is_rejected_specifically():
    # The motivating bypass: %2F must not let /nodes/{node} match a deeper mutation path.
    path = "/nodes/node-a%2Fqemu%2F9000%2Fconfig"
    assert canonical_path_violation(path) == "percent-encoded delimiter or control character"
    with pytest.raises(NonCanonicalPathRefused):
        assert_request_allowed("GET", path)


def test_valid_paths_remain_canonical_and_allowed():
    # Regression: legitimate allowlisted paths are untouched by canonicalization.
    for path in (
        "/nodes",
        "/nodes/pve-node-1",
        "/nodes/pve-node-1/status",
        "/nodes/pve-node-1/storage",
        "/nodes/pve-node-1/qemu",
        "/nodes/pve-node-1/lxc",
        "/cluster/resources",
        "/cluster/sdn/vnets",
        "/cluster/sdn/zones",
    ):
        assert canonical_path_violation(path) is None, path
        assert path_is_allowed(path), path
        assert_request_allowed("GET", path)  # does not raise


def test_all_allowlisted_templates_are_canonical_and_allowed():
    """Regression: every allowlisted template, instantiated concretely, stays canonical + valid."""
    for template in ALLOWED_PATH_TEMPLATES:
        concrete = template.replace("{node}", "pve-node-1")
        assert "{" not in concrete, template
        assert canonical_path_violation(concrete) is None, concrete
        assert path_is_allowed(concrete), concrete
        assert_request_allowed("GET", concrete)  # does not raise


# --- canonical absolute request path: no query/fragment/matrix/whitespace/control ---

# Each of these is a non-canonical *request form* that must be refused before any lookup.
NON_CANONICAL_REQUEST_FORMS = [
    "/nodes?full=1",  # query string
    "/nodes?anything",  # bare query
    "/nodes/node-a;param=value",  # matrix parameter
    "/nodes/node-a#fragment",  # fragment
    "/nodes/node-a ",  # raw trailing space
    "/nodes /node-a",  # raw internal space
    "/nodes\n",  # raw newline (C0 control)
    "/nodes\t/status",  # raw tab
    "/nodes\x00",  # raw NUL
    "/nodes\x1f",  # raw C0 control
    "/nodes\x7f",  # raw DEL
    "/nodes\x85",  # raw C1 control (NEL)
    "nodes",  # relative (no leading slash)
    "",  # empty
]


@pytest.mark.parametrize("path", NON_CANONICAL_REQUEST_FORMS, ids=lambda p: repr(p))
def test_non_canonical_request_forms_refused_before_lookup(path):
    assert canonical_path_violation(path) is not None, repr(path)
    assert not path_is_allowed(path), repr(path)
    with pytest.raises((NonCanonicalPathRefused, CrossHostRequestRefused)):
        assert_request_allowed("GET", path)
    t = FakeProxmoxReadOnlyTransport({path: [{"node": "x"}]})
    with pytest.raises((NonCanonicalPathRefused, CrossHostRequestRefused)):
        t.get(path)
    assert t.calls == []  # refused before any canned-response lookup


def test_query_string_refused_even_for_allowlisted_prefix():
    # /nodes is allowlisted, but ANY query string is refused in this milestone.
    assert canonical_path_violation("/nodes?full=1") == "query string not permitted"
    with pytest.raises(NonCanonicalPathRefused):
        assert_request_allowed("GET", "/nodes?full=1")


def test_relative_path_is_refused():
    assert canonical_path_violation("nodes") == "path must be absolute (exactly one leading slash)"
    with pytest.raises(NonCanonicalPathRefused):
        assert_request_allowed("GET", "nodes")


# --- offline: no network-capable imports -----------------------------------------


def test_fake_transport_and_policy_have_no_network_imports():
    import secp_plugin_proxmox.readonly_normalize as nz
    import secp_plugin_proxmox.readonly_policy as pol
    import secp_plugin_proxmox.readonly_transport as tr

    # Match actual import statements (not docstring prose that merely names these modules).
    forbidden = (
        "import httpx",
        "from httpx",
        "import requests",
        "from requests",
        "import aiohttp",
        "import socket",
        "from socket",
        "import ssl",
        "import subprocess",
        "from subprocess",
        "import http.client",
        "from http.client",
        "import urllib.request",
        "from urllib.request",
        "import paramiko",
    )
    for module in (tr, pol, nz):
        src = inspect.getsource(module)
        for token in forbidden:
            assert token not in src, f"{module.__name__} must not use `{token}`"


# --- normalizer: redaction, provider-neutral, no evidence labels -----------------


def test_normalizer_redacts_and_extracts_identifiers_only():
    observed = normalize_proxmox_observations(FULL_INVENTORY)
    assert observed["nodes"] == ["pve-node-1", "pve-node-2"]
    assert observed["storage"] == ["local-lvm"]
    assert observed["network_segments"] == ["vmbr0"]
    assert observed["cidr_reservations"] == ["10.60.0.0/16"]
    # It must NOT choose an evidence source / verification level, and must not persist.
    assert "evidence_source" not in observed
    assert "verification_level" not in observed
    # No description / notes / tags / secret material survives anywhere.
    blob = str(observed).lower()
    for leak in ("description", "notes", "hunter2", "password", "token", "tags", "ticket", "lab"):
        assert leak not in blob, leak


def test_normalizer_does_not_infer_isolation_from_inventory():
    observed = normalize_proxmox_observations(FULL_INVENTORY)
    assert "isolation" not in observed  # never inferred from inventory presence/names


# --- fail-closed comparison (via the EXISTING pipeline) --------------------------


def test_missing_observations_are_unverifiable():
    findings = compare_boundary_to_evidence(VALID_ONBOARDING_BOUNDARY, _payload({}))
    assert summarize_findings(findings) == EvidenceStatus.unverifiable
    assert findings_pass(findings) is False


def test_malformed_nodes_response_is_unverifiable_not_fail():
    # A present-but-malformed (non-list) response is omitted -> unverifiable, never inferred.
    observed = normalize_proxmox_observations({"/nodes": {"node": "pve-node-1"}})
    assert "nodes" not in observed
    findings = compare_boundary_to_evidence(VALID_ONBOARDING_BOUNDARY, _payload(observed))
    node_finding = next(f for f in findings if f["check"] == "nodes")
    assert node_finding["status"] == EvidenceStatus.unverifiable.value


def test_incomplete_fully_segregated_blocks_approval():
    """Even COMPLETE generic inventory (+ dedicated vmid/quota facts) cannot pass isolation:
    without an explicit isolation observation, fully_segregated is unverifiable and blocks
    approval. A future passing evaluator requires a separately reviewed isolation schema that
    represents every ADR-015 isolation assertion explicitly (see module docstring)."""
    dedicated = {
        "vmid_range": {"start": 9000, "end": 9100},
        "quotas": VALID_ONBOARDING_BOUNDARY["quotas"],
    }
    observed = normalize_proxmox_observations(FULL_INVENTORY, dedicated=dedicated)
    findings = compare_boundary_to_evidence(VALID_ONBOARDING_BOUNDARY, _payload(observed))
    by_check = {f["check"]: f["status"] for f in findings}
    # inventory dimensions are observed and match...
    assert by_check["nodes"] == EvidenceStatus.passed.value
    assert by_check["storage"] == EvidenceStatus.passed.value
    assert by_check["network_segments"] == EvidenceStatus.passed.value
    # ...but isolation is unverifiable, so the whole result blocks approval.
    assert by_check[CHECK_ISOLATION] == EvidenceStatus.unverifiable.value
    assert findings_pass(findings) is False


def test_no_fully_segregated_passing_fixture_in_plugin_package():
    """Guardrail: the plugin package ships no fixture/evaluator that makes fully_segregated pass.
    A future passing evaluator requires a separately reviewed isolation schema/contract that
    represents every ADR-015 isolation assertion explicitly."""
    import secp_plugin_proxmox

    pkg_dir = Path(secp_plugin_proxmox.__file__).parent
    for name in ("readonly_normalize.py", "readonly_policy.py", "readonly_transport.py"):
        src = (pkg_dir / name).read_text(encoding="utf-8").lower()
        # A passing isolation fixture would have to assert route_to_protected; its absence proves
        # the plugin ships no fully_segregated-passing observation or evaluator.
        assert "route_to_protected" not in src


# --- injectable only through the existing plugin seam ----------------------------


def test_injectable_through_plugin_transport_factory_get_only():
    plugin = ProxmoxPlugin(transport_factory=fake_transport_factory(DISCOVER_INVENTORY))
    result = plugin.discover(
        DiscoveryRequest(target_id="t-1", plugin_name="proxmox", config=GOOD_CONFIG, scope=None),
        ProviderCredential.from_secret("tok"),
    )
    assert result.ok
    assert {r.resource_type for r in result.resources} <= {"node", "vm", "container", "storage"}


def test_capabilities_and_health_unchanged():
    report = ProxmoxPlugin().health()
    assert set(report.capabilities) == {"validate", "health", "discover", "status"}
    assert report.simulated is False and report.healthy is True
    assert report.version == "0.1.0" and report.contract_version == "1"
    plugin = ProxmoxPlugin()
    for call in (
        lambda: plugin.plan({}, []),
        lambda: plugin.apply(None, None),
        lambda: plugin.reset(None, "i", None),
        lambda: plugin.destroy(["i"], None),
    ):
        with pytest.raises(UnsupportedCapabilityError):
            call()


# --- architecture boundary + live seal -------------------------------------------


def test_api_package_does_not_import_the_fake_transport_or_policy():
    api_pkg = Path(__file__).resolve().parents[1] / "secp_api"
    needles = (
        "readonly_transport",
        "readonly_policy",
        "readonly_normalize",
        "FakeProxmoxReadOnlyTransport",
        "secp_plugin_proxmox",
    )
    for py in api_pkg.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        text = py.read_text(encoding="utf-8")
        for needle in needles:
            assert needle not in text, f"{py.name} references {needle!r}"


def test_live_evidence_seal_is_unchanged():
    from secp_api.errors import LiveEvidenceSealedError
    from secp_api.onboarding import B1B0_LIVE_EVIDENCE_SEALED
    from secp_worker.onboarding.target_evidence import SealedProviderTargetEvidenceCollector

    assert B1B0_LIVE_EVIDENCE_SEALED is True
    with pytest.raises(LiveEvidenceSealedError):
        SealedProviderTargetEvidenceCollector().collect(declared_boundary={})
