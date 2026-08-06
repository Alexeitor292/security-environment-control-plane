"""The hardened Proxmox discovery transport.

The adversary model has two halves and the second is the one that bites:

1. an attacker on the network path, against whom ambient system trust is not a defence;
2. **our own error handling**, which in the existing transport puts the API token into every
   traceback that touches a failed request — because `httpx.HTTPStatusError` carries `.request`,
   and `.request.headers` holds `Authorization: PVEAPIToken=…`.

No test here opens a socket. Construction is asserted to contact nothing.
"""

from __future__ import annotations

import pickle

import pytest
from secp_worker.proxmox_discovery_transport import (
    HardenedProxmoxDiscoveryTransport,
    ProxmoxDiscoveryTransportError,
    _status_reason,
)

BASE = "https://pve.example.test:8006/api2/json"
TOKEN = "secpdisc@pam!discovery=00000000-0000-0000-0000-000000000000"


def _transport(**overrides) -> HardenedProxmoxDiscoveryTransport:
    kwargs = dict(base_url=BASE, ca_path="/etc/secp/pve-ca.pem", token=TOKEN)
    kwargs.update(overrides)
    return HardenedProxmoxDiscoveryTransport(**kwargs)


# --- the credential never becomes renderable ------------------------------------------------------


def test_the_token_is_not_in_repr_str_or_format():
    t = _transport()
    assert TOKEN not in repr(t)
    assert TOKEN not in str(t)
    assert TOKEN not in f"{t}"
    assert "redacted" in repr(t)


def test_the_transport_cannot_be_serialized():
    """A picklable transport is a file containing an API token."""
    t = _transport()
    with pytest.raises(ProxmoxDiscoveryTransportError, match="not_serializable"):
        pickle.dumps(t)
    with pytest.raises(ProxmoxDiscoveryTransportError, match="not_serializable"):
        t.__getstate__()


def test_the_token_is_not_reachable_through_ordinary_attribute_access():
    """Name-mangled slots, so a generic "log the object's fields" helper finds nothing."""
    t = _transport()
    assert not hasattr(t, "token")
    assert not hasattr(t, "_token")
    assert TOKEN not in str(vars(t)) if hasattr(t, "__dict__") else True


def test_the_error_type_carries_only_a_reason_code():
    """Inherited contract: never a URL, host, port, token, CA path or backend error."""
    err = ProxmoxDiscoveryTransportError("proxmox_discovery_permission_denied")
    assert BASE not in str(err)
    assert TOKEN not in str(err)
    assert str(err) == "proxmox_discovery_permission_denied"


# --- fail closed at construction ------------------------------------------------------------------


def test_an_unpinned_ca_cannot_be_constructed():
    """The whole point. A transport that would fall back to ambient system trust must not exist,
    rather than existing and being checked later."""
    for bad in ("", "   ", None):
        with pytest.raises(ProxmoxDiscoveryTransportError, match="ca_not_pinned"):
            _transport(ca_path=bad)


def test_an_absent_token_cannot_be_constructed():
    for bad in ("", "   ", None):
        with pytest.raises(ProxmoxDiscoveryTransportError, match="token_absent"):
            _transport(token=bad)


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://pve.example.test:8006/api2/json",  # plaintext
        "https://pve.example.test:8006/api2/json?x=1",  # query in the base
        "ftp://pve.example.test/api2/json",
        "pve.example.test:8006",
    ],
)
def test_a_non_https_or_malformed_base_url_is_refused(bad_url):
    """Delegated to the plugin's own validator so the base-URL grammar has ONE owner.

    The exception TYPE is the plugin's to choose — this asserts refusal, not which class — so the
    two do not have to be kept in step. ``ValueError`` is its base today.
    """
    with pytest.raises(ValueError):
        _transport(base_url=bad_url)


def test_construction_contacts_nothing():
    """No socket, no DNS, no CA file read at construction — the CA is read when a request is made.

    Asserted by constructing with a CA path that does not exist: if construction opened it, this
    would raise.
    """
    t = _transport(ca_path="/nonexistent/path/to/ca.pem")
    assert isinstance(t, HardenedProxmoxDiscoveryTransport)


# --- a mutation is not representable --------------------------------------------------------------


def test_there_is_no_method_parameter_at_all():
    """Not "a non-GET is refused" — a non-GET cannot be written.

    The difference matters: a refusal is a check somebody can later move or make conditional; an
    absent parameter is a shape the caller cannot express.
    """
    import inspect

    assert not hasattr(HardenedProxmoxDiscoveryTransport, "request")
    assert not hasattr(HardenedProxmoxDiscoveryTransport, "post")
    assert not hasattr(HardenedProxmoxDiscoveryTransport, "put")
    assert not hasattr(HardenedProxmoxDiscoveryTransport, "patch")
    assert not hasattr(HardenedProxmoxDiscoveryTransport, "delete")

    params = inspect.signature(HardenedProxmoxDiscoveryTransport.get).parameters
    assert "method" not in params
    assert set(params) == {"self", "path", "params"}


def test_the_public_surface_is_exactly_one_operation():
    public = {
        name
        for name in dir(HardenedProxmoxDiscoveryTransport)
        if not name.startswith("_") and callable(getattr(HardenedProxmoxDiscoveryTransport, name))
    }
    assert public == {"get"}


# --- structural: what this module may not reach ---------------------------------------------------


def _module_imports() -> set[str]:
    import ast
    import pathlib

    source = (
        pathlib.Path(__file__).resolve().parents[3]
        / "apps"
        / "worker"
        / "secp_worker"
        / "proxmox_discovery_transport.py"
    ).read_text(encoding="utf-8")
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names.add(module)
            names.update(f"{module}.{a.name}" for a in node.names)
    return names


def test_the_transport_cannot_reach_opentofu_ssh_or_a_subprocess():
    """Structural, via the import table rather than a text scan — the docstring names several of
    these in order to explain why they are absent, and a substring guard would trip on itself."""
    imported = _module_imports()
    for forbidden in ("subprocess", "secp_worker.ssh_channel", "os", "shutil"):
        assert forbidden not in imported, forbidden
    assert not any("plan_gen" in n or "provisioning" in n for n in imported), sorted(imported)
    assert not any("opentofu" in n.lower() for n in imported), sorted(imported)


def test_it_reuses_the_hardened_primitives_rather_than_redefining_them():
    """The duplication guard. Seven transports already exist here; an eighth that re-derives
    build_ssl_context / read_capped_body / parse_bounded_json is the failure mode."""
    imported = _module_imports()
    assert "secp_worker.hardened_http" in imported
    for primitive in (
        "secp_worker.hardened_http.build_ssl_context",
        "secp_worker.hardened_http.open_hardened_client",
        "secp_worker.hardened_http.read_capped_body",
        "secp_worker.hardened_http.parse_bounded_json",
    ):
        assert primitive in imported, primitive


def test_it_reuses_the_plugin_policy_rather_than_a_second_allowlist():
    """The closed GET allowlist has one owner. A local copy here would drift from
    PROXMOX_READONLY_POLICY_VERSION and nothing would notice."""
    import pathlib

    source = (
        pathlib.Path(__file__).resolve().parents[3]
        / "apps"
        / "worker"
        / "secp_worker"
        / "proxmox_discovery_transport.py"
    ).read_text(encoding="utf-8")
    assert "readonly_policy" in source
    assert "assert_request_allowed" in source
    assert "assert_no_params" in source
    # And it does NOT define its own path allowlist.
    assert "ALLOWED_PATH_TEMPLATES" not in source


# --- status mapping -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status,reason",
    [
        (401, "proxmox_discovery_unauthenticated"),
        (403, "proxmox_discovery_permission_denied"),
        (404, "proxmox_discovery_endpoint_absent"),
        (501, "proxmox_discovery_endpoint_unsupported"),
        (500, "proxmox_discovery_request_refused"),
        (418, "proxmox_discovery_request_refused"),
    ],
)
def test_status_codes_map_to_closed_reasons(status, reason):
    assert _status_reason(status) == reason


def test_permission_denied_is_distinguishable_from_a_generic_failure():
    """Load-bearing on this surface.

    A denied SDN *index* read returns 200 with an empty list, so a 403 is the one unambiguous
    denial signal available — and an operator resolves it with a grant rather than a retry.
    """
    assert _status_reason(403) != _status_reason(500)
    assert _status_reason(403) != _status_reason(401)
