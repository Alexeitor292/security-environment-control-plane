"""The transport allowlist IS the typed operation grammar — equal to it, not merely compatible.

This file exists because of a defect with a specific shape, and the shape recurs in this codebase:
**a quantity derived in two places, where the copies can drift.** The engine declared twenty-four
reviewed read operations. The transport enforced a hand-maintained twelve-template allowlist plus a
blanket "no query parameters" rule. Nothing compared the two, so eighteen operations were refused
at the wire — including ``GET /cluster/sdn``, the SDN authority preflight that every "the SDN index
was empty and we were allowed to see it" claim in this system rests on, and every operation
carrying ``?pending=1`` or ``?type=vm``.

Both lists looked correct in review. The bug was that there were two.

So the allowlist is now DERIVED from the operation types, and this file pins two directions:

* **nothing narrower** — every typed operation, and every operation the planner can produce, is
  accepted;
* **nothing broader** — a request that is not one of those typed operations is not expressible,
  and the grammar admits no code, template or query pair that no operation type declares.

No test here opens a socket. The grammatical refusal happens before any client is built, which is
itself asserted rather than assumed.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
from dataclasses import dataclass
from typing import ClassVar

import pytest
from secp_api.discovery_observation import Observation
from secp_worker.proxmox_discovery_operations import (
    GetNodeStatusOperation,
    GetVersionOperation,
    discovery_operation_types,
    discovery_request_grammar,
)
from secp_worker.proxmox_discovery_plan import (
    SOURCE_NODE_INDEX,
    phase_one_operations,
    phase_three_operations,
    phase_two_operations,
)
from secp_worker.proxmox_discovery_transport import (
    HardenedProxmoxDiscoveryTransport,
    ProxmoxDiscoveryTransportError,
)

BASE = "https://pve.example.test:8006/api2/json"
TOKEN = "secpdisc@pve!discovery=00000000-0000-0000-0000-000000000000"

TRANSPORT_SOURCE = (
    pathlib.Path(__file__).resolve().parents[3]
    / "apps"
    / "worker"
    / "secp_worker"
    / "proxmox_discovery_transport.py"
)


def _transport() -> HardenedProxmoxDiscoveryTransport:
    """A constructed transport. Contacts nothing: the CA is read at request time, and every test
    below either refuses before that or asserts the client is never opened."""
    return HardenedProxmoxDiscoveryTransport(
        base_url=BASE, ca_path="/nonexistent/ca.pem", token=TOKEN
    )


def _probe(operation_type: type):
    """One instance of a type, with syntactically valid provenance-marked segments."""
    placeholders = operation_type.path_template.count("{")
    if placeholders == 0:
        return operation_type()
    return operation_type(*(["probe"] * placeholders), SOURCE_NODE_INDEX)


def _sealed(monkeypatch) -> list[str]:
    """Replace the client opener with one that fails the test if it is ever reached."""
    import secp_worker.proxmox_discovery_transport as module

    opened: list[str] = []

    def _forbidden(*args, **kwargs):
        opened.append("open_hardened_client")
        raise AssertionError("the transport opened a client for a request it should have refused")

    monkeypatch.setattr(module, "open_hardened_client", _forbidden)
    return opened


# === the allowlist equals the typed operation set =================================================


def test_the_grammar_keys_are_exactly_the_operation_codes():
    """Equality in both directions, which is the property a subset check would not give."""
    grammar = discovery_request_grammar()
    declared = {t.operation_code for t in discovery_operation_types()}
    assert set(grammar) == declared, set(grammar).symmetric_difference(declared)
    # And no type shares a code with another: a collision would silently drop one from the grammar.
    codes = [t.operation_code for t in discovery_operation_types()]
    assert len(codes) == len(set(codes)), sorted(codes)


def test_every_grammar_entry_is_its_own_types_template_and_declared_query():
    """The grammar carries nothing a type did not declare — not a widened template, not an extra
    query pair, not a relaxed value."""
    grammar = discovery_request_grammar()
    for operation_type in discovery_operation_types():
        template, query = grammar[operation_type.operation_code]
        assert template == operation_type.path_template, operation_type
        assert query == _probe(operation_type).query_parameters(), operation_type


def test_the_engine_declares_the_reviewed_operation_count():
    """A count, so an operation silently leaving the set is visible. Fourteen non-SDN reads plus
    ten SDN reads — the twenty-four the review covered."""
    from secp_worker.proxmox_discovery_operations import FIRST_MVP_OPERATIONS
    from secp_worker.proxmox_sdn_operations import SDN_OPERATIONS

    assert len(FIRST_MVP_OPERATIONS) == 14
    assert len(SDN_OPERATIONS) == 10
    assert len(discovery_operation_types()) == 24
    assert len(discovery_request_grammar()) == 24


def test_the_sdn_authority_preflight_is_in_the_allowlist():
    """Named explicitly because its absence was the worst consequence of the drift: without
    ``GET /cluster/sdn`` an empty SDN index cannot be distinguished from a denied one, and every
    'no zones exist' claim becomes unfalsifiable."""
    grammar = discovery_request_grammar()
    assert grammar["sdn_root_authority"] == ("/cluster/sdn", ())


@pytest.mark.parametrize("operation_type", discovery_operation_types(), ids=lambda t: t.__name__)
def test_every_typed_operation_is_accepted_by_the_transport(operation_type):
    """Nothing narrower. Each of the twenty-four passes the transport's own grammar check."""
    operation = _probe(operation_type)
    path, query = _transport()._assert_grammatical(operation)
    assert path == operation.rendered_path()
    assert query == operation.query_parameters()


def test_every_operation_the_planner_can_produce_is_accepted():
    """Reachability, not just the type list: the planner is what actually constructs operations,
    and an operation it can build that the transport refuses is a discovery run that fails at the
    wire for reasons no unit test would show."""
    observations = {
        "node_names": Observation.observed(["pve1", "pve2"]),
        "storage_ids": Observation.observed({"pve1": ["local", "local-lvm"], "pve2": ["local"]}),
        "existing_vnets": Observation.observed({"vnet0": {}, "vnet1": {}}),
        "existing_sdn_zones": Observation.observed({"zone0": {}}),
    }
    planned: list[object] = []
    ops, _refusals = phase_one_operations()
    planned.extend(ops)
    ops, _refusals = phase_two_operations(observations, len(planned))
    planned.extend(ops)
    ops, _refusals = phase_three_operations(observations, len(planned))
    planned.extend(ops)

    assert len(planned) > 24, len(planned)
    transport = _transport()
    for operation in planned:
        transport._assert_grammatical(operation)

    # And the planner exercises every phase's operation kinds, so this is not vacuous.
    produced = {type(op).operation_code for op in planned}
    assert "api_version" in produced
    assert "node_status" in produced
    assert "storage_content" in produced
    assert "sdn_subnets_pending" in produced
    assert "node_sdn_bridges" in produced


# === nothing broader: what is not expressible =====================================================


def test_there_is_no_generic_get_on_the_transport():
    """The forbidden shape, named. ``get(path)`` is what lets a caller aim the credential."""
    assert not hasattr(HardenedProxmoxDiscoveryTransport, "get")
    assert not hasattr(HardenedProxmoxDiscoveryTransport, "request")
    assert not hasattr(HardenedProxmoxDiscoveryTransport, "fetch")
    public = {n for n in dir(HardenedProxmoxDiscoveryTransport) if not n.startswith("_")}
    assert public == {"execute"}


def test_the_only_entry_point_takes_an_operation_and_nothing_else():
    params = inspect.signature(HardenedProxmoxDiscoveryTransport.execute).parameters
    assert set(params) == {"self", "operation"}


def test_a_raw_path_string_is_not_an_operation():
    """A caller-supplied raw path has nowhere to go: a string is not a reviewed operation type."""
    with pytest.raises(ProxmoxDiscoveryTransportError, match="operation_not_reviewed"):
        _transport().execute("/nodes/pve1/qemu/100/status/current")


@pytest.mark.parametrize(
    "raw",
    [
        "/version",  # even a path that IS in the allowlist
        "/access/users",
        "https://evil.test/api2/json/version",
        b"/version",
        {"path": "/version"},
        ("/version", {"pending": "1"}),
        None,
        42,
    ],
)
def test_no_raw_input_of_any_shape_is_executable(raw):
    """Raw paths, raw query strings, mappings, tuples and bytes are all the same refusal: they are
    not instances of a reviewed operation type."""
    with pytest.raises(ProxmoxDiscoveryTransportError, match="operation_not_reviewed"):
        _transport().execute(raw)


def test_an_untyped_lookalike_carrying_a_real_operation_code_is_refused():
    """The impostor case. It renders a legitimate path and declares a legitimate code — and is
    still refused, because the check is on the TYPE, not on what the object says about itself."""

    @dataclass(frozen=True)
    class _Lookalike:
        operation_code: ClassVar[str] = "api_version"
        path_template: ClassVar[str] = "/version"

        def rendered_path(self) -> str:
            return "/version"

        def query_parameters(self):
            return ()

    with pytest.raises(ProxmoxDiscoveryTransportError, match="operation_not_reviewed"):
        _transport().execute(_Lookalike())


def test_a_subclass_of_a_real_operation_is_refused():
    """Subclassing is the cheapest way to inherit a type check. ``type(x) not in SET`` refuses it;
    ``isinstance`` would not — and the object could then override ``rendered_path``."""

    class _Sneaky(GetVersionOperation):
        def rendered_path(self) -> str:
            return "/access/users"

    with pytest.raises(ProxmoxDiscoveryTransportError, match="operation_not_reviewed"):
        _transport().execute(_Sneaky())


def test_a_rendered_path_outside_its_own_template_is_refused():
    """A genuine operation type whose rendered path was mutated after construction. The frozen
    dataclass validates at construction; this reaches past that, which is exactly the route the
    transport's second check exists for — it is the last thing before the wire."""
    operation = GetNodeStatusOperation("pve1", SOURCE_NODE_INDEX)
    object.__setattr__(operation, "node", "pve1/../../access/users")
    with pytest.raises(ProxmoxDiscoveryTransportError, match="path_outside_its_template"):
        _transport().execute(operation)


@pytest.mark.parametrize(
    "node",
    [
        "..",
        "pve1/qemu",
        "pve1%2F..%2Faccess",
        "pve1?x=1",
        "pve1#frag",
        "",
        "-leading-hyphen-is-not-a-safe-segment" * 3,
    ],
)
def test_an_unsafe_interpolated_segment_is_refused_at_the_transport(node):
    """Checked HERE as well as at construction. A segment that reached the transport by some other
    route must not be sent on the strength of having been checked earlier."""
    operation = GetNodeStatusOperation("pve1", SOURCE_NODE_INDEX)
    object.__setattr__(operation, "node", node)
    with pytest.raises(ProxmoxDiscoveryTransportError, match="path_outside_its_template"):
        _transport().execute(operation)


def test_a_query_the_type_did_not_declare_is_refused():
    """Byte-identical, not "a subset of the allowed keys". A query pair that a real operation type
    never declares is refused even when the pair itself is legitimate for some OTHER type — the
    grammar is per-operation, so ``?pending=1`` being valid somewhere does not make it valid here.
    """
    operation = GetVersionOperation()
    for forged in (
        (("pending", "1"),),  # valid on the SDN reads, not on /version
        (("type", "vm"),),  # valid on /cluster/resources, not on /version
        (("node", "pve1"),),
        (("x", "y"), ("z", "w")),
    ):
        object.__setattr__(operation, "query_parameters", lambda forged=forged: forged)
        with pytest.raises(ProxmoxDiscoveryTransportError, match="query_outside_the_grammar"):
            _transport().execute(operation)


def test_a_declared_query_value_cannot_be_changed_by_a_caller():
    """``?pending=1`` is a FIXED value owned by its type. A caller cannot make it ``pending=0``,
    which would silently turn a pending-state read into an active-state read while every downstream
    fact still claimed to describe pending SDN configuration."""
    from secp_worker.proxmox_sdn_operations import GetSdnZonesOperation

    grammar = discovery_request_grammar()
    assert grammar["sdn_zones_pending"] == ("/cluster/sdn/zones", (("pending", "1"),))

    operation = GetSdnZonesOperation()
    object.__setattr__(operation, "query_parameters", lambda: (("pending", "0"),))
    with pytest.raises(ProxmoxDiscoveryTransportError, match="query_outside_the_grammar"):
        _transport().execute(operation)


def test_a_type_in_the_set_but_absent_from_the_grammar_is_still_refused(monkeypatch):
    """The two checks are separate, and this exercises the SECOND one on its own.

    The scenario is a type that joined the closed set — an edit to the operations module — without
    a grammar entry to describe what it may send. The type check passes; the code check must refuse
    anyway. Without this, the code check could be deleted and only the first would be tested.
    """
    import secp_worker.proxmox_discovery_operations as operations

    class _Undeclared:
        operation_code = "undeclared_read"
        path_template = "/access/users"

        def rendered_path(self) -> str:
            return "/access/users"

        def query_parameters(self):
            return ()

    # First, the anti-drift property itself, stated as a fact rather than assumed: widening the
    # type set widens the grammar IN LOCKSTEP, because the grammar is computed from the set. The
    # state "a type is in the set but has no grammar entry" is therefore not reachable by editing
    # the set — which is the whole reason the two can no longer disagree.
    monkeypatch.setattr(
        operations,
        "discovery_operation_types",
        lambda: (*operations.FIRST_MVP_OPERATIONS, _Undeclared),
    )
    assert "undeclared_read" in operations.discovery_request_grammar()

    # Second, the code check on its own. Reached by dropping the entry from the GRAMMAR while the
    # type set keeps the type — the one arrangement the derivation cannot produce, and exactly what
    # this branch is defence against.
    real_grammar = operations.discovery_request_grammar()
    monkeypatch.setattr(
        operations,
        "discovery_request_grammar",
        lambda: {k: v for k, v in real_grammar.items() if k != "undeclared_read"},
    )
    with pytest.raises(ProxmoxDiscoveryTransportError, match="operation_not_reviewed"):
        _transport()._assert_grammatical(_Undeclared())


# === a refused request never reaches the network ==================================================


def test_a_refusal_happens_before_a_client_is_opened(monkeypatch):
    """Order is the property. Refusing after opening a connection would mean the target was already
    contacted — with the credential — for a request nobody reviewed."""
    opened = _sealed(monkeypatch)
    with pytest.raises(ProxmoxDiscoveryTransportError, match="operation_not_reviewed"):
        _transport().execute("/access/users")
    with pytest.raises(ProxmoxDiscoveryTransportError, match="operation_not_reviewed"):
        _transport().execute(object())
    operation = GetNodeStatusOperation("pve1", SOURCE_NODE_INDEX)
    object.__setattr__(operation, "node", "..")
    with pytest.raises(ProxmoxDiscoveryTransportError, match="path_outside_its_template"):
        _transport().execute(operation)
    assert opened == [], "a client was opened for a refused request"


def test_the_grammar_check_runs_before_the_ssl_context_is_built(monkeypatch):
    """The CA path is deliberately nonexistent here: if the context were built first, this would
    fail with a file error rather than the grammatical refusal."""
    import secp_worker.proxmox_discovery_transport as module

    built: list[str] = []

    def _forbidden(*args, **kwargs):
        built.append("build_ssl_context")
        raise AssertionError("an SSL context was built for a refused request")

    monkeypatch.setattr(module, "build_ssl_context", _forbidden)
    with pytest.raises(ProxmoxDiscoveryTransportError, match="operation_not_reviewed"):
        _transport().execute("/version")
    assert built == []


# === structural: no method, no fallback ===========================================================


def test_no_http_method_other_than_get_appears_in_the_transport():
    """Not "a non-GET is refused" — a non-GET is not written anywhere in the module."""
    tree = ast.parse(TRANSPORT_SOURCE.read_text(encoding="utf-8"))
    methods = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    }
    assert methods == {"GET"}, methods


def test_the_transport_has_no_fallback_path():
    """A fallback is how a hardened transport quietly becomes an unhardened one: a retry without
    the pinned CA, a second base URL, a redirect that gets followed on the second attempt.

    Checked through the AST rather than as a substring scan. The module's docstring EXPLAINS why
    ``trust_env`` and an injectable client are defects, so a text scan trips on the prose that
    documents the fix — the guard reports the very sentence describing its own property.
    """
    tree = ast.parse(TRANSPORT_SOURCE.read_text(encoding="utf-8"))

    for node in ast.walk(tree):
        if isinstance(node, ast.keyword):
            if node.arg in {"verify", "trust_env"}:
                raise AssertionError(f"the transport passes {node.arg}= to a client")
            if node.arg == "follow_redirects" and not (
                isinstance(node.value, ast.Constant) and node.value.value is False
            ):
                raise AssertionError("the transport enables redirect following")
        if isinstance(node, ast.Attribute) and node.attr in {"trust_env", "verify"}:
            raise AssertionError(f"the transport touches .{node.attr}")

    # A swallowed transport error is the other fallback shape: the request fails, nothing is
    # raised, and the caller reads the absence of an exception as a successful read.
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            body = [n for n in node.body if not isinstance(n, ast.Expr)]
            assert body, "an exception handler in the transport has an empty body"
            assert not all(isinstance(n, ast.Pass) for n in body), "a transport error is swallowed"

    # And exactly one call reaches the network, so there is no second attempt to fall back to.
    streams = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "stream"
    ]
    assert len(streams) == 1, len(streams)


def test_the_transport_resolves_no_credential_and_names_no_target():
    """It receives a token and a base URL from its constructor. It must not reach a resolver, a
    secret store, an environment variable or a hardcoded host."""
    tree = ast.parse(TRANSPORT_SOURCE.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    for banned in ("os", "secp_worker.preflight.secret_resolution", "dotenv", "keyring"):
        assert banned not in imported, banned

    source = TRANSPORT_SOURCE.read_text(encoding="utf-8")
    for banned in ("getenv", "environ", "SecretMaterial", "resolve("):
        assert banned not in source, banned


# === the production factory =======================================================================


def test_the_production_factory_builds_the_hardened_transport_and_nothing_else():
    """The hardened class was reached by no production code: every caller was a test fake. A class
    that only fakes can obtain is a hardened transport nothing is hardened by."""
    from secp_worker.proxmox_discovery_transport import HardenedDiscoveryTransportFactory

    built = HardenedDiscoveryTransportFactory().build(
        base_url=BASE, ca_path="/nonexistent/ca.pem", token=TOKEN
    )
    assert type(built) is HardenedProxmoxDiscoveryTransport


def test_the_factory_matches_the_composition_seam_exactly():
    """Signature equality with the protocol, so the production factory cannot drift out of the
    shape ``run_full_discovery`` calls."""
    from secp_worker.proxmox_discovery_composition import TransportFactory
    from secp_worker.proxmox_discovery_transport import HardenedDiscoveryTransportFactory

    declared = inspect.signature(TransportFactory.build).parameters
    actual = inspect.signature(HardenedDiscoveryTransportFactory.build).parameters
    assert set(actual) == set(declared) == {"self", "base_url", "ca_path", "token"}
    for name in ("base_url", "ca_path", "token"):
        assert actual[name].kind is inspect.Parameter.KEYWORD_ONLY, name


def test_the_factory_holds_no_credential_and_no_target():
    """A factory that stored the token would extend its lifetime past the one function body the
    composition confines it to."""
    from secp_worker.proxmox_discovery_transport import HardenedDiscoveryTransportFactory

    factory = HardenedDiscoveryTransportFactory()
    assert HardenedDiscoveryTransportFactory.__slots__ == ()
    assert not hasattr(factory, "__dict__")
    assert inspect.signature(HardenedDiscoveryTransportFactory).parameters == {}
    assert TOKEN not in repr(factory)


def test_the_factory_refuses_to_build_an_unpinned_or_uncredentialed_transport():
    """Fail-closed at BUILD, not at first request: a transport that would fall back to ambient
    system trust must not come into existence."""
    from secp_worker.proxmox_discovery_transport import HardenedDiscoveryTransportFactory

    factory = HardenedDiscoveryTransportFactory()
    with pytest.raises(ProxmoxDiscoveryTransportError, match="ca_not_pinned"):
        factory.build(base_url=BASE, ca_path="", token=TOKEN)
    with pytest.raises(ProxmoxDiscoveryTransportError, match="token_absent"):
        factory.build(base_url=BASE, ca_path="/nonexistent/ca.pem", token="")
    with pytest.raises(ValueError):
        factory.build(base_url="http://pve.example.test", ca_path="/x.pem", token=TOKEN)


def test_building_contacts_nothing(monkeypatch):
    """Construction opens no client. Asserted by sealing the opener, not by inspecting the code."""
    from secp_worker.proxmox_discovery_transport import HardenedDiscoveryTransportFactory

    opened = _sealed(monkeypatch)
    HardenedDiscoveryTransportFactory().build(
        base_url=BASE, ca_path="/nonexistent/ca.pem", token=TOKEN
    )
    assert opened == []
