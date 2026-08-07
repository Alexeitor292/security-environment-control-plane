"""The `/version` vertical slice, through the real production composition.

Only fake credentials and a bounded fake transport are used. Nothing contacts a host.

The defect class this file is written against is "a correct module reached by nothing": every
component below already had unit tests before this file existed, and none of that proved the
production path selected any of them. So the assertions are about REACHABILITY — the transport is
instantiated, the typed operation is the one that runs, the parsed patch version arrives in the
observation, the evidence carries HTTPS fields rather than a fabricated argv.
"""

from __future__ import annotations

import ast
import pathlib
from datetime import UTC, datetime

import pytest
from secp_api.discovery_observation import Observation
from secp_api.discovery_operation_evidence import (
    FIRST_MVP_TRANSPORTS,
    DiscoveryOperationEvidence,
    DiscoveryOperationManifest,
    OperationEvidenceError,
    TransportKind,
    active_transport_set,
    first_mvp_manifest_refusals,
)
from secp_api.enums import DiscoveryObservationState as S
from secp_worker.preflight.secret_resolution import SUPPORTED_PURPOSES, ResolutionPurpose
from secp_worker.proxmox_discovery_composition import (
    PRODUCTION_TRANSPORT_KIND,
    run_version_discovery,
)
from secp_worker.proxmox_discovery_operations import GetVersionOperation

START = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
END = datetime(2026, 8, 6, 12, 0, 1, tzinfo=UTC)
AUTHORITY = "pve.example.test:8006"

_VERSION_PAYLOAD = {"version": "9.1.1", "release": "9.1", "repoid": "abc1234567"}


class _BoundedFakeTransport:
    """Records what was asked and returns a bounded canned body. Opens no socket."""

    def __init__(self, payload=None, raises: Exception | None = None) -> None:
        self.payload = payload if payload is not None else dict(_VERSION_PAYLOAD)
        self.raises = raises
        self.calls: list[tuple[str, tuple[tuple[str, str], ...]]] = []

    def execute(self, operation):
        """Takes an OPERATION, not a path — the same seam the production transport implements.

        A fake accepting ``get(path, params)`` would keep passing after the real transport stopped
        offering that shape, which is exactly how a test suite goes on proving a seam that no longer
        exists.
        """
        self.calls.append((operation.rendered_path(), operation.query_parameters()))
        if self.raises is not None:
            raise self.raises
        return self.payload


# --- the credential purpose ----------------------------------------------------------------------


def test_the_discovery_purpose_exists_and_is_distinct():
    assert ResolutionPurpose.proxmox_readonly_discovery.value == "proxmox_readonly_discovery"
    assert ResolutionPurpose.proxmox_readonly_discovery in SUPPORTED_PURPOSES
    assert (
        ResolutionPurpose.proxmox_readonly_discovery
        is not ResolutionPurpose.readonly_staging_preflight
    )


def test_there_is_no_generic_proxmox_purpose():
    """A generic ``proxmox_token`` would fit a read-only discovery token AND a controlled-live apply
    credential, so the first would silently become usable for the second."""
    names = {p.value for p in ResolutionPurpose}
    for generic in ("proxmox", "proxmox_token", "proxmox_api", "http", "generic"):
        assert generic not in names


def test_purpose_confusion_is_refused_in_both_directions():
    """A purpose is a separation boundary, not a label."""
    discovery = ResolutionPurpose.proxmox_readonly_discovery
    staging = ResolutionPurpose.readonly_staging_preflight
    assert discovery != staging
    assert discovery.value != staging.value
    # Neither is substitutable for the other by value, which is what a contract comparison uses.
    assert {discovery} != {staging}


# --- the vertical slice --------------------------------------------------------------------------


def test_the_typed_version_operation_is_the_one_that_runs():
    transport = _BoundedFakeTransport()
    result = run_version_discovery(
        transport=transport,
        operation=GetVersionOperation(),
        target_authority_identity=AUTHORITY,
        started_at=START,
        completed_at=END,
    )
    assert transport.calls == [("/version", ())]
    assert result.failed is False


def test_the_patch_version_reaches_the_observation():
    """9.1.1 must not become 9.1 anywhere along the path."""
    result = run_version_discovery(
        transport=_BoundedFakeTransport(),
        operation=GetVersionOperation(),
        target_authority_identity=AUTHORITY,
        started_at=START,
        completed_at=END,
    )
    obs = result.observations
    assert obs["pve_version_full"].value == "9.1.1"
    assert obs["pve_version_major"].value == 9
    assert obs["pve_version_minor"].value == 1
    assert obs["pve_version_patch"].value == 1
    assert obs["pve_release"].value == "9.1"
    assert obs["pve_repoid"].value == "abc1234567"
    assert all(o.is_usable for o in obs.values())


def test_a_two_part_version_is_malformed_not_defaulted():
    """A default patch would be a fact nobody observed, in the one field where an invented value
    silently changes provider compatibility."""
    transport = _BoundedFakeTransport(payload={"version": "9.1", "release": "9.1", "repoid": "x"})
    result = run_version_discovery(
        transport=transport,
        operation=GetVersionOperation(),
        target_authority_identity=AUTHORITY,
        started_at=START,
        completed_at=END,
    )
    patch = result.observations["pve_version_patch"]
    assert patch.state is S.observed_malformed
    assert patch.value is None


@pytest.mark.parametrize(
    "payload", [{"version": 91}, {}, {"release": "9.1"}, [1, 2, 3], "not-an-object"]
)
def test_a_malformed_response_never_becomes_an_empty_version(payload):
    result = run_version_discovery(
        transport=_BoundedFakeTransport(payload=payload),
        operation=GetVersionOperation(),
        target_authority_identity=AUTHORITY,
        started_at=START,
        completed_at=END,
    )
    for obs in result.observations.values():
        assert obs.is_usable is False
        assert obs.value is None


def test_a_transport_failure_produces_observations_not_an_exception():
    """ "The probe failed" and "the fact is absent" are different facts, and an exception collapses
    them."""

    class _Denied(Exception):
        pass

    transport = _BoundedFakeTransport(raises=_Denied("proxmox_discovery_permission_denied"))
    result = run_version_discovery(
        transport=transport,
        operation=GetVersionOperation(),
        target_authority_identity=AUTHORITY,
        started_at=START,
        completed_at=END,
    )
    assert result.failed is True
    assert result.failure_reason == "proxmox_discovery_permission_denied"
    for obs in result.observations.values():
        # A 403 is a DENIAL naming the privilege to grant, not an anonymous probe failure. It used
        # to arrive here as probe_failed, which is what made unobserved_privileges() empty.
        assert obs.state is S.permission_denied
        # /version is declared to need no privilege, so a 403 on it means SECP's model of the
        # endpoint is wrong. "unknown_privilege" says exactly that rather than naming one we have
        # no basis for — and Observation refuses a denial with no named privilege at all.
        assert obs.missing_privilege == "unknown_privilege"
        assert obs.value is None
    # The failure is still recorded as an operation — a run that refused is evidence too.
    assert result.manifest.operations[0].response_status_classification == "refused"


# --- the evidence is HTTPS-shaped ----------------------------------------------------------------


def test_the_operation_evidence_carries_https_fields_and_no_argv():
    result = run_version_discovery(
        transport=_BoundedFakeTransport(),
        operation=GetVersionOperation(),
        target_authority_identity=AUTHORITY,
        started_at=START,
        completed_at=END,
    )
    (evidence,) = result.manifest.operations
    assert evidence.transport_kind is TransportKind.proxmox_https_api
    assert evidence.request_method == "GET"
    assert evidence.canonical_rendered_path == "/version"
    assert evidence.canonical_path_template == "/version"
    assert evidence.request_body_present is False
    assert evidence.rendered_argv == ()
    assert evidence.response_digest.startswith("sha256:")
    assert evidence.parser_implementation_id
    assert "pve_version_patch" in evidence.observation_field_codes
    assert "rendered_argv" not in evidence.canonical()


def test_a_fabricated_argv_on_an_https_record_is_refused():
    """The exact shortcut this contract exists to prevent: signing a command that never ran."""
    with pytest.raises(OperationEvidenceError, match="not a command"):
        DiscoveryOperationEvidence(
            operation_code="api_version",
            transport_kind=TransportKind.proxmox_https_api,
            request_method="GET",
            canonical_rendered_path="/version",
            rendered_argv=("GET", "/api2/json/version"),
        )


@pytest.mark.parametrize(
    "path", ["/version?token=abc", "/version/PVEAPIToken=x", "/nodes/Authorization"]
)
def test_credential_shaped_material_cannot_enter_signed_evidence(path):
    with pytest.raises(OperationEvidenceError, match="credential-shaped"):
        DiscoveryOperationEvidence(
            operation_code="api_version",
            transport_kind=TransportKind.proxmox_https_api,
            request_method="GET",
            canonical_rendered_path=path,
        )


def test_a_non_get_https_operation_is_refused():
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        with pytest.raises(OperationEvidenceError, match="only GET"):
            DiscoveryOperationEvidence(
                operation_code="x",
                transport_kind=TransportKind.proxmox_https_api,
                request_method=method,
                canonical_rendered_path="/version",
            )


# --- the transport set is derived ----------------------------------------------------------------


def test_the_production_transport_set_is_https_only():
    result = run_version_discovery(
        transport=_BoundedFakeTransport(),
        operation=GetVersionOperation(),
        target_authority_identity=AUTHORITY,
        started_at=START,
        completed_at=END,
    )
    assert active_transport_set(result.manifest) == FIRST_MVP_TRANSPORTS
    assert first_mvp_manifest_refusals(result.manifest) == ()
    assert PRODUCTION_TRANSPORT_KIND is TransportKind.proxmox_https_api


def test_an_empty_manifest_fails():
    """Not a clean run.

    A run that recorded nothing is indistinguishable from one that executed nothing.
    """
    assert "discovery_manifest_empty" in first_mvp_manifest_refusals(DiscoveryOperationManifest())


def test_a_manifest_containing_a_legacy_host_command_fails():
    legacy = DiscoveryOperationEvidence(
        operation_code="version",
        transport_kind=TransportKind.legacy_host_command,
        rendered_argv=("pvesh", "get", "/version"),
    )
    manifest = DiscoveryOperationManifest(operations=(legacy,))
    reasons = first_mvp_manifest_refusals(manifest)
    assert "discovery_manifest_contains_legacy_host_command" in reasons


def test_a_mixed_manifest_fails():
    """ "Some of this came over HTTPS" is not a property anyone can act on."""
    https = DiscoveryOperationEvidence(
        operation_code="api_version",
        transport_kind=TransportKind.proxmox_https_api,
        request_method="GET",
        canonical_rendered_path="/version",
    )
    legacy = DiscoveryOperationEvidence(
        operation_code="version",
        transport_kind=TransportKind.legacy_host_command,
        rendered_argv=("pvesh", "get", "/version"),
    )
    reasons = first_mvp_manifest_refusals(DiscoveryOperationManifest(operations=(https, legacy)))
    assert "discovery_manifest_contains_legacy_host_command" in reasons
    assert any(r.startswith("discovery_manifest_transport_set_not_https_only") for r in reasons)


# --- the legacy path is unreachable --------------------------------------------------------------


def _imports_of(module_path: pathlib.Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(module_path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names.add(module)
            names.update(f"{module}.{a.name}" for a in node.names)
            names.update(a.name for a in node.names)
    return names


_WORKER = pathlib.Path(__file__).resolve().parents[3] / "apps" / "worker" / "secp_worker"
_COMPOSITION = _WORKER / "proxmox_discovery_composition.py"
_OPERATIONS = _WORKER / "proxmox_discovery_operations.py"


@pytest.mark.parametrize("module", [_COMPOSITION, _OPERATIONS])
def test_the_production_composition_cannot_reach_the_legacy_ssh_path(module):
    """Structural, over the import graph — not a text scan.

    The composition's own docstring names the legacy path in order to explain that it is absent, so
    a substring guard would trip on the very comment documenting the property.
    """
    imported = _imports_of(module)
    for banned in (
        "subprocess",
        "secp_worker.ssh_channel",
        "secp_worker.target_discovery.probe_executor",
        "secp_worker.target_discovery.seams",
        "secp_plugin_proxmox.live_collector",
    ):
        assert banned not in imported, banned
    assert not any("ssh" in name.lower() for name in imported), sorted(imported)


def test_the_composition_has_no_fallback_branch():
    """An HTTPS failure must stop, not retry over SSH.

    A fallback would mean the safest configuration silently becomes the least safe one at exactly
    the moment something is already wrong.
    """
    source = _COMPOSITION.read_text(encoding="utf-8")
    tree = ast.parse(source)
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    for banned in ("ReadOnlyProbeExecutor", "LiveReadOnlyProxmoxCollector", "build_ssh_argv"):
        assert banned not in called


def test_the_composition_reads_no_credential_from_the_environment():
    imported = _imports_of(_COMPOSITION)
    assert "os" not in imported
    assert "os.environ" not in imported
    assert "secp_worker.secrets" not in imported


def test_the_composition_exposes_no_generic_get_to_orchestration():
    """Orchestration selects an operation TYPE. There is nowhere to put a path."""
    import inspect

    from secp_worker.proxmox_discovery_composition import run_version_discovery as run

    params = set(inspect.signature(run).parameters)
    assert "path" not in params
    assert "url" not in params
    assert "method" not in params
    assert params == {
        "transport",
        "operation",
        "target_authority_identity",
        "started_at",
        "completed_at",
    }


def test_the_operation_type_admits_no_caller_input():
    op = GetVersionOperation()
    assert op.rendered_path() == "/version"
    assert op.query_parameters() == ()
    import dataclasses

    assert dataclasses.fields(GetVersionOperation) == ()


# --- observation states survive to the manifest --------------------------------------------------


def test_every_observation_field_code_is_bound_into_the_evidence():
    """A fact must be traceable to the request that supplied it without re-deriving the mapping."""
    result = run_version_discovery(
        transport=_BoundedFakeTransport(),
        operation=GetVersionOperation(),
        target_authority_identity=AUTHORITY,
        started_at=START,
        completed_at=END,
    )
    (evidence,) = result.manifest.operations
    assert set(evidence.observation_field_codes) == set(result.observations)


def test_the_authority_identity_is_bound_but_no_url_is():
    result = run_version_discovery(
        transport=_BoundedFakeTransport(),
        operation=GetVersionOperation(),
        target_authority_identity=AUTHORITY,
        started_at=START,
        completed_at=END,
    )
    canonical = result.manifest.canonical()[0]
    assert canonical["target_authority_identity"] == AUTHORITY
    assert "https://" not in str(canonical)


def test_an_observation_carries_no_value_when_unusable():
    """Re-asserted here rather than assumed from #137: the production path must not reintroduce a
    null that reads as the fact."""
    obs = Observation.probe_failed("proxmox_discovery_transport_failed")
    assert "value" not in obs.projected()
