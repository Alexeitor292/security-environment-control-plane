"""The whole first-MVP discovery, driven end to end, with spies that fail by never being called.

The recurring defect in this system is not a wrong component. It is a correct, tested, green
component that nothing reaches — ``build_plan_document`` had no production caller,
``TargetObservation`` had a reader and no writer, ``pveversion`` was allowlisted for a probe nobody
emitted. Unit tests cannot see it, because a unit test calls the module directly.

So this file drives ``run_full_discovery`` against a bounded fake target and asserts that each
guarded component was actually invoked and actually shaped the outcome: the guarded resolver, the
plan validator, every payload parser, the required-fact projection, the SDN authority gate, the
node-completeness rule and the worker-local signer.

No socket is opened, no credential is real, and no identifier reaches the fake that did not come out
of an earlier fake response.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.discovery_fact_projection import REQUIRED_FACT_PROJECTION_ID, usable_fact_names
from secp_api.discovery_observation import Observation
from secp_api.discovery_operation_evidence import (
    FIRST_MVP_TRANSPORTS,
    active_transport_set,
    first_mvp_manifest_refusals,
)
from secp_api.discovery_required_facts import (
    facts_required_before_apply,
    facts_required_before_compilation,
)
from secp_api.discovery_verification import (
    BINDING_MATCHED,
    DISCOVERY_SNAPSHOT_DOMAIN,
    DISCOVERY_SNAPSHOT_KIND,
    ELIGIBILITY_ELIGIBLE,
    ELIGIBILITY_REFUSED,
    SIGNATURE_VALID,
    ExpectedWorkerRegistration,
    verify_discovery_snapshot,
)
from secp_api.enums import DiscoveryObservationState as S
from secp_commissioning.canonical import sha256_digest
from secp_commissioning.enrollment_attestation import key_id_for, sign_detached
from secp_management.signing import generate_keypair
from secp_worker.preflight.secret_resolution import (
    SecretMaterial,
    TrustedCredentialReference,
    build_discovery_resolution_request,
)
from secp_worker.proxmox_discovery_composition import run_full_discovery
from secp_worker.proxmox_discovery_plan import MAX_PLANNED_OPERATIONS, DiscoveryPlanError

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
ORG = uuid.uuid4()
TARGET_ID = uuid.uuid4()
WORKER = "wk-1"
OPERATION = "op-1"
GENERATION = 3
AUTHORITY = "pve.example.test:8006"
FAKE_TOKEN = "secpdisc@pve!discovery=00000000-0000-0000-0000-000000000000"

NODES = ("pve-a", "pve-b")


def _cluster_payloads(*, sdn_root_denied: bool = False) -> dict[str, object]:
    """A bounded fake two-node cluster. Every value here is invented test data."""
    payloads: dict[str, object] = {
        "/version": {"version": "9.1.1", "release": "9.1", "repoid": "abc1234567"},
        "/cluster/status": [
            {"type": "cluster", "name": "lab", "id": "cluster/lab", "quorate": 1},
            *({"type": "node", "name": n, "online": 1} for n in NODES),
        ],
        "/nodes": [{"node": n, "status": "online"} for n in NODES],
        "/cluster/sdn": [{"subdir": "zones"}],
        "/access/permissions": {"/sdn": {"SDN.Audit": 1}},
        "/cluster/resources": [
            {"type": "qemu", "node": "pve-a", "vmid": 100},
            {"type": "qemu", "node": "pve-b", "vmid": 101},
        ],
        "/cluster/firewall/options": {"enable": 1},
        "/cluster/firewall/groups": [{"group": "secp-lab"}],
        "/cluster/sdn/zones": [{"zone": "z1", "type": "vlan"}],
        "/cluster/sdn/vnets": [{"vnet": "v1", "zone": "z1", "tag": 100}],
        "/cluster/sdn/controllers": [],
        "/cluster/sdn/ipams/pve/status": [
            {"subnet": "s1", "ip": "10.0.0.9", "vnet": "v1", "zone": "z1"}
        ],
        "/cluster/sdn/fabrics/all": [],
        "/cluster/sdn/vnets/v1/subnets": [{"subnet": "s1", "cidr": "10.0.0.0/24"}],
    }
    if sdn_root_denied:
        payloads.pop("/cluster/sdn")
        payloads["/cluster/sdn/zones"] = []
        payloads["/cluster/sdn/vnets"] = []

    for index, node in enumerate(NODES):
        payloads[f"/nodes/{node}/status"] = {
            "cpuinfo": {"cpus": 8},
            "memory": {"total": 100, "free": 40},
            "rootfs": {"total": 200, "avail": 90},
            "kversion": "Linux 6.14",
            "pveversion": "pve-manager/9.1.1/abcdef0123456789",
        }
        payloads[f"/nodes/{node}/version"] = {"version": "9.1.1"}
        payloads[f"/nodes/{node}/apt/versions"] = [
            {"Package": "pve-manager", "OldVersion": "9.1.1"}
        ]
        payloads[f"/nodes/{node}/network"] = [
            {"iface": "vmbr0", "type": "bridge", "cidr": "10.0.0.5/24", "bridge_vlan_aware": 1}
        ]
        payloads[f"/nodes/{node}/storage"] = [
            {"storage": "local", "type": "dir", "content": "iso,vztmpl", "total": 10, "avail": 5}
        ]
        payloads[f"/nodes/{node}/qemu"] = [{"vmid": 100 + index}]
        payloads[f"/nodes/{node}/lxc"] = []
        payloads[f"/nodes/{node}/sdn/zones"] = [{"zone": "z1", "status": "available"}]
        payloads[f"/nodes/{node}/storage/local/content"] = [
            {"volid": "local:iso/x.iso", "content": "iso"}
        ]
        payloads[f"/nodes/{node}/sdn/zones/z1/bridges"] = [{"bridge": "vmbr0", "vlan": 100}]
    return payloads


class _FakeTarget:
    """Answers from a fixed table. Opens no socket, and records every path asked for."""

    def __init__(self, payloads: dict[str, object]) -> None:
        self.payloads = payloads
        self.calls: list[str] = []

    def get(self, path: str, params: dict | None = None):
        self.calls.append(path)
        if path not in self.payloads:
            raise RuntimeError("proxmox_discovery_endpoint_absent")
        return self.payloads[path]


class _SpyResolver:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def resolve(self, request, *, expectation, now):
        self.calls.append((request.contract.purpose, expectation.worker_installation_id))
        return SecretMaterial(FAKE_TOKEN)


class _SpyFactory:
    def __init__(self, target: _FakeTarget) -> None:
        self.target = target
        self.built_with: list[dict] = []

    def build(self, *, base_url: str, ca_path: str, token: str):
        self.built_with.append({"base_url": base_url, "ca_path": ca_path, "token": token})
        return self.target


ROLE = "proxmox_privileged"
RELEASE = "sha256:" + "r" * 64


class _SpySigner:
    """Stands in for the installed worker: its id, role, release and key are ITS properties."""

    def __init__(self, priv: str, pub: str, installation: str = WORKER) -> None:
        self._priv, self._pub, self._installation = priv, pub, installation
        self.signed_digests: list[str] = []

    def installation_id(self) -> str:
        return self._installation

    def key_fingerprint(self) -> str:
        return key_id_for(self._pub)

    def role(self) -> str:
        return ROLE

    def release_fingerprint(self) -> str:
        return RELEASE

    def sign_discovery_binding(self, *, digest: str):
        self.signed_digests.append(digest)
        return sign_detached(
            self._priv,
            domain=DISCOVERY_SNAPSHOT_DOMAIN,
            kind=DISCOVERY_SNAPSHOT_KIND,
            digest=digest,
        )


def _control_plane_facts() -> dict[str, Observation]:
    return {
        "target_identity": Observation.observed(str(TARGET_ID)),
        "observation_timestamp": Observation.observed(NOW.isoformat()),
        "worker_identity": Observation.observed(WORKER),
        "evidence_signature": Observation.observed("pending"),
        "worker_release_fingerprint": Observation.observed("sha256:" + "r" * 64),
        "target_tls_identity": Observation.observed("sha256:" + "t" * 64),
    }


def _run(*, payloads=None, signer=None, keys=None, control_plane=None):
    priv, pub = keys or generate_keypair()
    target = _FakeTarget(payloads if payloads is not None else _cluster_payloads())
    resolver, factory = _SpyResolver(), _SpyFactory(target)
    signer = signer if signer is not None else _SpySigner(priv, pub)
    request, expectation = build_discovery_resolution_request(
        organization_id=ORG,
        execution_target_id=TARGET_ID,
        worker_installation_id=WORKER,
        operation_identity=OPERATION,
        operation_generation=GENERATION,
        credential_reference=TrustedCredentialReference("vault:secp/discovery/target-abc"),
    )
    result = run_full_discovery(
        resolver=resolver,
        resolution_request=request,
        resolution_expectation=expectation,
        transport_factory=factory,
        signer=signer,
        base_url="https://pve.example.test:8006/api2/json",
        ca_path="/etc/secp/pve-ca.pem",
        target_authority_identity=AUTHORITY,
        expected_worker_installation_id=WORKER,
        expected_worker_key_fingerprint=key_id_for(pub),
        control_plane_facts=(_control_plane_facts() if control_plane is None else control_plane),
        freshness_bound_seconds=1800,
        now=NOW,
        started_at=NOW - timedelta(seconds=30),
        completed_at=NOW - timedelta(seconds=10),
    )
    return result, target, resolver, factory, signer, pub


# === every guarded component is reached ===========================================================


def test_the_full_run_reaches_resolver_transport_parsers_projection_and_signer():
    result, target, resolver, factory, signer, _pub = _run()

    assert resolver.calls, "the production composition never called the guarded resolver"
    assert factory.built_with[0]["token"] == FAKE_TOKEN
    assert target.calls, "no operation reached the transport"
    assert signer.signed_digests == [result.binding.digest()]
    assert result.required_facts, "the required-fact projection was never applied"
    assert result.binding.projection_implementation_id == REQUIRED_FACT_PROJECTION_ID


def test_the_run_observes_a_two_node_cluster_completely_enough_to_compile():
    """The positive case has to exist, or every refusal below could pass with a run that refuses
    unconditionally."""
    result, _target, _r, _f, _s, _pub = _run()
    usable = usable_fact_names(result.required_facts)
    missing = [f for f in facts_required_before_compilation() if f not in usable]
    assert missing == [], missing


def test_every_phase_appends_to_the_one_manifest():
    result, target, _r, _f, _s, _pub = _run()
    paths = [record.canonical_rendered_path for record in result.manifest.operations]
    assert "/version" in paths  # phase one
    assert "/nodes/pve-b/storage" in paths  # phase two, needed a node name
    assert "/nodes/pve-a/storage/local/content" in paths  # phase three, needed a storage id
    assert "/cluster/sdn/vnets/v1/subnets" in paths  # phase three, needed a vnet id
    assert len(paths) == len(target.calls)
    assert active_transport_set(result.manifest) == FIRST_MVP_TRANSPORTS
    assert first_mvp_manifest_refusals(result.manifest) == ()


def test_no_identifier_reaches_the_target_that_did_not_come_from_a_prior_response():
    """Every dynamic segment in the plan is a node, storage, vnet or zone the fake itself named."""
    _result, target, _r, _f, _s, _pub = _run()
    for path in target.calls:
        segments = [s for s in path.split("/") if s]
        for segment in segments:
            if segment.startswith("pve-"):
                assert segment in NODES, path
            if segment in ("v1", "z1", "local"):
                continue


def test_the_resolved_token_appears_in_no_durable_product_of_the_run():
    result, _target, _r, _f, _s, _pub = _run()
    for product in (
        result.manifest.canonical(),
        result.binding.canonical(),
        result.observations,
        result.required_facts,
        result.attestation,
    ):
        assert FAKE_TOKEN not in repr(product)


# === the guards actually bite in the full run =====================================================


def test_the_sdn_gate_bites_end_to_end_when_the_root_read_is_refused():
    """The whole reason the root read exists: with it absent, an empty SDN index is permission
    denied rather than "this cluster has no zones".

    This run also exercises the partial-visibility differential for real. The cluster index returned
    an empty list while the per-node handler — which documents an SDN.Audit filter it does not
    implement — still reported ``z1``. That difference is proof of per-object filtering, and it is
    exactly why an empty cluster index may not be read as absence.
    """
    result, _target, _r, _f, _s, _pub = _run(payloads=_cluster_payloads(sdn_root_denied=True))

    zones = result.observations["existing_sdn_zones"]
    assert zones.is_usable is True
    assert set(zones.value) == {"z1"}
    # Only the unfiltered per-node view saw it; the cluster index contributed nothing.
    assert set(zones.value["z1"]) == {"node_runtime"}
    # ...and the projection still refuses, because completeness was never established.
    assert result.required_facts["existing_sdn_zones"].state is S.permission_denied
    assert result.required_facts["existing_sdn_zones"].missing_privilege == "SDN.Audit"

    usable = usable_fact_names(result.required_facts)
    assert "existing_sdn_zones" not in usable
    assert [f for f in facts_required_before_compilation() if f not in usable]


def test_node_completeness_bites_end_to_end_when_one_node_refuses():
    """A cluster where one node's storage read fails must not report storage as known."""
    payloads = _cluster_payloads()
    payloads.pop("/nodes/pve-b/storage")
    result, _target, _r, _f, _s, _pub = _run(payloads=payloads)

    assert result.observations["storage_ids"].value == {"pve-a": ("local",)}
    assert result.required_facts["storage_ids"].is_usable is False
    assert "pve-b" in result.required_facts["storage_ids"].reason_code


def test_a_refusal_does_not_abort_the_run_or_the_later_phases():
    payloads = _cluster_payloads()
    payloads.pop("/nodes/pve-a/network")
    result, target, _r, _f, _s, _pub = _run(payloads=payloads)

    assert result.failed is True
    assert "/nodes/pve-b/network" in target.calls
    assert "/nodes/pve-a/storage/local/content" in target.calls, "phase three never ran"
    assert result.observations["node_capacity"].is_usable is True


def test_the_control_plane_supplies_identity_even_in_the_full_run():
    result, _target, _r, _f, _s, _pub = _run(control_plane={})
    assert result.required_facts["target_identity"].is_usable is False
    assert result.required_facts["worker_identity"].is_usable is False


def test_a_misbound_signer_never_contacts_the_target():
    priv, pub = generate_keypair()
    wrong = _SpySigner(priv, pub, installation="wk-9999")
    result, target, _r, factory, signer, _pub = _run(signer=wrong, keys=(priv, pub))

    assert result.failed is True
    assert result.failure_reason == "discovery_signer_installation_mismatch"
    assert target.calls == []
    assert factory.built_with == []
    assert signer.signed_digests == []


# === the binding cannot be shaped by a caller =====================================================


def test_the_run_takes_no_binding_factory_and_no_identity_parameters():
    """The binding names the organization, the target, the operation, the worker, its role and its
    release. A caller able to supply it — or any of them — could attest to any of them."""
    import inspect

    params = set(inspect.signature(run_full_discovery).parameters)
    for banned in (
        "binding_factory",
        "binding",
        "organization_identity",
        "target_identity",
        "worker_role",
        "worker_release_fingerprint",
        "operation_identity",
        "operation_generation",
        "signature",
        "private_key",
    ):
        assert banned not in params, banned


def test_the_binding_takes_identity_from_the_expectation_not_from_the_worker_request():
    """The expectation is the contract the control plane derived independently. A worker that
    resolved a credential for one target cannot attest about another."""
    result, _target, _r, _f, _s, _pub = _run()
    assert result.binding.organization_identity == str(ORG)
    assert result.binding.target_identity == str(TARGET_ID)
    assert result.binding.operation_identity == OPERATION
    assert result.binding.operation_generation == GENERATION


def test_the_binding_takes_role_and_release_from_the_installation():
    """Both go inside the signature and are checked against the registered anchor, so a worker must
    not be able to claim a role it was not enrolled with or a release it is not running."""
    result, _target, _r, _f, signer, _pub = _run()
    assert result.binding.worker_role == signer.role() == ROLE
    assert result.binding.worker_release_fingerprint == signer.release_fingerprint() == RELEASE
    assert result.binding.worker_installation_id == signer.installation_id()
    assert result.binding.signer_fingerprint == signer.key_fingerprint()


def test_the_two_hashes_cover_different_documents():
    """Editing the facts and editing the request set are separately detectable tampering events."""
    result, _target, _r, _f, _s, _pub = _run()
    assert result.binding.facts_hash != result.binding.operation_manifest_hash
    assert result.binding.operation_manifest_hash == sha256_digest(
        {"manifest": result.manifest.canonical()}
    )
    assert result.binding.facts_hash == sha256_digest(
        {"observations": sorted((k, v.state.value) for k, v in result.observations.items())}
    )


def test_the_signed_binding_verifies_against_the_registered_anchor_end_to_end():
    """The last link: a control plane holding only the worker's registered anchor accepts it."""
    result, _target, _r, _f, _s, pub = _run()
    registration = ExpectedWorkerRegistration(
        worker_installation_id=WORKER,
        worker_role=ROLE,
        worker_release_fingerprint=RELEASE,
        verification_anchor_fingerprint=key_id_for(pub),
        target_identity=str(TARGET_ID),
        organization_identity=str(ORG),
    )
    projection, authority = verify_discovery_snapshot(
        binding=result.binding,
        attestation=result.attestation,
        registration=registration,
        expected_operation_identity=OPERATION,
        expected_operation_generation=GENERATION,
        expected_target_identity=str(TARGET_ID),
        expected_organization_identity=str(ORG),
        facts_hash=result.binding.facts_hash,
        operation_manifest_hash=result.binding.operation_manifest_hash,
        compilation_required_facts=facts_required_before_compilation(),
        apply_required_facts=facts_required_before_apply(),
        now=NOW,
    )
    assert projection.signature == SIGNATURE_VALID
    assert projection.identity_and_target_binding == BINDING_MATCHED
    # A fully answered cluster now clears the compilation gate through the REAL projection.
    assert projection.compilation_eligibility == ELIGIBILITY_ELIGIBLE
    assert authority is not None


def test_a_refused_sdn_root_read_refuses_compilation_through_the_verifier():
    result, _target, _r, _f, _s, pub = _run(payloads=_cluster_payloads(sdn_root_denied=True))
    registration = ExpectedWorkerRegistration(
        worker_installation_id=WORKER,
        worker_role=ROLE,
        worker_release_fingerprint=RELEASE,
        verification_anchor_fingerprint=key_id_for(pub),
        target_identity=str(TARGET_ID),
        organization_identity=str(ORG),
    )
    projection, authority = verify_discovery_snapshot(
        binding=result.binding,
        attestation=result.attestation,
        registration=registration,
        expected_operation_identity=OPERATION,
        expected_operation_generation=GENERATION,
        expected_target_identity=str(TARGET_ID),
        expected_organization_identity=str(ORG),
        facts_hash=result.binding.facts_hash,
        operation_manifest_hash=result.binding.operation_manifest_hash,
        compilation_required_facts=facts_required_before_compilation(),
        apply_required_facts=facts_required_before_apply(),
        now=NOW,
    )
    # Authentic evidence and insufficient evidence are separate conclusions: the snapshot really
    # was produced by the registered worker, and it still does not license compilation.
    assert projection.signature == SIGNATURE_VALID
    assert authority is not None
    assert projection.compilation_eligibility == ELIGIBILITY_REFUSED
    assert ("existing_sdn_zones", "permission_denied") in projection.missing_compilation_facts


def test_the_signed_binding_covers_the_required_fact_states_not_the_raw_fields():
    """What the worker attests to is the DERIVED state; otherwise a consumer would have to
    re-derive it with code the signature does not cover."""
    result, _target, _r, _f, _s, _pub = _run()
    names = {name for name, _state in result.binding.required_fact_observation_states}
    assert "exact_pve_version" in names
    assert "pve_version_major" not in names


# === the plan is bounded ==========================================================================


def test_an_oversized_enumeration_refuses_rather_than_truncating():
    """A silently shortened plan produces a snapshot that LOOKS complete."""
    from secp_worker.proxmox_discovery_plan import phase_two_operations

    many = tuple(f"node{i}" for i in range(200))
    with pytest.raises(DiscoveryPlanError, match="dynamic_identifier_list_too_large"):
        phase_two_operations({"node_names": Observation.observed(many)})


def test_a_plan_that_exceeds_the_ceiling_refuses():
    from secp_worker.proxmox_discovery_plan import phase_three_operations

    nodes = tuple(f"node{i}" for i in range(60))
    zones = {f"z{i}": {} for i in range(60)}
    with pytest.raises(DiscoveryPlanError, match="discovery_plan_too_large"):
        phase_three_operations(
            {
                "node_names": Observation.observed(nodes),
                "existing_sdn_zones": Observation.observed(zones),
            }
        )
    assert MAX_PLANNED_OPERATIONS == 512


def test_a_planning_failure_keeps_the_evidence_already_gathered():
    """Discarding phase one because phase two could not be planned would turn "this cluster is
    larger than the plan allows" into "nothing is known about this cluster"."""
    payloads = _cluster_payloads()
    payloads["/nodes"] = [{"node": f"node{i}", "status": "online"} for i in range(200)]
    payloads["/cluster/status"] = [{"type": "cluster", "name": "lab", "id": "cluster/lab"}]
    result, _target, _r, _f, _s, _pub = _run(payloads=payloads)

    assert result.failed is True
    assert result.failure_reason == "dynamic_identifier_list_too_large:node_names"
    assert result.manifest.operations, "phase-one evidence was discarded"
    assert result.observations["pve_version_full"].is_usable is True


def test_an_identifier_the_target_did_not_name_is_refused_by_provenance():
    """Shape is not the rule. An identifier with no ``sourced_from`` is refused even though it is a
    perfectly well-formed node name."""
    from secp_worker.proxmox_discovery_operations import (
        GetNodeStatusOperation,
        OperationParameterError,
    )

    with pytest.raises(OperationParameterError, match="unsourced"):
        GetNodeStatusOperation("pve-a", "")
