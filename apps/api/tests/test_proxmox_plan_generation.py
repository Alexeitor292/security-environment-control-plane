"""Tests for the reviewed Proxmox module bundle, plan generation, and the plan document.

The load-bearing tests here are the ones that would catch a regression nobody would otherwise
notice: byte-identical rendering across runs and across a manifest round-trip, the legacy fixture
path staying exactly as it was, and secrets being absent from the rendered workspace by inspection
rather than by intent.

The ``show -json`` fixture is written here rather than imported from a real-path module. It stands
in for what OpenTofu would report, so deriving it from the renderer's internals would make the
canonicalization test circular.
"""

from __future__ import annotations

import ipaddress

import pytest
from secp_api.range_enums import RangeResourceKind
from secp_api.range_providers.proxmox_manifest import (
    MANIFEST_KEY,
    attach_to_manifest,
    from_manifest_payload,
    to_manifest_payload,
    with_operation_generation,
)
from secp_api.range_providers.proxmox_model import (
    CloneStrategy,
    CloudInitSpec,
    CompiledTopology,
    DiskSpec,
    GuestAddress,
    GuestKind,
    GuestSpec,
    NicSpec,
    Ownership,
    SegmentRole,
)
from secp_api.range_providers.proxmox_network import compile_web_breach_lab
from secp_worker.provisioning.adapters.base import AdapterError, get_adapter
from secp_worker.provisioning.adapters.proxmox_bundle import (
    BUNDLE_ID,
    PROVIDER_ADDRESS,
    PROVIDER_SOURCE,
    PROVIDER_VERSION,
    RESOURCE_TYPES,
    render_bundle,
)
from secp_worker.provisioning.plan_document import (
    EXECUTION_STATUS_NOT_APPLIED,
    PlanDocumentError,
    build_plan_document,
    render_plan_document_text,
)
from secp_worker.provisioning.plan_json import canonicalize_plan_json, change_set_hash
from tests.test_proxmox_desired_state import (  # reuse the P2 fixtures verbatim
    make_identity,
    make_observation,
    make_request,
)

PROFILE = {
    "runner_kind": "opentofu",
    "executable": "tofu",
    "opentofu_version": "9.9.9",
    "binary_integrity": "sha256:" + "de" * 32,
    "adapter_kind": "proxmox",
    "module_bundle_id": BUNDLE_ID,
    "module_bundle_hash": "sha256:" + "ab" * 32,
    # Taken from the bundle's own constants: this file renders the REAL reviewed bundle, and
    # `render_bundle` refuses a profile whose provider pins are not its own. Repeating the literals
    # here would make a re-pin of the provider fail as a fixture mismatch rather than pass.
    "provider_source": PROVIDER_ADDRESS,
    "provider_version": PROVIDER_VERSION,
    "provider_checksum": "h1:" + "A" * 43 + "=",
    "provider_lockfile_hash": "sha256:" + "cd" * 32,
    "renderer_version": "secp-002b-1a/renderer/v1",
    "state_backend": {"kind": "http", "reference": "secp-fake-remote-state/lab"},
    "provider_mirror": {
        "identity": "secp-fake-offline-mirror",
        "network_access": "offline",
        "allow_runtime_download": False,
    },
    "activation_class": "isolated_lab",
}


def build_topology(include_lxc: bool = False, cloud_init: bool = True) -> CompiledTopology:
    """Compile the two-team lab from P2, then attach guests to its segments."""
    result = compile_web_breach_lab(make_request(), make_observation())
    assert not hasattr(result, "reason_ids"), getattr(result, "describe", lambda: "")()
    plan, _ledger = result

    def own(team: str | None, kind: RangeResourceKind) -> Ownership:
        return Ownership(
            organization_id="org1",
            target_id="tgt-lab-01",
            range_id="wbl001",
            generation=1,
            operation_generation=1,
            resource_kind=kind,
            team_ref=team,
        )

    guests: list[GuestSpec] = []
    for index, vnet in enumerate(
        sorted(
            (v for v in plan.vnets if v.role != SegmentRole.scoring),
            key=lambda v: v.name,
        )
    ):
        team = vnet.ownership.team_ref
        is_attacker = vnet.role == SegmentRole.attacker
        # Address inside the segment's own subnet, so cloud-init renders a coherent prefix.
        host = str(list(ipaddress.ip_network(vnet.subnet.cidr).hosts())[9])
        guests.append(
            GuestSpec(
                guest_ref=f"{team}-{vnet.role.value}",
                name=f"{team}-{vnet.role.value}",
                kind=GuestKind.qemu,
                vmid=9100 + index,
                node_name="pve1",
                template_ref="ubuntu-2404" if is_attacker else "dvwa",
                clone_strategy=CloneStrategy.full,
                cpu_cores=2,
                memory_mb=2048,
                disks=(DiskSpec(slot="scsi0", size_gb=20, storage_id="local-lvm"),),
                nics=(
                    NicSpec(
                        index=0,
                        vnet_name=vnet.name,
                        mac_address=f"02:53:45:00:00:{index:02X}",
                    ),
                ),
                address=GuestAddress(published_address=host),
                ownership=own(team, RangeResourceKind.virtual_machine),
                cloud_init=(
                    CloudInitSpec(user="secp", ssh_authorized_keys=("ssh-ed25519 AAAAC3Nza test",))
                    if cloud_init
                    else None
                ),
            )
        )

    if include_lxc:
        sensor_vnet = sorted(plan.vnets, key=lambda v: v.name)[0]
        guests.append(
            GuestSpec(
                guest_ref="shared-collector",
                name="shared-collector",
                kind=GuestKind.lxc,
                vmid=9200,
                node_name="pve2",
                template_ref="debian-12",
                clone_strategy=CloneStrategy.full,
                cpu_cores=1,
                memory_mb=512,
                disks=(DiskSpec(slot="rootfs", size_gb=8, storage_id="local-lvm"),),
                nics=(
                    NicSpec(index=0, vnet_name=sensor_vnet.name, mac_address="02:53:45:00:00:FF"),
                ),
                address=GuestAddress(
                    published_address=str(
                        list(ipaddress.ip_network(sensor_vnet.subnet.cidr).hosts())[19]
                    )
                ),
                ownership=own(sensor_vnet.ownership.team_ref, RangeResourceKind.lxc_container),
            )
        )

    return CompiledTopology(
        target=make_identity(),
        ownership=own(None, RangeResourceKind.network),
        network=plan,
        guests=tuple(guests),
    )


def payload_of(**kwargs) -> dict:
    return to_manifest_payload(build_topology(**kwargs))


def render(**kwargs) -> dict[str, str]:
    return render_bundle(payload_of(**kwargs), PROFILE)


# ======================================================================================
# The module bundle
# ======================================================================================


def test_bundle_renders_every_declared_area():
    files = render()
    assert set(files) == {
        "versions.tf",
        "variables.tf",
        "provider.tf",
        "network_foundation.tf",
        "network_range.tf",
        "network_segments.tf",
        "firewall.tf",
        "guests_qemu.tf",
        "outputs.tf",
    }


def test_lxc_file_appears_only_when_an_lxc_guest_exists():
    assert "guests_lxc.tf" not in render()
    assert "guests_lxc.tf" in render(include_lxc=True)
    # QEMU is the required kind and its file is always present, even alongside LXC.
    assert "guests_qemu.tf" in render(include_lxc=True)


def test_bundle_pins_its_provider_to_an_exact_version():
    versions = render()["versions.tf"]
    assert f'source  = "{PROVIDER_SOURCE}"' in versions
    assert f'version = "= {PROVIDER_VERSION}"' in versions
    assert 'required_version = "= 9.9.9"' in versions
    # Nothing floating.
    for token in ("latest", ">=", "~>", "^"):
        assert token not in versions


def test_bundle_refuses_a_profile_pinned_to_a_different_bundle():
    other = dict(PROFILE, module_bundle_id="some-other-bundle")
    with pytest.raises(AdapterError, match="module bundle"):
        render_bundle(payload_of(), other)


def test_zone_and_vnets_and_subnets_are_rendered():
    files = render()
    assert RESOURCE_TYPES["sdn_zone"] in files["network_foundation.tf"]
    assert files["network_range.tf"].count(f'resource "{RESOURCE_TYPES["sdn_vnet"]}"') == 5
    assert files["network_range.tf"].count(f'resource "{RESOURCE_TYPES["sdn_subnet"]}"') == 5


def test_unrouted_segments_render_snat_false():
    """A NAT'd segment has a path off-net, which is what default-deny exists to prevent."""
    network_range = render()["network_range.tf"]
    assert "snat = false" in network_range
    assert "snat = true" not in network_range


def test_nic_does_not_re_tag_the_vlan_the_vnet_already_carries():
    """Tagging at both the VNet and the device double-tags the frame and breaks the segment."""
    guests = render()["guests_qemu.tf"]
    assert "network_device" in guests
    assert "vlan_id" not in guests


def test_cloud_init_writes_no_gateway_on_an_unrouted_segment():
    guests = render()["guests_qemu.tf"]
    assert "ip_config" in guests
    assert "gateway" not in guests


def test_cloud_init_refuses_private_key_material():
    topology = build_topology()
    poisoned = topology.guests[0]
    payload = to_manifest_payload(topology)
    payload["guests"][0]["cloud_init"]["ssh_authorized_keys"] = [
        "-----BEGIN OPENSSH PRIVATE KEY-----"
    ]
    assert poisoned.cloud_init is not None
    with pytest.raises(AdapterError, match="private key"):
        render_bundle(payload, PROFILE)


def test_a_guest_attached_to_an_unknown_segment_is_refused():
    payload = payload_of()
    payload["guests"][0]["nics"][0]["vnet_name"] = "ghost"
    with pytest.raises(AdapterError, match="unknown segment"):
        render_bundle(payload, PROFILE)


def test_every_generated_object_carries_the_ownership_stamp():
    files = render()
    for name in ("network_foundation.tf", "network_range.tf", "firewall.tf", "guests_qemu.tf"):
        assert "secp.range=wbl001" in files[name], name
        assert "secp.org=org1" in files[name], name


def test_firewall_rules_render_in_compiled_order():
    """The compiled order is the order the isolation verifier evaluated; it must survive."""
    firewall = render()["firewall.tf"]
    block = next(
        chunk
        for chunk in firewall.split('\nresource "')
        if "secp-sg-t1atk" in chunk and "rule {" in chunk
    )
    mgmt = block.index("Deny all traffic to the Proxmox management plane")
    cross = block.index("Deny all traffic to team blue's segments")
    own = block.index("Allow team red to reach its own segments")
    assert mgmt < cross < own


# ======================================================================================
# Determinism
# ======================================================================================


def test_rendering_is_byte_identical_across_runs():
    assert render() == render()


def test_rendering_is_byte_identical_across_a_manifest_round_trip():
    """The plan must not change because the desired state went through JSON and back."""
    topology = build_topology()
    direct = render_bundle(to_manifest_payload(topology), PROFILE)
    round_tripped = render_bundle(
        to_manifest_payload(from_manifest_payload(to_manifest_payload(topology))), PROFILE
    )
    assert direct == round_tripped


def test_rendering_does_not_depend_on_input_collection_order():
    """A hand-edited or re-serialized manifest must render identically."""
    payload = payload_of()
    shuffled = dict(payload)
    shuffled["guests"] = list(reversed(payload["guests"]))
    shuffled["network"] = dict(payload["network"])
    shuffled["network"]["vnets"] = list(reversed(payload["network"]["vnets"]))
    shuffled["network"]["security_groups"] = list(reversed(payload["network"]["security_groups"]))
    shuffled["network"]["ip_sets"] = list(reversed(payload["network"]["ip_sets"]))
    assert render_bundle(shuffled, PROFILE) == render_bundle(payload, PROFILE)


def test_a_changed_desired_state_changes_the_rendering():
    """Determinism must not be achieved by ignoring the input."""
    base = render()
    changed_topology = build_topology()
    payload = to_manifest_payload(changed_topology)
    payload["guests"][0]["memory_mb"] = 4096
    assert render_bundle(payload, PROFILE) != base


def test_operation_generation_restamp_does_not_renumber_the_range():
    """A reset advances operation_generation only; allocations and addressing must not move."""
    topology = build_topology()
    reset = with_operation_generation(topology, 7)
    before = to_manifest_payload(topology)
    after = to_manifest_payload(reset)

    assert [v["subnet"]["cidr"] for v in before["network"]["vnets"]] == [
        v["subnet"]["cidr"] for v in after["network"]["vnets"]
    ]
    assert [g["vmid"] for g in before["guests"]] == [g["vmid"] for g in after["guests"]]
    assert after["ownership"]["operation_generation"] == 7
    assert after["guests"][0]["ownership"]["tags"]["secp.operation_generation"] == "7"


# ======================================================================================
# Secrets never enter
# ======================================================================================


def test_endpoint_and_token_appear_only_as_declared_variables():
    files = render()
    variables = files["variables.tf"]
    assert 'variable "pm_endpoint"' in variables
    assert 'variable "pm_api_token"' in variables
    assert "sensitive   = true" in variables
    # No defaults: a default would be a value, and a value would be persisted.
    assert "default" not in variables
    assert files["provider.tf"].count("var.pm_endpoint") == 1
    assert files["provider.tf"].count("var.pm_api_token") == 1


def test_no_rendered_file_embeds_a_url_or_a_literal_credential():
    """Checks configuration lines, not prose: a comment saying "secret-free" is not a secret."""
    from secp_worker.provisioning.rendering import _SECRET_LITERAL_RE

    for name, body in render(include_lxc=True).items():
        for line in body.splitlines():
            if line.strip().startswith("#"):
                continue
            assert "://" not in line, f"{name} embeds a URL: {line}"
            assert not _SECRET_LITERAL_RE.search(line), f"{name} assigns a literal secret: {line}"


def test_rendered_workspace_passes_the_existing_secret_free_guard():
    """The pre-existing renderer guard must accept this bundle unchanged."""
    from secp_worker.provisioning.rendering import _assert_secret_free

    _assert_secret_free(render(include_lxc=True))


# ======================================================================================
# The legacy fixture path is untouched
# ======================================================================================


def test_a_manifest_without_a_desired_state_renders_the_legacy_fixture_topology():
    legacy_manifest = {
        "manifest_version": 1,
        "topology": [
            {
                "team_ref": "red",
                "networks": [{"name": "net0", "cidr": "10.60.1.0/24", "bridge": "vmbr0"}],
                "nodes": [
                    {
                        "ref": "web",
                        "guest_kind": "vm",
                        "vmid": 9001,
                        "node": "pve1",
                        "image": "tmpl",
                        "storage": "local-lvm",
                        "vcpu": 2,
                        "memory_mb": 2048,
                        "disk_gb": 20,
                    }
                ],
            }
        ],
    }
    files = get_adapter("proxmox").render(legacy_manifest, dict(PROFILE, module_bundle_id="x"))
    # The inert fixture provider and fake resource types, exactly as before.
    assert "example.test/fake/labproxmox" in files["versions.tf"]
    assert "labfake_network" in files["main.tf"]
    assert "labfake_vm" in files["main.tf"]
    assert set(files) == {"versions.tf", "variables.tf", "provider.tf", "main.tf"}


def test_the_adapter_dispatches_to_the_bundle_when_a_desired_state_is_present():
    manifest = attach_to_manifest({"manifest_version": 1}, build_topology(), _ledger())
    files = get_adapter("proxmox").render(manifest, PROFILE)
    assert "labfake" not in files["versions.tf"]
    assert PROVIDER_SOURCE in files["versions.tf"]


def _ledger():
    from secp_api.range_providers.proxmox_ipam import AllocationLedger

    result = compile_web_breach_lab(make_request(), make_observation())
    return result[1] if isinstance(result, tuple) else AllocationLedger()


# ======================================================================================
# Canonical change set and the plan document
# ======================================================================================


def fixture_show_json(desired_state: dict, actions: tuple[str, ...] = ("create",)) -> dict:
    """Stand-in for ``tofu show -json``, with values that MUST NOT survive canonicalization."""
    changes = []
    for vnet in desired_state["network"]["vnets"]:
        changes.append(
            {
                "address": f"{RESOURCE_TYPES['sdn_vnet']}.{vnet['name']}",
                "mode": "managed",
                "type": RESOURCE_TYPES["sdn_vnet"],
                "name": vnet["name"],
                "provider_name": PROVIDER_SOURCE,
                "change": {
                    "actions": list(actions),
                    "before": None,
                    "after": {"api_token": "FAKE-TOKEN", "endpoint": "https://pve.example.test"},
                    "after_sensitive": {"api_token": True},
                },
            }
        )
    for guest in desired_state["guests"]:
        rtype = RESOURCE_TYPES["qemu_guest" if guest["kind"] == "qemu" else "lxc_guest"]
        changes.append(
            {
                "address": f"{rtype}.{guest['guest_ref'].replace('-', '_')}",
                "mode": "managed",
                "type": rtype,
                "name": guest["guest_ref"].replace("-", "_"),
                "provider_name": PROVIDER_SOURCE,
                "change": {
                    "actions": list(actions),
                    "before": None,
                    "after": {"root_password": "hunter2-fake"},
                    "after_sensitive": {"root_password": True},
                },
            }
        )
    return {"format_version": "1.2", "resource_changes": changes}


def canonical(desired_state: dict) -> tuple[dict, str]:
    change_set = canonicalize_plan_json(
        fixture_show_json(desired_state),
        kind="plan",
        workspace_hash="sha256:" + "11" * 32,
        provenance={"module_bundle_id": BUNDLE_ID},
    )
    return change_set, change_set_hash(change_set)


def test_canonicalization_drops_every_secret_from_the_fixture_plan():
    desired_state = payload_of()
    change_set, _ = canonical(desired_state)
    blob = repr(change_set)
    for leaked in ("FAKE-TOKEN", "hunter2-fake", "https://pve.example.test", "api_token"):
        assert leaked not in blob


def test_the_canonical_plan_hash_is_stable_for_identical_desired_state():
    """The hash is the approval anchor: identical desired state must re-derive it exactly."""
    first = canonical(payload_of())[1]
    second = canonical(payload_of())[1]
    assert first == second
    assert first.startswith("sha256:")
    assert len(first) == len("sha256:") + 64


def test_the_change_set_hash_alone_does_not_bind_resource_attributes():
    """A real limitation, pinned so nobody treats the change-set hash as the approval anchor.

    Canonicalization keeps address, type, action and replacement — deliberately, since before/after
    values are where secrets live. The consequence is that changing a guest's vmid produces an
    IDENTICAL change set and hash. Approving that hash would approve a different machine.
    """
    baseline = canonical(payload_of())[1]
    changed = payload_of()
    changed["guests"][0]["vmid"] = 9999
    assert canonical(changed)[1] == baseline


def test_the_plan_document_does_bind_resource_attributes():
    """Which is why the plan document binds the desired state as well as the change set."""
    base_state = payload_of()
    base_change_set, base_digest = canonical(base_state)
    base_document = build_plan_document(base_change_set, base_digest, desired_state=base_state)

    changed_state = payload_of()
    changed_state["guests"][0]["vmid"] = 9999
    changed_change_set, changed_digest = canonical(changed_state)
    changed_document = build_plan_document(
        changed_change_set, changed_digest, desired_state=changed_state
    )

    assert changed_document["change_set_hash"] == base_document["change_set_hash"]
    assert changed_document["desired_state_hash"] != base_document["desired_state_hash"]
    assert changed_document["plan_document_hash"] != base_document["plan_document_hash"]


def test_plan_document_states_not_applied_and_does_not_start_apply():
    desired_state = payload_of()
    change_set, digest = canonical(desired_state)
    document = build_plan_document(change_set, digest, desired_state=desired_state)

    assert document["execution_status"] == EXECUTION_STATUS_NOT_APPLIED
    assert document["execution_status"] == "NOT APPLIED"
    assert document["approval_starts_apply"] is False
    assert document["change_set_hash"] == digest
    # The document is pure data: nothing in it can be dereferenced to reach an executable.
    for forbidden in ("workdir", "plan_file", "executable", "argv", "command"):
        assert forbidden not in repr(document)


def test_plan_document_reports_provider_schema_as_unverified_by_default():
    """The bundle's resource types have not been checked against the pinned provider."""
    desired_state = payload_of()
    change_set, digest = canonical(desired_state)
    document = build_plan_document(change_set, digest, desired_state=desired_state)
    assert document["provider_schema_validation"] == "unverified"


def test_plan_document_refuses_to_carry_a_forbidden_key():
    desired_state = payload_of()
    change_set, digest = canonical(desired_state)
    change_set["provenance"]["api_token"] = "should-never-be-here"
    with pytest.raises(PlanDocumentError, match="forbidden key"):
        build_plan_document(change_set, digest, desired_state=desired_state)


def test_plan_document_summarizes_the_topology_for_review():
    desired_state = payload_of()
    change_set, digest = canonical(desired_state)
    document = build_plan_document(change_set, digest, desired_state=desired_state)

    assert document["summary"]["segment_count"] == 5
    assert document["summary"]["guest_count"] == 4
    assert document["egress"] == "none"
    roles = {segment["role"] for segment in document["segments"]}
    assert roles == {"scoring", "attacker", "vulnerable"}


def test_plan_document_text_leads_and_ends_with_the_execution_status():
    desired_state = payload_of()
    change_set, digest = canonical(desired_state)
    text = render_plan_document_text(
        build_plan_document(change_set, digest, desired_state=desired_state)
    )
    lines = text.splitlines()
    assert lines[0] == "EXECUTION STATUS: NOT APPLIED"
    assert lines[-1] == "EXECUTION STATUS: NOT APPLIED"
    assert "does not start an apply" in text


def test_plan_document_hash_changes_when_the_plan_changes():
    desired_state = payload_of()
    change_set, digest = canonical(desired_state)
    first = build_plan_document(change_set, digest, desired_state=desired_state)

    other = payload_of()
    other["guests"][0]["vmid"] = 9999
    other_change_set, other_digest = canonical(other)
    second = build_plan_document(other_change_set, other_digest, desired_state=other)

    assert first["plan_document_hash"] != second["plan_document_hash"]


# ======================================================================================
# Manifest round-trip
# ======================================================================================


def test_desired_state_round_trips_through_the_manifest():
    topology = build_topology(include_lxc=True)
    restored = from_manifest_payload(to_manifest_payload(topology))

    assert restored.target == topology.target
    assert restored.network.zone == topology.network.zone
    assert restored.network.vnets == tuple(sorted(topology.network.vnets, key=lambda v: v.name))
    assert len(restored.guests) == len(topology.guests)
    assert {g.guest_ref for g in restored.guests} == {g.guest_ref for g in topology.guests}


def test_attach_to_manifest_does_not_mutate_the_caller_manifest():
    """The caller's manifest may already be the immutable ADR-011 content."""
    original = {"manifest_version": 1}
    updated = attach_to_manifest(original, build_topology(), _ledger())
    assert MANIFEST_KEY not in original
    assert MANIFEST_KEY in updated


def test_an_unknown_desired_state_version_is_refused():
    payload = payload_of()
    payload["desired_state_version"] = 99
    with pytest.raises(Exception, match="unsupported desired_state_version"):
        from_manifest_payload(payload)
