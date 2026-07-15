"""SECP-002B-1B-PR5B — controlled-live render + render-safety scanner (ADR-022 §2/§3/§4).

These prove the controlled-live plan-only render boundary WITHOUT running any process (the plan-only
seal remains True): the renderer emits a real ``bpg/proxmox`` workspace for ONE LXC container only,
refuses every other shape, and the pure scanner refuses the fake fixture path and every dangerous
OpenTofu construct so the inert B1-A adapter can NEVER be promoted to a controlled-live plan.
"""

from __future__ import annotations

import pytest
from secp_worker.plan_gen.controlled_live import (
    CONTROLLED_LIVE_ADAPTER_KIND,
    SUPPORTED_RESOURCE_TYPES,
    ControlledLiveRenderError,
    render_controlled_live_workspace,
)
from secp_worker.plan_gen.render_scan import (
    CONTROLLED_LIVE_PROVIDER_SOURCE,
    ControlledLiveRenderRefused,
    RenderScanContract,
    controlled_live_render_scan,
)

_VERSION = "0.80.0"


_TEMPLATE = "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst"


def _manifest(**over) -> dict:
    node = {
        "ref": "c1",
        "guest_kind": "container",
        "vmid": 9001,
        "node": "pve-node-1",
        "storage": "local-lvm",
        "bridge": "vmbr9",
        "vcpu": 2,
        "memory_mb": 1024,
        "disk_gb": 8,
        "image": _TEMPLATE,
    }
    node.update(over)
    return {"topology": [{"team_ref": "t1", "nodes": [node]}]}


def _contract() -> RenderScanContract:
    return RenderScanContract(
        provider_source=CONTROLLED_LIVE_PROVIDER_SOURCE,
        provider_version=_VERSION,
        supported_resource_types=SUPPORTED_RESOURCE_TYPES,
    )


# --- the controlled-live renderer ----------------------------------------------------------------


def test_renders_a_real_bpg_proxmox_container_workspace():
    files = render_controlled_live_workspace(
        _manifest(), provider_version=_VERSION, state_backend_kind="http"
    )
    assert set(files) == {"versions.tf", "variables.tf", "provider.tf", "main.tf"}
    assert f'source  = "{CONTROLLED_LIVE_PROVIDER_SOURCE}"' in files["versions.tf"]
    assert f'version = "= {_VERSION}"' in files["versions.tf"]
    assert 'backend "http" {}' in files["versions.tf"]
    assert 'resource "proxmox_virtual_environment_container"' in files["main.tf"]
    # The OS uses an EXISTING reviewed vztmpl template reference (never a URL/download/upload).
    assert "operating_system {" in files["main.tf"]
    assert f'template_file_id = "{_TEMPLATE}"' in files["main.tf"]
    # The single container NIC uses the exact reviewed name; no network resource is created.
    assert 'name   = "veth0"' in files["main.tf"]
    # Endpoint + token are input variables only — never a literal.
    assert "var.pm_endpoint" in files["provider.tf"]
    assert "var.pm_api_token" in files["provider.tf"]
    assert "insecure  = false" in files["provider.tf"]


def test_the_workspace_has_no_fake_identifiers_or_secret_literals():
    files = render_controlled_live_workspace(
        _manifest(), provider_version=_VERSION, state_backend_kind="http"
    )
    blob = "\n".join(files.values()).lower()
    for fake in ("example.test", "labfake_", "0.0.0-fake", "fake/labproxmox"):
        assert fake not in blob
    # No secret VALUE literal (a quoted RHS on a token/password/secret key).
    assert 'token = "' not in blob
    assert 'password = "' not in blob


def test_the_adapter_kind_is_distinct_from_the_fake_adapter():
    assert CONTROLLED_LIVE_ADAPTER_KIND == "controlled_live_proxmox"
    assert CONTROLLED_LIVE_ADAPTER_KIND != "proxmox"


@pytest.mark.parametrize("kind", ["vm", "qemu", "", "container "])
def test_only_lxc_containers_are_supported(kind):
    with pytest.raises(ControlledLiveRenderError, match="unsupported_guest_kind"):
        render_controlled_live_workspace(
            _manifest(guest_kind=kind), provider_version=_VERSION, state_backend_kind="http"
        )


def test_network_creation_is_refused_before_rendering():
    m = _manifest()
    m["topology"][0]["networks"] = [{"name": "n", "cidr": "10.0.0.0/24", "bridge": "vmbr9"}]
    with pytest.raises(ControlledLiveRenderError, match="network_creation_unsupported"):
        render_controlled_live_workspace(m, provider_version=_VERSION, state_backend_kind="http")


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("vmid", "vmid_required"),
        ("vcpu", "vcpu_required"),
        ("memory_mb", "memory_required"),
        ("disk_gb", "disk_required"),
    ],
)
def test_missing_bounded_fields_fail_closed(field, reason):
    with pytest.raises(ControlledLiveRenderError, match=reason):
        render_controlled_live_workspace(
            _manifest(**{field: 0}), provider_version=_VERSION, state_backend_kind="http"
        )


def test_missing_node_storage_or_bridge_fails_closed():
    with pytest.raises(ControlledLiveRenderError, match="node_storage_bridge_required"):
        render_controlled_live_workspace(
            _manifest(storage=""), provider_version=_VERSION, state_backend_kind="http"
        )


def test_non_http_state_backend_is_refused():
    with pytest.raises(ControlledLiveRenderError, match="unsupported_state_backend_kind"):
        render_controlled_live_workspace(
            _manifest(), provider_version=_VERSION, state_backend_kind="s3"
        )


def test_empty_topology_is_refused():
    with pytest.raises(ControlledLiveRenderError, match="exactly_one_team_required"):
        render_controlled_live_workspace(
            {"topology": []}, provider_version=_VERSION, state_backend_kind="http"
        )


def test_more_than_one_team_is_refused():
    m = {"topology": [_manifest()["topology"][0], _manifest()["topology"][0]]}
    with pytest.raises(ControlledLiveRenderError, match="exactly_one_team_required"):
        render_controlled_live_workspace(m, provider_version=_VERSION, state_backend_kind="http")


def test_more_than_one_container_is_refused():
    m = _manifest()
    m["topology"][0]["nodes"].append(dict(m["topology"][0]["nodes"][0], ref="c2", vmid=9002))
    with pytest.raises(ControlledLiveRenderError, match="exactly_one_container_required"):
        render_controlled_live_workspace(m, provider_version=_VERSION, state_backend_kind="http")


@pytest.mark.parametrize(
    "bad_template",
    [
        "https://example.com/debian.tar.zst",  # a URL, not a vztmpl reference
        "debian-12.tar.zst",  # no datastore:vztmpl/ prefix
        "local:iso/debian.iso",  # an ISO, not a container template
        "",  # missing
        123,  # not a string
    ],
)
def test_a_non_vztmpl_container_template_is_refused(bad_template):
    with pytest.raises(ControlledLiveRenderError, match="container_template_invalid"):
        render_controlled_live_workspace(
            _manifest(image=bad_template), provider_version=_VERSION, state_backend_kind="http"
        )


# --- the render-safety scanner -------------------------------------------------------------------


def test_the_scanner_accepts_the_rendered_controlled_live_workspace():
    files = render_controlled_live_workspace(
        _manifest(), provider_version=_VERSION, state_backend_kind="http"
    )
    controlled_live_render_scan(files, contract=_contract())  # no raise


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ('resource "labfake_vm" "x" {}', "fake_provider_or_resource_identifier"),
        ('source = "example.test/fake/labproxmox"', "fake_provider_or_resource_identifier"),
        ('provisioner "local-exec" { command = "x" }', "forbidden_construct"),
        ('resource "x" "y" { provisioner "remote-exec" {} }', "forbidden_construct"),
        ('data "external" "x" {}', "forbidden_construct"),
        ('backend "local" {}', "forbidden_construct"),
        ('x = templatefile("t", {})', "forbidden_construct"),
        ('x = getenv("SECRET")', "forbidden_construct"),
        ('source = "registry.terraform.io/bpg/proxmox"', "remote_source_fetch"),
        ('source = "https://example.com/mod"', "remote_source_fetch"),
        ('api_token = "abc123secretvalue"', "secret_looking_literal"),
        ('password = "hunter2"', "secret_looking_literal"),
    ],
)
def test_the_scanner_refuses_dangerous_text(text, reason):
    # Wrap the dangerous text in an otherwise-valid workspace so only the target rule fires.
    files = {
        "versions.tf": (
            "terraform {\n  required_providers {\n    proxmox = {\n"
            f'      source  = "{CONTROLLED_LIVE_PROVIDER_SOURCE}"\n'
            f'      version = "= {_VERSION}"\n    }}\n  }}\n}}\n'
        ),
        "extra.tf": text,
    }
    with pytest.raises(ControlledLiveRenderRefused, match=reason):
        controlled_live_render_scan(files, contract=_contract())


@pytest.mark.parametrize("version_constraint", [">= 0.80.0", "~> 0.80", "latest", "0.80.0"])
def test_the_scanner_refuses_unpinned_provider_versions(version_constraint):
    files = {
        "versions.tf": (
            "terraform {\n  required_providers {\n    proxmox = {\n"
            f'      source  = "{CONTROLLED_LIVE_PROVIDER_SOURCE}"\n'
            f'      version = "{version_constraint}"\n    }}\n  }}\n}}\n'
        ),
    }
    with pytest.raises(ControlledLiveRenderRefused, match="provider_version_not_exactly_pinned"):
        controlled_live_render_scan(files, contract=_contract())


def test_the_scanner_refuses_an_unsupported_resource_type():
    files = {
        "versions.tf": (
            "terraform {\n  required_providers {\n    proxmox = {\n"
            f'      source  = "{CONTROLLED_LIVE_PROVIDER_SOURCE}"\n'
            f'      version = "= {_VERSION}"\n    }}\n  }}\n}}\n'
        ),
        "main.tf": 'resource "proxmox_virtual_environment_vm" "x" {}',  # VM, not the allowed LXC
    }
    with pytest.raises(ControlledLiveRenderRefused, match="unsupported_resource_type"):
        controlled_live_render_scan(files, contract=_contract())


def test_the_scanner_refuses_a_contract_that_is_not_the_reviewed_provider():
    bad = RenderScanContract(
        provider_source="hashicorp/proxmox",  # not the reviewed source
        provider_version=_VERSION,
        supported_resource_types=SUPPORTED_RESOURCE_TYPES,
    )
    with pytest.raises(ControlledLiveRenderRefused, match="provider_source_not_reviewed"):
        controlled_live_render_scan({"x.tf": "y"}, contract=bad)


def test_the_scanner_refuses_a_workspace_with_no_provider_declaration():
    with pytest.raises(ControlledLiveRenderRefused, match="provider_declaration_missing"):
        controlled_live_render_scan(
            {"main.tf": 'resource "proxmox_virtual_environment_container" "x" {}'},
            contract=_contract(),
        )
