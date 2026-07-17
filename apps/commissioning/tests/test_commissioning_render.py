"""Renderer — fixed basenames, template-digest pin, collisions, staging safety (defect #8, #9)."""

from __future__ import annotations

import pytest
from _support import OPERATOR_ROOT, build_engine
from secp_commissioning.errors import CommissioningError
from secp_commissioning.operator_template import (
    OPERATOR_ENTRYPOINT_TEMPLATE,
    entrypoint_template_digest,
)


def _mk(tmp_path, name):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


def test_render_is_deterministic(tmp_path):
    a = build_engine(_mk(tmp_path, "a"))
    b = build_engine(_mk(tmp_path, "b"))
    assert a.render.manifest_digest() == b.render.manifest_digest()


def test_render_roles_and_targets(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    roles = {f.role for f in e.render.files}
    assert roles == {
        "root_directory_manifest",
        "operator_preparation_bundle",
        "operator_entrypoint_template",
        "operator_service_definition_disabled",
    }
    assert all(f.target_path.startswith(OPERATOR_ROOT + "/") for f in e.render.files)
    assert all(f.owner_uid == 0 for f in e.render.files)


def test_entrypoint_template_digest_matches_plan(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    entry = next(f for f in e.render.files if f.role == "operator_entrypoint_template")
    assert entry.sha256 == entrypoint_template_digest() == e.plan.entrypoint_template_digest


def test_operator_entrypoint_is_fail_closed_and_value_free():
    t = OPERATOR_ENTRYPOINT_TEMPLATE
    assert "controlled_live_composition_not_installed" in t
    assert "build_operator_worker_registration" in t
    assert "Worker(" not in t
    for forbidden in ("registry.example", "secp-controlled-live-v1", "192.0.2", "PRIVATE KEY"):
        assert forbidden not in t
    for wf in ("DeployWorkflow", "ResetWorkflow", "DestroyWorkflow", "DiscoverWorkflow"):
        assert wf not in t


def test_service_unit_is_disabled(tmp_path):
    e = build_engine(_mk(tmp_path, "s"))
    unit = next(f for f in e.render.files if f.role == "operator_service_definition_disabled")
    text = unit.content.decode()
    assert "[Install]" not in text and "WantedBy" not in text


def test_render_refuses_symlinked_staging_dir(tmp_path):
    import os

    from _support import expected, locations, valid_descriptor_raw
    from secp_commissioning.descriptor import parse_descriptor
    from secp_commissioning.plan import HostFacts, build_plan
    from secp_commissioning.render import render_bundle

    target = _mk(tmp_path, "realdir")
    link = str(tmp_path / "link")
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink not supported on this host")
    d = parse_descriptor(valid_descriptor_raw())
    loc = locations()
    plan = build_plan(
        descriptor=d,
        locations=loc,
        facts=HostFacts(service_state_inspected=True, ordinary_worker_running=True),
        expected=expected(),
    )
    with pytest.raises(CommissioningError) as exc:
        render_bundle(descriptor=d, plan=plan, locations=loc, staging_dir=link)
    assert exc.value.reason_code == "render_staging_dir_symlink"


# --- defect #8: staging root must be trusted-owned + restrictive; partial writes are unlinked ---


def _plan_for():
    from _support import expected, locations, valid_descriptor_raw
    from secp_commissioning.descriptor import parse_descriptor
    from secp_commissioning.plan import HostFacts, build_plan

    d = parse_descriptor(valid_descriptor_raw())
    loc = locations()
    plan = build_plan(
        descriptor=d,
        locations=loc,
        facts=HostFacts(service_state_inspected=True, ordinary_worker_running=True),
        expected=expected(),
    )
    return d, loc, plan


def test_render_refuses_untrusted_staging_owner():
    from secp_commissioning.render import InMemoryStagingSeam, render_bundle

    d, loc, plan = _plan_for()
    seam = InMemoryStagingSeam(uid=1000, trusted_uid=0)  # not owned by the trusted identity
    with pytest.raises(CommissioningError) as exc:
        render_bundle(descriptor=d, plan=plan, locations=loc, staging_seam=seam)
    assert exc.value.reason_code == "render_staging_dir_untrusted_owner"
    assert seam.written == {}  # nothing written under an untrusted staging root


def test_render_refuses_world_writable_staging():
    from secp_commissioning.render import InMemoryStagingSeam, render_bundle

    d, loc, plan = _plan_for()
    seam = InMemoryStagingSeam(uid=0, mode=0o777, trusted_uid=0)  # group/other writable
    with pytest.raises(CommissioningError) as exc:
        render_bundle(descriptor=d, plan=plan, locations=loc, staging_seam=seam)
    assert exc.value.reason_code == "render_staging_dir_world_writable"


def test_render_unlinks_partial_staging_file_on_short_write():
    from secp_commissioning.render import InMemoryStagingSeam, render_bundle

    d, loc, plan = _plan_for()
    seam = InMemoryStagingSeam(fail_on="entrypoint.py")  # short write on this file
    with pytest.raises(CommissioningError) as exc:
        render_bundle(descriptor=d, plan=plan, locations=loc, staging_seam=seam)
    assert exc.value.reason_code == "render_short_write"
    assert "entrypoint.py" not in seam.written  # the partially-written file is not left behind
