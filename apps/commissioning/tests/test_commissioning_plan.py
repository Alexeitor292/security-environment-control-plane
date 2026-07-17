"""Plan engine — fixed paths, identity pins, invariant, service refusal (defects #1, #7, #9)."""

from __future__ import annotations

import pytest
from _support import (
    OPERATOR_ROOT,
    SOURCE_TREE_SHA,
    expected,
    locations,
    valid_descriptor_raw,
)
from secp_commissioning.descriptor import parse_descriptor
from secp_commissioning.errors import CommissioningError
from secp_commissioning.plan import HostFacts, build_plan


def _facts(**over):
    base = dict(service_state_inspected=True, ordinary_worker_running=True)
    base.update(over)
    return HostFacts(**base)


def _plan(raw=None, exp=None, facts=None):
    return build_plan(
        descriptor=parse_descriptor(raw or valid_descriptor_raw()),
        locations=locations(),
        facts=facts or _facts(),
        expected=exp or expected(),
    )


def test_plan_is_deterministic():
    assert _plan().digest() == _plan().digest()


def test_every_target_is_under_the_operator_root():
    p = _plan()
    assert all(d.path == OPERATOR_ROOT for d in p.directories)
    assert all(f.target_path.startswith(OPERATOR_ROOT + "/") for f in p.files)


def test_service_disabled_and_seals_false():
    p = _plan()
    assert p.services[0].enabled is False and p.services[0].running is False
    for k in (
        "operator_service_enabled",
        "operator_service_running",
        "external_contacts_performed",
        "workflows_submitted",
        "plan_execution_performed",
    ):
        assert p.evidence_preview[k] is False


@pytest.mark.parametrize(
    "override,reason",
    [
        (dict(release_source_sha="f" * 40), "ordinary_source_mismatch"),
        (dict(source_tree_sha="f" * 40), "source_tree_mismatch"),
        (dict(ordinary_worker_image_digest="sha256:" + "9" * 64), "ordinary_image_mismatch"),
        (dict(operator_image_digest="sha256:" + "9" * 64), "operator_image_mismatch"),
        (dict(control_plane_image_digest="sha256:" + "9" * 64), "control_plane_image_mismatch"),
        (dict(ordinary_task_queue="other-queue"), "ordinary_queue_mismatch"),
        (dict(operator_runtime_uid=999), "operator_runtime_uid_mismatch"),
        (dict(ordinary_health_command=("wrong",)), "health_mismatch"),
    ],
)
def test_identity_mismatch_is_refused(override, reason):
    with pytest.raises(CommissioningError) as exc:
        _plan(exp=expected(**override))
    assert exc.value.reason_code == reason


def test_service_state_not_inspected_refused():
    with pytest.raises(CommissioningError) as exc:
        _plan(facts=HostFacts(service_state_inspected=False))
    assert exc.value.reason_code == "service_state_not_inspected"


def test_ordinary_worker_not_running_refused():
    with pytest.raises(CommissioningError) as exc:
        _plan(facts=_facts(ordinary_worker_running=False))
    assert exc.value.reason_code == "ordinary_worker_not_running"


def test_operator_running_refused():
    with pytest.raises(CommissioningError) as exc:
        _plan(facts=_facts(operator_service_running=True))
    assert exc.value.reason_code == "operator_service_running"


def test_operator_enabled_refused():
    with pytest.raises(CommissioningError) as exc:
        _plan(facts=_facts(operator_service_enabled=True))
    assert exc.value.reason_code == "operator_service_enabled"


# --- defect #7: trusted pins must match the CURRENT implementation; control_plane.source bound ---


def test_expected_tool_version_mismatch_refused():
    with pytest.raises(CommissioningError) as exc:
        _plan(exp=expected(tool_version="9.9.9"))
    assert exc.value.reason_code == "expected_tool_version_mismatch"


def test_expected_contract_version_mismatch_refused():
    with pytest.raises(CommissioningError) as exc:
        _plan(exp=expected(contract_version="secp.commissioning.descriptor/v2"))
    assert exc.value.reason_code == "expected_contract_version_mismatch"


def test_operator_registration_symbol_mismatch_refused():
    with pytest.raises(CommissioningError) as exc:
        _plan(exp=expected(operator_registration_symbol="build_something_else"))
    assert exc.value.reason_code == "operator_registration_symbol_mismatch"


def test_control_plane_source_mismatch_refused():
    raw = valid_descriptor_raw(
        control_plane={"source": {"source_sha": "c" * 40, "source_tree_sha": SOURCE_TREE_SHA}}
    )
    with pytest.raises(CommissioningError) as exc:
        _plan(raw=raw)
    assert exc.value.reason_code == "control_plane_source_mismatch"


def test_digest_is_drift_independent():
    from secp_commissioning.plan import DirObservation

    present = _facts(
        directories={
            OPERATOR_ROOT: DirObservation(exists=True, owner_uid=0, owner_gid=0, mode=0o750)
        }
    )
    assert _plan().digest() == _plan(facts=present).digest()
