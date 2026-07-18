"""Signed artifact-purpose taxonomy (SECP-PR5E round 4 blocker 1).

Every image + security-sensitive wheel is bound to exactly one closed, role-scoped purpose in the
SIGNED manifest; the controller component->image mapping and the worker ordinary/operator images are
derived from this signed mapping. Missing / duplicate / unknown / kind-mismatched /
role-incompatible
/ incomplete purpose sets are refused.
"""

from __future__ import annotations

import copy
import json

import pytest
from _mgmt_support import default_artifacts, manifest_dict
from secp_management import ManagementError
from secp_management.release_bundle import (
    WORKER_DEPLOYMENT_PACKAGE_PURPOSE,
    parse_manifest_bytes,
    signed_controller_image_map,
    signed_deployment_package,
    signed_worker_image,
)


def _parse(role, arts):
    return parse_manifest_bytes(json.dumps(manifest_dict(role, arts)).encode())


def test_default_bundles_are_wellformed_with_purposes():
    cm = _parse("controller", default_artifacts("controller"))
    assert len(signed_controller_image_map(cm)) == 8
    wm = _parse("worker", default_artifacts("worker"))
    assert signed_worker_image(wm, "worker/ordinary").startswith("sha256:")
    assert signed_worker_image(wm, "worker/operator").startswith("sha256:")
    assert signed_deployment_package(wm).purpose == WORKER_DEPLOYMENT_PACKAGE_PURPOSE


def _first_image(arts):
    return next(i for i, a in enumerate(arts) if a["kind"] == "image_archive")


def test_missing_image_purpose_refused():
    arts = copy.deepcopy(default_artifacts("worker"))
    del arts[_first_image(arts)]["purpose"]
    with pytest.raises(ManagementError) as exc:
        _parse("worker", arts)
    assert exc.value.reason_code == "release_artifact_purpose_missing"


def test_unknown_purpose_refused():
    arts = copy.deepcopy(default_artifacts("worker"))
    arts[_first_image(arts)]["purpose"] = "worker/mystery"
    with pytest.raises(ManagementError) as exc:
        _parse("worker", arts)
    assert exc.value.reason_code == "release_artifact_purpose_unknown"


def test_role_incompatible_purpose_refused():
    # a controller/* image purpose in a WORKER bundle
    arts = copy.deepcopy(default_artifacts("worker"))
    arts[_first_image(arts)]["purpose"] = "controller/api"
    with pytest.raises(ManagementError) as exc:
        _parse("worker", arts)
    assert exc.value.reason_code == "release_artifact_purpose_role_incompatible"


def test_duplicate_purpose_refused():
    arts = copy.deepcopy(default_artifacts("worker"))
    # force both worker images to the same purpose
    imgs = [i for i, a in enumerate(arts) if a["kind"] == "image_archive"]
    arts[imgs[0]]["purpose"] = "worker/ordinary"
    arts[imgs[1]]["purpose"] = "worker/ordinary"
    with pytest.raises(ManagementError) as exc:
        _parse("worker", arts)
    assert exc.value.reason_code == "release_artifact_purpose_duplicate"


def test_kind_purpose_mismatch_refused():
    # a wheel purpose on an image_archive
    arts = copy.deepcopy(default_artifacts("worker"))
    arts[_first_image(arts)]["purpose"] = "worker/deployment-package"
    with pytest.raises(ManagementError) as exc:
        _parse("worker", arts)
    assert exc.value.reason_code == "release_artifact_purpose_kind_mismatch"


def test_purpose_on_compose_refused():
    arts = copy.deepcopy(default_artifacts("worker"))
    compose = next(a for a in arts if a["kind"].endswith("compose_template"))
    compose["purpose"] = "worker/ordinary"
    with pytest.raises(ManagementError) as exc:
        _parse("worker", arts)
    assert exc.value.reason_code == "release_artifact_purpose_unexpected"


def test_incomplete_purpose_set_refused():
    # drop one required controller component image entirely
    arts = [
        a
        for a in copy.deepcopy(default_artifacts("controller"))
        if a.get("purpose") != "controller/web"
    ]
    with pytest.raises(ManagementError) as exc:
        _parse("controller", arts)
    assert exc.value.reason_code == "release_purpose_set_incomplete"


def test_worker_missing_deployment_package_purpose_refused():
    arts = [a for a in copy.deepcopy(default_artifacts("worker")) if a["kind"] != "python_wheel"]
    with pytest.raises(ManagementError) as exc:
        _parse("worker", arts)
    assert exc.value.reason_code == "release_purpose_set_incomplete"
