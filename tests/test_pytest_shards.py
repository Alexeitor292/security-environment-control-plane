"""Unit tests for the CI pytest sharding planner/verifier (scripts/ci/pytest_shards.py).

These exercise the pure planning/inventory functions with synthetic inventories — no Git, no
pytest collection, no database — covering complete partition, missing/duplicate/new files, an
unmanaged test root, deterministic output, weighted balancing, malformed config, node-ID
normalization, and JUnit weight parsing.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_MOD_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "pytest_shards.py"
_spec = importlib.util.spec_from_file_location("pytest_shards", _MOD_PATH)
assert _spec and _spec.loader
ps = importlib.util.module_from_spec(_spec)
sys.modules["pytest_shards"] = ps  # dataclass creation looks up cls.__module__ in sys.modules
_spec.loader.exec_module(ps)


def _config(**over):
    base = dict(
        shard_count=4,
        roots=("apps/api/tests", "tests", "contracts/scenario-schema/tests"),
        test_globs=("test_*.py", "*_test.py"),
        exclusions=("apps/worker/secp_worker/preflight/self_test.py",),
        timings_path=".ci/pytest-timings.json",
        raw={},
    )
    base.update(over)
    return ps.Config(**base)


TRACKED = [
    "apps/api/tests/conftest.py",
    "apps/api/tests/test_a.py",
    "apps/api/tests/test_b.py",
    "tests/test_c.py",
    "tests/helpers.py",  # not a test file
    "contracts/scenario-schema/tests/test_schema.py",
    "apps/worker/secp_worker/preflight/self_test.py",  # excluded runtime module
    "apps/api/secp_api/models.py",  # source, not a test
]


# --- is_test_file / discovery -----------------------------------------------------------------


def test_is_test_file_matches_pytest_globs():
    globs = ("test_*.py", "*_test.py")
    assert ps.is_test_file("apps/api/tests/test_a.py", globs)
    assert ps.is_test_file("x/self_test.py", globs)
    assert not ps.is_test_file("apps/api/tests/conftest.py", globs)
    assert not ps.is_test_file("apps/api/secp_api/models.py", globs)


def test_managed_files_is_complete_and_excludes_allowlist_and_nontests():
    managed = ps.managed_files(_config(), TRACKED)
    assert managed == [
        "apps/api/tests/test_a.py",
        "apps/api/tests/test_b.py",
        "contracts/scenario-schema/tests/test_schema.py",
        "tests/test_c.py",
    ]
    # conftest, helpers, source, and the excluded runtime module are not managed tests
    assert "apps/api/tests/conftest.py" not in managed
    assert "apps/worker/secp_worker/preflight/self_test.py" not in managed


def test_new_managed_file_is_auto_included():
    managed = ps.managed_files(_config(), [*TRACKED, "apps/api/tests/test_brand_new.py"])
    assert "apps/api/tests/test_brand_new.py" in managed


def test_unmanaged_pytest_file_outside_roots_is_flagged():
    tracked = [*TRACKED, "apps/worker/tests/test_sneaky.py"]
    unmanaged = ps.unmanaged_pytest_files(_config(), tracked)
    assert unmanaged == ["apps/worker/tests/test_sneaky.py"]


def test_allowlisted_exclusion_is_not_flagged_as_unmanaged():
    assert ps.unmanaged_pytest_files(_config(), TRACKED) == []


# --- planning ---------------------------------------------------------------------------------


def test_complete_partition_assigns_every_file_exactly_once():
    files = [f"tests/test_{i}.py" for i in range(20)]
    shards = ps.plan_shards(files, {}, 4, 1.0)
    assert ps.verify_partition(shards, files) == []
    flat = [f for s in shards for f in s]
    assert sorted(flat) == sorted(files)
    assert len(flat) == len(set(flat))  # no duplicates


def test_verify_partition_detects_missing_file():
    files = ["tests/test_1.py", "tests/test_2.py"]
    shards = [["tests/test_1.py"], [], [], []]
    errs = ps.verify_partition(shards, files)
    assert any("test_2.py" in e and "NO shard" in e for e in errs)


def test_verify_partition_detects_duplicate_file():
    files = ["tests/test_1.py"]
    shards = [["tests/test_1.py"], ["tests/test_1.py"], [], []]
    errs = ps.verify_partition(shards, files)
    assert any("duplicate" in e for e in errs)


def test_verify_partition_detects_extra_unmanaged_assignment():
    errs = ps.verify_partition([["tests/test_ghost.py"], [], [], []], [])
    assert any("not a managed test file" in e for e in errs)


def test_plan_is_deterministic():
    files = [f"tests/test_{i}.py" for i in range(25)]
    weights = {f: (i % 5) + 0.5 for i, f in enumerate(files)}
    a = ps.plan_shards(files, weights, 4, 1.0)
    b = ps.plan_shards(files, weights, 4, 1.0)
    assert a == b


def test_weighted_balancing_keeps_shards_close():
    files = [f"tests/test_{i}.py" for i in range(40)]
    # widely varying weights
    weights = {f: float((i * 7) % 13 + 1) for i, f in enumerate(files)}
    shards = ps.plan_shards(files, weights, 4, 1.0)
    loads = [sum(weights[f] for f in s) for s in shards]
    # greedy LPT keeps the heaviest shard within ~1 max-item of the lightest
    assert max(loads) - min(loads) <= max(weights.values())


def test_fallback_weight_uses_median_new_files():
    files = ["tests/test_old.py", "tests/test_new.py"]
    weights = {"tests/test_old.py": 10.0}
    fb = ps.fallback_weight(weights)
    assert fb == 10.0  # median of a single known weight
    shards = ps.plan_shards(files, weights, 2, fb)
    assert ps.verify_partition(shards, files) == []


# --- node-id normalization --------------------------------------------------------------------


def test_normalize_node_id_canonicalizes_uuid_tokens():
    a = "t/x.py::test_k[col-8065c291-1667-4682-8bf9-f1e110351ea8]"
    b = "t/x.py::test_k[col-153bfe8b-c87b-44f3-845a-6c89c0f976b6]"
    assert ps.normalize_node_id(a) == ps.normalize_node_id(b)
    assert ps.normalize_node_id(a) == "t/x.py::test_k[col-<uuid>]"


def test_normalize_node_id_preserves_distinct_case_names():
    a = ps.normalize_node_id("t/x.py::test_k[alpha-8065c291-1667-4682-8bf9-f1e110351ea8]")
    b = ps.normalize_node_id("t/x.py::test_k[beta-153bfe8b-c87b-44f3-845a-6c89c0f976b6]")
    assert a != b  # distinct parametrized cases stay distinct


# --- config + junit ---------------------------------------------------------------------------


def test_load_config_rejects_malformed(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"shard_count": 0, "roots": ["tests"]}), encoding="utf-8")
    with pytest.raises(ps.InventoryError):
        ps.load_config(bad)

    noroots = tmp_path / "noroots.json"
    noroots.write_text(json.dumps({"shard_count": 4, "roots": []}), encoding="utf-8")
    with pytest.raises(ps.InventoryError):
        ps.load_config(noroots)


def test_load_config_parses_valid(tmp_path):
    good = tmp_path / "ok.json"
    good.write_text(
        json.dumps(
            {
                "shard_count": 3,
                "roots": ["tests"],
                "exclusions": [{"path": "x/self_test.py", "reason": "runtime"}],
            }
        ),
        encoding="utf-8",
    )
    cfg = ps.load_config(good)
    assert cfg.shard_count == 3
    assert cfg.roots == ("tests",)
    assert cfg.exclusions == ("x/self_test.py",)


def test_classname_to_file_resolves_module_and_strips_test_class():
    known = {"apps/api/tests/test_x.py", "contracts/scenario-schema/tests/test_y.py"}
    assert (
        ps._classname_to_file("apps.api.tests.test_x.TestFoo", known) == "apps/api/tests/test_x.py"
    )
    assert ps._classname_to_file("apps.api.tests.test_x", known) == "apps/api/tests/test_x.py"
    # hyphenated directory segment round-trips
    assert (
        ps._classname_to_file("contracts.scenario-schema.tests.test_y", known)
        == "contracts/scenario-schema/tests/test_y.py"
    )


def test_weights_from_junit_without_file_attr_uses_classname(tmp_path):
    xml = tmp_path / "j.xml"
    xml.write_text(
        "<testsuites><testsuite>"
        '<testcase classname="apps.api.tests.test_x.TestFoo" name="t1" time="1.0"/>'
        '<testcase classname="apps.api.tests.test_x" name="t2" time="0.5"/>'
        "</testsuite></testsuites>",
        encoding="utf-8",
    )
    weights = ps.weights_from_junit(xml, ["apps/api/tests/test_x.py"])
    assert weights == {"apps/api/tests/test_x.py": 1.5}


def test_weights_from_junit_aggregates_per_file(tmp_path):
    xml = tmp_path / "j.xml"
    xml.write_text(
        """<testsuites><testsuite>
        <testcase file="tests/test_a.py" name="t1" time="1.5"/>
        <testcase file="tests/test_a.py" name="t2" time="0.5"/>
        <testcase file="tests/test_b.py" name="t3" time="2.0"/>
        </testsuite></testsuites>""",
        encoding="utf-8",
    )
    weights = ps.weights_from_junit(xml)
    assert weights == {"tests/test_a.py": 2.0, "tests/test_b.py": 2.0}
