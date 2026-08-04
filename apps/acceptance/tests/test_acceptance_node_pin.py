"""The container-tier node pin maintains itself, in the REQUIRED gate.

WHY A PIN AT ALL
----------------
A JUnit report cannot express deselection. A run with the tier undeclared emits ``tests=N
skipped=0`` and is simply MISSING those nodes, with no attribute recording their absence — so a gate
that refused skips would happily pass a run where the entire container tier vanished. The only way
to notice is to compare against a number decided in advance.

That number therefore has to be a hand-maintained literal. Deriving it from collection would shrink
the expectation in step with any collapse, which satisfies "derived, not typed" in form while being
defeated in substance — the trap ``test_acceptance_reason_provenance.py`` documents the queue
stream hitting.

WHY THAT IS NORMALLY AWFUL, AND WHY IT IS NOT HERE
--------------------------------------------------
A hand-maintained count in a workflow file is a number nobody updates until something breaks —
and, with four streams adding container-tier modules at once, a guaranteed merge conflict on one
line. What makes it survivable is that THIS file runs in the ordinary CI shards (``apps/acceptance
/tests`` is in ``.ci/pytest-suite.json``), so a stream that adds a node is told the right number by
the required gate on its own PR, long before the acceptance workflow ever runs.

The pin is per MODULE, not one total. Two streams adding two modules do not collide, and — the part
a single integer gets wrong — a node silently lost from one module cannot be masked by a node gained
in another.
"""

from __future__ import annotations

import collections
import pathlib
import re
import subprocess
import sys

import pytest
import yaml
from secp_acceptance.tier import (
    ENV_TIER,
    EXPECTED_CONTAINER_NODES,
    EXPECTED_CONTAINER_NODES_BY_MODULE,
    TIER_CONTAINER,
)

ACCEPTANCE_TESTS = pathlib.Path(__file__).resolve().parent


def _repo_root() -> pathlib.Path:
    for parent in pathlib.Path(__file__).resolve().parents:
        if (parent / "pyproject.toml").is_file() and (parent / "infra").is_dir():
            return parent
    raise AssertionError("repository root not found from the test file location")


def _collect_container_nodes() -> tuple[str, ...]:
    """Collect the container tier for real, in a subprocess, and return its node ids.

    A SUBPROCESS because the tier is declared by an environment variable read at import time, and
    because collecting the real directory inside this session would recurse into it.

    Bytes are decoded as UTF-8 EXPLICITLY. ``subprocess.run(..., text=True)`` decodes through the
    locale codepage on Windows, which mangles the non-ASCII characters this repo's docstrings are
    full of and would corrupt node ids for no visible reason.
    """
    completed = subprocess.run(  # noqa: S603 - fixed argv, no user input, bounded
        [
            sys.executable,
            "-m",
            "pytest",
            str(ACCEPTANCE_TESTS),
            "-m",
            "container_tier",
            "--collect-only",
            "-q",
            "--no-header",
            "-p",
            "no:cacheprovider",
        ],
        cwd=_repo_root(),
        capture_output=True,
        timeout=300,
        check=False,
        env={**_env_with_tier()},
    )
    stdout = completed.stdout.decode("utf-8", errors="replace")
    # Node ids only: `path::test_name[param]`. The trailing summary lines carry no `::`.
    return tuple(
        line.strip() for line in stdout.splitlines() if "::" in line and not line.startswith(" ")
    )


def _env_with_tier() -> dict[str, str]:
    import os

    return {**os.environ, ENV_TIER: TIER_CONTAINER}


def _collected_by_module() -> dict[str, int]:
    counts: collections.Counter[str] = collections.Counter()
    for node in _collect_container_nodes():
        counts[node.split("::", 1)[0].replace("\\", "/").rsplit("/", 1)[-1]] += 1
    return dict(counts)


# --------------------------------------------------------------------------- controls


def test_the_collection_probe_actually_finds_nodes():
    """CONTROL, and the reason every count below means anything.

    A probe that returned nothing — wrong argv, wrong cwd, a collection error swallowed — would make
    a MISSING module indistinguishable from a module with zero nodes, and the per-module comparison
    would then be satisfied by a mapping that had quietly emptied.
    """
    nodes = _collect_container_nodes()
    assert nodes, "the collection probe found no container-tier nodes at all"
    assert all("::" in node for node in nodes)


def test_the_probe_reads_the_container_tier_and_not_the_hermetic_corpus():
    """The tier must actually be declared for the probe. Without it the conftest DESELECTS every
    container node and the probe would report zero — which the control above would catch, but this
    says why."""
    nodes = _collect_container_nodes()
    assert all("container" in node.split("::", 1)[0] for node in nodes), (
        f"collected a node from outside the container-tier modules: {nodes}"
    )


# --------------------------------------------------------------------------- the pin


def test_every_container_module_contributes_exactly_its_pinned_node_count():
    """THE guard. Equality per module, in both directions.

    A module that gained or lost a node fails here, on the PR that changed it, naming the module and
    the right number — rather than in the acceptance workflow, or (worse) not at all.
    """
    collected = _collected_by_module()
    assert collected == EXPECTED_CONTAINER_NODES_BY_MODULE, (
        f"container-tier node counts disagree with the pin.\n"
        f"  collected: {dict(sorted(collected.items()))}\n"
        f"  pinned   : {dict(sorted(EXPECTED_CONTAINER_NODES_BY_MODULE.items()))}\n"
        f"If a module legitimately gained or lost a node, update "
        f"EXPECTED_CONTAINER_NODES_BY_MODULE in secp_acceptance/tier.py in the SAME commit. "
        f"Deselection is invisible in JUnit, so this pin is the only thing standing between a "
        f"silently-undeclared tier and a green acceptance run."
    )


def test_the_total_is_derived_from_the_mapping_and_not_restated():
    """Two numbers that must agree are one number too many."""
    assert EXPECTED_CONTAINER_NODES == sum(EXPECTED_CONTAINER_NODES_BY_MODULE.values())
    assert EXPECTED_CONTAINER_NODES == len(_collect_container_nodes())


def test_no_container_module_is_missing_from_the_pin():
    """A NEW container-tier module must be pinned, not silently unmeasured.

    This is the direction that matters for four concurrent streams: a stream that adds a module and
    forgets the pin would otherwise contribute nodes that no count is watching.
    """
    collected = set(_collected_by_module())
    pinned = set(EXPECTED_CONTAINER_NODES_BY_MODULE)
    assert collected - pinned == set(), (
        f"these container-tier modules contribute nodes but are not pinned: "
        f"{sorted(collected - pinned)}"
    )
    assert pinned - collected == set(), (
        f"these modules are pinned but contribute no nodes (deleted? renamed? marker removed?): "
        f"{sorted(pinned - collected)}"
    )


# --------------------------------------------------------------------------- the workflow agrees


def _acceptance_workflow() -> dict:
    path = _repo_root() / ".github" / "workflows" / "acceptance.yml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_the_workflow_takes_the_count_from_the_harness_rather_than_restating_it():
    """The workflow must not carry its own copy of the number.

    It used to hold ``EXPECTED_CONTAINER_NODES: "13"`` as a YAML literal — a second source of truth
    that nothing compared against the first, so the two could drift apart silently and the drift
    would only ever surface as a confusing acceptance failure.
    """
    workflow = _acceptance_workflow()
    env = workflow.get("env", {}) or {}
    assert "EXPECTED_CONTAINER_NODES" not in env, (
        "the workflow declares its own EXPECTED_CONTAINER_NODES literal again; it must read the "
        "value from secp_acceptance.tier so there is exactly one source of truth"
    )
    text = (_repo_root() / ".github" / "workflows" / "acceptance.yml").read_text(encoding="utf-8")
    assert "secp_acceptance.tier" in text, (
        "the workflow no longer reads the pin from the harness at all"
    )


@pytest.mark.parametrize("job", ["container-tier", "prove-the-tier-can-fail"])
def test_both_jobs_enforce_the_node_count(job: str):
    """Both the real run and the negative control must compare against the pin.

    The negative control asserts every node REFUSES; without the count it would be satisfied by a
    run where only one node existed and refused.
    """
    steps = _acceptance_workflow()["jobs"][job].get("steps", [])
    run_text = "\n".join(str(step.get("run", "")) for step in steps)
    assert "EXPECTED_CONTAINER_NODES" in run_text, (
        f"job {job} does not compare anything against the pinned node count"
    )


def test_the_workflow_still_refuses_skips_and_deselection():
    """The two properties the pin exists alongside. A regression that removed either would leave
    the count as the only check, and a count alone cannot see a skip."""
    steps = _acceptance_workflow()["jobs"]["container-tier"].get("steps", [])
    run_text = "\n".join(str(step.get("run", "")) for step in steps)
    assert re.search(r"skipped", run_text), "the container-tier job no longer refuses skips"
    assert "deselect" in run_text.lower(), (
        "the container-tier job no longer explains/checks the deselection case"
    )
