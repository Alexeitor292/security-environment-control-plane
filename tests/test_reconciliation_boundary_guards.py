"""Boundary guards for the reconciliation contract (secp_reconciliation).

Two properties are load-bearing and are checked here rather than asserted in prose:

* **No provider-supplied identity or value leaves the contract.** A desired element's reference is
  authored control-plane content and may appear in a finding, an action or a plan. An *observed*
  element's reference and facet values are whatever a collector reported, and must appear nowhere:
  not in a report, a plan, a reset intent, an evidence document or a refusal.
* **A refusal carries only its bounded code** — the control plane's redacted-refusal convention.

The leak scan is count-based (``occurrences == 0``) and ships with a positive control, because a
scanner that silently matches nothing would agree with every input.
"""

from __future__ import annotations

import ast
import types
from datetime import timedelta
from pathlib import Path

import pytest
import secp_reconciliation
from reconciliation_support import NOW, desired, edge, network, node, observed, scope
from secp_reconciliation.v1 import (
    DriftKind,
    ReconciliationRefused,
    RefusalCode,
    ResetScope,
    build_reconciliation_evidence,
    build_refusal_evidence,
    build_reset_intent,
    canonical_json,
    plan_from_states,
)

# Values a collector could plausibly report that must never reach a contract output. Each is
# distinctive enough that a substring search cannot match it by accident.
SENTINELS = (
    "ZZPROVIDERREFZZ",
    "ZZ198.51.100.77ZZ",
    "ZZhttps://provider.invalid/api2/nodes/pve1ZZ",
    "ZZ/var/lib/vz/images/9001ZZ",
    "ZZBEGIN-PRIVATE-KEY-MATERIALZZ",
    "ZZroot@pam!token=deadbeefZZ",
)


def _observed_full_of_sentinels():
    return observed(
        network(
            "team-network",
            name=SENTINELS[0],
            address_space=SENTINELS[1],
            team=SENTINELS[2],
        ),
        node(
            "attacker-1",
            name=SENTINELS[2],
            role=SENTINELS[3],
            image=SENTINELS[4],
            address=SENTINELS[1],
        ),
        node(SENTINELS[0] + "-unmanaged", name=SENTINELS[5], image=SENTINELS[4]),
        node(SENTINELS[5] + "-also-unmanaged", image=SENTINELS[3]),
    )


def _occurrences(haystack: str) -> int:
    return sum(haystack.count(sentinel) for sentinel in SENTINELS)


def test_the_leak_scanner_finds_sentinels_when_they_are_present() -> None:
    """Positive control. Without this the zero-occurrence assertions below prove nothing about
    the scanner, only that it never matches."""
    assert _occurrences("prefix" + SENTINELS[0] + "suffix") == 1
    assert _occurrences(SENTINELS[1] + SENTINELS[1] + SENTINELS[4]) == 3
    assert _occurrences("nothing here") == 0


def test_no_provider_supplied_value_or_identity_reaches_any_contract_output() -> None:
    _, report, plan = plan_from_states(
        scope=scope(),
        desired=desired(network(), node()),
        observed=_observed_full_of_sentinels(),
        now=NOW,
    )
    intent = build_reset_intent(
        plan=plan,
        reset_scope=ResetScope.element_set,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    evidence = build_reconciliation_evidence(
        scope=scope(), report=report, plan=plan, evaluated_at=NOW
    )

    # The observation really did drive the outcome, so this is not a vacuous scan.
    assert any(finding.kind is DriftKind.divergent for finding in report.findings)
    assert len([f for f in report.findings if f.kind is DriftKind.unmanaged]) == 2
    assert plan.actions

    rendered = "\n".join(
        (
            repr(report),
            repr(plan),
            repr(intent),
            canonical_json(intent.document()),
            canonical_json(evidence),
        )
    )
    assert _occurrences(rendered) == 0


def test_an_unmanaged_finding_never_carries_a_reference_while_a_desired_side_one_does() -> None:
    _, report, _ = plan_from_states(
        scope=scope(),
        desired=desired(network(), node()),
        observed=_observed_full_of_sentinels(),
        now=NOW,
    )
    by_kind = {}
    for finding in report.findings:
        by_kind.setdefault(finding.kind, []).append(finding)
    assert all(finding.element_ref == "" for finding in by_kind[DriftKind.unmanaged])
    authored = {"team-network", "attacker-1"}
    assert all(
        finding.element_ref in authored
        for kind, findings in by_kind.items()
        if kind is not DriftKind.unmanaged
        for finding in findings
    )


def test_every_reference_a_plan_emits_is_one_the_desired_state_authored() -> None:
    wanted = desired(network(), node(), edge())
    _, _, plan = plan_from_states(
        scope=scope(), desired=wanted, observed=_observed_full_of_sentinels(), now=NOW
    )
    authored = {element.ref for element in wanted.elements}
    assert plan.actions
    assert {action.element_ref for action in plan.actions} <= authored


# --- Refusal shape ---------------------------------------------------------------------------


@pytest.mark.parametrize("code", list(RefusalCode))
def test_a_refusal_carries_only_its_bounded_code(code) -> None:
    error = ReconciliationRefused(code)
    assert error.args == (code.value,)
    assert str(error) == code.value
    assert vars(error) == {"code": code}
    assert _occurrences(repr(error)) == 0


def test_a_refusal_provoked_by_hostile_input_still_carries_only_its_code() -> None:
    hostile = observed(
        network(name=SENTINELS[0], address_space=SENTINELS[1]),
        collector_digest=SENTINELS[2],
    )
    with pytest.raises(ReconciliationRefused) as raised:
        plan_from_states(scope=scope(), desired=desired(network()), observed=hostile, now=NOW)
    error = raised.value
    assert error.code is RefusalCode.observation_unverified
    assert _occurrences(repr(error) + str(error) + repr(error.args)) == 0


def test_refusal_evidence_records_the_code_and_nothing_about_the_input() -> None:
    document = build_refusal_evidence(
        scope=scope(), code=RefusalCode.observed_state_inconsistent, evaluated_at=NOW
    )
    assert _occurrences(canonical_json(document)) == 0
    assert document["refusal_code"] == "reconciliation_observed_state_inconsistent"


# --- Dependency closure of the core -----------------------------------------------------------

# Modules the reconciliation core may import. Every one is pure computation: no socket, no HTTP,
# no subprocess, no filesystem, no provider SDK. `datetime` is here because freshness is compared,
# never read: the contract takes `now` as a parameter and calls no clock (asserted below).
ALLOWED_STDLIB_IMPORTS = frozenset(
    {"__future__", "dataclasses", "datetime", "enum", "hashlib", "ipaddress", "json"}
)

# First-party packages that are part of the surface being scanned.
SCANNED_PACKAGES = frozenset({"secp_reconciliation", "secp_plugin_simulator"})

# Which first-party packages each scanned package may import. This is a *layering* rule, and it has
# to be a per-package map rather than one flat allow-set: the contract is the lower layer, so a
# plugin may depend on it and it may not depend on a plugin. A flat "these packages are under scan,
# so importing them adds nothing" set permits both directions, which means the core could import a
# plugin package -- a layering inversion -- with every guard here still green.
FIRST_PARTY_IMPORTS_BY_PACKAGE: dict[str, frozenset[str]] = {
    "secp_reconciliation": frozenset({"secp_reconciliation"}),
    "secp_plugin_simulator": frozenset({"secp_plugin_simulator", "secp_reconciliation"}),
}


def _first_party_allowed(module_name: str) -> frozenset[str]:
    return FIRST_PARTY_IMPORTS_BY_PACKAGE[module_name.split(".", 1)[0]]


def test_the_first_party_layering_is_declared_for_every_scanned_package_and_is_asymmetric() -> None:
    """The rule the map exists to express, asserted directly: a plugin may import the contract, and
    the contract may not import a plugin. A symmetric rule would not be a layering at all."""
    assert set(FIRST_PARTY_IMPORTS_BY_PACKAGE) == SCANNED_PACKAGES
    assert "secp_reconciliation" in FIRST_PARTY_IMPORTS_BY_PACKAGE["secp_plugin_simulator"]
    assert "secp_plugin_simulator" not in FIRST_PARTY_IMPORTS_BY_PACKAGE["secp_reconciliation"]
    for package, allowed in FIRST_PARTY_IMPORTS_BY_PACKAGE.items():
        assert package in allowed, package
        assert allowed <= SCANNED_PACKAGES, package


# Narrow, reviewed exceptions as ``(module, imported top-level name)`` pairs. A bare module name
# would exempt a whole file, and a bare import name would exempt it everywhere — a pair exempts
# exactly one edge. `topology_adapter` is the contract's single declared seam onto the plugin
# contract; `plugin` is the pre-existing simulator plugin, untouched by this milestone.
IMPORT_EXCEPTIONS: tuple[tuple[str, str], ...] = (
    ("secp_reconciliation.v1.topology_adapter", "secp_plugin_api"),
    ("secp_plugin_simulator.plugin", "secp_plugin_api"),
    ("secp_plugin_simulator.plugin", "secp_scenario_schema"),
)


def test_every_import_exception_is_a_module_and_name_pair() -> None:
    """A bare-name exception list is structurally forbidden: an entry that is not a 2-tuple would
    exempt an import everywhere it appears rather than at one reviewed edge."""
    for entry in IMPORT_EXCEPTIONS:
        assert isinstance(entry, tuple)
        assert len(entry) == 2
        assert all(isinstance(part, str) and part for part in entry)


def test_the_exception_set_is_exactly_the_reviewed_one_the_adr_describes() -> None:
    """ADR-029 states how many exceptions exist and which package each belongs to. That is a
    countable claim, so it is counted here rather than left to a reader: a fourth exception, or a
    contract-side one beyond the single `topology_adapter` seam, fails until the ADR is updated
    with it.
    """
    assert set(IMPORT_EXCEPTIONS) == {
        ("secp_reconciliation.v1.topology_adapter", "secp_plugin_api"),
        ("secp_plugin_simulator.plugin", "secp_plugin_api"),
        ("secp_plugin_simulator.plugin", "secp_scenario_schema"),
    }
    contract_side = [
        entry for entry in IMPORT_EXCEPTIONS if entry[0].startswith("secp_reconciliation.")
    ]
    assert contract_side == [("secp_reconciliation.v1.topology_adapter", "secp_plugin_api")]

    adr = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "adr"
        / "ADR-029-reconciliation-and-drift-foundation.md"
    )
    body = " ".join(adr.read_text(encoding="utf-8").replace("`", "").split())
    assert "three of them, of which this milestone adds one" in body
    assert len(IMPORT_EXCEPTIONS) == 3
    assert "a plugin may import the contract; the contract may not import a plugin" in body


def _package_sources() -> list[tuple[str, Path]]:
    """Every source file of every scanned package, keyed by dotted module name. Discovered by
    walking the packages rather than listed, so a module added later is scanned automatically."""
    import secp_plugin_simulator

    found: list[tuple[str, Path]] = []
    for package in (secp_reconciliation, secp_plugin_simulator):
        root = Path(package.__file__).resolve().parent
        for path in sorted(root.rglob("*.py")):
            relative = path.relative_to(root).with_suffix("")
            parts = [part for part in relative.parts if part != "__init__"]
            found.append((".".join([package.__name__, *parts]), path))
    return found


def test_the_scan_covers_every_module_in_both_packages() -> None:
    names = {name for name, _ in _package_sources()}
    assert "secp_reconciliation" in names
    assert "secp_reconciliation.v1.topology_adapter" in names
    assert "secp_plugin_simulator.reconciliation" in names
    # every scanned module is importable under its scanned name (so the name is real, not derived)
    import importlib

    for name in sorted(names):
        assert isinstance(importlib.import_module(name), types.ModuleType)


def test_the_core_imports_only_pure_computation() -> None:
    violations: list[tuple[str, str]] = []
    for module_name, path in _package_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for statement in ast.walk(tree):
            if isinstance(statement, ast.Import):
                imported = [alias.name.split(".", 1)[0] for alias in statement.names]
            elif isinstance(statement, ast.ImportFrom):
                imported = [(statement.module or "").split(".", 1)[0]]
            else:
                continue
            allowed_first_party = _first_party_allowed(module_name)
            for name in imported:
                if name in ALLOWED_STDLIB_IMPORTS or name in allowed_first_party:
                    continue
                if (module_name, name) in IMPORT_EXCEPTIONS:
                    continue
                violations.append((module_name, name))
    assert violations == []


def test_no_exception_pair_is_stale() -> None:
    """An exception that no longer describes a real import is a licence nobody is using; it must
    be removed rather than left to authorize a future import silently."""
    edges: set[tuple[str, str]] = set()
    for module_name, path in _package_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for statement in ast.walk(tree):
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    edges.add((module_name, alias.name.split(".", 1)[0]))
            elif isinstance(statement, ast.ImportFrom):
                edges.add((module_name, (statement.module or "").split(".", 1)[0]))
    assert set(IMPORT_EXCEPTIONS) <= edges


def test_no_loaded_module_object_in_the_core_references_an_unallowed_module() -> None:
    """The static scan above reads source; this reads the *loaded* objects, so an import that
    arrived some other way still has to be an allowed one."""
    import importlib

    violations: list[tuple[str, str]] = []
    for module_name, _ in _package_sources():
        module = importlib.import_module(module_name)
        allowed_first_party = _first_party_allowed(module_name)
        for attribute, value in vars(module).items():
            if not isinstance(value, types.ModuleType):
                continue
            top_level = value.__name__.split(".", 1)[0]
            if top_level in ALLOWED_STDLIB_IMPORTS or top_level in allowed_first_party:
                continue
            if (module_name, top_level) in IMPORT_EXCEPTIONS:
                continue
            violations.append((module_name, attribute))
    assert violations == []
