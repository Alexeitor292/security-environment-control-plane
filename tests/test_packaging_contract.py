"""The packaging contract: every Python package is classified, and the classification is enforced.

THE HOLE THIS CLOSES
--------------------
``pyproject.toml`` declares each package three times (wheel ``packages``, pytest ``pythonpath``,
mypy ``mypy_path``) and ``infra/dev/Dockerfile.python`` COPYies each root a fourth time. The
existing image-closure guard checks the Dockerfile against the wheel list — but it DERIVES its
expectation from that same wheel list, and its second anchor (``_EXPECTED_PACKAGE_ROOTS``) is
hand-maintained in the test file. So a coordinated edit to those two places drops a package from the
wheel and the production image with every test still green, and the failure appears at runtime as
``ModuleNotFoundError``.

WHY NOT SIMPLY ASSERT THE THREE LISTS AGREE
-------------------------------------------
Because they must not always agree, and a guard that says otherwise is wrong in a way that is
expensive to discover: it goes red on a correct change, authored by someone who has no idea a guard
written elsewhere redefined what their ``pyproject.toml`` edit was allowed to look like. A test
harness must be importable and type-checked and must never ship in the production image. That
asymmetry is legitimate, so it is DECLARED in ``packaging-contract.toml`` and enforced as declared.

Worth recording precisely, because the proposal that prompted this was justified by a measurement
that does not hold: the three lists are NOT "identical, 10 entries each". Measured on ``main`` at
``bfdccd7e``, wheel ``packages`` had 10 entries while ``pythonpath`` and ``mypy_path`` had 9 — they
agree only after deriving package ROOTS from the wheel entries (10 packages over 9 roots, because
``apps/deployment`` hosts two), and compared as written their symmetric difference was 19, not 0. A
literal equality guard would have been red on the day it landed.

Those numbers are recorded here as a dated observation, NOT asserted anywhere. What
``test_the_three_lists_are_not_naively_equal`` pins is the invariant SHAPE behind them — wheel
entries are ``<root>/<name>`` while the two paths are ``<root>``, so they can never be equal as
written. Asserting the counts would make this file fail on every legitimate package addition, which
is the same trap the flat equality rule falls into.

THE ANCHOR IS THE FILESYSTEM
----------------------------
This file does not trust ``pyproject.toml`` or ``packaging-contract.toml`` to enumerate the
packages, because both are editable in the same breath — which IS the failure. It discovers package
directories on disk and requires each to be declared. Deleting a package from the wheel list and
from the manifest therefore leaves it discovered-but-undeclared, and this refuses. The only silent
path out is to actually delete the code, which is a real removal.

WHY THE RULES ARE A PURE FUNCTION
---------------------------------
:func:`contract_violations` takes the four inputs as plain data and returns the violations. The
repository is then one input among many, which matters because the repository currently contains
ZERO ``importable-only`` packages — the class that motivated the whole contract. Parametrising the
importable-only rules over the real manifest produced two *skips*, and a skipped body proves nothing
about itself while rendering as a pass. Driving the same rules over constructed inputs makes every
rule execute today, and :func:`test_the_real_repository_satisfies_the_contract` still holds the real
tree to all of them.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_PYPROJECT = _REPO / "pyproject.toml"
_MANIFEST = _REPO / "packaging-contract.toml"
_DOCKERFILE = _REPO / "infra" / "dev" / "Dockerfile.python"

CONTRACT_VERSION = "secp.packaging-contract/v1"

SHIPPED = "shipped"
IMPORTABLE_ONLY = "importable-only"
#: Closed on purpose. A third value is a refusal, never a behaviour to be inferred.
DISTRIBUTIONS = frozenset({SHIPPED, IMPORTABLE_ONLY})

_REQUIRED_KEYS = frozenset({"root", "distribution", "why"})
_MIN_WHY = 40

#: Directories that contain package ROOTS (``<container>/<root>/<package>``). Discovery walks these
#: rather than the whole tree; :func:`test_discovery_covers_every_wheel_package` proves the walk is
#: wide enough to see everything the wheel actually declares.
_CONTAINERS = ("apps", "contracts", "plugins")


# --------------------------------------------------------------------------- the rules


@dataclass(frozen=True)
class PackagingInputs:
    """Everything the contract is a function of. Plain data, so it can be constructed."""

    discovered: dict[str, str]  # name -> root, read from the FILESYSTEM
    declared: dict[str, dict]  # name -> {root, distribution, why}
    wheel_packages: tuple[str, ...]
    pythonpath: tuple[str, ...]
    mypy_path: tuple[str, ...]
    copied_before_install: frozenset[str]  # Dockerfile COPY sources preceding the install
    copied_at_all: frozenset[str]
    scripts: dict[str, str] = field(default_factory=dict)


def _covers(root: str, sources: frozenset[str]) -> bool:
    return any(root == source or root.startswith(source + "/") for source in sources)


def contract_violations(inputs: PackagingInputs) -> list[str]:
    """Every way the declared contract is not satisfied, as sorted bounded strings.

    Returns a LIST rather than raising, so one run reports every violation instead of only the
    first — a guard that stops at the first problem trains people to fix them one CI run at a time.
    """
    problems: list[str] = []

    # --- the anchor: disk and manifest must agree on WHICH packages exist ---
    for name in sorted(set(inputs.discovered) - set(inputs.declared)):
        problems.append(
            f"undeclared: {name} exists on disk ({inputs.discovered[name]}) but is not classified"
        )
    for name in sorted(set(inputs.declared) - set(inputs.discovered)):
        problems.append(f"stale: {name} is declared but has no code on disk")

    for name in sorted(set(inputs.declared) & set(inputs.discovered)):
        entry = inputs.declared[name]
        root = entry.get("root")
        if root != inputs.discovered[name]:
            problems.append(
                f"root-mismatch: {name} declares {root!r}, disk says {inputs.discovered[name]!r}"
            )
            continue

        # --- the declaration itself must be complete; nothing defaults ---
        if set(entry) != _REQUIRED_KEYS:
            problems.append(f"malformed: {name} has keys {sorted(entry)}")
            continue
        distribution = entry["distribution"]
        if distribution not in DISTRIBUTIONS:
            problems.append(f"unknown-distribution: {name} declares {distribution!r}")
            continue
        if not isinstance(entry["why"], str) or len(entry["why"].strip()) < _MIN_WHY:
            problems.append(f"unjustified: {name} has no real reason recorded")

        wheel_entry = f"{root}/{name}"
        if distribution == SHIPPED:
            if wheel_entry not in inputs.wheel_packages:
                problems.append(f"shipped-not-in-wheel: {name} would not be installed")
            if root not in inputs.pythonpath:
                problems.append(f"shipped-not-on-pythonpath: {name} ({root})")
            if root not in inputs.mypy_path:
                problems.append(f"shipped-not-on-mypy-path: {name} ({root})")
            if not _covers(root, inputs.copied_before_install):
                problems.append(
                    f"shipped-not-in-image: {root} is not COPYied before the install, so "
                    f"{name} installs but fails to import at runtime"
                )
        else:  # importable-only
            if root not in inputs.pythonpath:
                problems.append(f"importable-only-not-on-pythonpath: {name} ({root})")
            if root not in inputs.mypy_path:
                problems.append(f"importable-only-not-on-mypy-path: {name} ({root})")
            if wheel_entry in inputs.wheel_packages:
                problems.append(f"importable-only-in-wheel: {name} must not be installed")
            if _covers(root, inputs.copied_at_all):
                problems.append(
                    f"importable-only-in-image: {root} is COPYied into the production image"
                )

    # --- the wheel may not carry something unclassified or classified otherwise ---
    shipped = {n for n, e in inputs.declared.items() if e.get("distribution") == SHIPPED}
    for entry_path in inputs.wheel_packages:
        root, name = entry_path.rsplit("/", 1)
        if name not in shipped:
            problems.append(f"wheel-carries-unshipped: {name} is in the wheel but not '{SHIPPED}'")
        elif inputs.declared[name].get("root") != root:
            problems.append(f"wheel-root-mismatch: {name} at {root}")

    # --- an importable-only package may not share a ROOT with a shipped one ---
    # The image COPYies by root, so a shared root carries the importable-only package in regardless
    # of its declaration: true on paper, false in the artifact.
    shipped_roots = {inputs.declared[n].get("root") for n in shipped}
    for name, entry in sorted(inputs.declared.items()):
        if entry.get("distribution") == IMPORTABLE_ONLY and entry.get("root") in shipped_roots:
            problems.append(
                f"shared-root: {name} is '{IMPORTABLE_ONLY}' but shares root "
                f"{entry.get('root')!r} with a shipped package, so the image ships it anyway"
            )

    # --- an installed entry point must resolve inside the wheel ---
    importable_only = {
        n for n, e in inputs.declared.items() if e.get("distribution") == IMPORTABLE_ONLY
    }
    for script, target in sorted(inputs.scripts.items()):
        top_level = target.split(":", 1)[0].split(".", 1)[0]
        if top_level in importable_only:
            problems.append(f"script-targets-unshipped: {script} -> {top_level}")

    return sorted(problems)


# --------------------------------------------------------------------------- readers


def _pyproject() -> dict:
    return tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))


def _manifest() -> dict:
    return tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))


class DuplicatePackageName(AssertionError):
    """Two package roots declare the same top-level import name."""


def discover_packages(repo: Path | None = None) -> dict[str, str]:
    """Every importable package directory on disk, as ``{package_name: root}``.

    The independent witness. Reads neither ``pyproject.toml`` nor the manifest.

    Refuses a duplicate top-level name rather than letting the later root win. Keying by name is
    what makes the manifest readable, but it means a collision would silently collapse two packages
    into one entry — and the one that vanished would then be neither discovered nor required to be
    declared, which is a hole in the anchor itself. (Python could not import both anyway; one would
    shadow the other depending on path order.)
    """
    base = repo or _REPO
    found: dict[str, str] = {}
    for container in _CONTAINERS:
        container_dir = base / container
        if not container_dir.is_dir():
            continue
        for root in sorted(container_dir.iterdir()):
            if not root.is_dir():
                continue
            for candidate in sorted(root.iterdir()):
                if candidate.is_dir() and (candidate / "__init__.py").is_file():
                    where = f"{container}/{root.name}"
                    if candidate.name in found:
                        raise DuplicatePackageName(
                            f"{candidate.name} exists under both {found[candidate.name]} and "
                            f"{where}; one would shadow the other and only one could be declared"
                        )
                    found[candidate.name] = where
    return found


def _copy_sources(text: str) -> list[tuple[int, str]]:
    """``(position, source)`` for every project source the Dockerfile COPYies.

    Behaviourally identical to the reader in ``test_python_image_package_closure.py`` so the two
    guards cannot disagree about what the Dockerfile SAYS while disagreeing about what it should.
    """
    joined = text.replace("\\\n", " ")
    out: list[tuple[int, str]] = []
    for line in joined.splitlines():
        stripped = line.strip()
        if not stripped.upper().startswith("COPY "):
            continue
        tokens = stripped.split()[1:]
        if any(token.startswith("--") for token in tokens) or len(tokens) < 2:
            continue
        for source in tokens[:-1]:
            cleaned = source.removeprefix("./").rstrip("/") or "."
            out.append((text.find(f"COPY {source}"), cleaned))
    return out


def real_inputs() -> PackagingInputs:
    pyproject = _pyproject()
    text = _DOCKERFILE.read_text(encoding="utf-8")
    install_index = text.find("uv pip install")
    assert install_index != -1, "the Dockerfile must install the project"
    sources = _copy_sources(text)
    return PackagingInputs(
        discovered=discover_packages(),
        declared=_manifest().get("packages", {}),
        wheel_packages=tuple(pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]),
        pythonpath=tuple(pyproject["tool"]["pytest"]["ini_options"]["pythonpath"]),
        mypy_path=tuple(pyproject["tool"]["mypy"]["mypy_path"]),
        copied_before_install=frozenset(
            source for position, source in sources if 0 <= position < install_index
        ),
        copied_at_all=frozenset(source for _, source in sources),
        scripts=dict(pyproject["project"]["scripts"]),
    )


# --------------------------------------------------------------------------- the real repository


def test_the_manifest_exists_and_declares_its_contract_version():
    assert _MANIFEST.is_file(), "packaging-contract.toml is missing"
    assert _manifest()["contract"]["version"] == CONTRACT_VERSION


def test_discovery_is_not_vacuous():
    """If discovery found nothing, "every discovered package is declared" would be trivially true
    and this whole file would prove nothing."""
    found = discover_packages()
    assert len(found) >= 10, f"discovery found only {sorted(found)}"
    assert found.get("secp_api") == "apps/api"


def _make_package(base: Path, container: str, root: str, name: str) -> None:
    package = base / container / root / name
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")


def test_discovery_actually_walks_a_tree(tmp_path: Path):
    """CONTROL for the anchor. Every "is it declared?" assertion rests on this walk, and against
    the real repo a walk that returned a hardcoded answer would look identical."""
    _make_package(tmp_path, "apps", "alpha", "secp_alpha")
    _make_package(tmp_path, "plugins", "beta", "secp_beta")
    (tmp_path / "apps" / "alpha" / "not_a_package").mkdir()  # no __init__.py
    assert discover_packages(tmp_path) == {
        "secp_alpha": "apps/alpha",
        "secp_beta": "plugins/beta",
    }


def test_discovery_refuses_a_duplicate_top_level_name(tmp_path: Path):
    """A collision must not silently collapse two packages into one entry — the one that vanished
    would be neither discovered nor required to be declared, a hole in the anchor itself."""
    _make_package(tmp_path, "apps", "one", "secp_same")
    _make_package(tmp_path, "apps", "two", "secp_same")
    with pytest.raises(DuplicatePackageName) as exc:
        discover_packages(tmp_path)
    assert "secp_same" in str(exc.value)


def test_the_real_repository_has_no_duplicate_package_names():
    discover_packages()  # raises DuplicatePackageName if it does


def test_discovery_covers_every_wheel_package():
    """The walk must be at least as wide as the wheel list, or the anchor has a hole exactly where
    it matters most."""
    found = discover_packages()
    for entry in real_inputs().wheel_packages:
        root, name = entry.rsplit("/", 1)
        assert name in found, f"wheel declares {name} but discovery cannot see it (root {root})"
        assert found[name] == root


def test_the_real_repository_satisfies_the_contract():
    """The whole contract, over the real tree."""
    assert contract_violations(real_inputs()) == []


def test_the_three_lists_are_not_naively_equal():
    """Pins the STRUCTURE that makes a flat equality guard wrong, so it is not re-proposed.

    Deliberately free of hardcoded counts. At the time of writing they were 10 / 9 / 9 with a
    symmetric difference of 19 — but asserting those numbers would make this test fail on every
    legitimate package addition, which is the same trap the flat equality rule falls into. What is
    invariant is the SHAPE: wheel entries are ``<root>/<name>`` while the two paths are ``<root>``,
    so they can never be equal as written and can only agree after deriving roots.
    """
    inputs = real_inputs()
    assert inputs.wheel_packages and inputs.pythonpath and inputs.mypy_path
    assert set(inputs.wheel_packages) != set(inputs.pythonpath), (
        "wheel entries are <root>/<name>; pythonpath entries are <root>. If these ever compare "
        "equal, the shape assumed throughout this file has changed."
    )
    shipped_roots = {entry.rsplit("/", 1)[0] for entry in inputs.wheel_packages}
    # Every SHIPPED root must be on both paths. The reverse does not hold — an importable-only root
    # is on both paths and in no wheel entry — which is exactly the asymmetry a flat rule forbids.
    assert shipped_roots <= set(inputs.pythonpath)
    assert shipped_roots <= set(inputs.mypy_path)
    assert set(inputs.pythonpath) == set(inputs.mypy_path), (
        "importable or type-checked, but not both, is never intentional"
    )


def test_the_declared_shape_is_recorded_and_consistent():
    """Reports today's composition without gating on it.

    An earlier version asserted "exactly 10 shipped and 0 importable-only" on the grounds that a
    floor would let a package be added without anyone re-reading the manifest. That reasoning was
    wrong: :func:`test_every_package_on_disk_is_declared` already makes it impossible to add a
    package without editing the manifest, so the exact count added no protection and would have
    gone red on the first legitimate addition — reproducing, in miniature, the very failure this
    contract exists to prevent. Found by running the future state rather than reasoning about it.
    """
    declared = real_inputs().declared
    assert declared, "the manifest declares nothing"
    for name, entry in declared.items():
        assert entry["distribution"] in DISTRIBUTIONS, name
    # every declared package is discoverable and vice versa — the anchor, restated as one equality
    assert set(declared) == set(discover_packages())


# --------------------------------------------------------------------------- constructed inputs
#
# Every rule below executes TODAY, including the importable-only rules the real tree has no instance
# of. `_case` starts from a minimal, satisfied contract; each test perturbs exactly one thing.


def _case(**overrides) -> PackagingInputs:
    """A minimal SATISFIED contract, so any violation below is attributable to the perturbation."""
    base = {
        "discovered": {"secp_thing": "apps/thing"},
        "declared": {
            "secp_thing": {
                "root": "apps/thing",
                "distribution": SHIPPED,
                "why": "x" * _MIN_WHY,
            }
        },
        "wheel_packages": ("apps/thing/secp_thing",),
        "pythonpath": ("apps/thing",),
        "mypy_path": ("apps/thing",),
        "copied_before_install": frozenset({"apps/thing"}),
        "copied_at_all": frozenset({"apps/thing"}),
        "scripts": {},
    }
    base.update(overrides)
    return PackagingInputs(**base)  # type: ignore[arg-type]


def test_the_baseline_case_is_actually_satisfied():
    """CONTROL for every constructed test below. If the baseline already had violations, each
    perturbation would 'fail' for reasons that have nothing to do with it."""
    assert contract_violations(_case()) == []


# --- the original hole -------------------------------------------------------------------


def test_the_coordinated_two_place_removal_is_refused():
    """THE deliverable. Drop the package from the wheel list AND from the manifest — the exact edit
    that used to leave every test green — and the contract refuses, because the code is still on
    disk and is now unclassified."""
    violations = contract_violations(_case(declared={}, wheel_packages=()))
    assert violations == [
        "undeclared: secp_thing exists on disk (apps/thing) but is not classified"
    ]


def test_dropping_it_from_the_wheel_alone_is_also_refused():
    """The one-place version, which the old guard did catch — kept so a future simplification cannot
    quietly trade the easy case away for the hard one."""
    violations = contract_violations(_case(wheel_packages=()))
    assert "shipped-not-in-wheel: secp_thing would not be installed" in violations


def test_actually_deleting_the_code_is_a_clean_removal():
    """The escape hatch must exist and must be honest: remove the package from disk, the wheel and
    the manifest together and there is no violation. Otherwise the contract would forbid deleting a
    package, and the pressure would go straight back to weakening the guard."""
    assert contract_violations(_case(discovered={}, declared={}, wheel_packages=())) == []


def test_a_declaration_left_behind_after_the_code_is_deleted_is_refused():
    violations = contract_violations(_case(discovered={}, wheel_packages=()))
    assert violations == ["stale: secp_thing is declared but has no code on disk"]


# --- nothing defaults ---------------------------------------------------------------------


def test_an_unknown_distribution_refuses_rather_than_defaulting():
    """A third value is refused outright. It also, correctly, makes the wheel entry unaccounted for:
    an unclassifiable package cannot be the thing that authorises shipping it. Both are asserted, so
    a later change that dropped either one would be visible."""
    entry = {"root": "apps/thing", "distribution": "internal", "why": "x" * _MIN_WHY}
    assert contract_violations(_case(declared={"secp_thing": entry})) == [
        "unknown-distribution: secp_thing declares 'internal'",
        "wheel-carries-unshipped: secp_thing is in the wheel but not 'shipped'",
    ]


def test_a_missing_distribution_key_refuses():
    """Absent is not a value either — there is no default to fall back to."""
    entry = {"root": "apps/thing", "why": "x" * _MIN_WHY}
    assert contract_violations(_case(declared={"secp_thing": entry})) == [
        "malformed: secp_thing has keys ['root', 'why']",
        "wheel-carries-unshipped: secp_thing is in the wheel but not 'shipped'",
    ]


def test_an_empty_justification_refuses():
    entry = {"root": "apps/thing", "distribution": SHIPPED, "why": "   "}
    assert "unjustified: secp_thing has no real reason recorded" in contract_violations(
        _case(declared={"secp_thing": entry})
    )


def test_a_declared_root_that_disagrees_with_disk_refuses():
    entry = {"root": "apps/elsewhere", "distribution": SHIPPED, "why": "x" * _MIN_WHY}
    violations = contract_violations(_case(declared={"secp_thing": entry}))
    assert violations[0].startswith("root-mismatch: secp_thing")


# --- the importable-only class, exercised today -------------------------------------------


def _acceptance_like(**overrides) -> PackagingInputs:
    """The shape ``apps/acceptance`` will have: importable, type-checked, never shipped.

    Modelled on the real incoming case rather than an abstract one, so if the rules are wrong for
    that case they are wrong here.
    """
    base = {
        "discovered": {"secp_thing": "apps/thing", "secp_acceptance": "apps/acceptance"},
        "declared": {
            "secp_thing": {
                "root": "apps/thing",
                "distribution": SHIPPED,
                "why": "x" * _MIN_WHY,
            },
            "secp_acceptance": {
                "root": "apps/acceptance",
                "distribution": IMPORTABLE_ONLY,
                "why": "y" * _MIN_WHY,
            },
        },
        "wheel_packages": ("apps/thing/secp_thing",),
        "pythonpath": ("apps/thing", "apps/acceptance"),
        "mypy_path": ("apps/thing", "apps/acceptance"),
        "copied_before_install": frozenset({"apps/thing"}),
        "copied_at_all": frozenset({"apps/thing"}),
        "scripts": {},
    }
    base.update(overrides)
    return PackagingInputs(**base)  # type: ignore[arg-type]


def test_a_declared_importable_only_package_is_accepted():
    """The asymmetry must PASS — and pass because it was declared, which the next two tests
    establish by showing the same shape refused when the declaration is absent or different."""
    assert contract_violations(_acceptance_like()) == []


def test_the_same_asymmetry_undeclared_is_refused():
    """Attribution: identical inputs, declaration removed. If this passed, the previous test would
    be passing because the guard is weak rather than because the package is declared."""
    declared = dict(_acceptance_like().declared)
    del declared["secp_acceptance"]
    violations = contract_violations(_acceptance_like(declared=declared))
    assert violations == [
        "undeclared: secp_acceptance exists on disk (apps/acceptance) but is not classified"
    ]


def test_the_same_asymmetry_declared_shipped_is_refused():
    """The other half of the attribution: the classification, not merely its presence, is what the
    guard acts on. Declared ``shipped``, the identical layout is refused three ways."""
    declared = {
        name: (dict(entry) | {"distribution": SHIPPED} if name == "secp_acceptance" else entry)
        for name, entry in _acceptance_like().declared.items()
    }
    violations = contract_violations(_acceptance_like(declared=declared))
    assert "shipped-not-in-wheel: secp_acceptance would not be installed" in violations
    assert any(v.startswith("shipped-not-in-image: apps/acceptance") for v in violations)


def test_an_importable_only_package_that_reaches_the_wheel_is_refused():
    violations = contract_violations(
        _acceptance_like(
            wheel_packages=("apps/thing/secp_thing", "apps/acceptance/secp_acceptance")
        )
    )
    assert "importable-only-in-wheel: secp_acceptance must not be installed" in violations


def test_an_importable_only_package_copied_into_the_image_is_refused():
    violations = contract_violations(
        _acceptance_like(copied_at_all=frozenset({"apps/thing", "apps/acceptance"}))
    )
    assert violations == [
        "importable-only-in-image: apps/acceptance is COPYied into the production image"
    ]


def test_a_whole_repo_copy_would_ship_an_importable_only_package():
    """The realistic version of the previous test. A Dockerfile that copies ``.`` or ``apps`` sweeps
    the harness into the image without ever naming it — the failure would be invisible to any check
    that looked for the literal path."""
    violations = contract_violations(_acceptance_like(copied_at_all=frozenset({"apps"})))
    assert "importable-only-in-image: apps/acceptance is COPYied into the production image" in (
        violations
    )


def test_an_importable_only_package_must_still_be_importable_and_type_checked():
    violations = contract_violations(_acceptance_like(pythonpath=("apps/thing",)))
    assert "importable-only-not-on-pythonpath: secp_acceptance (apps/acceptance)" in violations
    violations = contract_violations(_acceptance_like(mypy_path=("apps/thing",)))
    assert "importable-only-not-on-mypy-path: secp_acceptance (apps/acceptance)" in violations


def test_an_importable_only_package_may_not_share_a_root_with_a_shipped_one():
    """The image copies by ROOT, so a shared root ships it regardless of the declaration — the
    declaration would be true on paper and false in the artifact."""
    declared = {
        "secp_thing": {"root": "apps/thing", "distribution": SHIPPED, "why": "x" * _MIN_WHY},
        "secp_helper": {
            "root": "apps/thing",
            "distribution": IMPORTABLE_ONLY,
            "why": "y" * _MIN_WHY,
        },
    }
    violations = contract_violations(
        _case(
            discovered={"secp_thing": "apps/thing", "secp_helper": "apps/thing"},
            declared=declared,
        )
    )
    assert any(v.startswith("shared-root: secp_helper") for v in violations)


# --- the wheel's own reverse direction ----------------------------------------------------


def test_the_wheel_may_not_carry_an_undeclared_package():
    violations = contract_violations(
        _case(wheel_packages=("apps/thing/secp_thing", "apps/ghost/secp_ghost"))
    )
    assert "wheel-carries-unshipped: secp_ghost is in the wheel but not 'shipped'" in violations


def test_a_console_script_may_not_target_an_importable_only_package():
    violations = contract_violations(
        _acceptance_like(scripts={"secp-acc": "secp_acceptance.cli:main"})
    )
    assert "script-targets-unshipped: secp-acc -> secp_acceptance" in violations


def test_a_console_script_targeting_a_shipped_package_is_fine():
    assert contract_violations(_case(scripts={"secp-thing": "secp_thing.cli:main"})) == []


# --- the image ordering rule --------------------------------------------------------------


def test_a_package_copied_only_after_the_install_is_refused():
    """Copied, but too late. The editable install resolves the package closure at install time, so a
    tree that arrives afterwards produces an image that builds clean and fails on import."""
    violations = contract_violations(
        _case(copied_before_install=frozenset(), copied_at_all=frozenset({"apps/thing"}))
    )
    assert any(v.startswith("shipped-not-in-image: apps/thing") for v in violations)


def test_violations_are_reported_together_not_one_per_run():
    """A guard that stops at the first problem trains people to fix them one CI run at a time."""
    violations = contract_violations(
        _case(wheel_packages=(), pythonpath=(), mypy_path=(), copied_before_install=frozenset())
    )
    assert len(violations) == 4
