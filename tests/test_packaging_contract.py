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

THE TWO AXES ARE INDEPENDENT, AND A TWO-VALUE MODEL DENIED IT
-------------------------------------------------------------
The first version of this contract had two classifications, ``shipped`` and ``importable-only``, and
it could not classify ``apps/api/socket_gate_tests`` at all: it refused the package under BOTH,
correctly, and each refusal was accurate. That is not a gap in the manifest — it is the model being
wrong about the artifact. Two facts were being treated as one:

* **membership of the distribution** — does the package appear in the wheel ``packages`` list?
* **presence in the production image** — does its source reach the image, and can it be imported
  there at runtime?

``shipped`` asserts both, ``importable-only`` denies both, and the model had no way to say that they
disagree. They do disagree, and the reason was established by building the artifacts rather than by
reading the intent off the file names:

1. ``uv build --wheel`` produces a wheel whose top-level entries are exactly the eleven declared
   ``packages``. ``socket_gate_tests`` is absent. It is not a member of the distribution.
2. ``infra/dev/Dockerfile.python`` does ``COPY apps/api ./apps/api`` — a whole-root copy. The
   package's source is therefore in the production image.
3. The image installs with ``uv pip install --system -e`` — **editable**. Hatchling's editable
   install writes a ``.pth`` file, ``_editable_impl_secp.pth``, whose lines are the package
   **ROOTS** (``/app/apps/api``, ``/app/apps/worker``, ...) and NOT the packages themselves. So
   ``/app/apps/api`` is on ``sys.path`` at runtime, and ``import socket_gate_tests`` **succeeds
   inside the production image**. Verified by performing that same editable install and importing
   the module, not by reading the Dockerfile.

So the honest description is neither "shipped" nor "deliberately absent": the package is *in the
image and importable there, while not being installed as a distribution*. That is what
``image-resident`` names. It is a third posture rather than an exemption, and it carries obligations
the other two do not — in particular it MUST share a root with a shipped package. A package in its
own root has no reason to be in the image, so ``image-resident`` there would be a lie used to dodge
``importable-only``'s image rule; that case is refused (``image-resident-in-own-root``).

``importable-only`` survives unchanged and is still the right class for ``apps/acceptance``, which
gets its own root, is copied by nothing, and is in no wheel entry.

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

import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_PYPROJECT = _REPO / "pyproject.toml"
_MANIFEST = _REPO / "packaging-contract.toml"
_DOCKERFILE = _REPO / "infra" / "dev" / "Dockerfile.python"

CONTRACT_VERSION = "secp.packaging-contract/v1"

#: Installed as a distribution AND present in the production image.
SHIPPED = "shipped"
#: In neither the distribution nor the image. Requires a root of its own, which is what makes the
#: absence real rather than declared.
IMPORTABLE_ONLY = "importable-only"
#: In the image and importable there, but NOT installed as a distribution — the state produced by a
#: whole-root ``COPY`` plus an editable install whose ``.pth`` lines are roots. See the module
#: docstring; this posture is only available to a package sharing a root with a shipped one.
IMAGE_RESIDENT = "image-resident"
#: Closed on purpose. A fourth value is a refusal, never a behaviour to be inferred.
DISTRIBUTIONS = frozenset({SHIPPED, IMPORTABLE_ONLY, IMAGE_RESIDENT})

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

    # Computed up front because the per-package rules below need them: `image-resident` is only
    # available to a package sharing a root with a shipped one, and `importable-only` is forbidden
    # from doing so.
    shipped = {n for n, e in inputs.declared.items() if e.get("distribution") == SHIPPED}
    shipped_roots = {inputs.declared[n].get("root") for n in shipped}

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
        elif distribution == IMAGE_RESIDENT:
            # Declares: not installed as a distribution, but present and importable in the image.
            # Every clause below is that sentence, enforced.
            if root not in inputs.pythonpath:
                problems.append(f"image-resident-not-on-pythonpath: {name} ({root})")
            if root not in inputs.mypy_path:
                problems.append(f"image-resident-not-on-mypy-path: {name} ({root})")
            if wheel_entry in inputs.wheel_packages:
                problems.append(
                    f"image-resident-in-wheel: {name} is declared uninstalled but the wheel "
                    f"installs it; declare it '{SHIPPED}' or take it out of the wheel"
                )
            if not _covers(root, inputs.copied_at_all):
                problems.append(
                    f"image-resident-absent-from-image: {root} is not COPYied into the production "
                    f"image, so {name} is not in the image its declaration describes"
                )
            # THE RULE THAT KEEPS THIS POSTURE HONEST. `image-resident` describes a package swept
            # into the image by a shipped sibling's whole-root COPY. In a root of its own there is
            # no sibling and no reason to copy it, so the posture would be a way to declare "in the
            # image, uninstalled" for a package that should simply be `importable-only` — dodging
            # that class's image rule while sounding more precise than it.
            if root not in shipped_roots:
                problems.append(
                    f"image-resident-in-own-root: {name} declares '{IMAGE_RESIDENT}' but {root!r} "
                    f"hosts no shipped package, so nothing sweeps it into the image; it is "
                    f"'{IMPORTABLE_ONLY}'"
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
    for entry_path in inputs.wheel_packages:
        root, name = entry_path.rsplit("/", 1)
        if name not in shipped:
            problems.append(f"wheel-carries-unshipped: {name} is in the wheel but not '{SHIPPED}'")
        elif inputs.declared[name].get("root") != root:
            problems.append(f"wheel-root-mismatch: {name} at {root}")

    # --- an importable-only package may not share a ROOT with a shipped one ---
    # The image COPYies by root, so a shared root carries the importable-only package in regardless
    # of its declaration: true on paper, false in the artifact. A package genuinely in that position
    # is `image-resident`, which says so; `importable-only` there is simply false.
    for name, entry in sorted(inputs.declared.items()):
        if entry.get("distribution") == IMPORTABLE_ONLY and entry.get("root") in shipped_roots:
            problems.append(
                f"shared-root: {name} is '{IMPORTABLE_ONLY}' but shares root "
                f"{entry.get('root')!r} with a shipped package, so the image ships it anyway"
            )

    # --- an installed entry point must resolve inside the wheel ---
    # A console script is installed by the DISTRIBUTION, so its target must be a distribution
    # member. `image-resident` is deliberately included: such a package resolves in the image only
    # by accident of the editable install's root-level `.pth`, so a script pointing at it works
    # today and breaks the moment the project is installed non-editable — the wheel does not carry
    # the module at all. Both non-shipped postures are therefore invalid script targets.
    uninstalled = {
        n
        for n, e in inputs.declared.items()
        if e.get("distribution") in (IMPORTABLE_ONLY, IMAGE_RESIDENT)
    }
    for script, target in sorted(inputs.scripts.items()):
        top_level = target.split(":", 1)[0].split(".", 1)[0]
        if top_level in uninstalled:
            problems.append(f"script-targets-uninstalled: {script} -> {top_level}")

    return sorted(problems)


# --------------------------------------------------------------------------- readers


def _pyproject(repo: Path | None = None) -> dict:
    return tomllib.loads(((repo or _REPO) / _PYPROJECT.name).read_text(encoding="utf-8"))


def _manifest(repo: Path | None = None) -> dict:
    return tomllib.loads(((repo or _REPO) / _MANIFEST.name).read_text(encoding="utf-8"))


def _dockerfile_text(repo: Path | None = None) -> str:
    if repo is None:
        return _DOCKERFILE.read_text(encoding="utf-8")
    return (repo / "infra" / "dev" / _DOCKERFILE.name).read_text(encoding="utf-8")


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


def real_inputs(repo: Path | None = None) -> PackagingInputs:
    """Read all four inputs from a repository tree — the real one by default.

    Parameterised by ``repo`` so the mutation tests can apply an edit to real files on disk and
    have THIS function re-read it, rather than hand-building a dict that only resembles what the
    reader would have produced. A mutation the readers cannot see is not a mutation.
    """
    pyproject = _pyproject(repo)
    text = _dockerfile_text(repo)
    install_index = text.find("uv pip install")
    assert install_index != -1, "the Dockerfile must install the project"
    sources = _copy_sources(text)
    return PackagingInputs(
        discovered=discover_packages(repo),
        declared=_manifest(repo).get("packages", {}),
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


def test_every_real_input_was_actually_read():
    """CONTROL, and it must run BEFORE the ``== []`` assertion below.

    ``contract_violations`` sweeps four inputs and returns the empty list when it finds nothing
    wrong. It returns the same empty list when it finds nothing AT ALL — a reader that silently
    produced an empty ``wheel_packages`` or an empty ``copied_at_all`` would make the next test
    green while checking nothing. So every field is asserted non-empty here first, and the two
    Dockerfile-derived fields are checked separately because they come from different slices of the
    same parse and a broken ``install_index`` would empty only one of them.
    """
    inputs = real_inputs()
    assert len(inputs.discovered) >= 10, sorted(inputs.discovered)
    assert len(inputs.declared) >= 10, sorted(inputs.declared)
    assert len(inputs.wheel_packages) >= 10, inputs.wheel_packages
    assert inputs.pythonpath and inputs.mypy_path
    assert inputs.copied_before_install, "no COPY was seen to precede the install"
    assert inputs.copied_at_all >= inputs.copied_before_install
    assert inputs.scripts, "pyproject declares console scripts; the reader saw none"
    # and the sweep reaches the specific package this contract's hardest case is about
    assert inputs.discovered.get("socket_gate_tests") == "apps/api"


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
    assert "script-targets-uninstalled: secp-acc -> secp_acceptance" in violations


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


# --- the image-resident posture, over constructed inputs ----------------------------------
#
# Modelled on the real `apps/api` shape: a shipped package and a harness sharing its root, where the
# root's wholesale COPY puts both in the image while only one is in the wheel.


def _resident_like(**overrides) -> PackagingInputs:
    base = {
        "discovered": {"secp_thing": "apps/thing", "thing_gate_tests": "apps/thing"},
        "declared": {
            "secp_thing": {
                "root": "apps/thing",
                "distribution": SHIPPED,
                "why": "x" * _MIN_WHY,
            },
            "thing_gate_tests": {
                "root": "apps/thing",
                "distribution": IMAGE_RESIDENT,
                "why": "z" * _MIN_WHY,
            },
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


def test_the_image_resident_baseline_is_satisfied():
    """CONTROL for the perturbations below, and the positive statement of the posture: a harness
    sharing a shipped root, absent from the wheel, present in the image, is admissible AS DECLARED.
    """
    assert contract_violations(_resident_like()) == []


def test_an_image_resident_package_that_reaches_the_wheel_is_refused():
    violations = contract_violations(
        _resident_like(wheel_packages=("apps/thing/secp_thing", "apps/thing/thing_gate_tests"))
    )
    assert any(v.startswith("image-resident-in-wheel: thing_gate_tests") for v in violations)
    assert "wheel-carries-unshipped: thing_gate_tests is in the wheel but not 'shipped'" in (
        violations
    )


def test_an_image_resident_package_whose_root_stops_being_copied_is_refused():
    """The posture asserts presence in the image. If the COPY goes, the declaration is stale and
    must refuse — otherwise `image-resident` would be a label that survives its own subject."""
    violations = contract_violations(
        _resident_like(copied_at_all=frozenset(), copied_before_install=frozenset())
    )
    assert any(v.startswith("image-resident-absent-from-image: apps/thing") for v in violations), (
        violations
    )


def test_an_image_resident_package_must_still_be_importable_and_type_checked():
    violations = contract_violations(_resident_like(pythonpath=()))
    assert "image-resident-not-on-pythonpath: thing_gate_tests (apps/thing)" in violations
    violations = contract_violations(_resident_like(mypy_path=()))
    assert "image-resident-not-on-mypy-path: thing_gate_tests (apps/thing)" in violations


def test_image_resident_cannot_be_used_to_smuggle_a_package_into_its_own_root():
    """THE anti-abuse rule, and the reason the third posture is not an escape hatch.

    Without it, anyone refused by `importable-only-in-image` could relabel the package
    `image-resident`, add a COPY for its own root, and ship a harness into production with a
    declaration that sounds MORE precise than the one it dodged. The posture describes a package
    swept in by a shipped sibling; with no sibling there is nothing doing the sweeping.
    """
    violations = contract_violations(
        _resident_like(
            discovered={"secp_thing": "apps/thing", "thing_gate_tests": "apps/gate"},
            declared=dict(_resident_like().declared)
            | {
                "thing_gate_tests": {
                    "root": "apps/gate",
                    "distribution": IMAGE_RESIDENT,
                    "why": "z" * _MIN_WHY,
                }
            },
            pythonpath=("apps/thing", "apps/gate"),
            mypy_path=("apps/thing", "apps/gate"),
            copied_at_all=frozenset({"apps/thing", "apps/gate"}),
        )
    )
    assert any(v.startswith("image-resident-in-own-root: thing_gate_tests") for v in violations), (
        violations
    )


def test_a_console_script_may_not_target_an_image_resident_package():
    """It would resolve today only through the editable install's root-level `.pth`, and break the
    moment the project is installed non-editable — the wheel does not carry the module at all."""
    violations = contract_violations(
        _resident_like(scripts={"secp-gate": "thing_gate_tests.server:main"})
    )
    assert "script-targets-uninstalled: secp-gate -> thing_gate_tests" in violations


def test_the_incoming_acceptance_harness_is_importable_only_not_resident():
    """``apps/acceptance`` must land as `importable-only`, and the model must make that the only
    admissible reading — otherwise the third posture added here would quietly become the default
    for anything test-shaped, which is exactly the naming-convention reasoning this contract
    refuses. Pinned before the package exists so it cannot land as the wrong class.
    """
    # as it will be: its own root, in no wheel entry, named by no COPY
    assert contract_violations(_acceptance_like()) == []

    # the same package declared `image-resident` instead is refused — nothing sweeps it in
    declared = dict(_acceptance_like().declared)
    declared["secp_acceptance"] = dict(declared["secp_acceptance"]) | {
        "distribution": IMAGE_RESIDENT
    }
    violations = contract_violations(_acceptance_like(declared=declared))
    assert any(v.startswith("image-resident-in-own-root: secp_acceptance") for v in violations), (
        violations
    )

    # and if the Dockerfile ever grew a COPY for its root, `importable-only` becomes false and
    # the guard says so rather than letting the declaration outlive its subject
    violations = contract_violations(
        _acceptance_like(copied_at_all=frozenset({"apps/thing", "apps/acceptance"}))
    )
    assert "importable-only-in-image: apps/acceptance is COPYied into the production image" in (
        violations
    )


# --------------------------------------------------------------------------- mutation-backed
#
# Everything above this line runs the rules over data. That proves the rules, and proves nothing
# about whether the READERS would ever hand them the data a real edit produces. These tests apply
# the edit to real files on disk, have `real_inputs` re-read it, and assert the refusal — so a
# mutation the readers cannot see fails here rather than passing quietly.

_CONTRACT_FILES = ("pyproject.toml", "packaging-contract.toml", "infra/dev/Dockerfile.python")


class MutationDidNotLand(AssertionError):
    """A substitution left the file unchanged, so any refusal observed after it is unattributed."""


def _materialise(tmp_path: Path) -> Path:
    """A writable repository whose contract inputs are the REAL ones.

    The three input FILES are copied verbatim. The package tree is rebuilt as a skeleton — one
    empty ``__init__.py`` per discovered package — because that is the entirety of what discovery
    reads, and copying the whole monorepo once per test makes these slow enough to get deleted.
    :func:`test_the_materialised_copy_reproduces_the_real_contract` proves the skeleton is faithful
    where it counts, and it runs before every test that depends on it.
    """
    repo = tmp_path / "repo"
    for rel in _CONTRACT_FILES:
        destination = repo / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text((_REPO / rel).read_text(encoding="utf-8"), encoding="utf-8")
    for name, root in discover_packages().items():
        package = repo / root / name
        package.mkdir(parents=True, exist_ok=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
    return repo


def _mutate(repo: Path, rel: str, old: str, new: str) -> str:
    """Apply one substitution to a real file, prove it LANDED, and return what disk now holds.

    The clauses, in order, because a mutation test that skips any of them can report a refusal it
    did not cause:

    1. ``old`` must occur EXACTLY once — zero occurrences mutate nothing and the test then measures
       the unmutated tree; several occurrences mutate more than the test claims to;
    2. the substitution must change the text;
    3. the result is written and then RE-READ FROM DISK, and the re-read must equal what was
       written — the re-read copy is what every later reader parses;
    4. the re-read must differ from the original, so the change is proven present in the bytes the
       guard will see rather than only in the string this function built;
    5. the file must still PARSE. A TOML file broken by the edit fails everything downstream, and
       that red would be misattributed to the guard instead of to the edit.

    The sixth clause — WHICH violation appeared — is the one clause this helper cannot perform for
    its caller, so every caller below asserts it explicitly.
    """
    target = repo / rel
    original = target.read_text(encoding="utf-8")

    occurrences = original.count(old)
    if occurrences != 1:
        raise MutationDidNotLand(f"{rel}: target text occurs {occurrences} times, expected 1")
    mutated = original.replace(old, new)
    if mutated == original:
        raise MutationDidNotLand(f"{rel}: the substitution changed nothing")

    target.write_text(mutated, encoding="utf-8")
    on_disk = target.read_text(encoding="utf-8")
    if on_disk != mutated:
        raise MutationDidNotLand(f"{rel}: re-read from disk differs from what was written")
    if on_disk == original:
        raise MutationDidNotLand(f"{rel}: re-read from disk is still the original")

    if rel.endswith(".toml"):
        tomllib.loads(on_disk)  # raises if the edit broke the file; red here is the EDIT's fault
    else:
        assert "uv pip install" in on_disk, f"{rel}: the edit removed the install step"
        assert _copy_sources(on_disk), f"{rel}: the edit removed every COPY"
    return on_disk


def _manifest_block(name: str) -> str:
    """The exact source text of one ``[packages.<name>]`` table, for removal as a unit.

    Removing a declaration one line at a time would leave the file unparseable, and the resulting
    red would be attributed to the guard rather than to the edit.
    """
    text = _MANIFEST.read_text(encoding="utf-8")
    start = text.index(f"[packages.{name}]")
    return text[start : text.index("\n\n", start) + 1]


def _redeclared(name: str, distribution: str) -> tuple[str, str]:
    """``(old_block, new_block)`` for re-classifying a real package, preserving root and why."""
    block = _manifest_block(name)
    entry = tomllib.loads(block)["packages"][name]
    replacement = (
        f"[packages.{name}]\n"
        f"root = {json.dumps(entry['root'])}\n"
        f"distribution = {json.dumps(distribution)}\n"
        f"why = {json.dumps(entry['why'])}\n"
    )
    return block, replacement


# --- controls for the harness itself, before anything depends on it -----------------------


def test_the_materialised_copy_reproduces_the_real_contract(tmp_path: Path):
    """CONTROL, and it must run BEFORE every mutation test below.

    Each of those asserts "clean before the mutation, refused after". If the copy were not clean to
    begin with — a file not copied, a skeleton package missing — the "after" refusal would prove
    nothing about the mutation. And if the skeleton were EMPTY, the discovery sweep would visit
    nothing and the contract would be vacuously satisfied, which reads identically to correct.
    """
    repo = _materialise(tmp_path)
    for rel in _CONTRACT_FILES:
        assert (repo / rel).read_text(encoding="utf-8") == (_REPO / rel).read_text(encoding="utf-8")
    assert discover_packages(repo) == discover_packages()  # the sweep visited the same packages
    assert len(discover_packages(repo)) >= 10, "the skeleton is too small to prove anything"
    assert discover_packages(repo)["socket_gate_tests"] == "apps/api"
    assert contract_violations(real_inputs(repo)) == []


def test_the_mutation_helper_refuses_a_substitution_that_did_not_land(tmp_path: Path):
    """Clause 1, self-applied. Without this the helper could silently no-op and every mutation test
    below would pass by measuring an unmutated tree."""
    repo = _materialise(tmp_path)
    with pytest.raises(MutationDidNotLand) as exc:
        _mutate(repo, "pyproject.toml", "text that is definitely not in the file", "x")
    assert "occurs 0 times" in str(exc.value)
    # the tree is untouched, so a failed mutation cannot leave a half-edited repo behind
    assert contract_violations(real_inputs(repo)) == []


def test_the_mutation_helper_refuses_an_ambiguous_target(tmp_path: Path):
    """Clause 1's other half: ``distribution = "shipped"`` appears many times, and a helper that
    replaced them all would produce a repo no reviewer intended and a refusal no test described."""
    repo = _materialise(tmp_path)
    with pytest.raises(MutationDidNotLand) as exc:
        _mutate(repo, "packaging-contract.toml", 'distribution = "shipped"', "x")
    assert "occurs 11 times" in str(exc.value)


def test_the_mutation_helper_refuses_an_edit_that_breaks_the_file(tmp_path: Path):
    """Clause 5. An unparseable TOML fails every downstream test, and that red would be read as the
    guard catching the mutation when it is really the edit being malformed."""
    repo = _materialise(tmp_path)
    with pytest.raises(tomllib.TOMLDecodeError):
        _mutate(repo, "pyproject.toml", "[tool.uv]", "[tool.uv")


# --- M1: a real shipped package silently dropped from the wheel AND the image -------------


def test_m1_a_shipped_package_dropped_from_wheel_manifest_and_image_is_refused(tmp_path: Path):
    """THE deliverable, over real files. ``secp_management`` is removed from all three places at
    once — the coordinated edit that used to leave every test green — while its code stays on disk.
    The filesystem anchor is the only thing left that knows it exists, and it refuses.
    """
    repo = _materialise(tmp_path)
    assert contract_violations(real_inputs(repo)) == [], "control: the copy must start clean"

    pyproject_after = _mutate(
        repo, "pyproject.toml", '    "apps/management/secp_management",\n', ""
    )
    _mutate(repo, "packaging-contract.toml", _manifest_block("secp_management"), "")
    dockerfile_after = _mutate(
        repo, "infra/dev/Dockerfile.python", "COPY apps/management ./apps/management\n", ""
    )

    # intent achieved, measured on the RE-READ text and again through the readers
    assert "apps/management/secp_management" not in pyproject_after
    assert "COPY apps/management" not in dockerfile_after
    inputs = real_inputs(repo)
    assert "apps/management/secp_management" not in inputs.wheel_packages
    assert "secp_management" not in inputs.declared
    assert not _covers("apps/management", inputs.copied_at_all)
    assert inputs.discovered["secp_management"] == "apps/management", "the code is still on disk"

    assert contract_violations(inputs) == [
        "undeclared: secp_management exists on disk (apps/management) but is not classified"
    ]


# --- M2: an undeclared package-like directory ---------------------------------------------


def test_m2_an_undeclared_package_like_directory_is_refused(tmp_path: Path):
    """The class of finding that produced ``socket_gate_tests`` in the first place. Nothing but the
    filesystem sweep can see a package nobody wrote down."""
    repo = _materialise(tmp_path)
    assert contract_violations(real_inputs(repo)) == [], "control: the copy must start clean"

    stowaway = repo / "apps" / "api" / "stowaway"
    stowaway.mkdir(parents=True)
    (stowaway / "__init__.py").write_text("", encoding="utf-8")
    assert (stowaway / "__init__.py").is_file(), "the mutation must exist on disk"

    inputs = real_inputs(repo)
    assert inputs.discovered.get("stowaway") == "apps/api", "the sweep must have SEEN it"
    assert contract_violations(inputs) == [
        "undeclared: stowaway exists on disk (apps/api) but is not classified"
    ]


def test_m2b_a_directory_without_an_init_is_correctly_not_a_package(tmp_path: Path):
    """Attribution for M2: the refusal is caused by the directory being an importable PACKAGE, not
    by any directory appearing. Without this, M2 would be consistent with a sweep that refused
    every new folder — which would refuse ``apps/api/migrations`` and be deleted within the week."""
    repo = _materialise(tmp_path)
    (repo / "apps" / "api" / "not_a_package").mkdir(parents=True)

    inputs = real_inputs(repo)
    assert "not_a_package" not in inputs.discovered
    assert contract_violations(inputs) == []


# --- M3: the harness is admitted only under its declared posture --------------------------


def test_m3_the_socket_gate_harness_is_admitted_as_image_resident(tmp_path: Path):
    """The positive half. The two refusals that make this the ONLY admissible posture are the two
    tests that follow."""
    repo = _materialise(tmp_path)
    assert real_inputs(repo).declared["socket_gate_tests"]["distribution"] == IMAGE_RESIDENT
    assert contract_violations(real_inputs(repo)) == []


def test_m3a_the_harness_declared_shipped_is_refused(tmp_path: Path):
    repo = _materialise(tmp_path)
    assert contract_violations(real_inputs(repo)) == [], "control: the copy must start clean"

    after = _mutate(repo, "packaging-contract.toml", *_redeclared("socket_gate_tests", SHIPPED))
    assert 'distribution = "shipped"' in after.split("[packages.socket_gate_tests]")[1]
    inputs = real_inputs(repo)
    assert inputs.declared["socket_gate_tests"]["distribution"] == SHIPPED  # intent achieved

    assert contract_violations(inputs) == [
        "shipped-not-in-wheel: socket_gate_tests would not be installed"
    ]


def test_m3b_the_harness_declared_importable_only_is_refused(tmp_path: Path):
    """Both refusals, and both are about the ARTIFACT: the root is copied, and it is copied because
    a shipped package lives in it. This is the pair that has no honest resolution under two values.
    """
    repo = _materialise(tmp_path)
    assert contract_violations(real_inputs(repo)) == [], "control: the copy must start clean"

    _mutate(repo, "packaging-contract.toml", *_redeclared("socket_gate_tests", IMPORTABLE_ONLY))
    inputs = real_inputs(repo)
    assert inputs.declared["socket_gate_tests"]["distribution"] == IMPORTABLE_ONLY

    assert contract_violations(inputs) == [
        "importable-only-in-image: apps/api is COPYied into the production image",
        "shared-root: socket_gate_tests is 'importable-only' but shares root 'apps/api' with a "
        "shipped package, so the image ships it anyway",
    ]


def test_m3c_an_unknown_posture_on_a_real_package_still_refuses(tmp_path: Path):
    """The value set is closed over real files too — adding a third posture did not turn
    ``distribution`` into free text."""
    repo = _materialise(tmp_path)
    _mutate(repo, "packaging-contract.toml", *_redeclared("socket_gate_tests", "test-only"))

    assert contract_violations(real_inputs(repo)) == [
        "unknown-distribution: socket_gate_tests declares 'test-only'"
    ]


# --- M4: the artifact posture changes without the contract changing -----------------------


def test_m4a_installing_the_harness_without_updating_the_contract_is_refused(tmp_path: Path):
    """Production-INSTALLED: the package is added to the wheel while the manifest still says it is
    not installed. The manifest is untouched, which is the point — the artifact moved under it."""
    repo = _materialise(tmp_path)
    assert contract_violations(real_inputs(repo)) == [], "control: the copy must start clean"

    before = real_inputs(repo).declared["socket_gate_tests"]
    _mutate(
        repo,
        "pyproject.toml",
        '    "apps/api/secp_api",\n',
        '    "apps/api/secp_api",\n    "apps/api/socket_gate_tests",\n',
    )
    inputs = real_inputs(repo)
    assert "apps/api/socket_gate_tests" in inputs.wheel_packages  # intent achieved
    assert inputs.declared["socket_gate_tests"] == before, "the manifest must be untouched"

    assert contract_violations(inputs) == [
        "image-resident-in-wheel: socket_gate_tests is declared uninstalled but the wheel "
        "installs it; declare it 'shipped' or take it out of the wheel",
        "wheel-carries-unshipped: socket_gate_tests is in the wheel but not 'shipped'",
    ]


def test_m4b_removing_the_harness_from_the_image_without_updating_the_contract_is_refused(
    tmp_path: Path,
):
    """The other direction: the declaration asserts presence in the image, so dropping the COPY
    makes it false. EVERY package in the root notices, each in the terms of its own posture — which
    is the evidence that the postures are enforced separately rather than by one shared
    approximation.

    The expectation is DERIVED from the manifest rather than typed. An earlier version listed the
    two violations literally and went red the moment ``apps/api`` gained a second
    ``image-resident`` package (``commit_exposure_survey``, on the commit-exposure survey branch) —
    even though the guard was behaving correctly and the new package was correctly declared. That
    is the exact-count trap :func:`test_the_declared_shape_is_recorded_and_consistent` records one
    level up: a literal list silently pins the POPULATION of a root, so a legitimate addition
    reads as a regression. Deriving keeps the assertion an exact equality — it is not a floor, and
    an unexpected extra violation still fails — while surviving a package being added.
    """
    repo = _materialise(tmp_path)
    assert contract_violations(real_inputs(repo)) == [], "control: the copy must start clean"

    after = _mutate(repo, "infra/dev/Dockerfile.python", "COPY apps/api ./apps/api\n", "")
    assert "COPY apps/api" not in after  # intent achieved, on the re-read text
    inputs = real_inputs(repo)
    assert not _covers("apps/api", inputs.copied_at_all)

    in_root = {n: e for n, e in inputs.declared.items() if e.get("root") == "apps/api"}
    postures = {e["distribution"] for e in in_root.values()}
    # CONTROL: the root must actually host BOTH postures, or "each in its own terms" is vacuous
    # and this test would pass while proving only that one rule fires.
    assert {SHIPPED, IMAGE_RESIDENT} <= postures, f"apps/api hosts only {sorted(postures)}"

    expected = sorted(
        (
            f"image-resident-absent-from-image: apps/api is not COPYied into the production "
            f"image, so {name} is not in the image its declaration describes"
            if entry["distribution"] == IMAGE_RESIDENT
            else f"shipped-not-in-image: apps/api is not COPYied before the install, so {name} "
            f"installs but fails to import at runtime"
        )
        for name, entry in in_root.items()
    )
    assert contract_violations(inputs) == expected


def test_m4c_a_console_script_pointed_at_the_harness_is_refused(tmp_path: Path):
    """Production-IMPORTABLE in the strongest sense — an installed entry point. It would resolve in
    today's image only through the editable ``.pth``, and vanish the moment the project is
    installed non-editable, because the wheel does not carry the module."""
    repo = _materialise(tmp_path)
    assert contract_violations(real_inputs(repo)) == [], "control: the copy must start clean"

    _mutate(
        repo,
        "pyproject.toml",
        'secpctl = "secp_management.cli:main"\n',
        'secpctl = "secp_management.cli:main"\n'
        'secp-socket-gate = "socket_gate_tests.live_api_server:main"\n',
    )
    inputs = real_inputs(repo)
    assert "secp-socket-gate" in inputs.scripts  # intent achieved

    assert contract_violations(inputs) == [
        "script-targets-uninstalled: secp-socket-gate -> socket_gate_tests"
    ]


# --- M5 / M6: the coordinated edit, and where the refusal comes from -----------------------


def test_m5_a_coordinated_manifest_and_pyproject_edit_cannot_hide_a_package(tmp_path: Path):
    """The two-place version of the original hole: drop the package from the wheel list and from
    the manifest in the same breath, leaving the Dockerfile alone so nothing else notices. Under
    the old guards this was silent. The filesystem still holds the code, so it refuses."""
    repo = _materialise(tmp_path)
    assert contract_violations(real_inputs(repo)) == [], "control: the copy must start clean"

    _mutate(repo, "pyproject.toml", '    "contracts/reconciliation/secp_reconciliation",\n', "")
    _mutate(repo, "packaging-contract.toml", _manifest_block("secp_reconciliation"), "")

    inputs = real_inputs(repo)
    assert "contracts/reconciliation/secp_reconciliation" not in inputs.wheel_packages
    assert "secp_reconciliation" not in inputs.declared
    assert inputs.discovered["secp_reconciliation"] == "contracts/reconciliation"

    assert contract_violations(inputs) == [
        "undeclared: secp_reconciliation exists on disk (contracts/reconciliation) but is not "
        "classified"
    ]


def test_m6_the_refusal_is_attributable_to_the_clause_the_test_names(tmp_path: Path):
    """Attribution, staged. Two edits are applied one at a time to the same repository, and the
    violation must CHANGE between them.

    A test that only observes "clean, then refused" is consistent with a guard that refuses any
    disturbance at all. Here stage 1 must produce the wheel clause and stage 2 the anchor clause —
    so the guard is demonstrably reading the specific thing each stage changed, and stage 2's
    refusal is not stage 1's leaking forward.
    """
    repo = _materialise(tmp_path)
    assert contract_violations(real_inputs(repo)) == [], "control: the copy must start clean"

    block = _manifest_block("secp_reconciliation")

    # Stage 1 — drop it from the wheel only. It is still DECLARED shipped, so the shipped clause is
    # the one that must speak.
    after = _mutate(
        repo, "pyproject.toml", '    "contracts/reconciliation/secp_reconciliation",\n', ""
    )
    assert "contracts/reconciliation/secp_reconciliation" not in after
    stage1 = contract_violations(real_inputs(repo))
    assert stage1 == ["shipped-not-in-wheel: secp_reconciliation would not be installed"]

    # Stage 2 — now also drop the declaration. The refusal must MOVE to the anchor clause.
    _mutate(repo, "packaging-contract.toml", block, "")
    stage2 = contract_violations(real_inputs(repo))
    assert stage2 == [
        "undeclared: secp_reconciliation exists on disk (contracts/reconciliation) but is not "
        "classified"
    ]
    assert stage1 != stage2, "the two clauses must be distinguishable, not one generic refusal"
