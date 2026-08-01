"""Every PRODUCT refusal code the harness asserts on must still exist in the product.

``secp_acceptance.reasons.PRODUCT_REASONS`` is a set of strings QUOTED from the product. Strings do
not break when the thing they quote is renamed — they just stop matching, and an
``expect_refusal(expected="a_code_nobody_emits_anymore")`` becomes a branch that can never be taken.
The failure mode is the worst kind available to an acceptance harness: the scenario still runs, the
product still refuses, and the harness records ``acceptance_unexpected_reason_code`` — or, if the
product stopped refusing entirely, ``acceptance_expected_refusal_absent`` — in a suite nobody reads
until the release it was supposed to gate.

So the harness BUILD fails instead. This file is the check ``reasons.py``'s docstring promises.

WHAT IS AND IS NOT PROVEN
-------------------------
Proven: each code is a literal that still appears in the shipped product packages, and the search
that finds it can actually fail. NOT proven: that the code is still emitted on the path the scenario
drives — only executing that path proves that, which is what the stage scenarios do. This file is
the cheap check that catches a rename at build time; it does not replace the expensive one.
"""

from __future__ import annotations

import pathlib

import pytest
from secp_acceptance.reasons import HARNESS_REASONS, PRODUCT_REASONS

#: The SHIPPED product packages — the ones in ``[tool.hatch.build.targets.wheel].packages``.
#: ``apps/acceptance`` is deliberately NOT here: it is where these strings are declared, so
#: including it would make every assertion below find its own definition and pass vacuously.
_PRODUCT_ROOTS = (
    "apps/api/secp_api",
    "apps/worker/secp_worker",
    "apps/commissioning/secp_commissioning",
    "apps/deployment/secp_operator_deployment",
    "apps/deployment/secp_discovery_activation",
    "apps/management/secp_management",
)


def _repo_root() -> pathlib.Path:
    here = pathlib.Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file() and (parent / "apps").is_dir():
            return parent
    raise AssertionError("repository root not found from the test file location")


def _product_sources() -> dict[str, str]:
    root = _repo_root()
    sources: dict[str, str] = {}
    for relative in _PRODUCT_ROOTS:
        package = root / relative
        assert package.is_dir(), f"product package {relative} is missing; the search roots drifted"
        for path in sorted(package.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            sources[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8")
    return sources


def _files_declaring(code: str) -> list[str]:
    """Files whose source contains ``code`` as a quoted string literal."""
    return [
        rel
        for rel, text in _product_sources().items()
        if f'"{code}"' in text or f"'{code}'" in text
    ]


# --------------------------------------------------------------------------- premise guards


def _git_tracked_product_sources() -> set[str]:
    """The product ``.py`` files GIT knows about — an INDEPENDENT second reading of the corpus.

    Deliberately not another filesystem walk. Git's index is maintained by a different tool with
    different semantics, so a bug in :func:`_product_sources` (a wrong root, a broken glob, an
    over-eager exclusion) cannot shrink both readings in step.
    """
    import subprocess

    result = subprocess.run(  # noqa: S603,S607 - fixed argv, no user input, bounded
        ["git", "ls-files", "--", *_PRODUCT_ROOTS],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, "git ls-files failed; cannot take the independent reading"
    return {
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip().endswith(".py") and "__pycache__" not in line
    }


def test_the_product_source_sweep_reads_the_whole_tracked_corpus():
    """The sweep must equal the tracked corpus EXACTLY — not merely exceed a floor.

    This replaced ``len(sources) > 50``. The real corpus is ~385 files, so that floor tolerated the
    sweep losing roughly seven-eighths of the product tree while still reporting itself healthy.
    That slack is only dangerous in one direction, but it is the direction that matters here:
    :func:`test_no_harness_reason_code_is_emitted_by_the_product` SUCCEEDS on "pattern not found",
    so a silently-shrunken corpus turns it into a vacuous pass.

    The expectation is derived from ``git ls-files`` rather than from :func:`_product_sources`, so
    a mutation that halves the sweep cannot halve the expectation with it. Deriving an expectation
    by calling the very function under test satisfies "derived, not typed" in form while being
    defeated in substance — credit to the queue-integration stream, which hit exactly that and
    found it only by mutation.
    """
    swept = set(_product_sources())
    tracked = _git_tracked_product_sources()
    assert tracked, "the independent reading found nothing; it is not a usable control"
    assert swept == tracked, (
        f"the sweep and the git-tracked inventory disagree.\n"
        f"  tracked but not swept: {sorted(tracked - swept)[:10]}\n"
        f"  swept but not tracked: {sorted(swept - tracked)[:10]}\n"
        f"(a newly added product module must be `git add`ed before this can see it)"
    )


def test_every_product_root_contributed_sources():
    sources = _product_sources()
    for relative in _PRODUCT_ROOTS:
        assert any(rel.startswith(relative) for rel in sources), f"no sources read from {relative}"


def test_the_provenance_search_can_actually_fail():
    """CONTROL. A search that matched everything would make this whole file decorative."""
    assert _files_declaring("this_reason_code_does_not_exist_anywhere") == []
    # ...and it must find one that does, or it would report every code as renamed
    assert _files_declaring("release_role_mismatch") != []


def test_the_acceptance_package_is_excluded_from_the_search():
    """The load-bearing exclusion. ``PRODUCT_REASONS`` is DECLARED in the acceptance package; if
    that package were in the search roots, every code would find its own declaration and this file
    would prove nothing at all."""
    assert not any(root.startswith("apps/acceptance") for root in _PRODUCT_ROOTS)
    assert not any(rel.startswith("apps/acceptance") for rel in _product_sources())


# --------------------------------------------------------------------------- provenance


@pytest.mark.parametrize("code", sorted(PRODUCT_REASONS))
def test_every_product_reason_code_still_exists_in_the_product(code: str):
    """One test per code, so a rename names the code that moved rather than failing a set diff."""
    declaring = _files_declaring(code)
    assert declaring, (
        f"PRODUCT_REASONS declares {code!r}, but no shipped product source contains it. Either the "
        f"product renamed it — in which case every scenario asserting on it is now asserting on a "
        f"branch that can never be taken — or it was never a product code and belongs in "
        f"HARNESS_REASONS."
    )


def test_no_harness_reason_code_is_emitted_by_the_product():
    """The other direction, and the reason the two vocabularies are kept disjoint.

    A ``HARNESS_REASONS`` member found in product source would mean the single fact a reader of the
    evidence most needs — WHO refused, the harness or the product — is ambiguous for that code.
    """
    leaked = {code: _files_declaring(code) for code in sorted(HARNESS_REASONS)}
    assert {code: files for code, files in leaked.items() if files} == {}


def test_the_two_vocabularies_are_disjoint_and_both_non_empty():
    assert not (HARNESS_REASONS & PRODUCT_REASONS)
    assert PRODUCT_REASONS and HARNESS_REASONS
