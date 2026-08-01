"""The container tier must fail loudly, never quietly.

These are hermetic tests OF the gate itself. They matter more than they look: every other proof in
this harness is conditional on the container tier having actually run, and the single cheapest way
for this whole program to produce a false green is a container tier that skipped and rendered as a
tick.

The three mechanisms in :mod:`secp_acceptance.tier` are tested here, and the two that live in pytest
HOOKS are tested by running a real pytest session over the real conftest — not by calling the hook
functions. Calling the function would prove the body works while leaving "is the hook wired up at
all?" unmeasured, and an unwired hook is exactly the failure that presents as a clean green run.
"""

from __future__ import annotations

import pytest
from secp_acceptance import AcceptanceError
from secp_acceptance.reasons import HARNESS_REASONS
from secp_acceptance.tier import (
    CONTAINER_TIER_STAGES,
    ENV_TIER,
    TIER_CONTAINER,
    TIER_HERMETIC,
    assert_tier_witnessed,
    container_tier_required,
    declared_tier,
    missing_witnesses,
    require_container_runtime_or_refuse,
    reset_witness,
    witness,
    witnessed,
)


@pytest.fixture(autouse=True)
def _clean_witness():
    """The witness is process-global by design. Isolate each test from the others."""
    reset_witness()
    yield
    reset_witness()


# --------------------------------------------------------------------------- tier declaration


def test_the_default_tier_is_hermetic(monkeypatch):
    monkeypatch.delenv(ENV_TIER, raising=False)
    assert declared_tier() == TIER_HERMETIC
    assert container_tier_required() is False


def test_an_empty_declaration_is_hermetic_not_an_error(monkeypatch):
    monkeypatch.setenv(ENV_TIER, "")
    assert declared_tier() == TIER_HERMETIC


def test_the_container_tier_must_be_declared_explicitly(monkeypatch):
    monkeypatch.setenv(ENV_TIER, TIER_CONTAINER)
    assert container_tier_required() is True


def test_a_misspelled_tier_refuses_rather_than_defaulting(monkeypatch):
    """The typo case. ``SECP_ACCEPTANCE_TIER=containers`` must not silently downgrade the
    acceptance workflow to a hermetic run that still exits green."""
    monkeypatch.setenv(ENV_TIER, "containers")
    with pytest.raises(AcceptanceError) as exc:
        declared_tier()
    assert exc.value.reason_code == "acceptance_tier_undeclared"


# --------------------------------------------------------------------------- mechanism 1: refuse


def test_the_container_tier_refuses_to_run_implicitly(monkeypatch):
    """A container body reached without the tier being declared is a gating bug. It must refuse
    rather than helpfully building privileged hosts on a developer's laptop."""
    monkeypatch.delenv(ENV_TIER, raising=False)
    with pytest.raises(AcceptanceError) as exc:
        require_container_runtime_or_refuse()
    assert exc.value.reason_code == "acceptance_tier_undeclared"


def test_an_absent_container_runtime_raises_and_never_skips(monkeypatch):
    """The load-bearing one. When the tier IS declared and Docker is not there, the harness raises
    a bounded refusal. It must not call ``pytest.skip`` — a skipped body proves nothing about itself
    but renders as a green tick.
    """
    monkeypatch.setenv(ENV_TIER, TIER_CONTAINER)

    def _unavailable():
        raise AcceptanceError("acceptance_container_runtime_unavailable")

    monkeypatch.setattr("secp_acceptance.shell.require_container_runtime", _unavailable)
    with pytest.raises(AcceptanceError) as exc:
        require_container_runtime_or_refuse()
    assert exc.value.reason_code == "acceptance_container_runtime_unavailable"
    # and specifically NOT the exception pytest.skip raises
    assert not isinstance(exc.value, type(pytest.skip.Exception))  # type: ignore[attr-defined]


def test_the_tier_module_cannot_skip_anything():
    """Structural. A future edit that "fixes" a failing acceptance run by reaching for
    ``pytest.skip`` in the gate would defeat every mechanism at once, and it is the single most
    tempting one-line change in this package.

    Checked over the parsed AST, not the source text: the module's own prose is *about* skipping, so
    a substring search over the source matches its docstring and proves nothing about the code.
    """
    import ast
    import inspect

    from secp_acceptance import tier

    tree = ast.parse(inspect.getsource(tier))

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "pytest" not in imported, "the tier gate must not be able to reach pytest's skip"

    called = {
        node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    }
    assert not any("skip" in name for name in called), f"a skip-shaped call appeared: {called}"


# --------------------------------------------------------------------------- mechanism 2: witness


def test_a_declared_tier_with_no_witness_fails(monkeypatch):
    monkeypatch.setenv(ENV_TIER, TIER_CONTAINER)
    assert witnessed() == frozenset()
    with pytest.raises(AcceptanceError) as exc:
        assert_tier_witnessed()
    assert exc.value.reason_code == "acceptance_container_tier_not_executed"


def test_a_partially_executed_tier_fails_too(monkeypatch):
    """ "Some container test ran" is not the claim. A tier that created hosts and never destroyed
    them, or never got as far as proving anything, is incomplete — and an incomplete tier that
    passed is the shape a partially-collected run takes."""
    monkeypatch.setenv(ENV_TIER, TIER_CONTAINER)
    witness(CONTAINER_TIER_STAGES[0])
    assert missing_witnesses() == CONTAINER_TIER_STAGES[1:]
    with pytest.raises(AcceptanceError) as exc:
        assert_tier_witnessed()
    assert exc.value.reason_code == "acceptance_container_tier_not_executed"


def test_a_fully_witnessed_tier_passes(monkeypatch):
    monkeypatch.setenv(ENV_TIER, TIER_CONTAINER)
    for stage in CONTAINER_TIER_STAGES:
        witness(stage)
    assert missing_witnesses() == ()
    assert_tier_witnessed()  # does not raise


def test_the_witness_check_is_inert_on_a_hermetic_run(monkeypatch):
    """An ordinary CI shard collects this directory. It must not be failed by a tier it never
    declared."""
    monkeypatch.delenv(ENV_TIER, raising=False)
    assert_tier_witnessed()  # does not raise, despite an empty witness


def test_an_unknown_witness_name_refuses():
    """A typo'd witness would satisfy nothing while looking like it satisfied something."""
    with pytest.raises(AcceptanceError) as exc:
        witness("fleet_creatd")
    assert exc.value.reason_code == "acceptance_tier_unknown_witness"


def test_every_tier_reason_code_is_in_the_closed_vocabulary():
    for code in (
        "acceptance_tier_undeclared",
        "acceptance_tier_unknown_witness",
        "acceptance_container_tier_not_executed",
        "acceptance_container_runtime_unavailable",
    ):
        assert code in HARNESS_REASONS


# --------------------------------------------------------------------------- the hooks, for real


def _acceptance_package_root() -> str:
    """``apps/acceptance`` — the directory that must be importable for ``secp_acceptance``.

    The parent session gets it from ``pyproject.toml``'s ``pythonpath``. A ``pytester`` subprocess
    runs in a scratch directory with none of that config, so it has to be handed over explicitly.
    """
    import pathlib

    return str(pathlib.Path(__file__).resolve().parents[1])


def _write_suite(pytester: pytest.Pytester, monkeypatch) -> None:
    """A miniature suite carrying one hermetic test and one container-tier test, over the REAL
    conftest — read from disk rather than restated, so this can never drift from the gate it tests.
    """
    import pathlib

    monkeypatch.setenv("PYTHONPATH", _acceptance_package_root())
    real = pathlib.Path(__file__).parent / "conftest.py"
    pytester.makeconftest(real.read_text(encoding="utf-8"))
    pytester.makepyfile(
        test_mini="""
        import pytest

        def test_hermetic_one():
            assert True

        @pytest.mark.container_tier
        def test_container_one():
            from secp_acceptance.tier import witness
            for stage in ("fleet_created", "fleet_proved", "fleet_destroyed"):
                witness(stage)
        """
    )


def test_hook_deselects_the_container_tier_when_it_was_not_declared(pytester, monkeypatch):
    """Mechanism 3, proven through a real session. DESELECTED, not skipped: the report must show
    zero skips, because a skip is what a reader misreads."""
    monkeypatch.delenv(ENV_TIER, raising=False)
    _write_suite(pytester, monkeypatch)
    result = pytester.runpytest_subprocess("-q")
    result.assert_outcomes(passed=1, skipped=0, failed=0, errors=0)


def test_hook_fails_the_session_when_a_declared_tier_did_not_execute(pytester, monkeypatch):
    """Mechanism 2, proven through a real session, and the most important test in this file.

    The container tier is DECLARED but its body is filtered out by ``-k``. Every collected test
    passes — and the session must still fail, because nothing witnessed the tier.
    """
    monkeypatch.setenv(ENV_TIER, TIER_CONTAINER)
    _write_suite(pytester, monkeypatch)
    result = pytester.runpytest_subprocess("-q", "-k", "hermetic")
    result.assert_outcomes(passed=1, failed=0, errors=0)  # the collected tests all passed...
    assert result.ret != 0, "a declared-but-unexecuted container tier must fail the session"
    result.stdout.fnmatch_lines(["*ACCEPTANCE TIER NOT EXECUTED*"])
    result.stdout.fnmatch_lines(["*acceptance_container_tier_not_executed*"])


def test_hook_passes_when_the_declared_tier_actually_executed(pytester, monkeypatch):
    """The control for the test above. Same declaration, same suite, nothing filtered — the tier
    runs, witnesses all three stages, and the session succeeds. Without this, the previous test
    could be passing because the gate fails unconditionally."""
    monkeypatch.setenv(ENV_TIER, TIER_CONTAINER)
    _write_suite(pytester, monkeypatch)
    result = pytester.runpytest_subprocess("-q")
    result.assert_outcomes(passed=2, failed=0, errors=0)
    assert result.ret == 0


def test_hook_refuses_a_misspelled_tier_declaration_at_configure_time(pytester, monkeypatch):
    """A typo must break the run at startup, not present as "no container tests were collected".

    Reported as pytest's own USAGE_ERROR: it exits non-zero with a bounded, attributable message
    and — the point — collects and runs NOTHING, so there is no partial green to misread.
    """
    monkeypatch.setenv(ENV_TIER, "container-tier")
    _write_suite(pytester, monkeypatch)
    result = pytester.runpytest_subprocess("-q")
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(["*acceptance_tier_undeclared*"])
    # No terminal summary is produced at all — not "0 passed", but no run. Asserted as the absence
    # of any outcome line, because `assert_outcomes` needs a summary that a usage error never
    # writes, and its ValueError would otherwise read as a broken test rather than as the proof.
    assert "passed" not in result.stdout.str()
    assert "skipped" not in result.stdout.str()
