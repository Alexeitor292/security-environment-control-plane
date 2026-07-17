"""CI regression — the optional-``temporalio`` import guard + stub contract (PR5B worker-startup).

CI shard 3 runs WITHOUT the optional ``worker`` extra (no ``temporalio``). At that point
``secp_worker.temporal_runtime`` falls back to an import-only stub. The stub must faithfully support
BOTH decorator forms so a bare ``@workflow.defn class DeployWorkflow`` returns the class UNCHANGED
(``__module__ == "secp_worker.temporal_workflows"``), not the decorator's inner function (which
would report ``__module__ == "secp_worker.temporal_runtime"`` — the exact CI failure this guards).

Every test forces the no-``temporalio`` path in a FRESH subprocess (via
``sys.modules["temporalio"] = None`` before the first ``secp_worker`` import), so the regression
runs deterministically even on a developer machine where ``temporalio`` IS installed. A separate
test proves an UNRELATED import
failure (a broken/partial temporalio, or a missing transitive dependency) is NOT silently swallowed
into the stub path.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

_WORKFLOW_NAMES = (
    "DeployWorkflow",
    "ResetWorkflow",
    "DestroyWorkflow",
    "DiscoverWorkflow",
    "EligibilityPreflightWorkflow",
    "ToolchainAttestationWorkflow",
    "RemoteStateReadinessWorkflow",
    "PlanSecretReadinessWorkflow",
    "RealPlanGenerationWorkflow",
)


def _run(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)], capture_output=True, text=True
    )


def test_forced_no_temporal_stub_preserves_workflow_identity_and_decorator_forms():
    """Under the forced no-``temporalio`` stub path: TEMPORAL_AVAILABLE is False; every workflow
    symbol is still a class defined in the clean workflow module; temporal_app re-exports the
    identical objects; and BOTH decorator forms return their target unchanged."""
    code = f"""
        import sys
        sys.modules["temporalio"] = None  # force the no-temporalio path before any secp import
        import secp_worker.temporal_runtime as tr
        import secp_worker.temporal_workflows as tw
        import secp_worker.temporal_app as ta

        assert tr.TEMPORAL_AVAILABLE is False, tr.TEMPORAL_AVAILABLE

        for n in {_WORKFLOW_NAMES!r}:
            cls = getattr(tw, n)
            assert isinstance(cls, type), (n, type(cls))
            assert cls.__module__ == "secp_worker.temporal_workflows", (n, cls.__module__)
            assert getattr(ta, n) is cls, n  # temporal_app re-exports the IDENTICAL object

        # BARE @workflow.defn: Python passes the class straight in; it returns unchanged.
        class _C:
            pass
        assert tr.workflow.defn(_C) is _C
        # BARE @workflow.run on a method-like function returns it unchanged too.
        def _run_method(self):
            return None
        assert tr.workflow.run(_run_method) is _run_method
        # CONFIGURED @activity.defn(name=...): returns a decorator returning the function unchanged.
        def _act():
            return 1
        deco = tr.activity.defn(name="registered_name")
        assert deco(_act) is _act
        # BARE @activity.defn on a function also returns it unchanged (defn may decorate functions).
        def _act2():
            return 2
        assert tr.activity.defn(_act2) is _act2

        print("OK")
    """
    result = _run(code)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("OK"), result.stdout


def test_forced_no_temporal_workflow_module_stays_import_clean():
    """Even on the stub path, importing ONLY the workflow module drags in no httpx / urllib.request
    / secp_api — the architectural isolation must hold regardless of whether temporalio is present.
    """
    code = """
        import sys
        sys.modules["temporalio"] = None
        import secp_worker.temporal_workflows  # noqa: F401  (import for its side effects only)
        import secp_worker.temporal_runtime as tr

        assert tr.TEMPORAL_AVAILABLE is False, tr.TEMPORAL_AVAILABLE
        bad = sorted(
            m for m in sys.modules
            if m in ("httpx", "urllib.request") or m.split(".")[0] == "secp_api"
        )
        assert bad == [], bad
        print("CLEAN")
    """
    result = _run(code)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("CLEAN"), result.stdout


def test_a_missing_transitive_dependency_is_not_swallowed_into_the_stub_path():
    """temporalio present but a transitive dependency missing (ModuleNotFoundError whose name is NOT
    'temporalio') must PROPAGATE — never be hidden behind stubs as a fake-healthy worker."""
    code = """
        import sys
        import importlib.abc

        class _Finder(importlib.abc.MetaPathFinder):
            def find_spec(self, name, path, target=None):
                if name == "temporalio" or name.startswith("temporalio."):
                    # temporalio itself resolves, but a transitive dep is absent.
                    raise ModuleNotFoundError("No module named 'grpc'", name="grpc")
                return None

        sys.modules.pop("temporalio", None)
        sys.meta_path.insert(0, _Finder())
        try:
            import secp_worker.temporal_runtime as tr
            print("SWALLOWED", tr.TEMPORAL_AVAILABLE)  # BAD: masked a broken environment
        except ModuleNotFoundError as e:
            print("PROPAGATED", e.name)
    """
    result = _run(code)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PROPAGATED grpc", result.stdout


def test_a_broken_temporalio_missing_attributes_is_not_swallowed_into_the_stub_path():
    """temporalio present but only partially importable (a plain ImportError, e.g. the module is
    there but ``activity``/``workflow`` cannot be imported) must PROPAGATE, not fall back to stubs.
    """
    code = """
        import sys
        import types

        sys.modules["temporalio"] = types.ModuleType("temporalio")  # present, missing attributes
        try:
            import secp_worker.temporal_runtime as tr
            print("SWALLOWED", tr.TEMPORAL_AVAILABLE)  # BAD
        except ImportError as e:
            print("PROPAGATED", type(e).__name__)
    """
    result = _run(code)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PROPAGATED ImportError", result.stdout
