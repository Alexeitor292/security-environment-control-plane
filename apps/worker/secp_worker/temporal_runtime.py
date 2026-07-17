"""Shared Temporal import guard — the SINGLE source of ``activity`` / ``workflow`` (ADR-010).

This module is IMPORT-CLEAN: it imports only ``temporalio`` (a default sandbox passthrough) and
nothing from ``secp_api`` / ``secp_worker`` and nothing I/O-capable. It is therefore safe to be
re-imported inside Temporal's workflow sandbox (the sandbox re-imports each workflow class's
defining module and everything it imports).

Both the sandbox-imported workflow module (:mod:`secp_worker.temporal_workflows`) and the HOST-only
activity module (:mod:`secp_worker.temporal_app`) obtain ``activity`` / ``workflow`` from HERE, so
the guard can never drift between them. ``temporalio`` is the optional ``worker`` extra; without it,
an import-only stub keeps the decorated definitions importable for tooling/tests that never run a
real worker — while faithfully preserving each definition's identity and ``__module__`` (the stub
supports BOTH the bare ``@workflow.defn`` and the configured ``@activity.defn(name=...)`` forms).
"""

from __future__ import annotations

from typing import Any, TypeVar

_T = TypeVar("_T")

try:  # ``temporalio`` is the optional ``worker`` extra.
    from temporalio import activity, workflow

    TEMPORAL_AVAILABLE = True
except ModuleNotFoundError as exc:  # pragma: no cover - exercised in no-temporalio subprocesses
    # Narrow ON PURPOSE. Fall back to stubs ONLY when the top-level ``temporalio`` package is itself
    # absent (the worker extra not installed). A ModuleNotFoundError whose missing module is NOT
    # ``temporalio`` means temporalio IS installed but a transitive dependency is missing — a broken
    # environment we must not hide. A plain ImportError (temporalio present but only partially
    # importable) or ANY other exception raised during temporalio initialization is not a
    # ModuleNotFoundError, is not caught here, and propagates. Silently stubbing those would mask a
    # real deployment problem as a healthy worker.
    if exc.name != "temporalio":
        raise

    def _passthrough_decorator(decorated: Any = None, **_kwargs: Any) -> Any:
        """A decorator no-op supporting BOTH decorator forms so definitions import unchanged:

        * BARE ``@workflow.defn`` / ``@workflow.run`` — Python passes the class/function straight in
          as ``decorated``; it is returned UNCHANGED (so its ``__module__`` stays its defining
          module, never this guard module);
        * CONFIGURED ``@activity.defn(name=...)`` — the options arrive as keywords with no
          positional object, so a decorator is returned that returns its later argument unchanged.

        Works for both classes and functions (``activity.defn`` decorates functions).
        """
        if decorated is not None:
            return decorated  # bare form: return the decorated class/function unchanged

        def _decorator(value: _T) -> _T:
            return value  # configured form: return the later-decorated object unchanged

        return _decorator

    class _Stub:
        """Import-only, decorator-shaped stand-in for ``temporalio.activity`` /
        ``temporalio.workflow`` when the optional ``worker`` extra is absent.

        It never runs a real worker; it only keeps decorated definitions importable, faithfully for
        both the bare and the configured decorator forms.
        """

        def defn(self, decorated: Any = None, **kwargs: Any) -> Any:
            return _passthrough_decorator(decorated, **kwargs)

        def __getattr__(self, _name: str) -> Any:
            # Any other decorator access (e.g. ``@workflow.run``) is the same passthrough. Attribute
            # VALUE access (e.g. ``workflow.execute_activity``) is never needed at import time —
            # workflow bodies only execute on a real worker — so returning the passthrough is safe.
            return _passthrough_decorator

    TEMPORAL_AVAILABLE = False
    activity = workflow = _Stub()  # type: ignore[assignment]
