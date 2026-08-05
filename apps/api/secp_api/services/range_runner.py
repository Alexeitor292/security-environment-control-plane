"""Background execution for range operations.

Deploying a range takes minutes, so the HTTP request that asks for one must not wait for it. The
route creates the operation row, hands the id to :func:`submit`, and returns ``202``; the UI polls.

The runner deliberately owns its own :func:`~secp_api.db.session_scope` session rather than
borrowing the request's. The request session is closed by the commit boundary before the response
reaches the socket (see :mod:`secp_api.deps`), so a background thread holding it would be using a
session that is already gone.

``inline`` mode exists so tests can drive a whole deploy/reset/destroy synchronously and assert on
the result without polling or sleeping. It is the same code path — only the scheduling differs.
"""

from __future__ import annotations

import logging
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor

from secp_api.db import session_scope
from secp_api.services.ranges import execute_operation

logger = logging.getLogger("secp.api.range")

_MODE = "thread"
_lock = threading.Lock()
_executor: ThreadPoolExecutor | None = None
_pending: dict[uuid.UUID, Future] = {}


def set_mode(mode: str) -> None:
    """``thread`` (default) or ``inline`` (tests run the operation on the calling thread)."""
    global _MODE
    if mode not in ("thread", "inline"):
        raise ValueError(f"unknown range runner mode '{mode}'")
    _MODE = mode


def get_mode() -> str:
    return _MODE


def _get_executor() -> ThreadPoolExecutor:
    global _executor
    with _lock:
        if _executor is None:
            _executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="secp-range-op")
        return _executor


def _run(operation_id: uuid.UUID) -> None:
    try:
        with session_scope() as session:
            execute_operation(session, operation_id)
    except Exception:  # pragma: no cover - the operation records its own failure; last-ditch
        logger.exception("range operation %s crashed outside its own error handling", operation_id)
    finally:
        with _lock:
            _pending.pop(operation_id, None)


def submit(operation_id: uuid.UUID) -> None:
    """Schedule an operation. Returns immediately in ``thread`` mode."""
    if _MODE == "inline":
        _run(operation_id)
        return
    future = _get_executor().submit(_run, operation_id)
    with _lock:
        _pending[operation_id] = future


def wait_for(operation_id: uuid.UUID, timeout: float | None = None) -> bool:
    """Block until a submitted operation finishes. Test/CLI helper; no route calls this."""
    with _lock:
        future = _pending.get(operation_id)
    if future is None:
        return True
    try:
        future.result(timeout=timeout)
    except Exception:  # pragma: no cover
        return False
    return True


def shutdown(wait: bool = True) -> None:
    global _executor
    with _lock:
        executor, _executor = _executor, None
    if executor is not None:
        executor.shutdown(wait=wait)
