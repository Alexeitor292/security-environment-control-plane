"""A live ASGI server harness: the real app, a real TCP socket, a real HTTP client.

PROVENANCE — this is a copy, not original work
----------------------------------------------
Copied verbatim (docstring adapted) from ``apps/api/socket_gate_tests/live_api_server.py`` on
branch ``feature/secp-api-socket-gate`` at commit ``10f84f729017285b5731af3d27c4f25dafaa0c6f``
(2026-07-31). That branch is not merged, so importing across branches is impossible and copying
with attribution is the deliberate choice rather than reinventing the harness.

**Follow-up owed:** when ``feature/secp-api-socket-gate`` lands, delete this module and import
``socket_gate_tests.live_api_server`` instead. Two copies of a determinism-critical harness must
not outlive the branch gap that forced them.

One deliberate deviation from the original: the ASGI application is annotated ``Any`` rather than
``object``. ``apps/api/tests`` is on the checked mypy path, where ``object`` fails to satisfy
``uvicorn.Config``'s app parameter. Behaviour is identical; nothing about the harness changes.

Why the harness exists at all
-----------------------------
Every other API test drives the app through ``fastapi.testclient.TestClient``, which runs the ASGI
app **to completion in-process**. That is fine for most assertions but it means no test in this
repository has ever observed a response as a *client over a socket* sees it. For the contract guard
that consumes this module, the socket is the whole point: a field set derived by importing
``secp_api.schemas_enrollment`` would be true by construction on both sides of the comparison and
would prove nothing about what the API actually serves.

Determinism
-----------
* **No fixed port, no port-probing race.** The listening socket is created and bound to port 0
  *here*, so the kernel-assigned port is read from the socket the server will actually serve on.
  Nothing binds, closes and re-binds a "known free" port.
* **No silent startup.** ``start()`` blocks until uvicorn reports ``started``, and raises
  ``LiveServerError`` on timeout, on a thread that died, or on an exception escaping ``serve()``.
  An unstarted server can never be mistaken for a started one.
* **No leaked processes or threads.** The server runs in a thread of this process (never a
  subprocess), and ``stop()`` refuses to return quietly if that thread outlives its bounded join.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import uvicorn

# Bounded, generous: these only have to cover process scheduling on a loaded CI runner, never a
# behaviour under test. Exceeding either is a harness failure and is reported as one.
STARTUP_TIMEOUT_SECONDS = 30.0
SHUTDOWN_TIMEOUT_SECONDS = 30.0
_POLL_INTERVAL_SECONDS = 0.01

_LISTEN_BACKLOG = 128


class LiveServerError(RuntimeError):
    """The harness could not deterministically start, serve, or stop the live server.

    Deliberately NOT an ``AssertionError`` subclass: a broken harness must never be absorbed by a
    test's expected-failure marker, it must surface as an error in its own right.
    """


@dataclass(frozen=True)
class LiveServer:
    """A running server's contact details. ``port`` is the kernel-assigned ephemeral port."""

    host: str
    port: int

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


class LiveApiServer:
    """Serve ``app`` on an ephemeral loopback port for the duration of a ``with`` block."""

    def __init__(self, app: Any, *, host: str = "127.0.0.1") -> None:
        self._app = app
        self._host = host
        self._listener: socket.socket | None = None
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self._serve_failure: list[BaseException] = []
        self._live: LiveServer | None = None

    # -- lifecycle ------------------------------------------------------------------------------

    def start(self) -> LiveServer:
        if self._thread is not None:
            raise LiveServerError("this LiveApiServer has already been started")

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Port 0: the kernel picks a free port and we read it back off the very socket uvicorn
            # is handed. No SO_REUSEADDR — nothing here may adopt a port another listener holds.
            listener.bind((self._host, 0))
            listener.listen(_LISTEN_BACKLOG)
            host, port = listener.getsockname()[:2]
        except BaseException:
            listener.close()
            raise
        self._listener = listener

        # Defaults elsewhere on purpose (event loop, HTTP protocol, lifespan): this must be the
        # production server, not a reduced stand-in. Logging is quietened only so a failing gate's
        # output is its own measurements.
        config = uvicorn.Config(self._app, log_level="warning", access_log=False)
        server = uvicorn.Server(config)
        self._server = server

        def _serve() -> None:
            try:
                server.run(sockets=[listener])
            except BaseException as exc:  # noqa: BLE001 - re-raised on the calling thread
                self._serve_failure.append(exc)

        thread = threading.Thread(target=_serve, name="secp-live-api-server", daemon=True)
        self._thread = thread
        thread.start()

        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while not server.started:
            if self._serve_failure:
                self.stop()
                raise LiveServerError("the live server raised while starting") from (
                    self._serve_failure[0]
                )
            if not thread.is_alive():
                raise LiveServerError("the live server thread exited before startup completed")
            if time.monotonic() >= deadline:
                self.stop()
                raise LiveServerError(
                    f"the live server did not report started within {STARTUP_TIMEOUT_SECONDS}s"
                )
            time.sleep(_POLL_INTERVAL_SECONDS)

        if port == 0:
            raise LiveServerError("the listening socket reported port 0 after bind")
        self._live = LiveServer(host=host, port=port)
        return self._live

    def stop(self) -> None:
        server, thread = self._server, self._thread
        if server is not None and thread is not None:
            server.should_exit = True
            thread.join(SHUTDOWN_TIMEOUT_SECONDS)
            if thread.is_alive():
                # Never "assume it went away": an orphaned server thread would hold the port and
                # silently corrupt any later run in this process.
                raise LiveServerError(
                    f"the live server thread was still alive {SHUTDOWN_TIMEOUT_SECONDS}s after "
                    "requesting shutdown"
                )
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        self._thread = None
        if self._serve_failure:
            failure = self._serve_failure[0]
            self._serve_failure = []
            raise LiveServerError("the live server raised while serving") from failure

    def __enter__(self) -> LiveServer:
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()


@contextmanager
def live_api_server(app: Any, *, host: str = "127.0.0.1") -> Iterator[LiveServer]:
    """Serve ``app`` over a real socket for the block; always stops it, loudly."""
    harness = LiveApiServer(app, host=host)
    live = harness.start()
    try:
        yield live
    finally:
        harness.stop()
