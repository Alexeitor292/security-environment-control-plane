"""A live ASGI server harness: the real app, a real TCP socket, a real HTTP client.

PROVENANCE — this is a byte-for-byte COPY of
``apps/api/socket_gate_tests/live_api_server.py`` from the unmerged branch
``feature/secp-api-socket-gate`` (commit 10f84f7), apart from this note.

It is copied rather than imported because that branch is not merged to ``main`` and this survey
branches from ``main``: importing it would make this branch un-runnable until the other lands, and
editing the original is forbidden while it is frozen under review. When the socket-gate PR merges,
this copy should be deleted and the import used instead.


Why this exists
---------------
Every existing API test drives the app through ``fastapi.testclient.TestClient`` (88 references
under ``apps/api/tests``). ``TestClient`` runs the ASGI app **to completion in-process**: the
request exit stack — and therefore every ``Depends``-with-yield teardown — is closed before the
call returns, so an assertion made "after the response" is in fact made after teardown. That makes
a whole class of response-ordering defects structurally unobservable, no matter which database is
underneath. CI already runs real PostgreSQL 16; what it has never had is the socket.

This harness supplies the missing half: ``uvicorn`` serving the real application object over a real
loopback TCP connection, so a response is genuinely *received by a client* while the server-side
request scope may still be open.

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

    def __init__(self, app: object, *, host: str = "127.0.0.1") -> None:
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
def live_api_server(app: object, *, host: str = "127.0.0.1") -> Iterator[LiveServer]:
    """Serve ``app`` over a real socket for the block; always stops it, loudly."""
    harness = LiveApiServer(app, host=host)
    live = harness.start()
    try:
        yield live
    finally:
        harness.stop()
