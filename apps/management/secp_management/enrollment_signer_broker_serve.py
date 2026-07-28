"""Fixed production entrypoint for the root-gated enrollment-signer broker (SECP-PR5H-B2,
2b-3b-iii).

``python -m secp_management.enrollment_signer_broker_serve`` — the ExecStart of the reviewed broker
systemd unit (``topology.BROKER_ENTRYPOINT``). It takes NO command-line argument and selects
nothing:
the socket path, the enrollment key path, the DB role, the DB coordinates, the systemd credential
id,
the peer allowlist and the single operation are all CODE CONSTANTS. It:

* refuses to start unless it is running as root on POSIX (production is a root systemd service);
* reads the dedicated-role DB plaintext ONLY from the fixed systemd credential
  (``$CREDENTIALS_DIRECTORY/secp-enrollment-signer-db``, tmpfs 0400) — never an env var, argv, or
  world-readable file — and builds the dedicated least-privilege ``secp_enrollment_signer`` Engine
  (the plaintext lives only inside the engine's connection config; it is never printed or
  persisted);
* composes the EXISTING production broker (``build_production_broker``: the hardened root key
reader +
  the DB advisory-lock ACTIVE-identity lease + the commissioning offer signer) behind the fixed
  EXACT
  non-root ``(api_uid, api_gid)`` peer allowlist;
* binds ONLY the fixed ``AF_UNIX`` socket (``bind_broker_socket``; no TCP, no path override, root:
  api-group 0660) and serves exactly ONE bounded operation (sign one authorized offer) per
  connection;
* fails closed on ANY credential / key / identity / socket / DB / peer-policy drift, emitting ONLY a
  bounded redacted reason code and a non-zero exit — never a path, secret, peer identity, or raw
  exception.

It NEVER imports ``secp_api`` (or the finalization engine): the two planes speak only the JSON
``sign_offer`` contract over the socket.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from secp_commissioning.enrollment_signer_role import EnrollmentSignerRoleError

from secp_management import ManagementError
from secp_management.enrollment_signer_broker import bind_broker_socket, build_production_broker
from secp_management.enrollment_signer_db import build_signer_role_engine, load_signer_db_password
from secp_management.topology import API_RUNTIME_GID, API_RUNTIME_UID

EXIT_OK = 0
EXIT_FAIL_CLOSED = 1

#: The fixed EXACT non-root peer allowlist (SO_PEERCRED) — the reviewed controller-API (uid, gid).
_ALLOWED_PEERS: tuple[tuple[int, int], ...] = ((API_RUNTIME_UID, API_RUNTIME_GID),)


def _require_posix_root() -> None:
    if os.name != "posix":
        raise ManagementError("enrollment_signer_broker_requires_posix")
    if int(getattr(os, "geteuid", lambda: -1)()) != 0:
        raise ManagementError("enrollment_signer_broker_requires_root")


def _emit(reason_code: str) -> None:
    """Emit ONLY a bounded redacted reason code to stderr (never a path/secret/peer/raw
    exception)."""
    print(reason_code, file=sys.stderr)


def _close_listener(listener: Any) -> None:
    path = None
    try:
        path = listener.getsockname()
    except Exception:  # noqa: BLE001 - best-effort teardown; never raises to the caller
        path = None
    try:
        listener.close()
    except Exception:  # noqa: BLE001
        pass
    if isinstance(path, str) and path.startswith("/"):
        try:
            os.unlink(path)
        except OSError:
            pass


def _serve_forever(broker: Any, listener: Any) -> None:  # pragma: no cover - production accept loop
    import signal

    def _stop(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    for sig in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None)):
        if sig is not None:
            try:
                signal.signal(sig, _stop)
            except (ValueError, OSError):
                pass  # not the main thread / unsupported — best effort
    try:
        broker.serve_forever(listener)
    except KeyboardInterrupt:
        pass


def run_broker(
    *,
    require_posix_root: Any = _require_posix_root,
    load_password: Any = load_signer_db_password,
    engine_builder: Any = build_signer_role_engine,
    broker_builder: Any = build_production_broker,
    socket_binder: Any = bind_broker_socket,
    serve: Any = _serve_forever,
) -> int:
    """Compose + serve the broker, or fail closed with a bounded reason code. Production passes no
    seam; tests inject verified fakes (the real ``build_production_broker`` refuses off-POSIX, so
    the
    composition + fail-closed paths are only exercisable through the seams)."""
    listener = None
    try:
        require_posix_root()
        password = load_password()  # ONLY from the systemd credential
        engine = engine_builder(password)
        broker = broker_builder(engine=engine, allowed_peers=_ALLOWED_PEERS)
        listener = socket_binder(socket_group_gid=API_RUNTIME_GID)
    except (ManagementError, EnrollmentSignerRoleError) as exc:
        _emit(getattr(exc, "reason_code", "enrollment_signer_broker_startup_failed"))
        return EXIT_FAIL_CLOSED
    except Exception:  # noqa: BLE001 - any startup fault is a bounded fail-closed refusal
        _emit("enrollment_signer_broker_startup_failed")
        return EXIT_FAIL_CLOSED
    try:
        serve(broker, listener)
    finally:
        _close_listener(listener)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(
        prog="python -m secp_management.enrollment_signer_broker_serve",
        description=(
            "Serve the root-gated enrollment-signer broker on its fixed UDS. No argument selects "
            "the socket, key, DB role, DSN, credential, peer policy, or operation — all are code "
            "constants."
        ),
    ).parse_args(argv)
    return run_broker()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
