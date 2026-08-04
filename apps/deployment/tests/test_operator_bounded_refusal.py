"""Every reachable exit is a BOUNDED refusal, never a traceback (WS-E).

A package whose entire value is that it refuses cleanly must not have an unbounded stack trace as
a reachable exit. It did: the hardened filesystem is POSIX + root only and refuses to *construct*
elsewhere, and that refusal was raised outside every per-dimension handler in
``load_verify_context``. On a non-POSIX host ``python -m secp_operator_deployment queue --json``
exited **1** — a code in none of the published tables — after printing a traceback containing
absolute deployment paths.

Two independent things had to be true, so both are pinned here:

* ``load_verify_context`` treats the filesystem as a dimension like any other and fails closed,
  carrying a bounded reason instead of raising (:func:`test_a_refusing_filesystem_yields_a_report`).
* ``main`` cannot emit a traceback for ANY escaping exception, because a fix that only handles the
  one known cause leaves the next one unhandled
  (:func:`test_no_escaping_exception_can_produce_a_traceback`).

The rendering guarantee is the load-bearing one: the exception MESSAGE is never printed, only a
bounded ``reason_code`` token. Exception messages are exactly where absolute paths live, so a
handler that rendered ``str(exc)`` would reintroduce the leak it was added to close.

``SystemExit`` and ``KeyboardInterrupt`` deliberately still propagate — those are the caller's
control flow, not a refusal, and swallowing argparse's ``SystemExit`` would break the command
grammar the rest of the suite depends on.

Nothing here contacts infrastructure; the failures are induced at the injection seams.
"""

from __future__ import annotations

import json

import pytest
from secp_operator_deployment.cli import (
    UNAVAILABLE_EXIT_CODE,
    _bounded_reason,
    main,
)
from secp_operator_deployment.verify import classify_reason_code

_PUBLISHED_EXIT_CODES = {0, 10, 11, 12, 13, 14, 15, 20}


class _Refusing:
    """Stands in for a backend that refuses to construct, carrying a bounded reason."""

    def __init__(self, reason: str = "filesystem_backend_non_posix") -> None:
        self.reason_code = reason


def _raise_refusal(reason: str = "filesystem_backend_non_posix"):  # noqa: ANN202
    def _fail():  # noqa: ANN202
        exc = RuntimeError("refused")
        exc.reason_code = reason  # type: ignore[attr-defined]
        raise exc

    return _fail


# --------------------------------------------------------------------------- the root cause


def test_a_refusing_filesystem_yields_a_report_rather_than_raising(monkeypatch):
    """The regression: this used to raise straight through every handler."""
    from secp_operator_deployment import production_context

    monkeypatch.setattr(production_context, "_production_fs", _raise_refusal())
    ctx = production_context.load_verify_context()

    assert ctx.profile is None
    assert ctx.profile_load_reason == "filesystem_backend_non_posix"
    assert ctx.expected is None
    assert ctx.host_observation is None
    assert ctx.installed_trust_ok is False
    # No host command could have run, and the count must say so rather than defaulting vaguely.
    assert ctx.host_commands_executed == 0


def test_the_filesystem_refusal_reason_is_catalogued():
    """An operator meeting this code must be able to look it up like any other."""
    for code in (
        "filesystem_backend_non_posix",
        "production_filesystem_unavailable",
        "unhandled_command_failure",
    ):
        assert classify_reason_code(code) is not None, code


@pytest.mark.parametrize("command", ["verify", "queue", "provenance"])
def test_every_command_survives_a_refusing_filesystem(monkeypatch, capsys, command):
    """All three commands resolve inputs; none may raise. `provenance` already behaved — the point
    is that `verify` and `queue` now do too, by the same mechanism."""
    from secp_operator_deployment import production_context

    monkeypatch.setattr(production_context, "_production_fs", _raise_refusal())

    code = main([command, "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert code in _PUBLISHED_EXIT_CODES, f"{command} exited {code}, outside every published table"
    assert code == payload["exit_code"]
    assert out.count("\n") == 1


# --------------------------------------------------------------------------- the top-level guard


def test_no_escaping_exception_can_produce_a_traceback(monkeypatch, capsys):
    """A fix that only handles the known cause leaves the next one unhandled, so the guard is
    tested against an exception it knows nothing about."""
    from secp_operator_deployment import cli

    def _explode(argv, deps=None):  # noqa: ANN001, ANN202
        raise ValueError("some unexpected internal failure")

    monkeypatch.setattr(cli, "run", _explode)

    code = main(["queue", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert code == UNAVAILABLE_EXIT_CODE == 20
    assert payload["status"] == "command_unavailable"
    assert payload["reason_code"] == "unhandled_command_failure"
    assert payload["exit_code"] == 20


def test_the_exception_message_is_never_rendered(monkeypatch, capsys):
    """Exception messages are exactly where absolute paths live. Only the bounded token may
    surface — this is the property that keeps the fix from reintroducing the leak."""
    from secp_operator_deployment import cli

    secret_ish = "/etc/secp/operator-deployment/profile.json"

    def _explode(argv, deps=None):  # noqa: ANN001, ANN202
        exc = RuntimeError(f"failed reading {secret_ish} for host 10.11.12.13")
        exc.reason_code = "filesystem_backend_non_posix"  # type: ignore[attr-defined]
        raise exc

    monkeypatch.setattr(cli, "run", _explode)

    main(["queue", "--json"])
    out = capsys.readouterr().out

    assert secret_ish not in out
    assert "10.11.12.13" not in out
    assert "Traceback" not in out
    assert json.loads(out)["reason_code"] == "filesystem_backend_non_posix"


def test_a_hostile_reason_code_is_replaced_rather_than_echoed():
    """``reason_code`` is attacker-adjacent only in the sense that it is arbitrary attribute data;
    it must still be bounded before it reaches a terminal."""
    for hostile in (
        "/etc/secp/profile.json",
        "https://vault.example/secret",
        "Contains Spaces And Caps",
        "x",  # too short for the bounded pattern
        "a" * 200,
        "",
        None,
        object(),
        b"bytes_reason",
    ):
        exc = RuntimeError("boom")
        exc.reason_code = hostile  # type: ignore[attr-defined]
        assert _bounded_reason(exc) == "unhandled_command_failure", hostile


def test_a_well_formed_reason_code_is_preserved():
    exc = RuntimeError("boom")
    exc.reason_code = "command_backend_non_posix"  # type: ignore[attr-defined]
    assert _bounded_reason(exc) == "command_backend_non_posix"


def test_an_exception_without_a_reason_code_still_yields_a_bounded_token():
    assert _bounded_reason(RuntimeError("boom")) == "unhandled_command_failure"


def test_systemexit_and_keyboardinterrupt_still_propagate(monkeypatch):
    """Swallowing argparse's SystemExit would silently break the command grammar; swallowing
    KeyboardInterrupt would make the command un-interruptible."""
    from secp_operator_deployment import cli

    for exc_type in (SystemExit, KeyboardInterrupt):

        def _explode(argv, deps=None, _e=exc_type):  # noqa: ANN001, ANN202
            raise _e()

        monkeypatch.setattr(cli, "run", _explode)
        with pytest.raises(exc_type):
            main(["queue", "--json"])


def test_an_unparsable_command_line_still_exits_through_argparse(capsys):
    """The guard must not convert a usage error into a report — a bad invocation is the caller's
    error, and argparse's own exit is the correct answer."""
    with pytest.raises(SystemExit):
        main(["not-a-command"])
    capsys.readouterr()


def test_the_human_rendering_of_a_bounded_failure_is_one_line(monkeypatch, capsys):
    from secp_operator_deployment import cli

    monkeypatch.setattr(cli, "run", _raising_run())

    code = main(["queue"])
    out = capsys.readouterr().out
    assert code == 20
    assert out.count("\n") == 1
    assert "Traceback" not in out
    assert "command_unavailable" in out


def _raising_run():  # noqa: ANN202
    def _explode(argv, deps=None):  # noqa: ANN001, ANN202
        raise RuntimeError("boom")

    return _explode
