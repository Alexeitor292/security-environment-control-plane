"""Process-level proof for the credential account serialization primitive."""

from __future__ import annotations

import multiprocessing

from secp_management.operator_credential_lock import credential_account_lock

_SERVICE = "secp-secpctl-lock-test"
_ACCOUNT = "https://lock-test.invalid"


def _hold_lock(entered, release) -> None:
    with credential_account_lock(_SERVICE, _ACCOUNT):
        entered.set()
        release.wait(10)


def _wait_for_lock(started, entered) -> None:
    started.set()
    with credential_account_lock(_SERVICE, _ACCOUNT):
        entered.set()


def test_the_account_lock_excludes_a_second_process() -> None:
    context = multiprocessing.get_context("spawn")
    first_entered = context.Event()
    first_release = context.Event()
    second_started = context.Event()
    second_entered = context.Event()
    first = context.Process(target=_hold_lock, args=(first_entered, first_release))
    second = context.Process(target=_wait_for_lock, args=(second_started, second_entered))
    first.start()
    try:
        assert first_entered.wait(5), "first process did not acquire the account lock"
        second.start()
        assert second_started.wait(5), "second process did not reach lock acquisition"
        assert not second_entered.wait(0.25), "two processes held one account lock together"
        first_release.set()
        assert second_entered.wait(5), "second process did not acquire after release"
        first.join(5)
        second.join(5)
        assert first.exitcode == 0
        assert second.exitcode == 0
    finally:
        first_release.set()
        for process in (first, second):
            if process.pid is not None and process.is_alive():
                process.terminate()
            if process.pid is not None:
                process.join(5)
