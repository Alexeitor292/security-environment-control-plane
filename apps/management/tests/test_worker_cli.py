"""secpctl worker enrollment commands (SECP-PR5H-B1, Phase 4).

Proves worker enroll/status/retry over an injected worker enroller: dry-run vs --write --confirm,
enroll-to-healthy, read-only status, resume-safe retry, the sealed default failing closed, malformed
invitation refusal, terminal/health exit categories, and — critically — that the worker path NEVER
uses the operator OIDC token or the controller client (it authenticates only by PoP + signed offer).
"""

from __future__ import annotations

import json

import pytest
from secp_management import cli
from secp_management.enrollment_cli import (
    EXIT_CONTROLLER_UNAVAILABLE,
    EXIT_ENROLLMENT_TERMINAL,
    EXIT_MALFORMED,
    EXIT_WORKER_HEALTH,
    EnrollmentCliDeps,
)

CA_PEM = "-----BEGIN CERTIFICATE-----\nMIIBfakeControllerCA000000000==\n-----END CERTIFICATE-----\n"

_INVITATION = {
    "enrollment_id": "sha256:" + "a" * 64,
    "invitation_id": "sha256:" + "b" * 64,
    "controller_installation_id": "controller-dev0001",
    "controller_key_id": "sha256:" + "c" * 64,
    "controller_trust_anchor_hex": "11" * 32,
    "controller_origin": "https://controller.example.test",
    "controller_ca_bundle_pem": CA_PEM,
    "transaction_id": "txn-0001",
    "release_digest": "sha256:" + "d" * 64,
    "deployment_site_label": "rack-01.eu_a",
    "created_at": "2026-07-27T00:00:00+00:00",
    "expires_at": "2999-07-27T01:00:00+00:00",
    "state": "invited",
    "revision": 0,
}


class _DriverError(Exception):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class _FakeEnroller:
    def __init__(self, *, error=None) -> None:
        self.error = error
        self.calls: list[str] = []

    def enroll(self, invitation, *, now):
        self.calls.append("enroll")
        if self.error:
            raise _DriverError(self.error)
        return {"enrollment_id": invitation["enrollment_id"], "state": "healthy", "revision": 5}

    def retry(self, invitation, *, now):
        self.calls.append("retry")
        if self.error:
            raise _DriverError(self.error)
        return {"enrollment_id": invitation["enrollment_id"], "state": "healthy", "revision": 5}

    def status(self, invitation):
        self.calls.append("status")
        if self.error:
            raise _DriverError(self.error)
        return {"enrollment_id": invitation["enrollment_id"], "state": "offer_transported"}


class _ExplodingClient:
    """A controller client that fails the test if the worker path ever touches it."""

    def create_invitation(self, **_):
        raise AssertionError("worker exchange must not use the controller client / operator token")

    def get_enrollment_status(self, **_):
        raise AssertionError("worker exchange must not use the controller client / operator token")

    def revoke_enrollment(self, **_):
        raise AssertionError("worker exchange must not use the controller client / operator token")


def _write_invitation(tmp_path, **over) -> str:
    body = {**_INVITATION, **over}
    path = tmp_path / "invitation.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return str(path)


def _deps(enroller) -> EnrollmentCliDeps:
    # a controller client that explodes if used, proving the worker path never touches it
    return EnrollmentCliDeps(controller_client=_ExplodingClient(), worker_enroller=enroller)


def _run(argv, enroller):
    return cli.run(argv, enrollment_deps=_deps(enroller))


def test_worker_enroll_dry_run_makes_no_driver_call(tmp_path):
    enr = _FakeEnroller()
    code, payload = _run(["worker", "enroll", "--invitation", _write_invitation(tmp_path)], enr)
    assert code == 0 and payload["mode"] == "dry_run" and enr.calls == []


def test_worker_enroll_write_drives_to_healthy(tmp_path):
    enr = _FakeEnroller()
    code, payload = _run(
        ["worker", "enroll", "--invitation", _write_invitation(tmp_path), "--write", "--confirm"],
        enr,
    )
    assert code == 0 and payload["mode"] == "written"
    assert payload["state"] == "healthy" and payload["revision"] == 5 and enr.calls == ["enroll"]


def test_worker_status_is_read_only(tmp_path):
    enr = _FakeEnroller()
    code, payload = _run(
        ["worker", "enrollment", "status", "--invitation", _write_invitation(tmp_path)], enr
    )
    assert code == 0 and payload["mode"] == "read" and enr.calls == ["status"]
    assert payload["state"] == "offer_transported"


def test_worker_retry_write_re_drives(tmp_path):
    enr = _FakeEnroller()
    code, payload = _run(
        [
            "worker",
            "enrollment",
            "retry",
            "--invitation",
            _write_invitation(tmp_path),
            "--write",
            "--confirm",
        ],
        enr,
    )
    assert code == 0 and payload["mode"] == "written" and enr.calls == ["retry"]


def test_sealed_worker_enroller_fails_closed(tmp_path):
    code, payload = cli.run(
        ["worker", "enroll", "--invitation", _write_invitation(tmp_path), "--write", "--confirm"]
    )
    assert code == EXIT_CONTROLLER_UNAVAILABLE
    assert payload["reason_code"] == "secpctl_worker_enroller_unavailable"


def test_a_malformed_invitation_file_is_refused(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    code, payload = _run(
        ["worker", "enroll", "--invitation", str(path), "--write", "--confirm"], _FakeEnroller()
    )
    assert code == EXIT_MALFORMED and payload["reason_code"] == "secpctl_invitation_file_invalid"


def test_an_invitation_missing_a_required_field_is_refused(tmp_path):
    path = _write_invitation(tmp_path)
    import pathlib

    data = json.loads(pathlib.Path(path).read_text())
    del data["controller_origin"]
    pathlib.Path(path).write_text(json.dumps(data), encoding="utf-8")
    code, payload = _run(
        ["worker", "enroll", "--invitation", path, "--write", "--confirm"], _FakeEnroller()
    )
    assert code == EXIT_MALFORMED


@pytest.mark.parametrize(
    "reason,expected",
    [
        ("enrollment_invitation_revoked", EXIT_ENROLLMENT_TERMINAL),
        ("enrollment_health_incomplete", EXIT_WORKER_HEALTH),
        ("enrollment_transport_not_activated", EXIT_CONTROLLER_UNAVAILABLE),
    ],
)
def test_driver_refusals_map_to_stable_exit_categories(tmp_path, reason, expected):
    code, payload = _run(
        ["worker", "enroll", "--invitation", _write_invitation(tmp_path), "--write", "--confirm"],
        _FakeEnroller(error=reason),
    )
    assert code == expected and payload["reason_code"] == reason


def test_no_url_ca_or_token_argument_on_worker_commands(tmp_path):
    for extra in (["--token", "x"], ["--url", "https://x"], ["--ca", "/x"]):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(
                ["worker", "enroll", "--invitation", _write_invitation(tmp_path), *extra]
            )


# --- the concrete adapter reaches the real (sealed-default) secp_worker driver -------------------


def test_concrete_worker_enroller_status_is_local_and_reads_the_durable_marker():
    """``status`` must never drive the exchange or contact the controller, and must not raise on a
    host that has never enrolled — an absent marker is simply ``unknown``."""
    from secp_commissioning.runtime import InMemoryFilesystem
    from secp_management.worker_enroller import build_worker_enroller
    from secp_worker.enrollment_state_store import DurableWorkerEnrollmentStateStore

    fs = InMemoryFilesystem()
    enroller = build_worker_enroller(fs)

    assert enroller.status(_INVITATION)["state"] == "unknown"

    DurableWorkerEnrollmentStateStore(fs).record(_INVITATION["enrollment_id"], "offer_verified")
    assert enroller.status(_INVITATION)["state"] == "offer_verified"


def test_the_production_composition_is_real_and_provisions_the_protected_key():
    """The composition is REAL, not sealed: it reaches the protected key seam, provisions the
    fixed-path pair under the CLI's ``--write --confirm`` authority, and then genuinely attempts the
    invitation-pinned transport. The controller origin is an RFC 6761 ``.test`` name, so the attempt
    fails closed with a bounded transport code — proving the transport is wired, not stubbed.

    (The health-gate refusal on an unprepared host is proven end to end against a faithful
    in-process controller in ``test_enrollment_health_probes.py``; duplicating it here would only
    re-test the driver.)"""
    from secp_commissioning.runtime import InMemoryFilesystem
    from secp_management.worker_enroller import build_worker_enroller
    from secp_worker.enrollment_driver import WorkerEnrollmentDriverError
    from secp_worker.enrollment_key import observe_local_worker_enrollment_key

    fs = InMemoryFilesystem()
    enroller = build_worker_enroller(fs)

    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        enroller.enroll(_INVITATION, now="2026-07-27T00:00:00+00:00")

    assert ei.value.reason_code == "enrollment_transport_failed"
    # the sealed default could never have got this far: the key seam really ran
    assert observe_local_worker_enrollment_key(fs)
    # and nothing was recorded, because no exchange step completed
    assert enroller.status(_INVITATION)["state"] == "unknown"


def test_an_invitation_without_a_ca_refuses_before_the_key_seam_runs():
    """The driver validates the invitation first, so a CA-less invitation cannot even cause a key to
    be provisioned on the host."""
    from secp_commissioning.runtime import InMemoryFilesystem
    from secp_management.worker_enroller import build_worker_enroller
    from secp_worker.enrollment_driver import WorkerEnrollmentDriverError
    from secp_worker.enrollment_key import observe_local_worker_enrollment_key

    fs = InMemoryFilesystem()
    enroller = build_worker_enroller(fs)

    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        enroller.enroll(
            {**_INVITATION, "controller_ca_bundle_pem": "  "},
            now="2026-07-27T00:00:00+00:00",
        )

    assert ei.value.reason_code == "enrollment_invitation_ca_missing"
    assert not observe_local_worker_enrollment_key(fs)  # no key was provisioned


def test_the_production_composition_builds_one_driver_per_invitation():
    """The transport carries the per-invitation origin + CA, and the probes pin the invitation at
    construction. A driver reused across enrollments would pin the FIRST invitation's origin/CA for
    every later one."""
    from secp_commissioning.runtime import InMemoryFilesystem
    from secp_management.worker_enroller import DriverWorkerEnroller
    from secp_worker.enrollment_state_store import DurableWorkerEnrollmentStateStore

    fs = InMemoryFilesystem()
    seen = []

    class _Driver:
        def __init__(self, inputs) -> None:
            self.inputs = inputs

        def enroll(self, inputs, *, now):
            from secp_worker.enrollment_driver import DriverOutcome

            return DriverOutcome(inputs.enrollment_id, "healthy", revision=5, already_healthy=False)

    def factory(inputs):
        driver = _Driver(inputs)
        seen.append(driver)
        return driver

    enroller = DriverWorkerEnroller(
        fs=fs, state_store=DurableWorkerEnrollmentStateStore(fs), driver_factory=factory
    )
    other = {**_INVITATION, "enrollment_id": "sha256:" + "e" * 64}
    enroller.enroll(_INVITATION, now="2026-07-27T00:00:00+00:00")
    enroller.enroll(other, now="2026-07-27T00:00:00+00:00")

    assert len(seen) == 2 and seen[0] is not seen[1]
    assert seen[0].inputs.enrollment_id != seen[1].inputs.enrollment_id
    # each driver was pinned to the CA chain of its own invitation
    assert all(d.inputs.controller_ca_bundle_pem == CA_PEM for d in seen)
