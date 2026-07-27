"""secpctl enrollment controller commands (SECP-PR5H-B1, Phase 4).

Proves invite/status/revoke over an injected controller client: dry-run vs --write --confirm, the
auto-generated idempotency key (reused across a lost-response retry, never printed), read-only
status, the sealed default failing closed, stable exit categories, deterministic JSON, and that no
``--url``/``--ca``/``--token`` or internal CAS coordinate argument is accepted.
"""

from __future__ import annotations

import json

import pytest
from secp_management import cli
from secp_management.enrollment_cli import (
    EXIT_AUTH_UNAVAILABLE,
    EXIT_CONTROLLER_UNAVAILABLE,
    EXIT_REVISION_CONFLICT,
    EXIT_TRANSPORT,
    EnrollmentCliDeps,
)
from secp_management.enrollment_controller_client import (
    ControllerEnrollmentStatus,
    ControllerInvitation,
    EnrollmentControllerClientError,
)

EID = "sha256:" + "a" * 64

_INV = ControllerInvitation(
    enrollment_id=EID,
    invitation_id="sha256:" + "b" * 64,
    controller_installation_id="controller-dev0001",
    controller_key_id="sha256:" + "c" * 64,
    controller_trust_anchor_hex="11" * 32,
    controller_origin="https://controller.example.test",
    release_digest="sha256:" + "d" * 64,
    transaction_id="txn-0001",
    deployment_site_label="rack-01.eu_a",
    created_at="2026-07-27T00:00:00+00:00",
    expires_at="2026-07-27T01:00:00+00:00",
    state="invited",
    revision=0,
)
_STATUS = ControllerEnrollmentStatus(
    enrollment_id=EID,
    state="healthy",
    revision=5,
    controller_installation_id="controller-dev0001",
    controller_key_fingerprint="sha256:c",
    worker_installation_id="worker-bbbbbbbb",
    worker_key_fingerprint="sha256:9",
    release_fingerprint="sha256:d",
    offer_fingerprint="sha256:e",
    result_fingerprint="sha256:f",
    expires_at="2026-07-27T01:00:00+00:00",
    updated_at="2026-07-27T00:30:00+00:00",
    refusal_reason="",
)


class _FakeClient:
    def __init__(self, *, error=None, transient=0):
        self.error = error
        self.transient = transient
        self.created_keys: list[str] = []
        self.revoked: list[int] = []

    def create_invitation(self, *, deployment_site_label, ttl_seconds, idempotency_key):
        self.created_keys.append(idempotency_key)
        if self.transient > 0:
            self.transient -= 1
            raise EnrollmentControllerClientError("secpctl_controller_transport_failed")
        if self.error:
            raise EnrollmentControllerClientError(self.error)
        return _INV

    def get_enrollment_status(self, *, enrollment_id):
        if self.error:
            raise EnrollmentControllerClientError(self.error)
        return _STATUS

    def revoke_enrollment(self, *, enrollment_id, expected_revision):
        self.revoked.append(expected_revision)
        if self.error:
            raise EnrollmentControllerClientError(self.error)
        return ControllerEnrollmentStatus(**{**_STATUS.__dict__, "state": "refused", "revision": 1})


def _deps(client, *, key="idem-key-000000000000000000") -> EnrollmentCliDeps:
    return EnrollmentCliDeps(controller_client=client, idempotency_key=lambda: key)


def _run(argv, client=None, key="idem-key-000000000000000000"):
    return cli.run(argv, enrollment_deps=_deps(client or _FakeClient(), key=key))


# --- invite create -------------------------------------------------------------------------------


def test_invite_create_dry_run_makes_no_controller_call():
    client = _FakeClient()
    code, payload = _run(["enrollment", "invite", "create", "--site", "rack-01.eu_a"], client)
    assert code == 0 and payload["mode"] == "dry_run"
    assert client.created_keys == []  # no controller contact in a dry run


def test_invite_create_write_returns_the_non_secret_invitation_and_hides_the_key():
    client = _FakeClient()
    code, payload = _run(
        ["enrollment", "invite", "create", "--site", "rack-01.eu_a", "--write", "--confirm"],
        client,
        key="secret-idem-key-1234567890",
    )
    assert code == 0 and payload["mode"] == "written"
    assert payload["enrollment_id"] == EID and payload["controller_origin"].startswith("https://")
    # the auto-generated idempotency key was used, and NEVER appears in the output
    assert client.created_keys == ["secret-idem-key-1234567890"]
    assert "secret-idem-key-1234567890" not in json.dumps(payload)
    assert "idempotency" not in json.dumps(payload)


def test_invite_create_retries_with_the_same_key_on_transient_failure():
    client = _FakeClient(transient=2)
    code, payload = _run(
        ["enrollment", "invite", "create", "--site", "s", "--write", "--confirm"],
        client,
        key="stable-key-0000000000000000",
    )
    assert code == 0 and payload["mode"] == "written"
    # three attempts, all with the IDENTICAL key (idempotent lost-response retry)
    assert client.created_keys == ["stable-key-0000000000000000"] * 3


# --- status (read-only) --------------------------------------------------------------------------


def test_status_is_read_only_and_bounded():
    code, payload = _run(["enrollment", "status", "--enrollment-id", EID])
    assert code == 0 and payload["mode"] == "read"
    assert payload["state"] == "healthy" and payload["revision"] == 5
    assert "controller_trust_anchor_hex" not in payload  # bounded fingerprints only


# --- revoke --------------------------------------------------------------------------------------


def test_revoke_requires_write_and_confirm():
    client = _FakeClient()
    code, payload = _run(
        ["enrollment", "revoke", "--enrollment-id", EID, "--expected-revision", "0"], client
    )
    assert code == 0 and payload["mode"] == "dry_run" and client.revoked == []


def test_revoke_write_reports_the_terminal_state():
    client = _FakeClient()
    code, payload = _run(
        [
            "enrollment",
            "revoke",
            "--enrollment-id",
            EID,
            "--expected-revision",
            "0",
            "--write",
            "--confirm",
        ],
        client,
    )
    assert code == 0 and payload["state"] == "refused" and client.revoked == [0]


# --- sealed default + stable exit categories -----------------------------------------------------


def test_sealed_default_fails_closed():
    code, payload = cli.run(["enrollment", "status", "--enrollment-id", EID])
    assert code == EXIT_CONTROLLER_UNAVAILABLE
    assert payload["reason_code"] == "secpctl_controller_client_unavailable"


@pytest.mark.parametrize(
    "reason,expected_exit",
    [
        ("secpctl_operator_auth_expired", EXIT_AUTH_UNAVAILABLE),
        ("secpctl_controller_revision_conflict", EXIT_REVISION_CONFLICT),
        ("secpctl_controller_transport_failed", EXIT_TRANSPORT),
        ("secpctl_controller_unavailable", EXIT_CONTROLLER_UNAVAILABLE),
    ],
)
def test_error_reasons_map_to_stable_exit_categories(reason, expected_exit):
    code, payload = _run(
        ["enrollment", "status", "--enrollment-id", EID], _FakeClient(error=reason)
    )
    assert code == expected_exit and payload["reason_code"] == reason


def test_json_output_is_deterministic():
    _, payload = _run(["enrollment", "status", "--enrollment-id", EID])
    a = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    b = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    assert a == b and payload["command"] == "enrollment status"


# --- the surface accepts NO url/ca/token/CAS argument --------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        ["--url", "https://evil"],
        ["--ca", "/tmp/ca.pem"],
        ["--token", "abc"],
        ["--state-digest", "sha256:x"],
        ["--predecessor-digest", "sha256:x"],
        ["--sequence", "1"],
    ],
)
def test_no_privileged_or_internal_argument_is_accepted(extra):
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["enrollment", "status", "--enrollment-id", EID, *extra])
