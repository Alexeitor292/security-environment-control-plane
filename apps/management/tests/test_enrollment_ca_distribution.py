"""Controller-CA distribution through the invitation (SECP WS-B).

The controller CA travels IN the invitation rather than in the signed release bundle. These are the
failure-injection tests for that path: the CA must survive the invitation-file projection, be
bounded independently of the other fields, be grammar-checked in THIS layer rather than at
``ssl.create_default_context``, and be sourced from the operator's own bootstrap-recorded locator
rather than from anything the controller asserts about itself.

The single most important test here is
``test_the_ca_survives_the_invitation_file_projection``: ``load_invitation_file`` ends with a
projection over ``_REQUIRED_INVITATION_KEYS`` and performs NO unknown-key rejection, so a CA absent
from that tuple parses fine and is then silently discarded — surfacing much later as an opaque TLS
error with nothing pointing back at the truncation.
"""

from __future__ import annotations

import json

import pytest
from secp_management import ManagementError
from secp_management.enrollment_cli import (
    EXIT_CONTROLLER_UNAVAILABLE,
    EXIT_ENROLLMENT_TERMINAL,
    EXIT_MALFORMED,
    EXIT_WORKER_HEALTH,
    EnrollmentCliDeps,
    LocatorControllerCaBundleProvider,
    SealedControllerCaBundleProvider,
    WorkerCliError,
    controller_key_fingerprint,
    invite_create,
    load_invitation_file,
    worker_enroll,
    worker_retry,
    worker_status,
)
from secp_management.transaction import WriteGate


class _FakeCa:
    def read_pem(self) -> str:
        return CA_PEM


def _pem(body: str) -> str:
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


CA_PEM = _pem("MIIBfakeControllerCA000000000==")
# A synthetic chain sized like a real one, used here only to exercise the bound cheaply. The REAL
# measurements are in `test_enrollment_ca_real_chain.py`, which generates actual certificates:
# production controller CA 599B, ecdsa-p256 root+intermediate 1023B, RSA-4096 root+intermediate
# 3480B (42% of the 8192 CA bound). An earlier version of this comment claimed a 4096-byte cap
# "would have rejected" an enterprise chain — measurement shows it would not have. The 8192 CA
# bound is right with >2x margin on the largest realistic shape; the whole-file cap is 16384 to stay
# CONSISTENT with a CA field allowed to reach 8192, not because any measured chain needs it.
ENTERPRISE_CHAIN = "".join(
    f"-----BEGIN CERTIFICATE-----\n{('MIIFake' + str(n)) * 160}\n-----END CERTIFICATE-----\n"
    for n in range(2)
)

_INVITATION = {
    "enrollment_id": "sha256:" + "a" * 64,
    "invitation_id": "sha256:" + "b" * 64,
    "controller_installation_id": "controller-dev0001",
    "controller_key_id": "sha256:" + "c" * 64,
    "controller_origin": "https://controller.example.test",
    "controller_ca_bundle_pem": CA_PEM,
    "transaction_id": "txn-0001",
    "release_digest": "sha256:" + "d" * 64,
    "expires_at": "2999-07-27T01:00:00+00:00",
}


def _write(tmp_path, **over) -> str:
    body = {**_INVITATION, **over}
    for key in [k for k, v in over.items() if v is _ABSENT]:
        body.pop(key, None)
    path = tmp_path / "invitation.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return str(path)


class _ABSENT:
    """Sentinel: drop the key entirely rather than overriding its value."""


# --- the projection guard (the defect this design is most exposed to) ----------------------------


def test_the_ca_survives_the_invitation_file_projection(tmp_path):
    """`load_invitation_file` returns a projection over `_REQUIRED_INVITATION_KEYS` with no
    unknown-key rejection. If the CA is not on that tuple it parses and is silently DROPPED, and the
    worker later fails TLS with nothing naming the cause. This test fails loudly on that."""
    loaded = load_invitation_file(_write(tmp_path))

    assert loaded["controller_ca_bundle_pem"] == CA_PEM


def test_an_invitation_without_a_ca_is_refused(tmp_path):
    with pytest.raises(WorkerCliError) as ei:
        load_invitation_file(_write(tmp_path, controller_ca_bundle_pem=_ABSENT))

    assert ei.value.reason_code == "secpctl_invitation_file_invalid"


def test_an_ordinary_enterprise_root_plus_intermediate_chain_is_accepted(tmp_path):
    """The bound must not reject the real-world case it exists to serve."""
    assert 2000 < len(ENTERPRISE_CHAIN.encode("utf-8")) < 8192

    loaded = load_invitation_file(_write(tmp_path, controller_ca_bundle_pem=ENTERPRISE_CHAIN))

    assert loaded["controller_ca_bundle_pem"] == ENTERPRISE_CHAIN


# --- bounds: whole file, per field, and the CA's own ----------------------------------------------


def test_an_oversized_ca_has_its_own_reason_code(tmp_path):
    huge = "-----BEGIN CERTIFICATE-----\n" + ("A" * 9000) + "\n-----END CERTIFICATE-----\n"

    with pytest.raises(WorkerCliError) as ei:
        load_invitation_file(_write(tmp_path, controller_ca_bundle_pem=huge))

    assert ei.value.reason_code == "secpctl_invitation_ca_too_large"


def test_an_oversized_ordinary_field_is_distinguishable_from_a_malformed_file(tmp_path):
    """Without a PER-FIELD bound only the whole-file cap applies, so one oversized field can crowd a
    required field out of the budget and the failure reads as a malformed file instead."""
    with pytest.raises(WorkerCliError) as ei:
        load_invitation_file(_write(tmp_path, transaction_id="t" * 2000))

    assert ei.value.reason_code == "secpctl_invitation_field_too_large"


def test_a_file_over_the_whole_file_cap_is_refused(tmp_path):
    with pytest.raises(WorkerCliError) as ei:
        load_invitation_file(_write(tmp_path, deployment_site_label="x" * 20000))

    assert ei.value.reason_code == "secpctl_invitation_file_invalid"


# --- PEM grammar: refuse in THIS layer, not at ssl.create_default_context -------------------------


@pytest.mark.parametrize(
    "value",
    [
        "not a pem at all",
        "-----BEGIN CERTIFICATE-----\nAAAA\n",  # no END
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----",
        # a PRIVATE KEY must never be loaded as a trust anchor
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        # a certificate followed by a key: the key block must poison the whole value
        CA_PEM + "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
        "-----BEGIN CERTIFICATE-----\nAA\x00AA\n-----END CERTIFICATE-----\n",  # control character
    ],
)
def test_a_malformed_or_wrong_kind_pem_refuses_with_a_ca_specific_code(tmp_path, value):
    with pytest.raises(WorkerCliError) as ei:
        load_invitation_file(_write(tmp_path, controller_ca_bundle_pem=value))

    assert ei.value.reason_code == "secpctl_invitation_ca_invalid"


# --- the CA source: the operator's locator, never the controller's own claim ----------------------


class _FakeLocator:
    def __init__(self, path="/etc/secp/controller/tls/ca-bundle.pem") -> None:
        self.ca_bundle_path = path


class _FakeLocatorProvider:
    def __init__(self, locator=None, error=None) -> None:
        self._locator = locator or _FakeLocator()
        self._error = error

    def locate(self):
        if self._error:
            raise ManagementError(self._error)
        return self._locator


class _FakeFs:
    def __init__(self, content=None, error=False) -> None:
        self._content = content
        self._error = error
        self.reads: list[str] = []

    def safe_read(self, path, *, max_bytes, expected_uid):
        self.reads.append(path)
        if self._error:
            raise OSError("unreadable")
        return self._content


def test_the_ca_is_read_from_the_bootstrap_recorded_locator_path():
    fs = _FakeFs(content=CA_PEM.encode("utf-8"))
    provider = LocatorControllerCaBundleProvider(fs, _FakeLocatorProvider())

    assert provider.read_pem() == CA_PEM
    # the path came from the locator recorded at controller bootstrap, not from any CLI/API input
    assert fs.reads == ["/etc/secp/controller/tls/ca-bundle.pem"]


def test_an_unreadable_ca_bundle_fails_closed_without_leaking_the_path():
    provider = LocatorControllerCaBundleProvider(_FakeFs(error=True), _FakeLocatorProvider())

    with pytest.raises(ManagementError) as ei:
        provider.read_pem()

    assert ei.value.reason_code == "secpctl_controller_ca_unavailable"
    assert "/etc/secp" not in str(ei.value)


def test_a_ca_bundle_that_is_not_a_certificate_chain_is_refused_at_the_source():
    fs = _FakeFs(content=b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
    provider = LocatorControllerCaBundleProvider(fs, _FakeLocatorProvider())

    with pytest.raises(ManagementError) as ei:
        provider.read_pem()

    assert ei.value.reason_code == "secpctl_invitation_ca_invalid"


def test_the_provider_repr_never_carries_the_ca_path():
    provider = LocatorControllerCaBundleProvider(_FakeFs(), _FakeLocatorProvider())

    assert "/etc/secp" not in repr(provider) and "redacted" in repr(provider)


# --- invite create composes the CA in, and fails closed without one -------------------------------


class _RecordingClient:
    def __init__(self) -> None:
        self.calls = 0

    def create_invitation(self, **_):
        self.calls += 1
        raise AssertionError("the controller must not be contacted without a CA")


def test_invite_create_fails_closed_before_contacting_the_controller_without_a_ca():
    """An invitation is SINGLE-USE. Resolving the CA first means a missing CA cannot burn one."""
    client = _RecordingClient()
    deps = EnrollmentCliDeps(controller_client=client, ca_bundle=SealedControllerCaBundleProvider())

    code, report = invite_create(
        deps,
        deployment_site_label="rack-01.eu_a",
        ttl_seconds=3600,
        gate=WriteGate(write=True, confirm=True),
    )

    assert code == EXIT_CONTROLLER_UNAVAILABLE
    assert report["reason_code"] == "secpctl_controller_ca_unavailable"
    assert client.calls == 0


# --- the operator's out-of-band verification aid -------------------------------------------------


def test_the_controller_key_fingerprint_is_short_grouped_and_derived_from_the_key_id():
    fingerprint = controller_key_fingerprint("sha256:" + "ab" * 32)

    assert fingerprint == "abababab abababab abababab abababab"
    assert "sha256:" not in fingerprint  # the prefix carries no comparison value


def test_the_fingerprint_of_a_different_controller_key_differs():
    a = controller_key_fingerprint("sha256:" + "a" * 64)
    b = controller_key_fingerprint("sha256:" + "b" * 64)

    assert a != b


def test_exit_categories_for_the_new_ca_refusals_are_stable():
    from secp_management.enrollment_cli import exit_for

    assert exit_for("secpctl_invitation_ca_invalid") == EXIT_MALFORMED
    assert exit_for("secpctl_invitation_ca_too_large") == EXIT_MALFORMED
    assert exit_for("secpctl_invitation_field_too_large") == EXIT_MALFORMED
    assert exit_for("secpctl_controller_ca_unavailable") == EXIT_CONTROLLER_UNAVAILABLE


# --- a completed drive that did not reach healthy must not exit 0 ---------------------------------


class _StateEnroller:
    """Reports whatever authoritative state the controller would have reported."""

    def __init__(self, state: str) -> None:
        self._state = state

    def enroll(self, invitation, *, now):
        return {
            "enrollment_id": invitation["enrollment_id"],
            "state": self._state,
            "revision": 3,
            "already_healthy": False,
        }

    def retry(self, invitation, *, now):
        return self.enroll(invitation, now=now)

    def status(self, invitation):
        return {"enrollment_id": invitation["enrollment_id"], "state": self._state}


@pytest.mark.parametrize(
    ("state", "expected_exit"),
    [
        ("healthy", 0),
        ("refused", EXIT_ENROLLMENT_TERMINAL),
        ("recovery_required", EXIT_ENROLLMENT_TERMINAL),
        ("verified", EXIT_WORKER_HEALTH),  # the exchange stopped short of healthy
        ("invited", EXIT_WORKER_HEALTH),
    ],
)
def test_worker_enroll_exit_code_follows_the_authoritative_state(tmp_path, state, expected_exit):
    """An operator scripting `secpctl worker enroll` must not read a refused or recovery-required
    enrollment as a success. Only `healthy` is exit 0."""
    deps = EnrollmentCliDeps(worker_enroller=_StateEnroller(state), ca_bundle=_FakeCa())

    code, report = worker_enroll(
        deps, invitation_file=_write(tmp_path), gate=WriteGate(write=True, confirm=True)
    )

    assert code == expected_exit
    assert report["state"] == state
    if expected_exit != 0:
        assert report["reason_code"]  # the non-zero outcome is named, not just a bare state


def test_worker_retry_uses_the_same_exit_semantics_as_enroll(tmp_path):
    deps = EnrollmentCliDeps(
        worker_enroller=_StateEnroller("recovery_required"), ca_bundle=_FakeCa()
    )

    code, report = worker_retry(
        deps, invitation_file=_write(tmp_path), gate=WriteGate(write=True, confirm=True)
    )

    assert code == EXIT_ENROLLMENT_TERMINAL
    assert report["reason_code"] == "enrollment_recovery_required"


def test_worker_status_is_a_read_and_stays_exit_zero_on_an_in_progress_marker(tmp_path):
    """`status` reports the LOCAL restart marker, not a controller state. Reporting `offer_verified`
    is a successful read of an in-progress enrollment, not a failed one."""
    deps = EnrollmentCliDeps(worker_enroller=_StateEnroller("offer_verified"), ca_bundle=_FakeCa())

    code, report = worker_status(deps, invitation_file=_write(tmp_path))

    assert code == 0
    assert report["state"] == "offer_verified"
    assert "reason_code" not in report


def test_the_enroll_report_carries_the_fingerprint_for_out_of_band_verification(tmp_path):
    deps = EnrollmentCliDeps(worker_enroller=_StateEnroller("healthy"), ca_bundle=_FakeCa())

    _code, report = worker_enroll(
        deps, invitation_file=_write(tmp_path), gate=WriteGate(write=True, confirm=True)
    )

    assert report["controller_key_id"] == _INVITATION["controller_key_id"]
    assert report["controller_key_fingerprint"] == controller_key_fingerprint(
        _INVITATION["controller_key_id"]
    )


def test_the_dry_run_shows_the_fingerprint_before_the_worker_commits(tmp_path):
    """The dry run is where an operator verifies the controller identity out of band."""
    deps = EnrollmentCliDeps(worker_enroller=_StateEnroller("healthy"), ca_bundle=_FakeCa())

    code, report = worker_enroll(
        deps, invitation_file=_write(tmp_path), gate=WriteGate(write=False, confirm=False)
    )

    assert code == 0 and report["mode"] == "dry_run"
    assert report["controller_key_fingerprint"] == controller_key_fingerprint(
        _INVITATION["controller_key_id"]
    )


# --- TRIPWIRE: the production CLI wiring this feature needs is NOT on this branch -----------------
# `_production_enrollment_deps` lives in `apps/management/secp_management/cli.py`, which Stream C
# owns. WS-B must not edit it, so the CA provider is composed there by Stream C, not here.
#
# Until that lands, `EnrollmentCliDeps.ca_bundle` falls to `SealedControllerCaBundleProvider` in
# production, and EVERY `secpctl enrollment invite create` then refuses
# `secpctl_controller_ca_unavailable`
# — the CA distribution feature ships INERT.
#
# These tests make that loud. The xfail FLIPS TO A FAILURE the moment the wiring lands (strict), so
# nobody has to remember to come back and delete it; the companion test states the exact required
# shape so the requirement is readable in the codebase, not only in a hand-off message.


def test_the_production_cli_does_not_yet_compose_the_ca_provider():
    """States the gap explicitly: today production gets the SEALED provider.

    This is the honest status of the feature on this branch, not an assertion that it is correct.
    """
    from secp_management.enrollment_cli import (
        EnrollmentCliDeps,
        SealedControllerCaBundleProvider,
    )

    assert isinstance(EnrollmentCliDeps().ca_bundle, SealedControllerCaBundleProvider)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "PENDING Stream C: cli.py:_production_enrollment_deps must pass "
        "ca_bundle=LocatorControllerCaBundleProvider(fs, locator_provider), sharing ONE "
        "FileControllerApiLocatorProvider with HttpsEnrollmentControllerClient. Strict xfail, so "
        "this FAILS (and must be deleted) the moment the wiring lands."
    ),
)
def test_production_enrollment_deps_composes_the_real_ca_provider(monkeypatch, tmp_path):
    from secp_management import cli
    from secp_management.enrollment_cli import LocatorControllerCaBundleProvider

    deps = cli._production_enrollment_deps()
    assert isinstance(deps.ca_bundle, LocatorControllerCaBundleProvider)


def test_the_ca_provider_resolves_through_the_locator_it_was_given():
    """The security constraint behind the requirement, provable without touching cli.py.

    The provider reads the CA path from the locator instance it is handed. That is why the wiring
    must share ONE ``FileControllerApiLocatorProvider`` with the controller client: two instances
    could resolve two DIFFERENT locators, handing the worker a CA chain the operator's own client
    never pinned its TLS to.
    """
    counting = _CountingLocatorProvider()
    provider = LocatorControllerCaBundleProvider(_FakeFs(content=CA_PEM.encode("utf-8")), counting)

    assert provider.read_pem() == CA_PEM
    assert counting.calls == 1, "the provider must resolve through the locator it was given"


class _CountingLocatorProvider(_FakeLocatorProvider):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def locate(self):
        self.calls += 1
        return super().locate()
