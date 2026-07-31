"""OS keystore bindings for the operator credential (SECP-PR5H-B2, Workstream C).

Only one binding can execute on any given host, so the tests are split:

* the PURE marshalling — size bounds and key composition — runs everywhere and is where the
  security-relevant properties live (an oversized record must refuse before any OS call, a malformed
  account must never reach a keystore key);
* resolution is exercised for every platform string by driving ``sys.platform``, which proves the
  no-fallback rule holds on hosts that have no binding at all — Linux included, where this slice
  deliberately ships none (see the module docstring);
* a real round trip against the platform's own keystore runs only where that keystore exists. On
  this repository's Windows development hosts that is a genuine end-to-end exercise of the ctypes
  binding; the macOS binding has no host here and is covered only structurally.
"""

from __future__ import annotations

import sys

import pytest
from secp_management import ManagementError
from secp_management.operator_credential_backends import (
    BACKEND_MACOS_KEYCHAIN,
    BACKEND_WINDOWS_CREDENTIAL_MANAGER,
    MAX_SECRET_BYTES,
    MacOSKeychainBinding,
    WindowsCredentialManagerBinding,
    require_identifier,
    require_storable,
    resolve_secret_store_binding,
    target_name,
)

SERVICE = "secp-secpctl-operator"
ACCOUNT = "https://controller.invalid"
#: A namespaced service used ONLY by the live round-trip test, so it can never collide with — or
#: delete — a real operator credential on a developer's machine.
SELFTEST_SERVICE = "secp-secpctl-operator-selftest"


# --- size bounds ----------------------------------------------------------------------------------


def test_the_shared_secret_bound_is_the_tightest_supported_keystores():
    """Windows documents ``CRED_MAX_CREDENTIAL_BLOB_SIZE`` as 5*512 bytes (wincred.h). Applying it
    on every platform means a credential that stores on one operator workstation stores on all of
    them, instead of failing only on Windows."""
    assert MAX_SECRET_BYTES == 5 * 512 == 2560


def test_a_secret_at_the_bound_is_accepted_and_one_byte_over_is_refused():
    assert require_storable(b"x" * MAX_SECRET_BYTES) == b"x" * MAX_SECRET_BYTES
    with pytest.raises(ManagementError) as ei:
        require_storable(b"x" * (MAX_SECRET_BYTES + 1))
    assert ei.value.reason_code == "secpctl_credential_too_large"


@pytest.mark.parametrize("value", [b"", "", None, 0, []])
def test_a_non_bytes_or_empty_secret_is_refused(value):
    with pytest.raises(ManagementError) as ei:
        require_storable(value)
    assert ei.value.reason_code == "secpctl_credential_record_invalid"


def test_an_oversized_secret_never_echoes_its_content_in_the_refusal():
    with pytest.raises(ManagementError) as ei:
        require_storable(b"SENSITIVE" * 600)
    assert "SENSITIVE" not in f"{ei.value!r} {ei.value}"


# --- identifiers and key composition --------------------------------------------------------------


@pytest.mark.parametrize("value", ["a", SERVICE, ACCOUNT, "x" * 255])
def test_bounded_identifiers_are_accepted(value):
    assert require_identifier(value) == value


@pytest.mark.parametrize("value", ["", " ", "a b", "a\tb", "a\nb", "x" * 256, None, 7, b"bytes"])
def test_unbounded_or_unsafe_identifiers_are_refused(value):
    with pytest.raises(ManagementError) as ei:
        require_identifier(value)
    assert ei.value.reason_code == "secpctl_credential_account_invalid"


def test_the_flat_key_composes_the_service_and_the_account():
    assert target_name(SERVICE, ACCOUNT) == f"{SERVICE}:{ACCOUNT}"


def test_two_different_accounts_never_compose_the_same_key():
    assert target_name(SERVICE, ACCOUNT) != target_name(SERVICE, "https://other.invalid")


def test_a_malformed_account_cannot_reach_a_keystore_key():
    with pytest.raises(ManagementError) as ei:
        target_name(SERVICE, "has space")
    assert ei.value.reason_code == "secpctl_credential_account_invalid"


# --- resolution and the no-fallback rule ----------------------------------------------------------


KNOWN_BACKENDS = {BACKEND_WINDOWS_CREDENTIAL_MANAGER, BACKEND_MACOS_KEYCHAIN}


@pytest.mark.parametrize(
    "platform", ["win32", "darwin", "linux", "linux2", "freebsd13", "aix", "emscripten", ""]
)
def test_resolution_yields_a_named_os_backend_or_nothing_at_all(platform, monkeypatch):
    """There is no third, degraded binding to fall through to. Whatever the platform, the resolver
    returns one of the named OS backends or ``None`` — and ``None`` is what makes the store above
    seal itself."""
    monkeypatch.setattr(sys, "platform", platform)
    binding = resolve_secret_store_binding()
    assert binding is None or binding.backend_id in KNOWN_BACKENDS


@pytest.mark.parametrize("platform", ["freebsd13", "aix", "emscripten", "sunos5", ""])
def test_an_unsupported_platform_resolves_to_nothing(platform, monkeypatch):
    monkeypatch.setattr(sys, "platform", platform)
    assert resolve_secret_store_binding() is None


@pytest.mark.parametrize("platform", ["linux", "linux2"])
def test_linux_resolves_to_nothing_in_this_slice(platform, monkeypatch):
    """Linux ships NO binding here: the Secret Service is only reachable through a subprocess (which
    SECP-PR5E §12 forbids the management installer from importing), a hand-rolled D-Bus client, or a
    new dependency. Until one of those is reviewed, a Linux operator gets a bounded refusal and
    nothing is stored — the failure that must NOT quietly become a file."""
    monkeypatch.setattr(sys, "platform", platform)
    assert resolve_secret_store_binding() is None


def test_each_binding_refuses_construction_on_the_wrong_platform(monkeypatch):
    """A binding must never construct itself off its own platform, where its OS calls are
    meaningless — that is how a 'works everywhere' fallback gets introduced by accident."""
    for binding_type, wrong_platform in (
        (WindowsCredentialManagerBinding, "linux"),
        (MacOSKeychainBinding, "win32"),
    ):
        monkeypatch.setattr(sys, "platform", wrong_platform)
        with pytest.raises(ManagementError) as ei:
            binding_type()
        assert ei.value.reason_code == "secpctl_credential_store_unavailable"


def test_a_resolved_binding_never_reveals_its_target_in_a_repr():
    binding = resolve_secret_store_binding()
    if binding is None:
        pytest.skip("no OS keystore binding on this host")
    rendered = repr(binding)
    assert "<bound>" in rendered
    assert ACCOUNT not in rendered and SERVICE not in rendered


# --- a real round trip, where the platform allows it ----------------------------------------------


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Credential Manager only")
def test_windows_credential_manager_round_trip():
    """A genuine exercise of the ctypes binding against the real Credential Manager, under a
    namespaced selftest service so it can never touch a real operator credential. The entry is
    removed in ``finally`` whatever happens."""
    binding = WindowsCredentialManagerBinding()
    assert binding.backend_id == BACKEND_WINDOWS_CREDENTIAL_MANAGER
    secret = b'{"v":1,"a":"https://controller.invalid","e":2000000000,"s":"","t":"round-trip"}'
    try:
        assert binding.get_secret(service=SELFTEST_SERVICE, account=ACCOUNT) is None
        binding.set_secret(service=SELFTEST_SERVICE, account=ACCOUNT, secret=secret)
        assert binding.get_secret(service=SELFTEST_SERVICE, account=ACCOUNT) == secret

        # a second write REPLACES rather than appends
        replacement = secret.replace(b"round-trip", b"replaced!!")
        binding.set_secret(service=SELFTEST_SERVICE, account=ACCOUNT, secret=replacement)
        assert binding.get_secret(service=SELFTEST_SERVICE, account=ACCOUNT) == replacement

        # a DIFFERENT account under the same service is a different entry
        assert binding.get_secret(service=SELFTEST_SERVICE, account="https://other.invalid") is None

        assert binding.delete_secret(service=SELFTEST_SERVICE, account=ACCOUNT) is True
        assert binding.delete_secret(service=SELFTEST_SERVICE, account=ACCOUNT) is False
        assert binding.get_secret(service=SELFTEST_SERVICE, account=ACCOUNT) is None
    finally:
        try:
            binding.delete_secret(service=SELFTEST_SERVICE, account=ACCOUNT)
        except ManagementError:
            pass


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Credential Manager only")
def test_windows_credential_manager_refuses_an_oversized_blob_before_calling_the_os():
    binding = WindowsCredentialManagerBinding()
    with pytest.raises(ManagementError) as ei:
        binding.set_secret(
            service=SELFTEST_SERVICE, account=ACCOUNT, secret=b"x" * (MAX_SECRET_BYTES + 1)
        )
    assert ei.value.reason_code == "secpctl_credential_too_large"
    assert binding.get_secret(service=SELFTEST_SERVICE, account=ACCOUNT) is None
