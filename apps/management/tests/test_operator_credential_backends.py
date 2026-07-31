"""OS keystore bindings for the operator credential (SECP-PR5H-B2, Workstream C).

Only one binding can execute on any given host, so the tests are split:

* the PURE marshalling — size bounds and key composition — runs everywhere and is where the
  security-relevant properties live (an oversized record must refuse before any OS call, a malformed
  account must never reach a keystore key);
* resolution is exercised for every platform string by driving ``sys.platform``, which proves the
  no-fallback rule holds on hosts with no keystore, no ``secretstorage``, or no Secret Service;
* a real round trip against the platform's own keystore runs only where that keystore exists. On
  this repository's Windows development hosts that is a genuine end-to-end exercise of the ctypes
  binding; the macOS and Linux bindings have no host here and are covered structurally — for Linux
  that means the attribute set, which is the part a bug would make dangerous rather than merely
  broken.
"""

from __future__ import annotations

import sys

import pytest
from secp_management import ManagementError
from secp_management.operator_credential_backends import (
    BACKEND_MACOS_KEYCHAIN,
    BACKEND_SECRET_SERVICE,
    BACKEND_WINDOWS_CREDENTIAL_MANAGER,
    MAX_SECRET_BYTES,
    SECRET_SERVICE_APPLICATION,
    MacOSKeychainBinding,
    SecretServiceBinding,
    WindowsCredentialManagerBinding,
    require_identifier,
    require_storable,
    resolve_secret_store_binding,
    secret_service_attributes,
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


KNOWN_BACKENDS = {
    BACKEND_WINDOWS_CREDENTIAL_MANAGER,
    BACKEND_MACOS_KEYCHAIN,
    BACKEND_SECRET_SERVICE,
}


@pytest.mark.parametrize(
    "platform", ["win32", "darwin", "linux", "linux2", "freebsd13", "aix", "emscripten", ""]
)
def test_resolution_yields_a_named_os_backend_or_nothing_at_all(platform, monkeypatch):
    """There is no fourth, degraded binding to fall through to. Whatever the platform, the resolver
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
def test_linux_without_a_reachable_secret_service_resolves_to_nothing(platform, monkeypatch):
    """An absent ``secretstorage``, no session bus, or an unreachable Secret Service must seal the
    store rather than degrade. Off Linux the library is not even installed (platform marker), so
    this exercises the absent-library arm of that rule."""
    monkeypatch.setattr(sys, "platform", platform)
    binding = resolve_secret_store_binding()
    assert binding is None or binding.backend_id == BACKEND_SECRET_SERVICE


def test_each_binding_refuses_construction_on_the_wrong_platform(monkeypatch):
    """A binding must never construct itself off its own platform, where its OS calls are
    meaningless — that is how a 'works everywhere' fallback gets introduced by accident."""
    for binding_type, wrong_platform in (
        (WindowsCredentialManagerBinding, "linux"),
        (MacOSKeychainBinding, "win32"),
        (SecretServiceBinding, "darwin"),
    ):
        monkeypatch.setattr(sys, "platform", wrong_platform)
        with pytest.raises(ManagementError) as ei:
            binding_type()
        assert ei.value.reason_code == "secpctl_credential_store_unavailable"


# --- the Secret Service attribute set -------------------------------------------------------------


def test_the_secret_service_attribute_set_scopes_every_lookup_to_this_tool():
    attributes = secret_service_attributes(SERVICE, ACCOUNT)
    assert attributes == {
        "service": SERVICE,
        "account": ACCOUNT,
        "application": SECRET_SERVICE_APPLICATION,
    }
    # the fixed application attribute is what stops a logout from removing another application's
    # item that happens to share a service/account pair
    assert SECRET_SERVICE_APPLICATION == "secpctl"


def test_two_controllers_never_share_a_secret_service_attribute_set():
    assert secret_service_attributes(SERVICE, ACCOUNT) != secret_service_attributes(
        SERVICE, "https://other.invalid"
    )


def test_the_secret_is_never_part_of_the_secret_service_attribute_set():
    """Attributes are stored UNENCRYPTED beside the item and are readable by anything that can
    search the collection; only the secret itself is protected."""
    values = set(secret_service_attributes(SERVICE, ACCOUNT).values())
    assert all(len(value) <= 255 for value in values)
    assert not any("token" in value.lower() for value in values)


@pytest.mark.parametrize("account", ["", "has space", "x" * 256, None])
def test_a_malformed_account_cannot_reach_a_secret_service_lookup(account):
    with pytest.raises(ManagementError) as ei:
        secret_service_attributes(SERVICE, account)
    assert ei.value.reason_code == "secpctl_credential_account_invalid"


# --- the Secret Service binding, driven against a stand-in for the documented API -----------------
#
# `secretstorage` installs only under a `sys_platform == "linux"` marker, so on this host the real
# library is absent and a Linux keyring does not exist. These drive the binding's OWN logic against
# a stand-in following the documented SecretStorage 3.x contract: `dbus_init() -> DBusConnection`,
# which is NOT closed automatically, `get_default_collection`, `Collection.is_locked`,
# `Collection.search_items` matching items that carry AT LEAST the searched attributes,
# `Collection.create_item(label, attributes, secret, replace=)`, `Item.get_secret() -> bytes` and
# `Item.delete()`. They prove the refusal, selection and connection-closing rules; they cannot
# prove the library itself behaves as documented.


class _FakeItem:
    def __init__(self, collection, attributes, secret):
        self._collection = collection
        self.attributes = dict(attributes)
        self.secret = bytes(secret)

    def get_secret(self):
        return self.secret

    def delete(self):
        self._collection.items.remove(self)


class _FakeCollection:
    def __init__(self, *, locked=False, fail=None):
        self.items: list[_FakeItem] = []
        self.locked = locked
        self.fail = fail

    def is_locked(self):
        return self.locked

    def search_items(self, attributes):
        if self.fail:
            raise RuntimeError(self.fail)
        for item in list(self.items):
            if all(item.attributes.get(key) == value for key, value in attributes.items()):
                yield item

    def create_item(self, label, attributes, secret, replace=False):
        if self.fail:
            raise RuntimeError(self.fail)
        if replace:
            self.items = [i for i in self.items if i.attributes != dict(attributes)]
        item = _FakeItem(self, attributes, secret)
        self.items.append(item)
        return item


class _FakeConnection:
    def __init__(self, module):
        self._module = module

    def close(self):
        self._module.closed += 1


class _FakeSecretStorage:
    """Stands in for the `secretstorage` module the platform marker keeps off this host."""

    def __init__(self, collection=None, *, init_error=None, collection_error=None):
        self.collection = collection if collection is not None else _FakeCollection()
        self.init_error = init_error
        self.collection_error = collection_error
        self.opened = 0
        self.closed = 0

    def dbus_init(self):
        if self.init_error:
            raise RuntimeError(self.init_error)
        self.opened += 1
        return _FakeConnection(self)

    def get_default_collection(self, connection):
        if self.collection_error:
            raise RuntimeError(self.collection_error)
        return self.collection


def _linux_with(module, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "secretstorage", module)
    return module


RECORD = b'{"v":1,"a":"https://controller.invalid","e":2000000000,"s":"","t":"linux-round-trip"}'


def test_the_secret_service_binding_round_trips_and_closes_every_connection(monkeypatch):
    fake = _linux_with(_FakeSecretStorage(), monkeypatch)
    binding = SecretServiceBinding()
    assert binding.backend_id == BACKEND_SECRET_SERVICE

    assert binding.get_secret(service=SERVICE, account=ACCOUNT) is None
    binding.set_secret(service=SERVICE, account=ACCOUNT, secret=RECORD)
    assert binding.get_secret(service=SERVICE, account=ACCOUNT) == RECORD
    assert binding.delete_secret(service=SERVICE, account=ACCOUNT) is True
    assert binding.delete_secret(service=SERVICE, account=ACCOUNT) is False
    assert binding.get_secret(service=SERVICE, account=ACCOUNT) is None

    # jeepney does not close the D-Bus socket for us; every connection opened must be closed
    assert fake.opened == fake.closed > 0


def test_the_secret_service_binding_stores_the_scoping_attributes_and_one_item(monkeypatch):
    fake = _linux_with(_FakeSecretStorage(), monkeypatch)
    binding = SecretServiceBinding()
    binding.set_secret(service=SERVICE, account=ACCOUNT, secret=RECORD)
    binding.set_secret(service=SERVICE, account=ACCOUNT, secret=RECORD.replace(b"round", b"again"))
    assert len(fake.collection.items) == 1, "replace=True must not leave a second credential"
    assert fake.collection.items[0].attributes == secret_service_attributes(SERVICE, ACCOUNT)


def test_the_secret_service_binding_never_touches_another_applications_item(monkeypatch):
    """A logout must remove only items carrying the full attribute set this tool writes."""
    collection = _FakeCollection()
    fake = _linux_with(_FakeSecretStorage(collection), monkeypatch)
    foreign = _FakeItem(collection, {"service": SERVICE, "account": ACCOUNT}, b"not-ours")
    collection.items.append(foreign)

    binding = SecretServiceBinding()
    assert binding.get_secret(service=SERVICE, account=ACCOUNT) is None
    binding.set_secret(service=SERVICE, account=ACCOUNT, secret=RECORD)
    assert binding.delete_secret(service=SERVICE, account=ACCOUNT) is True
    assert collection.items == [foreign]
    assert fake.opened == fake.closed


def test_two_controllers_are_two_items_in_the_secret_service(monkeypatch):
    fake = _linux_with(_FakeSecretStorage(), monkeypatch)
    binding = SecretServiceBinding()
    binding.set_secret(service=SERVICE, account=ACCOUNT, secret=RECORD)
    binding.set_secret(service=SERVICE, account="https://other.invalid", secret=RECORD)
    assert len(fake.collection.items) == 2
    assert binding.delete_secret(service=SERVICE, account=ACCOUNT) is True
    assert len(fake.collection.items) == 1


def test_a_locked_collection_is_refused_and_never_unlocked(monkeypatch):
    """`Collection.unlock()` raises a GUI prompt — and returns True when the prompt was DISMISSED,
    an inversion that is easy to get backwards. The binding must not call it at all."""
    fake = _linux_with(_FakeSecretStorage(_FakeCollection(locked=True)), monkeypatch)
    with pytest.raises(ManagementError) as ei:
        SecretServiceBinding()
    assert ei.value.reason_code == "secpctl_credential_store_locked"
    assert fake.opened == fake.closed == 1
    assert not hasattr(_FakeCollection, "unlock"), "the stand-in offers no unlock to call"


def test_a_locked_keyring_seals_the_store_rather_than_degrading(monkeypatch):
    _linux_with(_FakeSecretStorage(_FakeCollection(locked=True)), monkeypatch)
    assert resolve_secret_store_binding() is None


@pytest.mark.parametrize(
    "module",
    [
        _FakeSecretStorage(init_error="no session bus"),
        _FakeSecretStorage(collection_error="no default collection"),
    ],
)
def test_an_unreachable_secret_service_is_unavailable_not_empty(module, monkeypatch):
    _linux_with(module, monkeypatch)
    with pytest.raises(ManagementError) as ei:
        SecretServiceBinding()
    assert ei.value.reason_code == "secpctl_credential_store_unavailable"
    assert module.opened == module.closed
    assert resolve_secret_store_binding() is None


def test_an_absent_secretstorage_is_a_bounded_refusal(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "secretstorage", None)  # import raises ImportError
    with pytest.raises(ManagementError) as ei:
        SecretServiceBinding()
    assert ei.value.reason_code == "secpctl_credential_store_unavailable"
    assert resolve_secret_store_binding() is None


def test_a_backend_failure_mid_operation_refuses_and_still_closes_the_connection(monkeypatch):
    collection = _FakeCollection()
    fake = _linux_with(_FakeSecretStorage(collection), monkeypatch)
    binding = SecretServiceBinding()
    collection.fail = "d-bus went away"
    for attempt in (
        lambda: binding.get_secret(service=SERVICE, account=ACCOUNT),
        lambda: binding.set_secret(service=SERVICE, account=ACCOUNT, secret=RECORD),
        lambda: binding.delete_secret(service=SERVICE, account=ACCOUNT),
    ):
        with pytest.raises(ManagementError) as ei:
            attempt()
        assert ei.value.reason_code == "secpctl_credential_backend_failed"
    assert fake.opened == fake.closed


def test_a_backend_failure_never_echoes_the_upstream_message(monkeypatch):
    collection = _FakeCollection()
    _linux_with(_FakeSecretStorage(collection), monkeypatch)
    binding = SecretServiceBinding()
    collection.fail = "SENSITIVE-DBUS-DETAIL"
    with pytest.raises(ManagementError) as ei:
        binding.get_secret(service=SERVICE, account=ACCOUNT)
    assert "SENSITIVE-DBUS-DETAIL" not in f"{ei.value!r} {ei.value}"


def test_an_oversized_stored_item_is_refused_on_read(monkeypatch):
    """A keystore entry larger than any supported backend accepts cannot have been written by this
    code, so it is a corrupt record rather than a credential."""
    collection = _FakeCollection()
    _linux_with(_FakeSecretStorage(collection), monkeypatch)
    binding = SecretServiceBinding()
    collection.items.append(
        _FakeItem(
            collection, secret_service_attributes(SERVICE, ACCOUNT), b"x" * (MAX_SECRET_BYTES + 1)
        )
    )
    with pytest.raises(ManagementError) as ei:
        binding.get_secret(service=SERVICE, account=ACCOUNT)
    assert ei.value.reason_code == "secpctl_credential_record_invalid"


def test_an_oversized_secret_is_refused_before_the_secret_service_is_touched(monkeypatch):
    collection = _FakeCollection()
    fake = _linux_with(_FakeSecretStorage(collection), monkeypatch)
    binding = SecretServiceBinding()
    opened_before = fake.opened
    with pytest.raises(ManagementError) as ei:
        binding.set_secret(service=SERVICE, account=ACCOUNT, secret=b"x" * (MAX_SECRET_BYTES + 1))
    assert ei.value.reason_code == "secpctl_credential_too_large"
    assert collection.items == [] and fake.opened == opened_before


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
