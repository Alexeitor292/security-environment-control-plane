"""OS secret-storage bindings for the operator credential — SECP-PR5H-B2, Workstream C.

This module is the ONLY place in the ``secpctl auth`` surface that talks to an operating-system
keystore. It contains bindings and nothing else: no policy, no lifecycle, no expiry rule, no account
derivation. :mod:`secp_management.operator_credential_store` owns all of that and drives a binding
through the narrow :class:`SecretStoreBinding` seam, so the no-plaintext-fallback rules are enforced
in ONE reviewed place and are not restated per platform.

Three bindings ship, one per supported operator workstation, and **no process is ever spawned**:

* **Windows** — Credential Manager via ``advapi32`` ``CredWriteW`` / ``CredReadW`` / ``CredDeleteW``
  (``wincred.h``), through :mod:`ctypes`. A ``CRED_TYPE_GENERIC`` credential is "stored securely" by
  the OS and its blob is bounded by ``CRED_MAX_CREDENTIAL_BLOB_SIZE`` (5*512 bytes).
* **macOS** — Keychain Services via the CURRENT ``SecItemAdd`` / ``SecItemCopyMatching`` /
  ``SecItemUpdate`` / ``SecItemDelete`` API (the ``SecKeychain*`` family has been deprecated since
  10.10 and is deliberately not used), through :mod:`ctypes` against the system frameworks at their
  fixed absolute paths.
* **Linux** — the freedesktop Secret Service (GNOME Keyring / KWallet) through ``secretstorage``,
  which speaks the Secret Service D-Bus API directly over pure-Python jeepney.

The Linux choice is the one that needed a dependency, so the reasoning is recorded here. libsecret's
``secret-tool`` is the obvious route and is NOT usable: it needs a subprocess, and SECP-PR5E §12
forbids the management installer from importing ``subprocess`` at all
(``tests/test_management_plane_boundary.py``) — it is a local-first installer, never a process
driver. The plane's one reviewed exec seam,
``secp_operator_deployment.host_process.RealCommandRunner``, cannot carry it either: it pins
``stdin=DEVNULL``, and the secret has to travel on stdin precisely so it never reaches ``argv``.
Hand-rolling the D-Bus client is several hundred lines no host in this repository can execute.
``secretstorage`` is preferred over ``keyring`` because it CANNOT resolve the cleartext
``keyrings.alt`` family — there is no plaintext backend for it to fall through to.

Three deliberate non-goals, so the omissions are legible rather than accidental:

* There is NO fallback binding. An unsupported platform, a missing framework, an absent
  ``secretstorage``, or an unreachable Secret Service resolves to ``None`` and the store above fails
  closed. Nothing is ever written to a file, an environment variable, or a process-lifetime cache.
* **A locked keyring is refused, never unlocked.** ``Collection.unlock()`` raises a GUI prompt and a
  read-only ``secpctl auth status`` must not make one appear. (Note the inverted return:
  ``unlock()`` returns ``True`` when the prompt was DISMISSED, i.e. still locked. Not calling it
  sidesteps that trap entirely.) A locked collection is ``secpctl_credential_store_locked`` — a
  DISTINCT code from
  the generic unavailable one, and reachable, because the binding still constructs on a locked
  keyring so every operation can carry that code to the operator. On Linux a locked keyring is the
  most likely failure, so collapsing it into "no credential store" would hand the operator the one
  message that does not say what to do.
* No binding enumerates credentials. secpctl can only ever USE the account named by the reviewed
  controller locator, so listing would be output with no operation behind it and more OS paths that
  no test here can exercise.

**A KNOWN ASYMMETRY, stated rather than left to be discovered.** The no-prompt guarantee above is
LINUX-ONLY. The macOS binding sets no ``kSecUseAuthenticationUI`` and no accessibility attribute, so
on a locked keychain ``SecItemCopyMatching`` may present a system unlock prompt — meaning a
read-only ``secpctl auth status`` can raise UI on macOS where it provably cannot on Linux.

It is documented rather than fixed, and the reason is the fix's own risk profile. Suppressing the
prompt means resolving another ``in_dll`` constant; if that symbol does not resolve, the existing
``except`` turns the failure into ``secpctl_credential_store_unavailable`` and the ENTIRE macOS
binding disappears — the platform silently loses secure storage altogether and falls back to the
sealed store. No host in this repository, and no CI runner, can execute that code to find out which
way it goes. Shipping an unverifiable change whose failure mode is "macOS has no credential storage"
is worse than shipping a documented prompt, so this waits for a macOS host. Fixing it there is a
small, well-scoped change.

``secretstorage``/jeepney read the session D-Bus address from the environment — that is inherent to
reaching the operator's own session bus. No code HERE reads, writes, or branches on an environment
variable, and no binding resolves an executable through ``PATH``.

One further asymmetry is STATIC rather than behavioural, and it is why this module carries a typed
seam. Windows is the only platform whose API surface a type checker cannot see from anywhere else:
typeshed declares ``ctypes.WinDLL`` and ``ctypes.get_last_error`` only under ``sys.platform ==
'win32'``, and ``CREDENTIALW`` cannot even be built off Windows. CI checks types on Linux, so that
half of the module was invisible there. The ``TYPE_CHECKING`` block below the Windows section header
declares it — the two ctypes members, the four ``advapi32`` entry points, the structure's field
types — so the binding is checked on every platform against a named description instead of being
excluded or blanketed in suppressions. macOS and Linux need no equivalent: ``CDLL`` and
``secretstorage`` are visible everywhere.

Every failure is one bounded reason code. A binding never returns, logs, or embeds the secret, the
account, the target name, an OS error string, or an upstream exception.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any, NoReturn, Protocol, cast, runtime_checkable

from secp_management import ManagementError

#: Backend identifiers reported by ``StoredCredentialStatus.backend``.
BACKEND_WINDOWS_CREDENTIAL_MANAGER = "windows_credential_manager"
BACKEND_MACOS_KEYCHAIN = "macos_keychain"
BACKEND_SECRET_SERVICE = "secret_service"

#: The TIGHTEST secret size any supported keystore accepts, applied on EVERY platform so a
#: credential that stores on one operator workstation stores on all of them. The bound is Windows'
#: documented ``CRED_MAX_CREDENTIAL_BLOB_SIZE`` (wincred.h, ``CREDENTIALW.CredentialBlobSize``).
MAX_SECRET_BYTES = 5 * 512

#: Windows ``CRED_MAX_GENERIC_TARGET_NAME_LENGTH`` (wincred.h).
_MAX_TARGET_NAME_LEN = 32767
_MAX_IDENTIFIER_LEN = 255


class OperatorCredentialBackendError(ManagementError):
    """A bounded, closed keystore refusal — carries ONLY a reason code, never the secret, the
    account, the target name, an OS status, or a raw exception."""


def _reject(reason_code: str) -> NoReturn:
    raise OperatorCredentialBackendError(reason_code)


@runtime_checkable
class SecretStoreBinding(Protocol):
    """The narrow seam between the credential store's policy and one OS keystore.

    ``service`` and ``account`` are bounded, non-secret identifiers chosen by code above; ``secret``
    is opaque bytes. A binding performs NO validation of the secret's meaning and NO expiry logic —
    it stores and retrieves bytes under a key, or refuses.
    """

    @property
    def backend_id(self) -> str:
        """The stable, code-owned identifier reported in ``auth status``."""
        ...

    def set_secret(self, *, service: str, account: str, secret: bytes) -> None:
        """Replace any existing secret stored under ``(service, account)``."""
        ...

    def get_secret(self, *, service: str, account: str) -> bytes | None:
        """The stored secret, or ``None`` when no entry exists. A backend FAILURE is a refusal, not
        a ``None`` — an unreachable keystore must never look like an absent credential."""
        ...

    def delete_secret(self, *, service: str, account: str) -> bool:
        """Remove ONLY the entry under ``(service, account)``. Returns whether one was removed."""
        ...


def require_identifier(value: object, *, reason: str = "secpctl_credential_account_invalid") -> str:
    """A bounded, printable, whitespace-free, control-free non-secret identifier."""
    if (
        not isinstance(value, str)
        or not (1 <= len(value) <= _MAX_IDENTIFIER_LEN)
        or any(ch.isspace() or ord(ch) < 0x21 or ord(ch) == 0x7F for ch in value)
    ):
        _reject(reason)
    return value


def require_storable(secret: object) -> bytes:
    """Bound the secret to what EVERY supported keystore accepts.

    Refusing here — before any OS call — means an oversized credential is one bounded refusal on
    every platform rather than a silent truncation on one of them.
    """
    if not isinstance(secret, (bytes, bytearray)) or not secret:
        _reject("secpctl_credential_record_invalid")
    if len(secret) > MAX_SECRET_BYTES:
        _reject("secpctl_credential_too_large")
    return bytes(secret)


def target_name(service: str, account: str) -> str:
    """The single flat key a keystore addressing one string (Windows) uses.

    :func:`require_identifier` makes both parts whitespace-free but NOT colon-free (a colon is
    printable), so the separator alone does not guarantee an unambiguous split. It does not need
    to: the key is only ever WRITTEN by this function and is never parsed back.
    """
    key = f"{require_identifier(service)}:{require_identifier(account)}"
    if len(key) > _MAX_TARGET_NAME_LEN:
        _reject("secpctl_credential_account_invalid")
    return key


# --- Windows: Credential Manager ------------------------------------------------------------------


_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2
_ERROR_NOT_FOUND = 1168


if TYPE_CHECKING:
    # THE WINDOWS TYPE BOUNDARY, and the whole of it. Everything below this block is checked
    # normally, on every platform, against these declarations — which is the point: the alternative
    # was excluding the module or blanketing it in suppressions, and both of those stop checking the
    # POLICY code (the size bound, the reason codes, the fail-closed returns) as well as the FFI.
    #
    # What is declared is exactly what a non-Windows type surface lacks and nothing else: the two
    # `ctypes` members typeshed guards behind `sys.platform == "win32"`, the four `advapi32` entry
    # points, and the field types of `CREDENTIALW` (which cannot be built off Windows at all,
    # because `ctypes.wintypes` does not import there).
    #
    # The one property this deliberately does NOT mirror is the field ORDER in
    # `_windows_structures` — the part that is load-bearing for the OS, since a transposed field
    # hands it a pointer where it expects a length. Annotations carry no layout, so ordering stays a
    # property of the runtime class, verified where it is actually executed: on a Windows host, by
    # `test_windows_credential_manager_round_trip`.
    import ctypes
    from ctypes import wintypes

    class _CredentialW(ctypes.Structure):
        """The static field TYPES of wincred.h ``CREDENTIALW``.

        A complete mirror rather than only the fields in use, so that a name absent here reads as
        absent from the struct rather than merely untouched by this binding.
        """

        Flags: int
        Type: int
        TargetName: str | None
        Comment: str | None
        LastWritten: wintypes.FILETIME
        CredentialBlobSize: int
        CredentialBlob: ctypes._Pointer[ctypes.c_byte]
        Persist: int
        AttributeCount: int
        Attributes: int | None
        TargetAlias: str | None
        UserName: str | None

    class _WinEntryPoint(Protocol):
        """The ctypes knobs every resolved entry point carries.

        Both are WRITTEN and never read: pinning them is what stops ctypes defaulting a 64-bit
        pointer to ``int`` and handing the OS a truncated address, so they belong in the declared
        surface even though no code here reads them back.
        """

        argtypes: tuple[type[Any], ...]
        restype: type[Any] | None

    class _CredWriteW(_WinEntryPoint, Protocol):
        def __call__(self, credential: Any, flags: int, /) -> int: ...

    class _CredReadW(_WinEntryPoint, Protocol):
        def __call__(self, target: str, type: int, flags: int, out: Any, /) -> int: ...

    class _CredDeleteW(_WinEntryPoint, Protocol):
        def __call__(self, target: str, type: int, flags: int, /) -> int: ...

    class _CredFree(_WinEntryPoint, Protocol):
        def __call__(self, buffer: Any, /) -> None: ...

    class _Advapi32(Protocol):
        """The FOUR ``advapi32`` entry points this binding resolves, and no others.

        Naming them one by one rather than typing the handle ``Any`` is what makes a call with the
        wrong arity or a call to a fifth, unresolved entry point a type error here.
        """

        CredWriteW: _CredWriteW
        CredReadW: _CredReadW
        CredDeleteW: _CredDeleteW
        CredFree: _CredFree

    class _WindowsCtypes(Protocol):
        """:mod:`ctypes` narrowed to the two members it has ONLY on a Windows interpreter.

        ``WinDLL`` is declared as returning the ``advapi32`` surface above because ``advapi32`` is
        the only library this module ever loads. Narrowing it once, here, is what keeps the loader
        typed at its call site instead of returning ``Any`` into the rest of the binding.
        """

        def WinDLL(self, name: str, *, use_last_error: bool = ...) -> _Advapi32: ...

        def get_last_error(self) -> int: ...


def _windows_ctypes() -> _WindowsCtypes:
    """:mod:`ctypes` seen through its Windows-only surface.

    A ``cast`` rather than a ``type: ignore``: both members genuinely exist on a Windows
    interpreter, so what is being stated is WHICH surface this is, not that an error should be
    suppressed — and unlike a suppression it keeps the two results typed for every caller. Every
    caller is already past a ``sys.platform`` gate, so this can only be reached where the surface
    is real.

    This is one of the module's TWO unchecked steps, and they are the whole of it: this one, and
    the structure cast at the end of :func:`_windows_structures`. Both exist because a runtime
    ctypes object cannot carry the declared shape; neither suppresses a diagnostic.
    """
    import ctypes

    return cast("_WindowsCtypes", ctypes)


def _windows_structures() -> tuple[_Advapi32, type[_CredentialW]]:
    """The ``advapi32`` handle and the ``CREDENTIALW`` structure, built on first use.

    ``ctypes.wintypes`` does not import off Windows, so the whole binding is constructed lazily and
    a non-Windows import can never fail at module load.
    """
    import ctypes
    from ctypes import wintypes

    class _CREDENTIALW(ctypes.Structure):
        # wincred.h ``_CREDENTIALW``, in declaration order. The order is load-bearing: a
        # transposed field would hand the OS a pointer where it expects a length.
        _fields_ = (
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        )

    try:
        advapi32 = _windows_ctypes().WinDLL("advapi32", use_last_error=True)
        advapi32.CredWriteW.argtypes = (ctypes.POINTER(_CREDENTIALW), wintypes.DWORD)
        advapi32.CredWriteW.restype = wintypes.BOOL
        advapi32.CredReadW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.POINTER(_CREDENTIALW)),
        )
        advapi32.CredReadW.restype = wintypes.BOOL
        advapi32.CredDeleteW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD)
        advapi32.CredDeleteW.restype = wintypes.BOOL
        advapi32.CredFree.argtypes = (ctypes.c_void_p,)
        advapi32.CredFree.restype = None
    except Exception:  # noqa: BLE001 - an unusable API surface is a bounded refusal
        _reject("secpctl_credential_store_unavailable")
    # The runtime class is assembled from `wintypes` field descriptors that exist only on Windows,
    # so it cannot BE the declared shape; `_CredentialW` is that shape's static mirror and this is
    # where the two are tied together. Field types are mirrored above; field ORDER lives here.
    return advapi32, cast("type[_CredentialW]", _CREDENTIALW)


class WindowsCredentialManagerBinding:
    """Windows Credential Manager (``CRED_TYPE_GENERIC``), persisted for this user on this machine.

    ``CRED_PERSIST_LOCAL_MACHINE`` is chosen over ``CRED_PERSIST_ENTERPRISE`` deliberately: the
    operator credential must not roam to other machines through a roaming profile.
    """

    __slots__ = ("_advapi32", "_credential_type")
    # Annotations only (no assignment), so the slots are typed without creating class attributes
    # that would collide with ``__slots__`` — the same shape as ``MacOSKeychainBinding._fw``. Here
    # they are also load-bearing for a second reason: on a non-Windows type surface the platform
    # gate in ``__init__`` is statically always-true, which makes the assignment after it
    # unreachable, so a checker there would infer NOTHING for either attribute and every method
    # below would silently stop being checked.
    _advapi32: _Advapi32
    _credential_type: type[_CredentialW]

    def __init__(self) -> None:
        if sys.platform != "win32":
            _reject("secpctl_credential_store_unavailable")
        self._advapi32, self._credential_type = _windows_structures()

    def __repr__(self) -> str:  # never a target name or a secret
        return "WindowsCredentialManagerBinding(<bound>)"

    @property
    def backend_id(self) -> str:
        return BACKEND_WINDOWS_CREDENTIAL_MANAGER

    def set_secret(self, *, service: str, account: str, secret: bytes) -> None:
        import ctypes

        blob = require_storable(secret)
        credential = self._credential_type()
        credential.Flags = 0
        credential.Type = _CRED_TYPE_GENERIC
        credential.TargetName = target_name(service, account)
        credential.Comment = None
        credential.CredentialBlobSize = len(blob)
        buffer = ctypes.create_string_buffer(blob, len(blob))
        credential.CredentialBlob = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))
        credential.Persist = _CRED_PERSIST_LOCAL_MACHINE
        credential.AttributeCount = 0
        credential.Attributes = None
        credential.TargetAlias = None
        credential.UserName = None
        if not self._advapi32.CredWriteW(ctypes.byref(credential), 0):
            _reject("secpctl_credential_backend_failed")

    def get_secret(self, *, service: str, account: str) -> bytes | None:
        import ctypes

        target = target_name(service, account)
        pointer = ctypes.POINTER(self._credential_type)()
        if not self._advapi32.CredReadW(target, _CRED_TYPE_GENERIC, 0, ctypes.byref(pointer)):
            if _windows_ctypes().get_last_error() == _ERROR_NOT_FOUND:
                return None
            _reject("secpctl_credential_backend_failed")
        try:
            credential = pointer.contents
            size = int(credential.CredentialBlobSize)
            if size <= 0:
                return None
            address = ctypes.cast(credential.CredentialBlob, ctypes.c_void_p)
            return ctypes.string_at(address, size)
        finally:
            self._advapi32.CredFree(pointer)

    def delete_secret(self, *, service: str, account: str) -> bool:
        target = target_name(service, account)
        if self._advapi32.CredDeleteW(target, _CRED_TYPE_GENERIC, 0):
            return True
        if _windows_ctypes().get_last_error() == _ERROR_NOT_FOUND:
            return False
        _reject("secpctl_credential_backend_failed")


# --- macOS: Keychain Services (SecItem) -----------------------------------------------------------


_CORE_FOUNDATION_PATH = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
_SECURITY_PATH = "/System/Library/Frameworks/Security.framework/Security"

_ERR_SEC_SUCCESS = 0
_ERR_SEC_DUPLICATE_ITEM = -25299
_ERR_SEC_ITEM_NOT_FOUND = -25300
_K_CF_STRING_ENCODING_UTF8 = 0x08000100


def require_resolved_constants(resolved: dict[str, int | None]) -> dict[str, int]:
    """Require every Security/CoreFoundation constant to have resolved to a real address.

    ``ctypes.c_void_p.value`` is ``None`` for a NULL pointer. A constant that resolved to NULL means
    an unusable framework surface, and passing it on would build a ``SecItem*`` dictionary with a
    NULL key rather than fail loudly — exactly the "fail quietly" shape the explicit ``argtypes``
    declarations exist to prevent.

    This is a separate PURE function on purpose. Inline in ``_MacOSFrameworks.__init__`` the check
    was unreachable on every host in this repository — the enclosing constructor needs a real macOS
    Security framework to run at all — so the refusal could never be executed or proven. Extracted,
    it is exercised on every platform while the constructor that calls it stays macOS-only.
    """
    checked: dict[str, int] = {}
    for name, address in resolved.items():
        if address is None:
            _reject("secpctl_credential_store_unavailable")
        checked[name] = address
    return checked


class _MacOSFrameworks:
    """The CoreFoundation + Security entry points and constants this binding needs.

    Every signature is pinned with explicit ``argtypes``/``restype``. Leaving them to ctypes'
    defaults truncates pointers to ``int`` on 64-bit builds, which would hand the Security framework
    a malformed dictionary rather than fail loudly.
    """

    __slots__ = ("cf", "sec", "constants", "_ctypes")
    #: Annotation only, so the slot is typed without creating a colliding class attribute. Every
    #: value is a resolved, NON-NULL address — see the NULL check in ``__init__``.
    constants: dict[str, int]

    def __init__(self) -> None:
        import ctypes

        self._ctypes = ctypes
        try:
            cf = ctypes.CDLL(_CORE_FOUNDATION_PATH, use_errno=True)
            sec = ctypes.CDLL(_SECURITY_PATH, use_errno=True)
        except Exception:  # noqa: BLE001 - a missing framework is a bounded refusal
            _reject("secpctl_credential_store_unavailable")

        void_p = ctypes.c_void_p
        index = ctypes.c_ssize_t
        try:
            cf.CFStringCreateWithBytes.argtypes = (
                void_p,
                ctypes.POINTER(ctypes.c_ubyte),
                index,
                ctypes.c_uint32,
                ctypes.c_ubyte,
            )
            cf.CFStringCreateWithBytes.restype = void_p
            cf.CFDataCreate.argtypes = (void_p, ctypes.POINTER(ctypes.c_ubyte), index)
            cf.CFDataCreate.restype = void_p
            cf.CFDictionaryCreate.argtypes = (
                void_p,
                ctypes.POINTER(void_p),
                ctypes.POINTER(void_p),
                index,
                void_p,
                void_p,
            )
            cf.CFDictionaryCreate.restype = void_p
            cf.CFRelease.argtypes = (void_p,)
            cf.CFRelease.restype = None
            cf.CFDataGetLength.argtypes = (void_p,)
            cf.CFDataGetLength.restype = index
            cf.CFDataGetBytePtr.argtypes = (void_p,)
            cf.CFDataGetBytePtr.restype = void_p
            cf.CFGetTypeID.argtypes = (void_p,)
            cf.CFGetTypeID.restype = ctypes.c_ulong
            cf.CFDataGetTypeID.argtypes = ()
            cf.CFDataGetTypeID.restype = ctypes.c_ulong

            sec.SecItemAdd.argtypes = (void_p, ctypes.POINTER(void_p))
            sec.SecItemAdd.restype = ctypes.c_int32
            sec.SecItemCopyMatching.argtypes = (void_p, ctypes.POINTER(void_p))
            sec.SecItemCopyMatching.restype = ctypes.c_int32
            sec.SecItemUpdate.argtypes = (void_p, void_p)
            sec.SecItemUpdate.restype = ctypes.c_int32
            sec.SecItemDelete.argtypes = (void_p,)
            sec.SecItemDelete.restype = ctypes.c_int32

            resolved: dict[str, int | None] = {
                name: ctypes.c_void_p.in_dll(sec, name).value
                for name in (
                    "kSecClass",
                    "kSecClassGenericPassword",
                    "kSecAttrService",
                    "kSecAttrAccount",
                    "kSecValueData",
                    "kSecReturnData",
                    "kSecMatchLimit",
                    "kSecMatchLimitOne",
                )
            }
            resolved["kCFBooleanTrue"] = ctypes.c_void_p.in_dll(cf, "kCFBooleanTrue").value
            constants = require_resolved_constants(resolved)
            # The two callback tables are STRUCTS, so the dictionary needs their ADDRESS, not the
            # value of their first field -- `in_dll(...).value` would silently pass garbage.
            for name in ("kCFTypeDictionaryKeyCallBacks", "kCFTypeDictionaryValueCallBacks"):
                constants[name] = ctypes.addressof(ctypes.c_void_p.in_dll(cf, name))
        except Exception:  # noqa: BLE001 - an unusable framework surface is a bounded refusal
            _reject("secpctl_credential_store_unavailable")

        self.cf = cf
        self.sec = sec
        self.constants = constants

    def string(self, value: str) -> int:
        """A ``CFStringRef`` (owned by the caller) for a UTF-8 Python string."""
        ctypes = self._ctypes
        raw = value.encode("utf-8")
        buffer = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
        ref = self.cf.CFStringCreateWithBytes(
            None, buffer, len(raw), _K_CF_STRING_ENCODING_UTF8, False
        )
        if not ref:
            _reject("secpctl_credential_backend_failed")
        return ref

    def data(self, value: bytes) -> int:
        """A ``CFDataRef`` (owned by the caller) for opaque bytes."""
        ctypes = self._ctypes
        buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
        ref = self.cf.CFDataCreate(None, buffer, len(value))
        if not ref:
            _reject("secpctl_credential_backend_failed")
        return ref

    def dictionary(self, pairs: list[tuple[int, int]]) -> int:
        """A ``CFDictionaryRef`` (owned by the caller) over already-created CF values."""
        ctypes = self._ctypes
        count = len(pairs)
        keys = (ctypes.c_void_p * count)(*[k for k, _ in pairs])
        values = (ctypes.c_void_p * count)(*[v for _, v in pairs])
        ref = self.cf.CFDictionaryCreate(
            None,
            keys,
            values,
            count,
            self.constants["kCFTypeDictionaryKeyCallBacks"],
            self.constants["kCFTypeDictionaryValueCallBacks"],
        )
        if not ref:
            _reject("secpctl_credential_backend_failed")
        return ref

    def release(self, *refs: int) -> None:
        for ref in refs:
            if ref:
                self.cf.CFRelease(ref)

    def data_bytes(self, ref: int) -> bytes:
        """Copy a ``CFDataRef``'s contents out, refusing anything that is not CFData."""
        ctypes = self._ctypes
        if self.cf.CFGetTypeID(ref) != self.cf.CFDataGetTypeID():
            _reject("secpctl_credential_record_invalid")
        length = int(self.cf.CFDataGetLength(ref))
        if length <= 0 or length > MAX_SECRET_BYTES:
            _reject("secpctl_credential_record_invalid")
        pointer = self.cf.CFDataGetBytePtr(ref)
        if not pointer:
            _reject("secpctl_credential_record_invalid")
        return ctypes.string_at(pointer, length)


class MacOSKeychainBinding:
    """macOS Keychain Services generic-item storage through the current ``SecItem`` API."""

    __slots__ = ("_fw",)
    # Annotation only (no assignment), so it declares the slot's type without creating a class
    # attribute that would collide with ``__slots__``. Without it the frameworks handle infers as
    # untyped and every method that touches it loses checking.
    _fw: _MacOSFrameworks

    def __init__(self) -> None:
        if sys.platform != "darwin":
            _reject("secpctl_credential_store_unavailable")
        self._fw = _MacOSFrameworks()

    def __repr__(self) -> str:  # never a service / account / secret
        return "MacOSKeychainBinding(<bound>)"

    @property
    def backend_id(self) -> str:
        return BACKEND_MACOS_KEYCHAIN

    def _query(self, service: str, account: str, extra: list[tuple[int, int]]) -> tuple[int, list]:
        fw = self._fw
        owned: list[int] = []
        service_ref = fw.string(require_identifier(service))
        account_ref = fw.string(require_identifier(account))
        owned += [service_ref, account_ref]
        pairs = [
            (fw.constants["kSecClass"], fw.constants["kSecClassGenericPassword"]),
            (fw.constants["kSecAttrService"], service_ref),
            (fw.constants["kSecAttrAccount"], account_ref),
            *extra,
        ]
        query = fw.dictionary(pairs)
        owned.append(query)
        return query, owned

    def set_secret(self, *, service: str, account: str, secret: bytes) -> None:
        fw = self._fw
        blob = require_storable(secret)
        query, owned = self._query(service, account, [])
        value = fw.data(blob)
        owned.append(value)
        try:
            update = fw.dictionary([(fw.constants["kSecValueData"], value)])
            owned.append(update)
            status = fw.sec.SecItemUpdate(query, update)
            if status == _ERR_SEC_ITEM_NOT_FOUND:
                add_query, add_owned = self._query(
                    service, account, [(fw.constants["kSecValueData"], value)]
                )
                owned += add_owned
                status = fw.sec.SecItemAdd(add_query, None)
                if status == _ERR_SEC_DUPLICATE_ITEM:
                    status = fw.sec.SecItemUpdate(query, update)
            if status != _ERR_SEC_SUCCESS:
                _reject("secpctl_credential_backend_failed")
        finally:
            fw.release(*owned)

    def get_secret(self, *, service: str, account: str) -> bytes | None:
        import ctypes

        fw = self._fw
        query, owned = self._query(
            service,
            account,
            [
                (fw.constants["kSecReturnData"], fw.constants["kCFBooleanTrue"]),
                (fw.constants["kSecMatchLimit"], fw.constants["kSecMatchLimitOne"]),
            ],
        )
        result = ctypes.c_void_p()
        try:
            status = fw.sec.SecItemCopyMatching(query, ctypes.byref(result))
            if status == _ERR_SEC_ITEM_NOT_FOUND:
                return None
            if status != _ERR_SEC_SUCCESS or not result.value:
                _reject("secpctl_credential_backend_failed")
            raw = fw.data_bytes(result.value)
            # The read-side size bound lives HERE, in the binding, not only inside the framework
            # wrapper. `_MacOSFrameworks` cannot execute without a real Security framework, so a
            # bound stated only there is unreachable on every host this repository can run — while
            # the equivalent Linux check sits in its own `get_secret` and is exercised everywhere.
            # Keeping it at this layer gives macOS the same read-side guarantee AND makes it
            # testable. The wrapper keeps its own copy: bounding before `string_at` avoids copying
            # an absurd buffer out of CoreFoundation in the first place.
            if not (0 < len(raw) <= MAX_SECRET_BYTES):
                _reject("secpctl_credential_record_invalid")
            return raw
        finally:
            fw.release(*owned)
            if result.value:
                fw.release(result.value)

    def delete_secret(self, *, service: str, account: str) -> bool:
        fw = self._fw
        query, owned = self._query(service, account, [])
        try:
            status = fw.sec.SecItemDelete(query)
            if status == _ERR_SEC_ITEM_NOT_FOUND:
                return False
            if status != _ERR_SEC_SUCCESS:
                _reject("secpctl_credential_backend_failed")
            return True
        finally:
            fw.release(*owned)


# --- Linux: the freedesktop Secret Service through secretstorage ----------------------------------


#: The label an operator sees beside this credential in their keyring UI. Code-owned and non-secret.
SECRET_SERVICE_LABEL = "SECP secpctl operator credential"

#: The fixed attribute that scopes every search and delete to items THIS tool created, so a logout
#: can never remove an unrelated application's entry that happens to share a service/account pair.
SECRET_SERVICE_APPLICATION = "secpctl"

_ATTRIBUTE_SERVICE = "service"
_ATTRIBUTE_ACCOUNT = "account"
_ATTRIBUTE_APPLICATION = "application"


def _secretstorage() -> Any:
    """The ``secretstorage`` module, or a bounded refusal.

    Imported lazily and locally: the distribution installs it only under a ``sys_platform ==
    'linux'`` marker, so a top-level import would break every non-Linux host at module load.
    """
    try:
        import secretstorage
    except Exception:  # noqa: BLE001 - an absent backend library is a bounded refusal
        _reject("secpctl_credential_store_unavailable")
    return secretstorage


def secret_service_attributes(service: str, account: str) -> dict[str, str]:
    """The exact attribute set one credential is stored and searched under.

    Pure and separately tested. The Secret Service matches an item when it carries AT LEAST the
    searched attributes, so including the fixed application attribute narrows every lookup to this
    tool's own items rather than anything that happens to share a service/account pair.
    """
    return {
        _ATTRIBUTE_SERVICE: require_identifier(service),
        _ATTRIBUTE_ACCOUNT: require_identifier(account),
        _ATTRIBUTE_APPLICATION: SECRET_SERVICE_APPLICATION,
    }


class SecretServiceBinding:
    """The freedesktop Secret Service (GNOME Keyring / KWallet) via ``secretstorage``.

    Each operation opens and closes its own session-bus connection. jeepney's ``DBusConnection`` is
    not closed automatically and objects created inside a connection do not outlive it, so a
    per-operation connection is both simpler and safer than a long-lived one in a short-lived CLI.

    A locked collection is a REFUSAL and never an implicit unlock — see the module docstring.
    """

    __slots__ = ()

    def __init__(self) -> None:
        if not sys.platform.startswith("linux"):
            _reject("secpctl_credential_store_unavailable")
        # Probe once at construction so an absent library or an unreachable Secret Service resolves
        # to the SEALED store, rather than advertising a backend that refuses on every command.
        #
        # A LOCKED collection is deliberately NOT such a failure. The Secret Service is present and
        # reachable; the operator has simply not unlocked it, and they may well unlock it before the
        # next command. Refusing construction here would collapse that into the generic
        # `secpctl_credential_store_unavailable` — which on Linux is the MOST LIKELY failure and the
        # message that tells the operator the least. Constructing anyway lets every operation carry
        # `secpctl_credential_store_locked` through to them, which says what to do. Nothing is
        # weakened: a locked collection still refuses every read, write and delete.
        try:
            connection, _collection = self._connect()
        except OperatorCredentialBackendError as exc:
            if exc.reason_code != "secpctl_credential_store_locked":
                raise
            return  # reachable, merely locked; `_connect` already closed the probe connection
        connection.close()

    def __repr__(self) -> str:  # never a service / account / secret
        return "SecretServiceBinding(<bound>)"

    @property
    def backend_id(self) -> str:
        return BACKEND_SECRET_SERVICE

    def _connect(self) -> tuple[Any, Any]:
        """``(connection, collection)`` for one operation. The caller MUST close the connection.

        Named ``_connect`` rather than ``_open`` on purpose: the credential-surface source scan
        forbids the substring ``open(``, and ``self._open(`` would satisfy it spuriously.
        """
        module = _secretstorage()
        try:
            connection = module.dbus_init()
        except Exception:  # noqa: BLE001 - no session bus / no Secret Service is a bounded refusal
            _reject("secpctl_credential_store_unavailable")
        try:
            collection = module.get_default_collection(connection)
            locked = collection.is_locked()
        except Exception:  # noqa: BLE001
            connection.close()
            _reject("secpctl_credential_store_unavailable")
        if locked:
            connection.close()
            _reject("secpctl_credential_store_locked")
        return connection, collection

    def set_secret(self, *, service: str, account: str, secret: bytes) -> None:
        blob = require_storable(secret)
        attributes = secret_service_attributes(service, account)
        connection, collection = self._connect()
        try:
            # `replace=True` makes this an atomic replace of the item with these exact attributes,
            # so a renewal never leaves two credentials for one controller.
            collection.create_item(SECRET_SERVICE_LABEL, attributes, blob, replace=True)
        except Exception:  # noqa: BLE001 - never leaks the item, the attributes, or a D-Bus message
            _reject("secpctl_credential_backend_failed")
        finally:
            connection.close()

    def get_secret(self, *, service: str, account: str) -> bytes | None:
        attributes = secret_service_attributes(service, account)
        connection, collection = self._connect()
        try:
            items = list(collection.search_items(attributes))
            if not items:
                return None
            raw = bytes(items[0].get_secret())
            if not (0 < len(raw) <= MAX_SECRET_BYTES):
                _reject("secpctl_credential_record_invalid")
            return raw
        except ManagementError:
            raise
        except Exception:  # noqa: BLE001
            _reject("secpctl_credential_backend_failed")
        finally:
            connection.close()

    def delete_secret(self, *, service: str, account: str) -> bool:
        attributes = secret_service_attributes(service, account)
        connection, collection = self._connect()
        try:
            items = list(collection.search_items(attributes))
            for item in items:
                item.delete()
            return bool(items)
        except Exception:  # noqa: BLE001
            _reject("secpctl_credential_backend_failed")
        finally:
            connection.close()


# --- resolution -----------------------------------------------------------------------------------


def resolve_secret_store_binding() -> SecretStoreBinding | None:
    """The OS keystore binding for THIS platform, or ``None`` when none is available.

    ``None`` is the whole no-plaintext-fallback rule in one return value: the caller composes the
    SEALED store and every credential operation refuses. A platform with no binding, a framework
    that will not load, an absent ``secretstorage`` and an unreachable Secret Service all land here.
    There is no fourth binding to fall through to.

    A LOCKED keyring deliberately does NOT land here — the service is reachable, so the binding is
    returned and every operation refuses with ``secpctl_credential_store_locked`` instead of the
    generic unavailable code. Fail-closed either way; only the diagnostic differs.
    """
    try:
        if sys.platform == "win32":
            return WindowsCredentialManagerBinding()
        if sys.platform == "darwin":
            return MacOSKeychainBinding()
        if sys.platform.startswith("linux"):
            return SecretServiceBinding()
    except ManagementError:
        return None
    except Exception:  # noqa: BLE001 - an unexpected platform failure still fails CLOSED
        return None
    return None


__all__ = [
    "BACKEND_MACOS_KEYCHAIN",
    "BACKEND_SECRET_SERVICE",
    "BACKEND_WINDOWS_CREDENTIAL_MANAGER",
    "MAX_SECRET_BYTES",
    "SECRET_SERVICE_APPLICATION",
    "SECRET_SERVICE_LABEL",
    "MacOSKeychainBinding",
    "OperatorCredentialBackendError",
    "SecretServiceBinding",
    "SecretStoreBinding",
    "WindowsCredentialManagerBinding",
    "require_identifier",
    "require_resolved_constants",
    "require_storable",
    "resolve_secret_store_binding",
    "secret_service_attributes",
    "target_name",
]
