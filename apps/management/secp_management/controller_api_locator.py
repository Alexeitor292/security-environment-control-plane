"""Controller-API locator for secpctl's controller enrollment commands (SECP-PR5H-B1, Phase 4).

secpctl is management-plane and may NOT import ``secp_api``, read the database, or accept a
``--url``/``--ca`` argument. To operate the controller enrollment HTTPS API it needs the
controller's canonical HTTPS origin and the absolute path to the reviewed controller CA/trust
bundle from a SAFE, in-plane source. There is none in the bootstrap identity/evidence, so the
controller
bootstrap RECORDS one here: a protected, root-owned management config file that secpctl reads via
the hardened
filesystem seam (root-owned, non-symlink, non-hardlinked, non-group/other-writable, bounded). The
locator carries PUBLIC deployment facts only — an origin and a CA-bundle path, never a secret.

The shipped default provider is SEALED (``secpctl_controller_locator_unavailable``); a controller on
which ``secpctl bootstrap controller`` recorded the locator resolves it. No ``--url``/``--ca`` input
exists; the origin/CA are never chosen by a CLI argument, environment variable, or HTTP payload.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from threading import Lock
from typing import NoReturn, Protocol
from urllib.parse import urlsplit

from secp_commissioning.canonical import canonical_json
from secp_commissioning.runtime import FilesystemBackend, FilesystemError

from secp_management import ManagementError
from secp_management.layout import ManagementLocations

#: The fixed, code-owned path of the protected controller-API locator, recorded at controller
#: bootstrap and read (never chosen by a CLI/env input) by secpctl's controller client.
CONTROLLER_API_LOCATOR_PATH = "/etc/secp/controller/api-locator.json"

_LOCATOR_SCHEMA = "secp.management.controller-api-locator/v1"
_MODE = 0o644  # root-owned, world-readable PUBLIC config; NO group/other write
_MAX_BYTES = 4096
_MAX_ORIGIN_LEN = 269
_MAX_PATH_LEN = 512
_HTTPS_ORIGIN = re.compile(r"https://[a-z0-9.-]{1,253}(?::[1-9][0-9]{0,4})?")
_ABS_PATH = re.compile(r"/[A-Za-z0-9][A-Za-z0-9._/-]{0,510}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ControllerApiLocatorError(ManagementError):
    """A bounded, closed locator refusal — carries ONLY a reason code, never the origin, CA path, or
    a raw exception."""


def _reject(reason_code: str) -> NoReturn:
    raise ControllerApiLocatorError(reason_code)


@dataclass(frozen=True)
class ControllerApiLocator:
    """The controller's canonical HTTPS origin and the absolute path to the reviewed CA/trust
    bundle. Public deployment facts only. Its repr is redacted so neither value leaks into a log."""

    canonical_origin: str
    ca_bundle_path: str

    def __post_init__(self) -> None:
        try:
            origin_port = (
                urlsplit(self.canonical_origin).port
                if isinstance(self.canonical_origin, str)
                else None
            )
        except ValueError:
            _reject("secpctl_controller_locator_invalid")
        if (
            not isinstance(self.canonical_origin, str)
            or len(self.canonical_origin) > _MAX_ORIGIN_LEN
            or not _HTTPS_ORIGIN.fullmatch(self.canonical_origin)
            or _CONTROL.search(self.canonical_origin)
            or (origin_port is not None and not (1 <= origin_port <= 65535))
        ):
            _reject("secpctl_controller_locator_invalid")
        if (
            not isinstance(self.ca_bundle_path, str)
            or not (1 <= len(self.ca_bundle_path) <= _MAX_PATH_LEN)
            or not _ABS_PATH.fullmatch(self.ca_bundle_path)
            or ".." in self.ca_bundle_path.split("/")
            or _CONTROL.search(self.ca_bundle_path)
        ):
            _reject("secpctl_controller_locator_invalid")

    def __repr__(self) -> str:  # never the origin / CA path
        return "ControllerApiLocator(<redacted>)"


class ControllerApiLocatorProvider(Protocol):
    """Resolves the controller-API locator for secpctl's controller client."""

    def locate(self) -> ControllerApiLocator: ...


class SealedControllerApiLocatorProvider:
    """The shipped default: no locator is recorded, so controller commands fail closed."""

    def __repr__(self) -> str:
        return "SealedControllerApiLocatorProvider(<sealed>)"

    def locate(self) -> ControllerApiLocator:
        _reject("secpctl_controller_locator_unavailable")


def _require_root_regular(fs: FilesystemBackend, path: str, *, reason: str) -> None:
    st = fs.lstat(path)
    if (
        st is None
        or st.is_dir
        or st.is_symlink
        or st.is_special
        or not st.is_regular
        or st.uid != 0
        or st.gid != 0
        or st.nlink != 1
        or (st.mode & 0o022)  # no group/other write on a root-owned config
    ):
        _reject(reason)


class FileControllerApiLocatorProvider:
    """Reads the protected root-owned locator through the hardened filesystem seam. A missing file
    is ``secpctl_controller_locator_unavailable``; an unsafe or malformed file is
    ``secpctl_controller_locator_invalid``.

    The first valid value is an immutable snapshot for this provider instance. Production creates
    one provider per CLI invocation and shares it across the HTTPS destination, CA-bundle source,
    and credential-account selector. Re-reading the file independently in those consumers would
    permit one invocation to cross controller trust scopes if the locator changed between reads.
    """

    __slots__ = ("_fs", "_path", "_snapshot", "_snapshot_lock")

    def __init__(self, fs: FilesystemBackend, *, path: str = CONTROLLER_API_LOCATOR_PATH) -> None:
        self._fs = fs
        self._path = path
        self._snapshot: ControllerApiLocator | None = None
        self._snapshot_lock = Lock()

    def __repr__(self) -> str:
        return "FileControllerApiLocatorProvider(<redacted>)"

    def locate(self) -> ControllerApiLocator:
        with self._snapshot_lock:
            if self._snapshot is not None:
                return self._snapshot
            if self._fs.lstat(self._path) is None:
                _reject("secpctl_controller_locator_unavailable")
            _require_root_regular(self._fs, self._path, reason="secpctl_controller_locator_invalid")
            try:
                raw = self._fs.safe_read(self._path, max_bytes=_MAX_BYTES, expected_uid=0)
            except FilesystemError:
                _reject("secpctl_controller_locator_invalid")
            try:
                data = json.loads(raw.decode("utf-8"))
            except Exception:  # noqa: BLE001 - a malformed locator is a bounded refusal
                _reject("secpctl_controller_locator_invalid")
            if (
                not isinstance(data, dict)
                or data.get("schema") != _LOCATOR_SCHEMA
                or not isinstance(data.get("canonical_origin"), str)
                or not isinstance(data.get("ca_bundle_path"), str)
            ):
                _reject("secpctl_controller_locator_invalid")
            # Construction re-validates the grammar (raises the bounded invalid code). Publish the
            # snapshot only after every check succeeds, so a transient refusal is never cached.
            self._snapshot = ControllerApiLocator(
                canonical_origin=data["canonical_origin"], ca_bundle_path=data["ca_bundle_path"]
            )
            return self._snapshot


def record_controller_api_locator(
    fs: FilesystemBackend,
    *,
    canonical_origin: str,
    ca_bundle_path: str,
    write: bool,
    confirm: bool,
    path: str = CONTROLLER_API_LOCATOR_PATH,
) -> ControllerApiLocator:
    """Record the controller-API locator at controller bootstrap (root-gated; dry-run unless BOTH
    ``write`` and ``confirm``). Validates the inputs, atomically installs the canonical JSON
    root-owned ``0o644``, and reads it back through the provider to confirm — mirroring the reviewed
    key/artifact recording pattern."""
    locator = ControllerApiLocator(
        canonical_origin=canonical_origin, ca_bundle_path=ca_bundle_path
    )  # validates
    if not (write and confirm):
        return locator  # dry-run: validated but not written
    payload = canonical_json(
        {
            "schema": _LOCATOR_SCHEMA,
            "canonical_origin": locator.canonical_origin,
            "ca_bundle_path": locator.ca_bundle_path,
        }
    ).encode("utf-8")
    try:
        fs.atomic_install(path, payload, uid=0, gid=0, mode=_MODE)
    except FilesystemError:
        _reject("secpctl_controller_locator_write_failed")
    return FileControllerApiLocatorProvider(fs, path=path).locate()  # read-back confirmation


def record_fixed_controller_api_locator(
    fs: FilesystemBackend,
    *,
    canonical_origin: str,
    write: bool,
    confirm: bool,
    locations: ManagementLocations | None = None,
) -> ControllerApiLocator:
    """SECP-PR5H-B2: record the locator with the CA-bundle path PINNED to the fixed, code-owned
    controller CA-bundle location (the path the TLS producer writes). The origin is the operator's
    ``--public-origin``; the CA path is NEVER caller-supplied, so a recorded locator can only trust
    the installer-produced controller CA — not an arbitrary bundle. Dry-run unless write+confirm."""
    loc = locations if locations is not None else ManagementLocations()
    return record_controller_api_locator(
        fs,
        canonical_origin=canonical_origin,
        ca_bundle_path=loc.controller_ca_bundle_path(),
        write=write,
        confirm=confirm,
    )


__all__ = [
    "CONTROLLER_API_LOCATOR_PATH",
    "ControllerApiLocator",
    "ControllerApiLocatorError",
    "ControllerApiLocatorProvider",
    "FileControllerApiLocatorProvider",
    "SealedControllerApiLocatorProvider",
    "record_controller_api_locator",
    "record_fixed_controller_api_locator",
]
