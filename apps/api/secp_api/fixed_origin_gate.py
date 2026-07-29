"""The ONE fixed application-level ORIGIN-GATE primitive (SECP-PR5H-B2, 2b-3c-c, Defect-3 A).

A private in-controller surface is reached over a dedicated in-controller hop — the TLS-terminating
admission proxy, or the root installer's management-plane observer. TLS terminates BEFORE the API,
so the final hop proves itself with a high-entropy value read from a fixed, root-controlled file.
That value is deliberately NOT a setting: no caller can select a path, and the secret can never be
placed in an environment variable, a compose contract, a log record, or an evidence document.

Defect-3 A: this mechanism existed twice — two independent ``os.open``/``fstat``/parse
implementations that could drift apart under review. It now exists exactly ONCE, here, and every
private surface is rebuilt on it:

* the on-disk representation is exactly ``[0-9a-f]{64}\\n`` — 256 bits of lowercase hex plus one LF,
  65 bytes, and nothing else. There is no alternate encoding and no whitespace tolerance;
* the file is opened ``O_RDONLY | O_NOFOLLOW | O_CLOEXEC`` (a symlinked gate never opens, and the
  descriptor never leaks across an exec), and every posture fact is proven with ``fstat`` ON THE
  DESCRIPTOR — never a path ``stat`` a racing rename could invalidate: a regular file, exactly one
  link, root owner, a non-root API runtime group, mode ``0640``, and the exact expected size;
* the parsed material lives in an OPAQUE object whose ``repr``/``str`` are a constant ``<redacted>``
  and whose value is slot-private and name-mangled, so it cannot reach a log, an f-string, a
  traceback frame dump, a pickle, or a serialized model;
* verification accepts EXACTLY ONE raw header value, taken from the raw ASGI scope (never a parsed,
  comma-joined, last-wins header view), and compares it in constant time.

Each private surface owns a DOMAIN: a :class:`FixedOriginGate` binding a distinct header name, a
distinct fixed code-owned container path, and a distinct :class:`FixedOriginGateSecret` SUBCLASS
carrying its own closed reason-code prefix and its own error type. A domain authenticates only its
OWN exact secret type, so one surface's gate material can never authenticate another's — even if an
operator installed byte-identical secrets in both files.

This primitive is transport provenance ONLY. It is never an identity: each surface keeps its own
authentication (the worker's Ed25519 signed-nonce protocol; the readiness surface's read-only,
non-secret, no-sign observation).
"""

from __future__ import annotations

import hmac
import os
import re
import stat
from typing import ClassVar, NoReturn, SupportsIndex

from fastapi import Request

#: 256 bits rendered as lowercase hex — the ONE accepted secret strength.
FIXED_ORIGIN_GATE_HEX_BYTES = 64

#: The ONE accepted on-disk size: the hex value plus a single trailing LF.
FIXED_ORIGIN_GATE_FILE_BYTES = FIXED_ORIGIN_GATE_HEX_BYTES + 1

#: The ONE accepted on-disk mode: root owner, API runtime group read, nothing for other.
FIXED_ORIGIN_GATE_FILE_MODE = 0o640

_FILE_PATTERN = re.compile(rb"[0-9a-f]{64}\n")
_VALUE_PATTERN = re.compile(rb"[0-9a-f]{64}")
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_ZERO = b"\0" * FIXED_ORIGIN_GATE_HEX_BYTES


class FixedOriginGateError(RuntimeError):
    """A bounded, closed origin-gate refusal.

    It carries ONLY a code-owned reason code and whether the fixed path was ABSENT — never the gate
    value, the raw bytes, a path, or a third-party exception. ``absent`` separates "this controller
    was never configured with this gate" (the surface simply does not exist) from "a configured gate
    is present but could not be proven safe" (a bounded unavailability), so a domain can fail closed
    in the way its own contract requires without ever inspecting a reason string.
    """

    def __init__(self, reason_code: str, *, absent: bool = False) -> None:
        self.reason_code = reason_code
        self.absent = absent
        super().__init__(reason_code)


class FixedOriginGateSecret:
    """Opaque validated gate material whose ``repr``/``str`` never disclose its value.

    A DOMAIN subclasses this and overrides :attr:`reason_prefix` + :attr:`error_class`, so two
    domains never share a reason code and never share a type. The stored value is slot-private and
    name-mangled: there is no attribute, no ``__dict__``, and no serialization path that yields it.
    """

    __slots__ = ("__value",)

    #: The domain's closed reason-code prefix. Every refusal is ``f"{reason_prefix}_<what>"``.
    reason_prefix: ClassVar[str] = "fixed_origin_gate_secret"

    #: The domain's bounded error type (a :class:`FixedOriginGateError` subclass).
    error_class: ClassVar[type[FixedOriginGateError]] = FixedOriginGateError

    def __init__(self, value: bytes) -> None:
        if not isinstance(value, bytes) or _VALUE_PATTERN.fullmatch(value) is None:
            raise self.error_class(f"{self.reason_prefix}_invalid")
        self.__value = value

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    # A redacted repr is only half a control: `pickle`/`copy` reach slot state directly and would
    # hand out the raw value, so any serializer, structured logger or error reporter could bypass
    # the redaction above. Every serialization and copy path is therefore refused outright -- the
    # value leaves this object ONLY through `header_value()` (one outbound request) and through the
    # constant-time comparison. Refusing is safe: nothing legitimately copies or pickles a gate.
    def __reduce__(self) -> NoReturn:
        raise self.error_class(f"{self.reason_prefix}_not_serializable")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise self.error_class(f"{self.reason_prefix}_not_serializable")

    def __getstate__(self) -> NoReturn:
        raise self.error_class(f"{self.reason_prefix}_not_serializable")

    def __copy__(self) -> NoReturn:
        raise self.error_class(f"{self.reason_prefix}_not_serializable")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise self.error_class(f"{self.reason_prefix}_not_serializable")

    def header_value(self) -> str:
        """Return the value only for construction of the trusted hop's single upstream request."""

        return self.__value.decode("ascii")

    def matches_raw_header_values(self, values: tuple[bytes, ...]) -> bool:
        """Verify exactly one raw header value with a fixed-size constant-time comparison."""

        exactly_one = len(values) == 1
        candidate = values[0] if exactly_one and len(values[0]) == len(self.__value) else _ZERO
        matches = hmac.compare_digest(self.__value, candidate)
        return exactly_one and len(values[0]) == len(self.__value) and matches


class FixedOriginGate:
    """ONE fixed origin-gate DOMAIN: a header name, a code-owned path, and an opaque secret type.

    Instances are module-level constants of the owning domain. Nothing here is caller-selectable:
    :meth:`load` takes no path argument, so no setting, environment variable, header, query
    parameter or body can redirect the gate at another file.
    """

    __slots__ = ("_header_name_bytes", "container_path", "file_bytes", "header", "secret_class")

    def __init__(
        self,
        *,
        header: str,
        container_path: str,
        secret_class: type[FixedOriginGateSecret],
        file_bytes: int = FIXED_ORIGIN_GATE_FILE_BYTES,
    ) -> None:
        self.header = header
        self.container_path = container_path
        self.secret_class = secret_class
        self.file_bytes = file_bytes
        self._header_name_bytes = header.lower().encode("ascii")

    def __repr__(self) -> str:  # names the domain, never any material
        return f"FixedOriginGate({self.header!r})"

    @property
    def reason_prefix(self) -> str:
        return self.secret_class.reason_prefix

    @property
    def error_class(self) -> type[FixedOriginGateError]:
        return self.secret_class.error_class

    def parse(self, raw: bytes) -> FixedOriginGateSecret:
        """Parse the one closed on-disk representation: 256-bit lowercase hex plus one LF."""

        if not isinstance(raw, bytes) or len(raw) != self.file_bytes:
            raise self.error_class(f"{self.reason_prefix}_size_invalid")
        if _FILE_PATTERN.fullmatch(raw) is None:
            raise self.error_class(f"{self.reason_prefix}_format_invalid")
        return self.secret_class(raw[:-1])

    def load(self) -> FixedOriginGateSecret:
        """Read + validate the sole code-owned root-controlled gate path without following links.

        Posture is proven on the OPEN DESCRIPTOR, so the file that was checked is exactly the file
        that is read. An ABSENT path raises with ``absent=True``; every other fault is a bounded
        non-absent refusal, so "not configured" is never confused with "configured but unprovable".
        """

        prefix = self.reason_prefix
        error = self.error_class
        try:
            fd = os.open(self.container_path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
        except (FileNotFoundError, NotADirectoryError):
            raise error(f"{prefix}_open_failed", absent=True) from None
        except OSError:
            raise error(f"{prefix}_open_failed") from None
        try:
            metadata = os.fstat(fd)
            mode = metadata.st_mode & 0o7777
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != 0
                or metadata.st_gid <= 0
                or mode != FIXED_ORIGIN_GATE_FILE_MODE
                or metadata.st_size != self.file_bytes
            ):
                raise error(f"{prefix}_metadata_invalid")
            raw = os.read(fd, self.file_bytes + 1)
            if len(raw) != metadata.st_size:
                raise error(f"{prefix}_read_invalid")
            return self.parse(raw)
        finally:
            os.close(fd)

    def raw_header_values(self, request: Request) -> tuple[bytes, ...]:
        """Every RAW value carried under this domain's header name, straight from the ASGI scope.

        The raw scope is used deliberately: a parsed header view collapses repeats into one
        comma-joined string, which would let a duplicated header masquerade as a single value.
        """

        return tuple(
            value
            for name, value in request.scope.get("headers", ())
            if name.lower() == self._header_name_bytes
        )

    def authenticates(self, secret: object, request: Request) -> bool:
        """Whether ``request`` carries exactly one header value proving THIS domain's gate.

        ``secret`` must be this domain's EXACT secret type (``type(...) is``, never ``isinstance``),
        so a sibling domain's material — or a subclass, stub or test double — can never authenticate
        here even when the underlying bytes are identical.
        """

        if not isinstance(secret, self.secret_class) or type(secret) is not self.secret_class:
            return False
        return secret.matches_raw_header_values(self.raw_header_values(request))


__all__ = [
    "FIXED_ORIGIN_GATE_FILE_BYTES",
    "FIXED_ORIGIN_GATE_FILE_MODE",
    "FIXED_ORIGIN_GATE_HEX_BYTES",
    "FixedOriginGate",
    "FixedOriginGateError",
    "FixedOriginGateSecret",
]
