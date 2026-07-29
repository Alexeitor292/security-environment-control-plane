"""The ONE shared fixed ORIGIN-GATE primitive (SECP-PR5H-B2, 2b-3c-c, Defect-3 A).

Defect-3 A: the origin-gate mechanism existed twice — two independent ``os.open``/``fstat``/parse
implementations that could drift apart under review. This suite drives the single extracted
primitive and proves the posture it is responsible for, ONCE:

* the accepted on-disk representation is exactly ``[0-9a-f]{64}\\n`` and nothing else;
* posture is proven with ``fstat`` on the OPEN DESCRIPTOR — regular file, one link, root owner,
  non-root runtime group, mode 0640, exact size — and every defect fails closed to a bounded,
  domain-prefixed reason code;
* an ABSENT fixed path is distinguishable from a PRESENT-but-unprovable one, so a domain can render
  "this surface does not exist here" and "this configured control could not be proven" differently
  without either ever inspecting a reason string;
* the parsed material is opaque: no repr, str, f-string, attribute, ``__dict__``, ``vars`` or
  exception discloses it;
* verification accepts EXACTLY ONE raw header value in constant time;
* and the two shipped DOMAINS (worker admission, signer readiness) share the mechanism while
  sharing NO header, path, secret type or reason code — so neither can ever authenticate the other.
"""

from __future__ import annotations

import os
import stat

import pytest
from secp_api.fixed_origin_gate import (
    FIXED_ORIGIN_GATE_FILE_BYTES,
    FIXED_ORIGIN_GATE_FILE_MODE,
    FixedOriginGate,
    FixedOriginGateError,
    FixedOriginGateSecret,
)
from secp_api.signer_readiness_origin import (
    ENROLLMENT_SIGNER_READINESS_GATE,
    EnrollmentSignerReadinessGateError,
    EnrollmentSignerReadinessGateSecret,
)
from secp_api.worker_admission_origin import (
    WORKER_ADMISSION_PROXY_GATE,
    WorkerAdmissionProxyGateError,
    WorkerAdmissionProxyGateSecret,
)
from starlette.requests import Request

_HEX = "a" * 64
_VALUE = _HEX.encode()
_FILE = _VALUE + b"\n"
_POSIX = os.name == "posix"


def _gate_at(path: str) -> FixedOriginGate:
    """A gate domain pinned to a temp path — the production instances take no path argument."""
    return FixedOriginGate(
        header="X-SECP-Test-Gate",
        container_path=path,
        secret_class=EnrollmentSignerReadinessGateSecret,
    )


def _write(tmp_path, body: bytes, name: str = "gate.secret") -> str:
    path = tmp_path / name
    path.write_bytes(body)
    return str(path)


def _force_posture(monkeypatch, **over: int) -> None:
    """Present the production posture on the loader's OWN descriptor.

    A hermetic test cannot create a root-owned 0640 file, so the ``fstat`` result for a file of
    exactly the gate size is doctored. Every other descriptor is untouched, and the doctored values
    are the production ones unless a test overrides one to prove that defect fails closed."""
    real = os.fstat
    posture = {
        "kind": stat.S_IFREG,
        "mode": FIXED_ORIGIN_GATE_FILE_MODE,
        "nlink": 1,
        "uid": 0,  # root owner
        "gid": 10001,  # the dedicated non-root API runtime group
    }
    posture.update(over)

    def _fake(fd: int) -> os.stat_result:
        st = real(fd)
        if st.st_size != FIXED_ORIGIN_GATE_FILE_BYTES:
            return st
        return os.stat_result(
            (
                posture["kind"] | posture["mode"],
                st.st_ino,
                st.st_dev,
                posture["nlink"],
                posture["uid"],
                posture["gid"],
                st.st_size,
                0,
                0,
                0,
            )
        )

    monkeypatch.setattr(os, "fstat", _fake)


def _request(*header_values: bytes, name: bytes = b"x-secp-test-gate") -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"host", b"controller.internal"), *((name, v) for v in header_values)],
        }
    )


# --------------------------------------------------------------------------- the bytes contract


def test_the_one_accepted_on_disk_representation_round_trips() -> None:
    gate = _gate_at("/nonexistent")
    secret = gate.parse(_FILE)
    assert type(secret) is EnrollmentSignerReadinessGateSecret
    assert secret.header_value() == _HEX
    assert FIXED_ORIGIN_GATE_FILE_BYTES == 65


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"", "readiness_gate_secret_size_invalid"),
        (_VALUE, "readiness_gate_secret_size_invalid"),  # no trailing LF
        (_FILE + b"\n", "readiness_gate_secret_size_invalid"),
        (_FILE[:-1] + b"\r", "readiness_gate_secret_format_invalid"),
        (b"A" * 64 + b"\n", "readiness_gate_secret_format_invalid"),  # uppercase hex
        (b"g" * 64 + b"\n", "readiness_gate_secret_format_invalid"),  # not hex
        (b" " + b"a" * 63 + b"\n", "readiness_gate_secret_format_invalid"),
        (b"a" * 63 + b"\n\n", "readiness_gate_secret_format_invalid"),
        (b"\n" + b"a" * 64, "readiness_gate_secret_format_invalid"),
    ],
)
def test_every_non_conforming_on_disk_form_refuses(raw: bytes, code: str) -> None:
    gate = _gate_at("/nonexistent")
    with pytest.raises(EnrollmentSignerReadinessGateError) as exc:
        gate.parse(raw)
    assert exc.value.reason_code == code
    assert exc.value.absent is False


def test_a_non_bytes_or_malformed_value_never_constructs_a_secret() -> None:
    for bad in (None, "a" * 64, b"a" * 63, b"A" * 64, bytearray(b"a" * 64)):
        with pytest.raises(EnrollmentSignerReadinessGateError) as exc:
            EnrollmentSignerReadinessGateSecret(bad)  # type: ignore[arg-type]
        assert exc.value.reason_code == "readiness_gate_secret_invalid"


# --------------------------------------------------------------------------- opacity


def test_the_secret_is_opaque_in_every_disclosure_path() -> None:
    secret = EnrollmentSignerReadinessGateSecret(_VALUE)
    for rendering in (repr(secret), str(secret), f"{secret}", f"{secret!r}", format(secret)):
        assert _HEX not in rendering
        assert "<redacted>" in rendering
    assert repr(secret) == "EnrollmentSignerReadinessGateSecret(<redacted>)"
    # no instance dict at all: the value cannot be swept up by a serializer, an ``asdict``, a
    # ``__getstate__``, or a debugger's attribute dump of the object's own namespace
    assert not hasattr(secret, "__dict__")
    with pytest.raises(TypeError):
        vars(secret)
    # and no PUBLIC member discloses it — the storage slot is private and name-mangled
    public = sorted(n for n in dir(secret) if not n.startswith("_"))
    assert public == ["error_class", "header_value", "matches_raw_header_values", "reason_prefix"]
    assert not any(_HEX in str(getattr(secret, name)) for name in public)


def test_a_gate_refusal_never_carries_the_value_or_the_path() -> None:
    gate = _gate_at("/run/secp/some-fixed-gate.secret")
    with pytest.raises(EnrollmentSignerReadinessGateError) as exc:
        gate.parse(_VALUE + b"x" + b"\n")
    rendered = f"{exc.value} {exc.value.args!r} {exc.value.reason_code}"
    assert _HEX not in rendered
    assert "/run/secp" not in rendered
    # and the gate object itself names only its domain
    assert _HEX not in repr(gate) and gate.container_path not in repr(gate)


# --------------------------------------------------------------------------- header verification


def test_exactly_one_matching_raw_header_value_authenticates() -> None:
    gate = _gate_at("/nonexistent")
    secret = gate.parse(_FILE)
    assert gate.authenticates(secret, _request(_VALUE)) is True


@pytest.mark.parametrize(
    "values",
    [
        (),  # absent
        (_VALUE, _VALUE),  # duplicated (identical) — never collapsed into one
        (_VALUE, b"b" * 64),
        (b"b" * 64,),  # wrong
        (b"A" * 64,),  # right value, wrong case
        (_VALUE[:-1],),  # truncated
        (_VALUE + b"x",),  # extended
        (_VALUE + b"\n",),  # the FILE form, not the header form
        (b"",),
    ],
)
def test_every_other_header_shape_refuses(values: tuple[bytes, ...]) -> None:
    gate = _gate_at("/nonexistent")
    secret = gate.parse(_FILE)
    assert gate.authenticates(secret, _request(*values)) is False


def test_a_header_under_another_name_never_authenticates() -> None:
    gate = _gate_at("/nonexistent")
    secret = gate.parse(_FILE)
    other = _request(_VALUE, name=b"x-secp-admission-proxy-gate")
    assert gate.authenticates(secret, other) is False
    # the header NAME is matched case-insensitively (an ASGI server may not have lowercased it),
    # while the VALUE is compared byte-exactly — an upper-cased value never authenticates
    assert gate.authenticates(secret, _request(_VALUE, name=b"X-SECP-Test-Gate")) is True
    assert gate.authenticates(secret, _request(_VALUE.upper())) is False


# --------------------------------------------------------------------------- the loader posture


def test_an_absent_fixed_path_is_distinguishable_from_an_unprovable_one(tmp_path) -> None:
    gate = _gate_at(str(tmp_path / "never-installed.secret"))
    with pytest.raises(EnrollmentSignerReadinessGateError) as exc:
        gate.load()
    assert exc.value.reason_code == "readiness_gate_secret_open_failed"
    assert exc.value.absent is True


def test_a_present_gate_with_an_unsafe_posture_is_not_absent(tmp_path) -> None:
    """A real, ordinary (non-root, wrong-mode) file: PRESENT but unprovable — never absent, so a
    domain can never mistake a broken configured control for an unconfigured controller."""
    gate = _gate_at(_write(tmp_path, _FILE))
    with pytest.raises(EnrollmentSignerReadinessGateError) as exc:
        gate.load()
    assert exc.value.reason_code == "readiness_gate_secret_metadata_invalid"
    assert exc.value.absent is False


def test_the_production_posture_loads(tmp_path, monkeypatch) -> None:
    _force_posture(monkeypatch)
    gate = _gate_at(_write(tmp_path, _FILE))
    secret = gate.load()
    assert type(secret) is EnrollmentSignerReadinessGateSecret
    assert secret.header_value() == _HEX


@pytest.mark.parametrize(
    "defect",
    [
        {"uid": 1000},  # not root-owned
        {"gid": 0},  # root group (no dedicated non-root API runtime group)
        {"nlink": 2},  # hard-linked
        {"mode": 0o644},  # world-readable
        {"mode": 0o660},  # group-writable
        {"mode": 0o600},  # unreadable by the API runtime group
        {"kind": stat.S_IFIFO},  # not a regular file
    ],
)
def test_every_posture_defect_fails_closed(tmp_path, monkeypatch, defect: dict) -> None:
    _force_posture(monkeypatch, **defect)
    gate = _gate_at(_write(tmp_path, _FILE))
    with pytest.raises(EnrollmentSignerReadinessGateError) as exc:
        gate.load()
    assert exc.value.reason_code == "readiness_gate_secret_metadata_invalid"
    assert exc.value.absent is False


def test_a_wrong_sized_gate_file_fails_closed(tmp_path) -> None:
    gate = _gate_at(_write(tmp_path, _FILE + b"trailing"))
    with pytest.raises(EnrollmentSignerReadinessGateError) as exc:
        gate.load()
    assert exc.value.reason_code == "readiness_gate_secret_metadata_invalid"


@pytest.mark.skipif(not _POSIX, reason="O_NOFOLLOW is POSIX-only")
def test_a_symlinked_gate_never_opens(tmp_path) -> None:
    real = _write(tmp_path, _FILE, name="real.secret")
    link = tmp_path / "link.secret"
    os.symlink(real, link)
    gate = _gate_at(str(link))
    with pytest.raises(EnrollmentSignerReadinessGateError) as exc:
        gate.load()
    assert exc.value.reason_code == "readiness_gate_secret_open_failed"
    assert exc.value.absent is False  # a symlink is PRESENT, just never followed


def test_the_loader_leaks_no_descriptor(tmp_path, monkeypatch) -> None:
    _force_posture(monkeypatch)
    gate = _gate_at(_write(tmp_path, _FILE))
    opened: list[int] = []
    real_open, real_close = os.open, os.close
    monkeypatch.setattr(os, "open", lambda *a, **k: opened.append(real_open(*a, **k)) or opened[-1])
    monkeypatch.setattr(os, "close", lambda fd: (opened.remove(fd), real_close(fd)) and None)
    gate.load()
    assert opened == []


# --------------------------------------------------------------------------- domain separation


def test_the_two_shipped_domains_share_nothing_but_the_mechanism() -> None:
    admission, readiness = WORKER_ADMISSION_PROXY_GATE, ENROLLMENT_SIGNER_READINESS_GATE
    assert admission.header != readiness.header
    assert admission.header.lower() != readiness.header.lower()
    assert admission.container_path != readiness.container_path
    assert admission.secret_class is not readiness.secret_class
    assert admission.error_class is not readiness.error_class
    assert admission.reason_prefix != readiness.reason_prefix
    # both are built on the ONE primitive — there is no second parser/loader to review
    assert isinstance(admission, FixedOriginGate) and isinstance(readiness, FixedOriginGate)
    assert issubclass(admission.secret_class, FixedOriginGateSecret)
    assert issubclass(readiness.secret_class, FixedOriginGateSecret)
    assert issubclass(admission.error_class, FixedOriginGateError)
    assert issubclass(readiness.error_class, FixedOriginGateError)


def test_neither_domains_material_can_authenticate_the_other() -> None:
    """The structural proof: even with BYTE-IDENTICAL secrets, a domain accepts only its OWN exact
    secret type, so one surface's gate can never open the other."""
    admission_secret = WorkerAdmissionProxyGateSecret(_VALUE)
    readiness_secret = EnrollmentSignerReadinessGateSecret(_VALUE)
    assert admission_secret.header_value() == readiness_secret.header_value()

    admission_request = _request(_VALUE, name=b"x-secp-admission-proxy-gate")
    readiness_request = _request(_VALUE, name=b"x-secp-enrollment-signer-readiness-gate")

    assert WORKER_ADMISSION_PROXY_GATE.authenticates(admission_secret, admission_request) is True
    assert ENROLLMENT_SIGNER_READINESS_GATE.authenticates(readiness_secret, readiness_request)

    # cross-presented material: refused on BOTH sides
    assert WORKER_ADMISSION_PROXY_GATE.authenticates(readiness_secret, admission_request) is False
    assert ENROLLMENT_SIGNER_READINESS_GATE.authenticates(admission_secret, readiness_request) is (
        False
    )
    # cross-presented HEADER NAME: refused on both sides too
    assert WORKER_ADMISSION_PROXY_GATE.authenticates(admission_secret, readiness_request) is False
    assert (
        ENROLLMENT_SIGNER_READINESS_GATE.authenticates(readiness_secret, admission_request) is False
    )


def test_a_subclass_or_double_of_a_gate_secret_never_authenticates() -> None:
    class _Sneaky(EnrollmentSignerReadinessGateSecret):
        __slots__ = ()

    class _Fake:
        def matches_raw_header_values(self, values: tuple[bytes, ...]) -> bool:
            return True

    request = _request(_VALUE, name=b"x-secp-enrollment-signer-readiness-gate")
    assert ENROLLMENT_SIGNER_READINESS_GATE.authenticates(_Sneaky(_VALUE), request) is False
    assert ENROLLMENT_SIGNER_READINESS_GATE.authenticates(_Fake(), request) is False
    assert ENROLLMENT_SIGNER_READINESS_GATE.authenticates(None, request) is False


def test_each_domains_error_type_is_caught_by_the_shared_base() -> None:
    """A domain refusal is both its own bounded type AND the shared base, so the primitive can raise
    once while each domain keeps a distinct ``except`` clause."""
    assert issubclass(WorkerAdmissionProxyGateError, FixedOriginGateError)
    assert issubclass(EnrollmentSignerReadinessGateError, FixedOriginGateError)
    assert not issubclass(WorkerAdmissionProxyGateError, EnrollmentSignerReadinessGateError)
    assert not issubclass(EnrollmentSignerReadinessGateError, WorkerAdmissionProxyGateError)
    with pytest.raises(WorkerAdmissionProxyGateError):
        WORKER_ADMISSION_PROXY_GATE.parse(b"nope")
