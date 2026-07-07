"""Closed, typed READ-ONLY host probe contract (SECP-B5 §2).

A finite set of typed probes, each rendering a FIXED, discrete-token, READ-ONLY remote argv from the
CLOSED executable/verb allowlist below. There is no probe that accepts an arbitrary command, path,
user, endpoint, or option, and there is NO write verb anywhere in the type — a mutating remote
command
is not representable. ``assert_read_only`` is a belt-and-suspenders structural guard applied to
every
rendered argv before it is ever handed to the SSH runner.

Node-scoped and locator-scoped probes are parameterized ONLY by values validated to safe tokens
(reusing the B4 locator validation), so no path can be smuggled. This module renders + validates
commands and parses their output into typed, bounded, secret-free facts; it performs no I/O.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar

from secp_worker.deployment.locators import (
    BridgeLocator,
    FirewallGroupLocator,
    GuestLocator,
    ResourceLocator,
    ServiceIdentityLocator,
)

# The CLOSED executable allowlist. Nothing else may ever be exec'd as a probe.
_PVESH = "pvesh"
_PVEVERSION = "pveversion"
_CAT = "cat"
_READ_ONLY_EXECUTABLES = frozenset({_PVESH, _PVEVERSION, _CAT})
# The ONLY pvesh verb permitted. ``create``/``set``/``delete``/``push``/``pull`` are not
# representable.
_PVESH_READ_VERB = "get"
_JSON = ("--output-format", "json")
# Fixed, closed sysfs kernel-parameter files for nested virtualization (read-only). The module name
# is
# from a CLOSED set — never free input — so no arbitrary path can be read.
_NESTED_MODULES = ("kvm_intel", "kvm_amd")
_NESTED_PATH_RE = re.compile(r"^/sys/module/(kvm_intel|kvm_amd)/parameters/nested$")
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# Any token reaching the runner must contain no whitespace or shell metacharacter (belt-and-braces
# over shell=False). A pvesh path token must further be a strict slash-separated safe-token path.
_TOKEN_UNSAFE_RE = re.compile(r"[\s;&|<>$`\\(){}\[\]*?!~'\"\x00]")
_SAFE_PVESH_PATH_RE = re.compile(r"^(/[A-Za-z0-9._@-]+)+$")


class ProbeError(ValueError):
    """Raised for a malformed/unsafe probe or output. Never echoes a raw offending value."""


def _token(value: object, field: str) -> str:
    if not (isinstance(value, str) and _SAFE_TOKEN.match(value)):
        raise ProbeError(f"unsafe_probe_field:{field}")
    return value


# --- typed probe set -----------------------------------------------------------------------------


@dataclass(frozen=True)
class ProbeVersion:
    probe_code: ClassVar[str] = "version"


@dataclass(frozen=True)
class ProbeClusterStatus:
    probe_code: ClassVar[str] = "cluster_status"


@dataclass(frozen=True)
class ProbeNodeIdentity:
    probe_code: ClassVar[str] = "node_identity"


@dataclass(frozen=True)
class ProbeNodeCapacity:
    node: str
    probe_code: ClassVar[str] = "node_capacity"

    def __post_init__(self) -> None:
        _token(self.node, "node")


@dataclass(frozen=True)
class ProbeStorage:
    node: str
    probe_code: ClassVar[str] = "storage"

    def __post_init__(self) -> None:
        _token(self.node, "node")


@dataclass(frozen=True)
class ProbeVmidAvailability:
    probe_code: ClassVar[str] = "vmid_availability"


@dataclass(frozen=True)
class ProbeNestedVirtualization:
    module: str  # closed set: kvm_intel | kvm_amd
    probe_code: ClassVar[str] = "nested_virtualization"

    def __post_init__(self) -> None:
        if self.module not in _NESTED_MODULES:
            raise ProbeError("unsupported_nested_module")


@dataclass(frozen=True)
class ProbeCandidateLocatorPresence:
    locator: ResourceLocator
    probe_code: ClassVar[str] = "candidate_locator_presence"


ReadOnlyHostProbe = (
    ProbeVersion
    | ProbeClusterStatus
    | ProbeNodeIdentity
    | ProbeNodeCapacity
    | ProbeStorage
    | ProbeVmidAvailability
    | ProbeNestedVirtualization
    | ProbeCandidateLocatorPresence
)


# --- fixed read-only argv rendering --------------------------------------------------------------


def _locator_get_path(locator: ResourceLocator) -> str:
    """The read-only GET path for the exact candidate locator (never a write route)."""
    if isinstance(locator, BridgeLocator):
        return f"/nodes/{locator.node}/network/{locator.iface}"
    if isinstance(locator, FirewallGroupLocator):
        return f"/cluster/firewall/groups/{locator.group}"
    if isinstance(locator, ServiceIdentityLocator):
        return f"/access/users/{locator.userid}"
    if isinstance(locator, GuestLocator):
        # SECP-B6: a lightweight existence/status read (never the full guest config), so we never
        # inspect or retain an unrelated guest's configuration. A present candidate VMID is refused
        # as occupied regardless (a candidate is always allocated from the free pool).
        return f"/nodes/{locator.node}/qemu/{locator.vmid}/status/current"
    raise ProbeError("unsupported_candidate_locator")


def render_probe_argv(probe: ReadOnlyHostProbe) -> tuple[str, ...]:
    """Render a typed probe to a FIXED, read-only, discrete-token remote argv. Never a write
    verb."""
    if isinstance(probe, ProbeVersion):
        argv: tuple[str, ...] = (_PVESH, _PVESH_READ_VERB, "/version", *_JSON)
    elif isinstance(probe, ProbeClusterStatus):
        argv = (_PVESH, _PVESH_READ_VERB, "/cluster/status", *_JSON)
    elif isinstance(probe, ProbeNodeIdentity):
        argv = (_PVESH, _PVESH_READ_VERB, "/nodes", *_JSON)
    elif isinstance(probe, ProbeNodeCapacity):
        argv = (_PVESH, _PVESH_READ_VERB, f"/nodes/{probe.node}/status", *_JSON)
    elif isinstance(probe, ProbeStorage):
        argv = (_PVESH, _PVESH_READ_VERB, f"/nodes/{probe.node}/storage", *_JSON)
    elif isinstance(probe, ProbeVmidAvailability):
        argv = (_PVESH, _PVESH_READ_VERB, "/cluster/resources", "--type", "vm", *_JSON)
    elif isinstance(probe, ProbeNestedVirtualization):
        argv = (_CAT, f"/sys/module/{probe.module}/parameters/nested")
    elif isinstance(probe, ProbeCandidateLocatorPresence):
        argv = (_PVESH, _PVESH_READ_VERB, _locator_get_path(probe.locator), *_JSON)
    else:  # pragma: no cover - exhaustiveness guard
        raise ProbeError("unknown_probe")
    assert_read_only(argv)
    return argv


def assert_read_only(argv: Sequence[str]) -> None:
    """Fail closed unless ``argv`` is one of the CLOSED read-only forms. A structural guarantee that
    no
    write/install/upload/download/reload/restart command can ever be emitted by a probe."""
    if not argv:
        raise ProbeError("empty_probe_argv")
    # Defense in depth: no token may carry whitespace or a shell metacharacter even though the
    # runner is shell=False. This bounds any future code path that reaches assert_read_only with a
    # value derived from hostile output before the closed-form checks below.
    for tok in argv:
        if not isinstance(tok, str) or not tok or _TOKEN_UNSAFE_RE.search(tok):
            raise ProbeError("probe_token_unsafe")
    exe = argv[0]
    if exe not in _READ_ONLY_EXECUTABLES:
        raise ProbeError("executable_not_read_only")
    if exe == _PVESH:
        # pvesh MUST be a read (``get``). Any other verb (create/set/delete/push/pull/usage)
        # refused.
        if len(argv) < 2 or argv[1] != _PVESH_READ_VERB:
            raise ProbeError("pvesh_verb_not_read_only")
        for tok in argv[2:]:
            if tok.startswith("-") and tok not in ("--output-format", "json", "--type"):
                raise ProbeError("pvesh_option_not_allowed")
            if tok == "vm" or tok == "json" or tok == "--output-format" or tok == "--type":
                continue
            if not tok.startswith("/"):
                raise ProbeError("pvesh_arg_not_path")
            if not _SAFE_PVESH_PATH_RE.match(tok):
                raise ProbeError("pvesh_path_unsafe")
    elif exe == _CAT:
        # cat is restricted to the fixed nested-virt sysfs kernel parameter files ONLY.
        if len(argv) != 2 or not _NESTED_PATH_RE.match(argv[1]):
            raise ProbeError("cat_path_not_allowed")
    elif exe == _PVEVERSION:
        if len(argv) != 1:
            raise ProbeError("pveversion_takes_no_args")


def candidate_presence_probe(locator: ResourceLocator) -> ProbeCandidateLocatorPresence:
    _locator_get_path(locator)  # validate representability up front
    return ProbeCandidateLocatorPresence(locator)


# --- bounded, secret-free parsers ----------------------------------------------------------------

_MAX_OUTPUT_BYTES = 512 * 1024  # a read-only probe's output is small; refuse an oversized blob


def _reject_constant(_token: str) -> object:
    # json permits the non-standard ``NaN``/``Infinity``/``-Infinity`` literals by default; a
    # read-only probe's output must never carry a non-finite number. Fail closed at the source.
    raise ProbeError("malformed_probe_output")


def _load_json(stdout: bytes) -> object:
    if len(stdout) > _MAX_OUTPUT_BYTES:
        raise ProbeError("probe_output_too_large")
    try:
        return json.loads(stdout.decode("utf-8", "strict"), parse_constant=_reject_constant)
    except ProbeError:
        raise
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        # RecursionError (a RuntimeError) covers a deeply nested payload under the size cap; all
        # collapse to the same closed reason so no raw output or non-closed exception escapes.
        raise ProbeError("malformed_probe_output") from exc


def _int(value: object, *, lo: int = 0, hi: int = 10**15) -> int:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ProbeError("malformed_probe_output")
    if isinstance(value, float) and not math.isfinite(value):
        # inf/nan (e.g. a hostile ``1e400``) would raise OverflowError/ValueError from int();
        # reject as a closed malformed reason instead of leaking a non-ProbeError exception.
        raise ProbeError("malformed_probe_output")
    ivalue = int(value)
    if not (lo <= ivalue <= hi):
        raise ProbeError("malformed_probe_output")
    return ivalue


def parse_version_major_minor(stdout: bytes) -> tuple[int, int]:
    data = _load_json(stdout)
    version = data.get("version") if isinstance(data, dict) else None
    if not isinstance(version, str):
        raise ProbeError("malformed_probe_output")
    match = re.match(r"^(\d{1,3})\.(\d{1,3})", version)
    if not match:
        raise ProbeError("malformed_probe_output")
    return int(match.group(1)), int(match.group(2))


def parse_is_clustered(stdout: bytes) -> bool:
    data = _load_json(stdout)
    if not isinstance(data, list):
        raise ProbeError("malformed_probe_output")
    # A standalone node reports no ``cluster``-type entry (or quorate cluster of one is still a
    # cluster).
    return any(isinstance(item, dict) and item.get("type") == "cluster" for item in data)


def parse_node_identity(stdout: bytes) -> tuple[str, int]:
    data = _load_json(stdout)
    if not isinstance(data, list) or not data:
        raise ProbeError("malformed_probe_output")
    nodes = [i.get("node") for i in data if isinstance(i, dict) and isinstance(i.get("node"), str)]
    if not nodes:
        raise ProbeError("malformed_probe_output")
    return _token(nodes[0], "node"), len(nodes)


def parse_used_vmids(stdout: bytes) -> frozenset[int]:
    data = _load_json(stdout)
    if not isinstance(data, list):
        raise ProbeError("malformed_probe_output")
    used: set[int] = set()
    for item in data:
        if isinstance(item, dict) and isinstance(item.get("vmid"), int):
            used.add(_int(item["vmid"], lo=1, hi=999_999_999))
        if len(used) > 100_000:  # bounded
            raise ProbeError("probe_output_too_large")
    return frozenset(used)


def parse_nested_enabled(stdout: bytes) -> bool:
    # The sysfs file contains ``Y``/``1`` when nested virtualization is enabled.
    return stdout.strip().lower() in (b"y", b"1")


def parse_node_capacity(stdout: bytes) -> tuple[int, int, int]:
    """Return (cpu_total, mem_total_mb, mem_free_mb) — bounded ints only, no raw output retained."""
    data = _load_json(stdout)
    if not isinstance(data, dict):
        raise ProbeError("malformed_probe_output")
    raw_cpu = data.get("cpuinfo")
    raw_mem = data.get("memory")
    cpuinfo: dict = raw_cpu if isinstance(raw_cpu, dict) else {}
    memory: dict = raw_mem if isinstance(raw_mem, dict) else {}
    cpus = _int(cpuinfo.get("cpus", 0), hi=100_000)
    mem_total_mb = _int(memory.get("total", 0), hi=10**12) // (1024 * 1024)
    mem_free_mb = _int(memory.get("free", 0), hi=10**12) // (1024 * 1024)
    return cpus, mem_total_mb, mem_free_mb


def parse_storages(stdout: bytes) -> tuple[tuple[str, int, bool], ...]:
    """Return a bounded tuple of (storage_id, avail_mb, usable-for-images). Safe tokens + bounded
    ints."""
    data = _load_json(stdout)
    if not isinstance(data, list):
        raise ProbeError("malformed_probe_output")
    out: list[tuple[str, int, bool]] = []
    for item in data[:1024]:  # bounded
        if not isinstance(item, dict) or not isinstance(item.get("storage"), str):
            continue
        storage = _token(item["storage"], "storage")
        avail_mb = _int(item.get("avail", 0), hi=10**15) // (1024 * 1024)
        content = item.get("content")
        usable = bool(item.get("active", 0)) and (
            isinstance(content, str) and ("images" in content or "rootdir" in content)
        )
        out.append((storage, avail_mb, usable))
    return tuple(out)


# A SECP ownership marker as stamped into a provider-visible field:
# ``secp-owned:<hex>#secp<fp>-...``.
_MARKER_RE = re.compile(r"secp-owned:[0-9a-f]{8,64}#secp[0-9a-f]{8}-[a-z_]+-\d{1,3}")


def parse_owner_marker(stdout: bytes) -> str | None:
    """Extract ONLY a well-formed SECP ownership marker from a read body, if present. Nothing else
    from the raw body is retained or returned — no description text, config, secret, or address."""
    if len(stdout) > _MAX_OUTPUT_BYTES:
        raise ProbeError("probe_output_too_large")
    match = _MARKER_RE.search(stdout.decode("utf-8", "ignore"))
    return match.group(0) if match else None


def parse_locator_present(exit_code: int) -> bool:
    # A read GET returns 0 when the object exists, non-zero (not found) when absent. Presence is
    # derived from the closed exit code only — the raw body never leaves the executor.
    return exit_code == 0
