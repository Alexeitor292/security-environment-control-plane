"""The STRICT signed controller-Compose CONTRACT (SECP-PR5H-B2, 2b-3c-c deployability gap).

`4413f2f` made the enrollment-signer readiness route security-complete: the gate is generated,
authenticated, its runtime mount is validated after the API starts, and the management client sends
the authenticated header. It was NOT release-topology complete. The controller Compose template is a
**signed release artifact installed verbatim** — the installer never injects YAML — so nothing
proved that the signed artifact actually mounts the gate into the ordinary API. The management test
fixture was a placeholder comment, so a fully green CI proved nothing about the mount at all. A
release could therefore be signed, verified, installed and started with **no gate mount**, and the
readiness route would be permanently unreachable (a byte-identical 404) with no refusal anywhere.

This module closes that: one code-owned validator for the facts the controller installation contract
requires of the signed artifact, run at EVERY trust boundary (build, sign, verify, plan, install,
replay, managed-upgrade candidate, and the restored prior config after rollback). **A valid
signature is not sufficient** — a correctly signed but semantically invalid artifact still refuses,
before any host mutation.

Deliberately NOT a second Compose implementation. It inspects only what the contract requires and
refuses everything it does not understand:

* ``yaml.safe_load`` only — never ``load``/``full_load``/``unsafe_load``, no caller-supplied Loader,
  so no arbitrary object construction, no tag-driven instantiation;
* a subclass of ``SafeLoader`` that REJECTS duplicate mapping keys, because PyYAML's default
  last-wins would let a second ``volumes:`` silently displace the reviewed one;
* exactly ONE document (``compose_documents``) — a second document could carry an override;
* bounded input size, bounded nesting depth and bounded collection sizes;
* no ``${...}``/``$VAR`` interpolation anywhere in a contract-relevant source or target, because the
  bytes signed are not then the paths mounted;
* long-form binds only for the contract's targets: a short-form ``"a:b:ro"`` string is ambiguous and
  is refused rather than parsed;
* every entry inside ``services.api.volumes`` is canonicalized and grouped by the destination it
  actually resolves to (R8), AND every alternate API mount mechanism -- ``configs``, ``secrets``,
  ``tmpfs``, ``volumes_from``, ``devices``, ``use_api_socket`` -- is forbidden outright (R9). Those
  two statements together are what makes the API service's mount set knowable from the signed bytes;
  neither alone is sufficient, because an alternate surface never enters the grouping.

Every refusal is a bounded closed reason code naming the CONTRACT CLASS that failed — never a
deployment value, path, host name, image or credential from the artifact.
"""

from __future__ import annotations

import posixpath
from typing import Any, Final

import yaml
from secp_commissioning.enrollment_signer_binding_digest import (
    ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH,
    ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH,
)
from secp_commissioning.enrollment_signer_marker import ENROLLMENT_SIGNER_MARKER_PATH

from secp_management import ManagementError

#: The ordinary API service the contract constrains. Code-owned; never caller-selected.
CONTROLLER_API_SERVICE: Final = "api"

#: The two mounts the ordinary API MUST receive, as ``(source, target, reason_class)``. Both path
#: literals come from the plane-neutral contracts — this module defines no path of its own, so the
#: validator can never drift from the thing it validates.
#:
#: The marker is host-path == container-path (public installation facts, 0644). The readiness gate
#: is a 256-bit machine secret and is mounted at a distinct fixed container path.
REQUIRED_API_MOUNTS: Final[tuple[tuple[str, str, str], ...]] = (
    (ENROLLMENT_SIGNER_MARKER_PATH, ENROLLMENT_SIGNER_MARKER_PATH, "marker"),
    (
        ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH,
        ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH,
        "readiness_gate",
    ),
)

#: R9. ``services.api.volumes`` is not the only way Compose can put a filesystem object inside a
#: container. Each field below introduces an INDEPENDENT mount surface whose targets never enter the
#: R8 canonical-target grouping, so a perfectly valid reviewed volumes list could coexist with an
#: alternate mount that MASKS, collides with, or replaces the effective readiness-gate or
#: signer-marker destination. All six are refused outright on the ordinary API service:
#:
#: * ``configs`` / ``secrets`` -- file mounts with independently selected targets; a caller-chosen
#:   file can be placed exactly where the root-generated gate belongs;
#: * ``tmpfs`` -- filesystem mounts declared outside ``volumes``;
#: * ``volumes_from`` -- targets that cannot be derived here at all without evaluating another
#:   service or an external container;
#: * ``devices`` -- a separate host-path-to-container-path mapping surface;
#: * ``use_api_socket`` -- mounts the container-engine socket and delegated credentials, which is
#:   outside the ordinary API's authority entirely.
#:
#: PRESENCE is the refusal, even for ``[]``, ``null`` or ``false``: an empty declaration is still
#: outside the closed v1alpha2 B2 contract, and treating "empty" as "absent" would make the contract
#: depend on how a future Compose version resolves an empty field. Partially emulating the Compose
#: resolver instead -- deriving what these fields would actually mount -- would make this module a
#: second Compose implementation and could never be correct offline.
FORBIDDEN_API_MOUNT_SURFACES: Final = frozenset(
    {
        "configs",
        "secrets",
        "tmpfs",
        "volumes_from",
        "devices",
        "use_api_socket",
    }
)


_MAX_TEMPLATE_BYTES: Final = 1 * 1024 * 1024  # a controller compose template is small
_MAX_DEPTH: Final = 16
_MAX_MAPPING_KEYS: Final = 256
_MAX_SEQUENCE_ITEMS: Final = 256
_MAX_SCALAR_LEN: Final = 4096

#: Interpolation makes the SIGNED bytes and the MOUNTED path different things. Refused outright in
#: any contract-relevant scalar rather than being resolved by this module.
_INTERPOLATION_MARKERS: Final = ("$",)


class ControllerComposeContractError(ManagementError):
    """A signed controller Compose artifact that does not satisfy the installation contract."""


def _reject(reason_code: str) -> None:
    raise ControllerComposeContractError(reason_code)


class _NoDuplicateKeySafeLoader(yaml.SafeLoader):
    """``SafeLoader`` (no arbitrary object construction) that additionally REFUSES duplicate keys.

    PyYAML's default is last-wins, so a document with two ``volumes:`` keys under ``services.api``
    parses cleanly and silently discards the first. That is precisely how a reviewed mount could be
    signed and then not exist at runtime, so a duplicate key is a contract failure, not a merge."""


def _no_duplicate_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False):  # noqa: ANN202
    mapping: dict[Any, Any] = {}
    if len(node.value) > _MAX_MAPPING_KEYS:
        _reject("controller_compose_document_too_large")
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError:  # an unhashable key is not a shape this contract understands
            _reject("controller_compose_unsupported_structure")
            raise  # pragma: no cover - _reject always raises
        if duplicate:
            _reject("controller_compose_duplicate_key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_NoDuplicateKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicate_mapping
)


def _bounded(value: object, depth: int = 0) -> None:
    """Refuse a document that is deeper, wider or longer than the contract can need."""
    if depth > _MAX_DEPTH:
        _reject("controller_compose_document_too_deep")
    if isinstance(value, dict):
        if len(value) > _MAX_MAPPING_KEYS:
            _reject("controller_compose_document_too_large")
        for key, item in value.items():
            _bounded(key, depth + 1)
            _bounded(item, depth + 1)
    elif isinstance(value, (list, tuple)):
        if len(value) > _MAX_SEQUENCE_ITEMS:
            _reject("controller_compose_document_too_large")
        for item in value:
            _bounded(item, depth + 1)
    elif isinstance(value, str) and len(value) > _MAX_SCALAR_LEN:
        _reject("controller_compose_document_too_large")


def parse_controller_compose_document(content: bytes) -> dict[str, Any]:
    """Parse the signed template into ONE bounded, duplicate-key-free, safely constructed mapping.

    Never returns a partially trusted structure: anything this function cannot fully characterise is
    a bounded refusal."""
    if not isinstance(content, bytes) or not content:
        _reject("controller_compose_template_unreadable")
    if len(content) > _MAX_TEMPLATE_BYTES:
        _reject("controller_compose_document_too_large")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        _reject("controller_compose_malformed")
        raise  # pragma: no cover - _reject always raises
    try:
        documents = list(yaml.load_all(text, Loader=_NoDuplicateKeySafeLoader))
    except ControllerComposeContractError:
        raise  # a contract refusal raised from inside the loader keeps its own reason
    except yaml.YAMLError:
        _reject("controller_compose_malformed")
        raise  # pragma: no cover - _reject always raises
    if len(documents) == 0:
        # comments only / empty: there is no contract to satisfy, so it can never satisfy one.
        _reject("controller_compose_malformed")
    if len(documents) != 1:
        # a second document could override the first at runtime; the contract covers ONE.
        _reject("controller_compose_multiple_documents")
    document = documents[0]
    if not isinstance(document, dict):
        _reject("controller_compose_unsupported_structure")
    _bounded(document)
    return document


def _interpolated(value: str) -> bool:
    return any(marker in value for marker in _INTERPOLATION_MARKERS)


def _api_service(document: dict[str, Any]) -> dict[str, Any]:
    services = document.get("services")
    if not isinstance(services, dict):
        _reject("controller_compose_services_invalid")
    api = services.get(CONTROLLER_API_SERVICE)  # type: ignore[union-attr]
    if not isinstance(api, dict):
        _reject("controller_compose_api_service_missing")
    return api  # type: ignore[return-value]


#: Compose-level INDIRECTION: these make the effective service definition depend on bytes this
#: document does not contain, so a validated template could still resolve to a different mount set
#: at runtime. Refused rather than followed -- following them would make this a second Compose
#: implementation, and resolving them offline could not see what the daemon would see.
_FORBIDDEN_INDIRECTION: Final = ("extends", "!reset", "!override")
_FORBIDDEN_TOP_LEVEL: Final = ("include",)


def _assert_no_indirection(document: dict[str, Any], api: dict[str, Any]) -> None:
    for key in _FORBIDDEN_TOP_LEVEL:
        if key in document:
            _reject("controller_compose_indirection_forbidden")
    for key in _FORBIDDEN_INDIRECTION:
        if key in api:
            _reject("controller_compose_indirection_forbidden")


def _assert_no_alternate_mount_surface(api: dict[str, Any]) -> None:
    """R9: refuse every alternate API mount mechanism BEFORE ``volumes`` is even read.

    The order matters. ``volumes`` is canonicalized and grouped (R8) so no two entries can
    resolve to one reviewed destination; that guarantee is worth nothing if a sibling field can
    mount over the
    same path without ever entering the grouping. So this runs first, and it refuses on PRESENCE
    rather than trying to work out what the field would have mounted.

    The public reason names the CONTRACT CLASS only -- never which field, never a target, never a
    config or secret name. A refusal is emitted to operators and must not become a way to enumerate
    what a hostile release attempted."""
    for field in FORBIDDEN_API_MOUNT_SURFACES:
        if field in api:
            _reject("controller_compose_api_alternate_mount_surface_forbidden")


def _api_volumes(api: dict[str, Any]) -> list[Any]:
    volumes = api.get("volumes")
    if volumes is None:
        _reject("controller_compose_api_volumes_missing")
    if not isinstance(volumes, list):
        _reject("controller_compose_unsupported_volume_structure")
    return volumes  # type: ignore[return-value]


#: R8a: the EXACT top-level key set a required mount may carry, and the EXACT bind key set. A
#: closed allow-list, not a deny-list: a future Compose feature must not be able to silently broaden
#: the authority the ordinary API receives merely because this module has not heard of it yet.
REQUIRED_MOUNT_KEYS: Final = frozenset({"type", "source", "target", "read_only", "bind"})
REQUIRED_MOUNT_BIND_KEYS: Final = frozenset({"create_host_path"})

_MAX_TARGET_LEN: Final = 1024
#: the shapes a short-form string may take: `dst`, `src:dst`, `src:dst:opts`. Anything longer is a
#: representation this contract does not understand.
_MAX_SHORT_FORM_PARTS: Final = 3


def canonical_container_target(raw: object) -> str:
    """The ONE canonical POSIX container target, or a bounded refusal.

    R8. compose-go applies POSIX ``path.Clean`` to every volume target, so ``/run/secp/../secp/x``,
    ``/run/secp/x/``, ``/run//secp/x`` and ``/run/secp/./x`` are FOUR different strings that become
    ONE runtime destination. Comparing raw strings therefore let a valid required mount coexist with
    a WRITABLE alias that Compose would land on the very same path -- a full bypass of the read-only
    gate contract, and one that no amount of later Docker error checking may be relied on to catch.

    ``posixpath`` is used deliberately, never ``os.path``: the target is a path inside a Linux
    container and must be read identically on every host that validates or signs the release. On
    Windows ``os.path`` treats a backslash as a separator and would normalize it away.

    A noncanonical target is REFUSED, never silently normalized and accepted -- accepting it would
    make the bytes that were signed differ from the destination that is mounted, which is the exact
    ambiguity this contract exists to remove."""
    if not isinstance(raw, str) or not raw:
        _reject("controller_compose_target_invalid")
    text: str = raw  # type: ignore[assignment]
    if len(text) > _MAX_TARGET_LEN:
        _reject("controller_compose_target_too_long")
    if "\x00" in text:
        _reject("controller_compose_target_invalid")
    if "\\" in text:  # a backslash is a literal character in a POSIX path, never a separator
        _reject("controller_compose_target_invalid")
    if _interpolated(text):
        _reject("controller_compose_target_interpolated")
    if not text.startswith("/"):
        _reject("controller_compose_target_not_absolute")
    segments = text.split("/")[1:]
    if any(seg == "" for seg in segments):  # a repeated separator, or a trailing slash
        _reject("controller_compose_target_not_canonical")
    if any(seg in (".", "..") for seg in segments):
        _reject("controller_compose_target_not_canonical")
    canonical = posixpath.normpath(text)
    if canonical != text:  # a total check: nothing noncanonical may survive the checks above
        _reject("controller_compose_target_not_canonical")
    if canonical == "/":  # the container root is never a valid mount target here
        _reject("controller_compose_target_invalid")
    return canonical


def _declared_target(entry: Any) -> str:
    """The container target a ``volumes`` ENTRY declares, in every entry representation Compose
    accepts.

    Scope, stated precisely because an earlier comment here was easy to over-read: this covers every
    representation an entry INSIDE ``services.api.volumes`` may take -- a long-form bind, a named
    volume, a tmpfs entry, an image mount, or a short-form string. It does NOT and cannot cover
    Compose's other mount mechanisms; those are forbidden outright by
    :func:`_assert_no_alternate_mount_surface` (R9) rather than characterised here.

    An entry whose target cannot be extracted is REFUSED rather than skipped: skipping it is
    precisely how an alias would slip past."""
    if isinstance(entry, str):
        parts = entry.split(":")
        if not 1 <= len(parts) <= _MAX_SHORT_FORM_PARTS:
            _reject("controller_compose_unsupported_volume_structure")
        # `dst` (anonymous volume) -> the path IS the target; `src:dst[:opts]` -> the second field.
        return canonical_container_target(parts[0] if len(parts) == 1 else parts[1])
    if isinstance(entry, dict):
        if "target" not in entry:
            _reject("controller_compose_unsupported_volume_structure")
        return canonical_container_target(entry["target"])
    _reject("controller_compose_unsupported_volume_structure")
    raise AssertionError  # pragma: no cover - _reject always raises


def _group_by_canonical_target(volumes: list[Any]) -> dict[str, list[Any]]:
    """Every ``services.api.volumes`` entry, grouped by the destination Compose will ACTUALLY
    mount it at.

    This is the pre-pass R8 requires: it runs over every entry in that list -- binds, named volumes,
    tmpfs entries, image mounts and short forms alike -- BEFORE either required mount is
    examined, so a lexical alias is caught by construction. A runtime "duplicate mount point"
    error is not a security gate: the signed release must refuse before it is signed and before
    any host mutation.

    It covers the ``volumes`` LIST only. The two guarantees are therefore stated separately and
    together are exhaustive for the API service: every entry inside ``services.api.volumes`` is
    canonicalized and grouped (R8), and every alternate API mount mechanism is forbidden (R9)."""
    grouped: dict[str, list[Any]] = {}
    for entry in volumes:
        grouped.setdefault(_declared_target(entry), []).append(entry)
    return grouped


def _assert_required_mount(
    grouped: dict[str, list[Any]], source: str, target: str, kind: str
) -> None:
    """Prove EXACTLY ONE conforming long-form read-only bind at ``target``, and no rival entry."""
    claiming = grouped.get(target, [])
    if len(claiming) == 0:
        _reject(f"controller_compose_{kind}_mount_missing")
    if len(claiming) > 1:
        # a second entry resolving to the SAME canonical destination -- a `..`/`.`/repeated-slash/
        # trailing-slash alias, a short form, a named volume, a tmpfs, an image mount, or a second
        # bind -- makes the effective mount ambiguous or attacker-chosen.
        _reject(f"controller_compose_{kind}_mount_duplicate_target")
    entry = claiming[0]
    if isinstance(entry, str):
        # short form cannot express create_host_path:false and its read-only flag is positional.
        _reject(f"controller_compose_{kind}_mount_short_form")
    if not isinstance(entry, dict):
        _reject("controller_compose_unsupported_volume_structure")

    # R8a: the EXACT key set, checked BEFORE any value, so an unknown key can never be reached and
    # then ignored. `consistency`, `volume`, `tmpfs`, `image`, `cluster`, `subpath`, `selinux`,
    # `recursive` and anything not yet invented all land here as an EXTRA key. A MISSING key keeps
    # its own precise code -- reporting an omitted `create_host_path` as "unexpected key" would tell
    # an operator the wrong thing.
    if set(entry) - REQUIRED_MOUNT_KEYS:
        _reject(f"controller_compose_{kind}_mount_unexpected_key")
    if "bind" not in entry:
        # no bind block at all means no create_host_path, which is the risk that matters.
        _reject(f"controller_compose_{kind}_mount_create_host_path")
    if REQUIRED_MOUNT_KEYS - set(entry):
        _reject(f"controller_compose_{kind}_mount_invalid")
    bind = entry.get("bind")
    if not isinstance(bind, dict):
        _reject("controller_compose_unsupported_volume_structure")
    # `propagation` keeps its own named code: it is the one bind option that could reopen what
    # read_only closed, and it was called out by name in review.
    if "propagation" in bind:  # type: ignore[operator]
        _reject(f"controller_compose_{kind}_mount_propagation_forbidden")
    if set(bind) - REQUIRED_MOUNT_BIND_KEYS:  # type: ignore[arg-type]
        _reject(f"controller_compose_{kind}_mount_unexpected_key")

    for field in ("source", "target"):
        value = entry.get(field)
        if not isinstance(value, str):
            _reject(f"controller_compose_{kind}_mount_invalid")
        if _interpolated(value):  # signed bytes != mounted path
            _reject(f"controller_compose_{kind}_mount_interpolated")
    if entry.get("type") != "bind":
        _reject(f"controller_compose_{kind}_mount_invalid")
    if entry.get("source") != source:
        _reject(f"controller_compose_{kind}_mount_wrong_source")
    if entry.get("target") != target:  # byte-for-byte, not merely canonically equal
        _reject(f"controller_compose_{kind}_mount_wrong_target")
    if entry.get("read_only") is not True:  # the actual boolean, never a truthy string
        _reject(f"controller_compose_{kind}_mount_writable")
    # create_host_path MUST be present and false: with it absent or true, Docker silently creates a
    # DIRECTORY at a missing gate/marker path, and the API then sees a directory where the contract
    # promised a file -- an unauthenticated readiness route in the gate's case.
    if not isinstance(bind, dict) or bind.get("create_host_path") is not False:
        _reject(f"controller_compose_{kind}_mount_create_host_path")


def assert_controller_compose_contract(content: bytes) -> None:
    """Prove the SIGNED controller Compose artifact satisfies the installation contract.

    Runs at every trust boundary and BEFORE any host mutation. Raises
    :class:`ControllerComposeContractError` (a :class:`ManagementError`) with a bounded reason code
    naming the contract class that failed; never echoes a deployment value."""
    document = parse_controller_compose_document(content)
    api = _api_service(document)
    _assert_no_indirection(document, api)
    # R9 BEFORE R8: an alternate mount surface must be refused before `volumes` is read, because the
    # canonical-target grouping cannot see a mount that never appears in `volumes`.
    _assert_no_alternate_mount_surface(api)
    volumes = _api_volumes(api)
    # R8: canonicalize and group EVERY entry's destination FIRST, then validate the required
    # mounts. Doing it in that order is what makes a normalized alias impossible.
    grouped = _group_by_canonical_target(volumes)
    for source, target, kind in REQUIRED_API_MOUNTS:
        _assert_required_mount(grouped, source, target, kind)


def controller_compose_contract_reason(content: bytes) -> str | None:
    """:func:`assert_controller_compose_contract` as a reason code, for fail-closed observers that
    classify rather than raise. ``None`` means the artifact satisfies the contract."""
    try:
        assert_controller_compose_contract(content)
    except ManagementError as exc:
        return exc.reason_code
    except Exception:  # noqa: BLE001 - an unclassifiable artifact is never a passing one
        return "controller_compose_unsupported_structure"
    return None


__all__ = [
    "CONTROLLER_API_SERVICE",
    "FORBIDDEN_API_MOUNT_SURFACES",
    "REQUIRED_MOUNT_BIND_KEYS",
    "REQUIRED_MOUNT_KEYS",
    "REQUIRED_API_MOUNTS",
    "ControllerComposeContractError",
    "canonical_container_target",
    "assert_controller_compose_contract",
    "controller_compose_contract_reason",
    "parse_controller_compose_document",
]
