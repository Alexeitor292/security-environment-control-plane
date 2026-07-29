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
  is refused rather than parsed.

Every refusal is a bounded closed reason code naming the CONTRACT CLASS that failed — never a
deployment value, path, host name, image or credential from the artifact.
"""

from __future__ import annotations

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


def _api_volumes(api: dict[str, Any]) -> list[Any]:
    volumes = api.get("volumes")
    if volumes is None:
        _reject("controller_compose_api_volumes_missing")
    if not isinstance(volumes, list):
        _reject("controller_compose_unsupported_volume_structure")
    return volumes  # type: ignore[return-value]


def _entry_target(entry: Any) -> str | None:
    """The container target an entry claims, for duplicate/short-form detection across ALL entries.

    A short-form string (``"src:dst:ro"``) is understood only well enough to notice that it TARGETS
    a contract path; it is never accepted as satisfying the contract."""
    if isinstance(entry, str):
        parts = entry.split(":")
        return parts[1] if len(parts) >= 2 else None
    if isinstance(entry, dict):
        target = entry.get("target")
        return target if isinstance(target, str) else None
    return None


def _matches_long_form_bind(entry: Any, source: str, target: str) -> bool:
    return (
        isinstance(entry, dict)
        and entry.get("type") == "bind"
        and entry.get("source") == source
        and entry.get("target") == target
    )


def _assert_required_mount(volumes: list[Any], source: str, target: str, kind: str) -> None:
    """Prove EXACTLY ONE conforming long-form read-only bind for ``target``, and no rival entry."""
    # 1. no other entry may claim this target -- an alias, a short form, or a second bind with a
    #    different source would make the effective mount ambiguous or attacker-chosen.
    claiming = [e for e in volumes if _entry_target(e) == target]
    if len(claiming) == 0:
        _reject(f"controller_compose_{kind}_mount_missing")
    if len(claiming) > 1:
        _reject(f"controller_compose_{kind}_mount_duplicate_target")
    entry = claiming[0]
    if isinstance(entry, str):
        # short form cannot express create_host_path:false and its read-only flag is positional.
        _reject(f"controller_compose_{kind}_mount_short_form")
    if not isinstance(entry, dict):
        _reject("controller_compose_unsupported_volume_structure")

    # 2. it must be the exact long-form bind this contract requires.
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
    if entry.get("target") != target:  # unreachable via `claiming`, kept as a total check
        _reject(f"controller_compose_{kind}_mount_wrong_target")
    if entry.get("read_only") is not True:
        _reject(f"controller_compose_{kind}_mount_writable")

    # 3. no propagation or writable override may reopen what read_only closed.
    bind = entry.get("bind")
    if bind is not None and not isinstance(bind, dict):
        _reject("controller_compose_unsupported_volume_structure")
    if isinstance(bind, dict) and "propagation" in bind:
        _reject(f"controller_compose_{kind}_mount_propagation_forbidden")
    # 4. create_host_path MUST be present and false: with it absent or true, Docker silently
    #    creates a DIRECTORY at a missing gate/marker path, and the API then sees a directory where
    #    the contract promised a file -- an unauthenticated readiness route in the gate's case.
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
    volumes = _api_volumes(api)
    for source, target, kind in REQUIRED_API_MOUNTS:
        _assert_required_mount(volumes, source, target, kind)


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
    "REQUIRED_API_MOUNTS",
    "ControllerComposeContractError",
    "assert_controller_compose_contract",
    "controller_compose_contract_reason",
    "parse_controller_compose_document",
]
