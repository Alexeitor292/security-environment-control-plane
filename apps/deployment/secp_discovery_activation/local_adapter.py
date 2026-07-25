"""Closed, production-capable local Docker/Compose activation adapter.

This module is the only production composition for :class:`ActivationAdapter`.  Its public
surface contains no path, argv, service-name, image-reference, or generic command parameter.  All
host processes run through the existing executable-object pinning and bounded streaming runner;
construction performs no filesystem, process, or network operation.

The adapter deliberately uses two independent durability boundaries:

* worker-owned state is validated/prepared by :mod:`secp_discovery_activation.state`; and
* root-owned configuration changes are recorded in a fixed, fsync'd transaction journal before
  the first artifact or Compose mutation.

Rollback will replace or remove an artifact only when its current content *and* metadata still
match either the authenticated before-image or the transaction's recorded after-image.  Drift is
therefore a recovery-required refusal, never permission to overwrite a foreign object.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import stat
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, NoReturn, Protocol

from secp_operator_deployment.host_process import CommandResult, CommandRunner, RealCommandRunner
from secp_operator_deployment.pinned_exec import ExecutablePin

from secp_discovery_activation.adapters import (
    ActivationAdapterError,
    CompensationResult,
    ContainerRuntimeObservation,
    FixedInputBinding,
    HostObservation,
    MutationReceipt,
    WorkerPublicObservation,
)
from secp_discovery_activation.evidence import (
    ROLE_ADMISSION_CA,
    ROLE_ADMISSION_PROXY_GATE,
    ROLE_ADMISSION_SERVER_CERTIFICATE,
    ROLE_ADMISSION_SERVER_KEY,
    ROLE_CONTROLLER_OVERRIDE,
    ROLE_PROFILE,
    ROLE_PROXY_CONTRACT,
    ROLE_WORKER_OVERRIDE,
    ROLE_WORKER_RUNTIME_OVERLAY,
    ROLE_WORKER_STATE,
    ActivationEvidence,
    WorkerGeneration,
)
from secp_discovery_activation.handoff import (
    ControllerOffer,
    HandoffAttestation,
    WorkerResult,
    handoff_bytes,
)
from secp_discovery_activation.handoff import (
    attestation_bytes as handoff_attestation_bytes,
)
from secp_discovery_activation.layout import (
    ADMISSION_CONNECT_TIMEOUT_SECONDS,
    ADMISSION_PROXY_CONTAINER,
    ADMISSION_PROXY_CONTAINER_PORT,
    ADMISSION_PROXY_SERVICE,
    ADMISSION_REQUEST_TIMEOUT_SECONDS,
    ADMISSION_ROUTES,
    CONTROLLER_API_SERVICE,
    MAX_ADMISSION_RESPONSE_BYTES,
    ORDINARY_TASK_QUEUE,
    ORDINARY_WORKER_CONTAINER,
    ORDINARY_WORKER_SERVICE,
    PRODUCTION_LAYOUT,
)
from secp_discovery_activation.migration_heads import (
    ACCEPTED_CONTROLLER_MIGRATION_HEADS,
    CURRENT_CONTROLLER_MIGRATION_HEAD,
)
from secp_discovery_activation.profile import (
    DeploymentProfile,
    parse_https_endpoint,
    parse_private_listener,
    parse_profile_bytes,
    validate_dns_identity,
)
from secp_discovery_activation.render import ActivationRender, RenderedArtifact
from secp_discovery_activation.runtime_overlay import (
    MAX_RUNTIME_OVERLAY_BYTES,
    import_runtime_overlay,
)
from secp_discovery_activation.split_adapters import (
    ApiRollbackFenceObservation,
    ApiRollbackFenceState,
    ControllerCompensation,
    ControllerObservation,
    ControllerReceipt,
    WorkerCompensation,
    WorkerNodeObservation,
    WorkerObservation,
    WorkerReceipt,
)
from secp_discovery_activation.state import (
    PreparedStateReceipt,
    RealWorkerStateFilesystem,
    WorkerStateBackend,
)
from secp_discovery_activation.tls import (
    ValidatedAdmissionCA,
    ValidatedTLSMaterial,
    import_tls_material,
)

# These are repository-owned topology, not profile-provided paths.  Keeping the base deployments
# separate prevents the narrow override from becoming a second production stack.
CONTROLLER_BASE_COMPOSE_PATH = "/etc/secp/controller/docker-compose.yml"
WORKER_BASE_COMPOSE_PATH = "/etc/secp/worker/docker-compose.yml"
EVIDENCE_ATTESTATION_PATH = PRODUCTION_LAYOUT.evidence_attestation_path
CONTROLLER_OFFER_PATH = PRODUCTION_LAYOUT.controller_offer_outbox_path
CONTROLLER_OFFER_ATTESTATION_PATH = PRODUCTION_LAYOUT.controller_offer_outbox_attestation_path
WORKER_RESULT_PATH = PRODUCTION_LAYOUT.worker_result_outbox_path
WORKER_RESULT_ATTESTATION_PATH = PRODUCTION_LAYOUT.worker_result_outbox_attestation_path

_JOURNAL_SCHEMA = "secp.discovery-activation.transaction/v1"
_MAX_JOURNAL_BYTES = 1024 * 1024
_MAX_ARTIFACT_BYTES = 512 * 1024
_MAX_COMMAND_OUTPUT = 64 * 1024
_MAX_PROBE_OUTPUT = 4096
_COMMAND_TIMEOUT_SECONDS = 20
_COMPOSE_TIMEOUT_SECONDS = 300
_PUBLICATION_TIMEOUT_SECONDS = 180
_PUBLICATION_POLL_SECONDS = 2.0
_TLS_TIMEOUT_SECONDS = ADMISSION_CONNECT_TIMEOUT_SECONDS

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HMAC_SHA256 = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|[+-]\d{2}:\d{2})$")
_CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

# --- PR5F.1 controller Compose environment (code-owned fixed path) ------------------------------
# The controller base Compose file interpolates ${SECP_*} variables.  The production command runner
# uses a fixed child environment and never inherits ambient process/shell state, so those values
# must be supplied explicitly via --env-file.  This path is code-owned; no profile-provided value
# is admitted.  The file is a secret-bearing, immutable transaction input: its bytes are never
# journaled, echoed, or placed in any public evidence/status surface — only a private digest/owner/
# mode binding proves the same file remains present through activation and rollback.
CONTROLLER_ENV_FILE_PATH = "/etc/secp/controller/secp.env"
_MAX_CONTROLLER_ENV_BYTES = 64 * 1024
_MAX_CONTROLLER_ENV_LINES = 512
_MAX_ENV_NAME_LENGTH = 128
_MAX_ENV_LINE_LENGTH = 4096
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _assert_env_value_defines_name(value: str) -> None:
    """Refuse any value that compose would not resolve to the same non-empty literal we see.

    ``docker compose --env-file`` uses compose-go's dotenv parser, which (a) lets a double-quoted
    value span multiple physical lines, so a later physical line that textually looks like
    ``NAME=...`` can actually be the *continuation* of the previous value and define no new name;
    (b) performs ``$VAR``/``${VAR}`` expansion inside unquoted *and* double-quoted values, resolving
    an undefined reference to the empty string; and (c) strips an inline `` #`` comment from an
    unquoted value.  Because the production runner spawns compose with a fixed child environment
    (``PATH``/``LC_ALL`` only), a value such as ``${DATABASE_URL}`` or ``"$TOKEN"`` expands to the
    empty string at runtime — a name our parser would otherwise count as defined while compose
    blank-substitutes it.  To keep name coverage *sound* (parser returns a name ⇒ compose defines it
    non-empty) we admit only values whose runtime result we can prove verbatim without modelling
    expansion:

    * a single-quoted ``'literal'`` — compose-go treats single quotes as fully literal (no
      expansion, no comment), so any balanced non-empty interior is safe; this is the escape hatch
      for values that must contain ``$``/``#``/``"``/spaces;
    * a double-quoted ``"literal"`` with no ``$`` (would expand) and no backslash (an escape we do
      not model), balanced on one line;
    * an unquoted token with no ``$`` (expansion), no ``#`` (inline comment), and no quote
      character.

    Anything else — an empty value, an unbalanced/multi-line quote, or an unquoted value bearing
    ``$``/``#``/quotes — refuses closed.  Values are never inspected beyond this structural check.
    """
    if not value:
        _closed("controller_env_empty_value")
    first = value[0]
    if first == "'":
        interior = value[1:-1]
        if len(value) < 2 or value[-1] != "'" or not interior or "'" in interior:
            _closed("controller_env_unparsable")
    elif first == '"':
        interior = value[1:-1]
        if (
            len(value) < 2
            or value[-1] != '"'
            or not interior
            or '"' in interior
            or "$" in interior
            or "\\" in interior
        ):
            _closed("controller_env_unparsable")
    elif "$" in value or "#" in value or "'" in value or '"' in value:
        _closed("controller_env_unparsable")


def _parse_controller_env_names(raw: bytes) -> frozenset[str]:
    """Strictly parse the fixed controller environment file and return only its assigned names.

    Bounded and fail-closed: reject NUL/invalid UTF-8, oversize, too many/too-long lines, malformed
    assignments, empty/multi-line-quoted values (see :func:`_assert_env_value_defines_name`), and
    duplicate names.  Blank lines and ``#`` comments are allowed.  Values are never returned,
    interpreted, logged, or echoed — only the set of soundly assigned variable NAMES is exposed.
    """
    if not (0 < len(raw) <= _MAX_CONTROLLER_ENV_BYTES) or b"\x00" in raw:
        _closed("controller_env_unparsable")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _closed("controller_env_unparsable")
    if text.startswith("\ufeff"):  # compose-go strips a leading UTF-8 BOM; match it so an
        text = text[1:]  # editor-added BOM (common on Windows) does not refuse a valid file
    lines = text.split("\n")
    if len(lines) > _MAX_CONTROLLER_ENV_LINES:
        _closed("controller_env_unparsable")
    names: set[str] = set()
    for line in lines:
        if len(line) > _MAX_ENV_LINE_LENGTH:
            _closed("controller_env_unparsable")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        eq = stripped.find("=")
        if eq <= 0:
            _closed("controller_env_malformed")
        name = stripped[:eq].strip()
        if len(name) > _MAX_ENV_NAME_LENGTH or not _ENV_NAME.fullmatch(name):
            _closed("controller_env_malformed")
        _assert_env_value_defines_name(stripped[eq + 1 :])
        if name in names:
            _closed("controller_env_duplicate_name")
        names.add(name)
    return frozenset(names)


def _required_compose_variables(raw: bytes) -> frozenset[str]:
    """Return the variable names the base Compose file requires for interpolation.

    Supports only the plain ``${NAME}`` and ``$NAME`` forms, with ``$$`` an escaped literal ``$``.
    Any other interpolation syntax (default/alternate/error forms, or a bare ``$``) is unsupported
    and refuses closed before staging — a defaulted variable must never silently blank-substitute.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _closed("controller_base_compose_unparsable")
    required: set[str] = set()
    index, length = 0, len(text)
    while index < length:
        if text[index] != "$":
            index += 1
            continue
        if index + 1 >= length:
            _closed("controller_base_compose_interpolation_unsupported")
        nxt = text[index + 1]
        if nxt == "$":  # escaped literal dollar sign, not an interpolation reference
            index += 2
            continue
        if nxt == "{":
            end = text.find("}", index + 2)
            if end == -1:
                _closed("controller_base_compose_interpolation_unsupported")
            name = text[index + 2 : end]
            if not _ENV_NAME.fullmatch(name):  # any modifier (:- - :? ? :+ +) is unsupported
                _closed("controller_base_compose_interpolation_unsupported")
            required.add(name)
            index = end + 1
            continue
        if nxt.isalpha() or nxt == "_":
            cursor = index + 1
            while cursor < length and (text[cursor].isalnum() or text[cursor] == "_"):
                cursor += 1
            required.add(text[index + 1 : cursor])
            index = cursor
            continue
        _closed("controller_base_compose_interpolation_unsupported")
    return frozenset(required)


def _assert_controller_env_coverage(base_compose: bytes, env: bytes) -> None:
    """Prove the fixed controller environment file defines every variable the base Compose file
    interpolates.  Values are never inspected — only names are compared — so which secrets are
    present is never revealed; a missing required name refuses with one bounded reason code."""
    if not _required_compose_variables(base_compose) <= _parse_controller_env_names(env):
        _closed("controller_env_missing_required_variable")


_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SSH_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_PROXY_GATE_SECRET = re.compile(rb"^[0-9a-f]{64}\n$")

_WORKER_FORMAT = (
    "{{.Id}}|{{.Image}}|{{.State.Running}}|"
    "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|"
    "{{.RestartCount}}|{{.State.StartedAt}}"
)
_RUNTIME_FORMAT = "{{json .Config}}\n{{json .HostConfig}}"
_NETWORKS_FORMAT = (
    '{{range $name, $network := .NetworkSettings.Networks}}{{printf "%s\\n" $name}}{{end}}'
)
_NAMES_FORMAT = "{{.Names}}"
_NAME_FORMAT = "{{.Name}}"
_MOUNTS_FORMAT = (
    "{{range .Mounts}}"
    '{{printf "%s|%s|%s|%t|%s\\n" .Type .Source .Destination .RW .Propagation}}'
    "{{end}}"
)
_WORKLOAD_IDENTITY_FORMAT = "{{json .Id}}\n{{json .Path}}\n{{json .Args}}\n{{json .Config}}"

_ACTIVATION_PROBE = ("python", "-m", "secp_worker.activation_probe")
_WORKER_TLS_PROBE = ("python", "-m", "secp_worker.admission_tls_probe")
_HEALTH_PROBE = ("python", "-m", "secp_worker.health", "check")
_API_BASELINE_MIGRATION_HEAD = "c4e2f9a1b7d3"
# SECP-PR5H-A (ADR-027): a live controller is "migration ready" at EITHER head inside the bounded
# window, so PR5F activation keeps working mid-rollout; the exact OBSERVED head is still bound
# into the signed offer, so an old-head offer only validates against an old-head controller.
_API_MIGRATION_HEAD = CURRENT_CONTROLLER_MIGRATION_HEAD
_API_ACCEPTED_MIGRATION_HEADS = ACCEPTED_CONTROLLER_MIGRATION_HEADS
_API_ALEMBIC_WORKDIR = "/app/apps/api"
_API_ALEMBIC_CONFIG = "/app/apps/api/alembic.ini"
_API_MIGRATION_PROBE = (
    "python",
    "-m",
    "alembic",
    "--config",
    _API_ALEMBIC_CONFIG,
    "current",
)
_API_ROLLBACK_COMPATIBILITY_PROBE = (
    "python",
    "-m",
    "secp_api.discovery_activation_rollback_probe",
)
_API_ROLLBACK_FENCE_COMMAND = (
    "python",
    "-m",
    "secp_api.discovery_activation_rollback_fence",
)
_API_ROLLBACK_FENCE_OUTPUT = {
    "engage": (
        '{"action":"engage","observation_complete":true,"rollback_fence_state":"engaged"}\n'
    ),
    "release": (
        '{"action":"release","observation_complete":true,"rollback_fence_state":"released"}\n'
    ),
}
_API_ROLLBACK_FENCE_OBSERVE_OUTPUT: dict[str, ApiRollbackFenceState] = {
    '{"action":"observe","observation_complete":true,"rollback_fence_state":"engaged"}\n': (
        "engaged"
    ),
    '{"action":"observe","observation_complete":true,"rollback_fence_state":"released"}\n': (
        "released"
    ),
}
_API_MIGRATION_DOWNGRADE = (
    "python",
    "-m",
    "alembic",
    "downgrade",
    _API_BASELINE_MIGRATION_HEAD,
)

# The operator package, when eventually installed, is a systemd unit.  Docker-name checks are
# retained as a defense against an unreviewed containerized substitute.
_OPERATOR_UNIT_PATHS = (
    "/etc/systemd/system/secp-operator-worker.service",
    "/run/systemd/system/secp-operator-worker.service",
    "/usr/lib/systemd/system/secp-operator-worker.service",
    "/lib/systemd/system/secp-operator-worker.service",
)
_OPERATOR_CONTAINER_NAMES = frozenset({"secp-operator-worker", "secp-controlled-live-operator"})
_OPERATOR_TOKEN = re.compile(r"(?:^|[^a-z0-9])operator(?:[^a-z0-9]|$)")
_WORKER_TOKEN = re.compile(r"(?:^|[^a-z0-9])worker(?:[^a-z0-9]|$)")
_OPERATOR_QUEUE_ENV_KEY = "SECP_TEMPORAL_" + "OPERATOR_TASK_QUEUE"
_TEMPORAL_QUEUE_ENV_KEYS = frozenset({"SECP_TEMPORAL_TASK_QUEUE", _OPERATOR_QUEUE_ENV_KEY})

_ROLE_PATHS: dict[str, str] = {
    ROLE_PROFILE: PRODUCTION_LAYOUT.profile_path,
    ROLE_WORKER_OVERRIDE: PRODUCTION_LAYOUT.worker_compose_override_path,
    ROLE_WORKER_RUNTIME_OVERLAY: PRODUCTION_LAYOUT.worker_runtime_overlay_path,
    ROLE_PROXY_CONTRACT: PRODUCTION_LAYOUT.proxy_contract_path,
    ROLE_CONTROLLER_OVERRIDE: PRODUCTION_LAYOUT.controller_compose_override_path,
    ROLE_ADMISSION_CA: PRODUCTION_LAYOUT.ca_certificate_path,
    ROLE_ADMISSION_SERVER_CERTIFICATE: PRODUCTION_LAYOUT.server_certificate_path,
    ROLE_ADMISSION_SERVER_KEY: PRODUCTION_LAYOUT.server_private_key_path,
    ROLE_ADMISSION_PROXY_GATE: PRODUCTION_LAYOUT.admission_proxy_gate_path,
    "activation_evidence": PRODUCTION_LAYOUT.evidence_path,
    "activation_evidence_attestation": EVIDENCE_ATTESTATION_PATH,
    "controller_offer": CONTROLLER_OFFER_PATH,
    "controller_offer_attestation": CONTROLLER_OFFER_ATTESTATION_PATH,
    "worker_result": WORKER_RESULT_PATH,
    "worker_result_attestation": WORKER_RESULT_ATTESTATION_PATH,
    "worker_controller_offer_inbox": PRODUCTION_LAYOUT.worker_controller_offer_inbox_path,
    "worker_controller_offer_inbox_attestation": (
        PRODUCTION_LAYOUT.worker_controller_offer_inbox_attestation_path
    ),
    "controller_worker_result_inbox": PRODUCTION_LAYOUT.controller_worker_result_inbox_path,
    "controller_worker_result_inbox_attestation": (
        PRODUCTION_LAYOUT.controller_worker_result_inbox_attestation_path
    ),
}
# Repository-owned fixed files the hardened trusted-ancestor reader may open in addition to the
# profile/artifact roles and the transaction journals: the two base Compose files, the code-owned
# controller environment file, and the fixed worker runtime-overlay import.  These are fixed product
# topology, never profile-provided, so the opener must admit them explicitly — otherwise a correctly
# provisioned file refuses closed with ``activation_path_not_fixed`` and the corresponding
# controller/worker install/rollback path is inoperative.  Every non-role path handed to
# ``_read_absolute``/``_open_parent`` must be a member here (see the completeness test).
_FIXED_CODE_OWNED_PATHS: frozenset[str] = frozenset(
    {
        CONTROLLER_BASE_COMPOSE_PATH,
        WORKER_BASE_COMPOSE_PATH,
        CONTROLLER_ENV_FILE_PATH,
        PRODUCTION_LAYOUT.worker_runtime_overlay_import_path,
    }
)
_COMMON_RESULT_ROLES = (
    "activation_evidence",
    "activation_evidence_attestation",
)
_CONTROLLER_MUTABLE_ROLES = (
    ROLE_PROXY_CONTRACT,
    ROLE_CONTROLLER_OVERRIDE,
    ROLE_ADMISSION_CA,
    ROLE_ADMISSION_SERVER_CERTIFICATE,
    ROLE_ADMISSION_SERVER_KEY,
    ROLE_ADMISSION_PROXY_GATE,
    "controller_offer",
    "controller_offer_attestation",
    *_COMMON_RESULT_ROLES,
)
_WORKER_MUTABLE_ROLES = (
    ROLE_WORKER_OVERRIDE,
    ROLE_WORKER_RUNTIME_OVERLAY,
    ROLE_ADMISSION_CA,
    "worker_result",
    "worker_result_attestation",
    *_COMMON_RESULT_ROLES,
)
_CONTROLLER_ROLES = (
    ROLE_PROXY_CONTRACT,
    ROLE_CONTROLLER_OVERRIDE,
    ROLE_ADMISSION_CA,
    ROLE_ADMISSION_SERVER_CERTIFICATE,
    ROLE_ADMISSION_SERVER_KEY,
    ROLE_ADMISSION_PROXY_GATE,
)


def _base_compose_path(host_role: LocalHostRole) -> str:
    if host_role is LocalHostRole.controller:
        return CONTROLLER_BASE_COMPOSE_PATH
    if host_role is LocalHostRole.worker:
        return WORKER_BASE_COMPOSE_PATH
    _closed("local_host_role_invalid")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _security_hardened(runtime: _RuntimeProjection, *, expected_user: str | None) -> bool:
    no_new_privileges = runtime.security_options in {
        ("no-new-privileges",),
        ("no-new-privileges:true",),
    }
    return bool(
        (expected_user is None or runtime.user == expected_user)
        and runtime.read_only
        and not runtime.privileged
        and runtime.cap_add == ()
        and runtime.cap_drop == ("ALL",)
        and no_new_privileges
    )


def _has_mount(
    runtime: _RuntimeProjection,
    *,
    source: str,
    destination: str,
    read_write: bool,
) -> bool:
    return (
        "bind",
        source,
        destination,
        read_write,
        "rprivate",
    ) in runtime.mounts


def _closed(reason: str) -> NoReturn:
    raise ActivationAdapterError(reason)


def _lexical_path_overlap(left: str, right: str) -> bool:
    left = left.rstrip("/") or "/"
    right = right.rstrip("/") or "/"
    return bool(
        left == right
        or left == "/"
        or right == "/"
        or left.startswith(right + "/")
        or right.startswith(left + "/")
    )


_FilesystemObjectIdentity = tuple[int, int, int]


@dataclass(frozen=True, repr=False)
class _ResolvedPathIdentity:
    identities: tuple[_FilesystemObjectIdentity, ...]
    complete: bool
    missing_suffix: tuple[str, ...]


@dataclass(frozen=True)
class MountSourceIdentityClassification:
    """Non-path identity binding and overlap result for one mounted host source."""

    source_binding: str
    protected_bindings: tuple[str, ...]
    overlaps: tuple[bool, ...]

    def __post_init__(self) -> None:
        if (
            _SHA256.fullmatch(self.source_binding) is None
            or not self.protected_bindings
            or len(self.protected_bindings) != len(self.overlaps)
            or any(_SHA256.fullmatch(value) is None for value in self.protected_bindings)
            or any(type(value) is not bool for value in self.overlaps)
        ):
            raise ValueError("mount source identity classification invalid")


class MountSourceIdentityResolver(Protocol):
    """Classify mounted sources against protected host objects without following links."""

    def classify(
        self,
        *,
        source_paths: tuple[str, ...],
        protected_paths: tuple[str, ...],
    ) -> tuple[MountSourceIdentityClassification, ...]: ...


_MountInventoryItem = tuple[str, str, str, str, bool, str]
_ClassifiedMountInventoryItem = tuple[_MountInventoryItem, MountSourceIdentityClassification | None]


class PosixMountSourceIdentityResolver:
    """Resolve mount sources by securely walking path components and comparing object identity."""

    @staticmethod
    def _flags() -> tuple[int, int]:
        path_flag = getattr(os, "O_PATH", 0)
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        close_on_exec = getattr(os, "O_CLOEXEC", 0)
        if (
            os.name != "posix"
            or not path_flag
            or not no_follow
            or os.open not in os.supports_dir_fd
        ):
            _closed("mount_source_identity_resolver_unavailable")
        return (
            path_flag | no_follow | close_on_exec,
            path_flag | no_follow | close_on_exec | getattr(os, "O_DIRECTORY", 0),
        )

    @classmethod
    def _resolve(
        cls,
        path: str,
        *,
        allow_missing_suffix: bool,
        reason: str,
    ) -> _ResolvedPathIdentity:
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or len(path) > 4096
            or "\x00" in path
        ):
            _closed(reason)
        if path == "/":
            parts: tuple[str, ...] = ()
        else:
            parts = tuple(path.removeprefix("/").split("/"))
            if any(not part or part in {".", ".."} or len(part) > 255 for part in parts):
                _closed(reason)

        flags, root_flags = cls._flags()
        current: int | None = None
        try:
            try:
                current = os.open("/", root_flags)
            except OSError:
                _closed(reason)
            root = os.fstat(current)
            if not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode):
                _closed(reason)
            identities: list[_FilesystemObjectIdentity] = [
                (root.st_dev, root.st_ino, stat.S_IFMT(root.st_mode))
            ]
            for index, component in enumerate(parts):
                child: int | None = None
                try:
                    child = os.open(component, flags, dir_fd=current)
                except FileNotFoundError:
                    if allow_missing_suffix:
                        return _ResolvedPathIdentity(
                            identities=tuple(identities),
                            complete=False,
                            missing_suffix=parts[index:],
                        )
                    _closed(reason)
                except OSError as exc:
                    if exc.errno == errno.ELOOP:
                        _closed("mount_source_identity_symlink_refused")
                    _closed(reason)
                try:
                    metadata = os.fstat(child)
                    if stat.S_ISLNK(metadata.st_mode):
                        _closed("mount_source_identity_symlink_refused")
                    if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
                        _closed(reason)
                    identities.append(
                        (metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode))
                    )
                    os.close(current)
                    current = child
                    child = None
                finally:
                    if child is not None:
                        os.close(child)
            return _ResolvedPathIdentity(
                identities=tuple(identities),
                complete=True,
                missing_suffix=(),
            )
        except ActivationAdapterError:
            raise
        except OSError:
            _closed(reason)
        finally:
            if current is not None:
                os.close(current)

    @staticmethod
    def _binding(value: _ResolvedPathIdentity) -> str:
        raw = json.dumps(
            {
                "schema": "secp.discovery-activation.mount-path-identity/v1",
                "complete": value.complete,
                "identities": value.identities,
                "missing_suffix": value.missing_suffix,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return _digest(raw)

    @staticmethod
    def _overlaps(
        source_path: str,
        source: _ResolvedPathIdentity,
        protected_path: str,
        protected: _ResolvedPathIdentity,
    ) -> bool:
        if _lexical_path_overlap(source_path, protected_path):
            return True
        source_endpoint = source.identities[-1]
        if source_endpoint in protected.identities:
            # The mounted source is the protected object or one of its existing ancestors. This is
            # valid even when the protected path has a not-yet-created suffix.
            return True
        if protected.complete and protected.identities[-1] in source.identities:
            # Symmetric ancestry is sound only for a complete protected path. For an incomplete
            # path, its final identity is merely the nearest existing parent and may also be in an
            # unrelated sibling's ancestry.
            return True
        return False

    def classify(
        self,
        *,
        source_paths: tuple[str, ...],
        protected_paths: tuple[str, ...],
    ) -> tuple[MountSourceIdentityClassification, ...]:
        if (
            not source_paths
            or not protected_paths
            or len(source_paths) > 256
            or len(protected_paths) > 32
            or len(set(source_paths)) != len(source_paths)
            or len(set(protected_paths)) != len(protected_paths)
        ):
            _closed("mount_source_identity_request_invalid")
        protected = tuple(
            self._resolve(
                path,
                allow_missing_suffix=True,
                reason="mount_protected_identity_unresolvable",
            )
            for path in protected_paths
        )
        protected_bindings = tuple(self._binding(value) for value in protected)
        classified: list[MountSourceIdentityClassification] = []
        for source_path in source_paths:
            source = self._resolve(
                source_path,
                allow_missing_suffix=False,
                reason="mount_source_identity_unresolvable",
            )
            classified.append(
                MountSourceIdentityClassification(
                    source_binding=self._binding(source),
                    protected_bindings=protected_bindings,
                    overlaps=tuple(
                        self._overlaps(source_path, source, protected_path, protected_value)
                        for protected_path, protected_value in zip(
                            protected_paths, protected, strict=True
                        )
                    ),
                )
            )
        return tuple(classified)


@dataclass(frozen=True, repr=False)
class _BoundFile:
    """Content+metadata binding kept private to the root-owned transaction boundary."""

    content: bytes
    digest: str
    uid: int
    gid: int
    mode: int

    def __repr__(self) -> str:
        return (
            f"_BoundFile(size={len(self.content)}, digest={self.digest!r}, "
            f"uid={self.uid}, gid={self.gid}, mode={oct(self.mode)!r})"
        )

    def safe(self) -> dict[str, object]:
        return {
            "digest": self.digest,
            "uid": self.uid,
            "gid": self.gid,
            "mode": self.mode,
        }

    def journal(self) -> dict[str, object]:
        return self.safe() | {"content_b64": base64.b64encode(self.content).decode("ascii")}

    def fixed_input(self) -> FixedInputBinding:
        return FixedInputBinding(
            content_digest=self.digest,
            owner_uid=self.uid,
            owner_gid=self.gid,
            mode=self.mode,
        )


@dataclass(frozen=True)
class ArtifactPosture:
    artifacts_prepared: bool
    worker_config_installed: bool
    configuration_artifact_digests: tuple[tuple[str, str], ...]
    base_compose_binding: FixedInputBinding | None = None
    recovery_required: bool = False


@dataclass(frozen=True)
class RollbackContext:
    transaction_id: str
    container_runtime: ExecutablePin
    compose_runtime: ExecutablePin
    before_worker_present: bool
    before_worker_image_digest: str | None
    before_worker_running: bool
    before_worker_healthy: bool
    controller_override_preexisting: bool
    worker_override_preexisting: bool
    controller_changed: bool
    controller_runtime_changed: bool
    worker_config_changed: bool
    worker_recreated: bool
    host_role: LocalHostRole | None = None
    profile: DeploymentProfile | None = None
    before_worker_observation: HostObservation | None = None
    before_controller_observation: ControllerObservation | None = None
    before_worker_generation_digest: str | None = None
    base_compose_binding: FixedInputBinding | None = None
    controller_env_binding: FixedInputBinding | None = None


class ActivationArtifactStore(Protocol):
    """Closed fixed-layout persistence seam; callers cannot select a path or role."""

    def posture(self, host_role: LocalHostRole) -> ArtifactPosture: ...

    def operator_service_present(self) -> bool: ...

    def stage(
        self,
        profile: DeploymentProfile,
        worker_override: RenderedArtifact,
        before: HostObservation,
        *,
        host_role: LocalHostRole,
        transaction_id: str,
        state_receipt: dict[str, object],
    ) -> MutationReceipt: ...

    def stage_controller(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        before: ControllerObservation,
        *,
        transaction_id: str,
    ) -> MutationReceipt: ...

    def install_controller(
        self, rendered: ActivationRender, tls_material: ValidatedTLSMaterial
    ) -> None: ...

    def install_worker(
        self,
        worker_override: RenderedArtifact,
        ca_certificate: ValidatedAdmissionCA,
        runtime_overlay: _BoundFile,
    ) -> None: ...

    def validated_runtime_overlay(self, expected_digest: str) -> _BoundFile: ...

    def assert_base_compose_unchanged(
        self, host_role: LocalHostRole, expected: FixedInputBinding
    ) -> None: ...

    def transaction_base_compose_binding(self) -> FixedInputBinding: ...

    def assert_controller_env_unchanged(self, expected: FixedInputBinding) -> None: ...

    def transaction_controller_env_binding(self) -> FixedInputBinding: ...

    def record_worker_tls_proof(
        self,
        *,
        ca_certificate_fingerprint: str,
        expected_server_certificate_fingerprint: str,
        expected_server_dns_identity: str,
    ) -> None: ...

    def worker_tls_proof(self) -> tuple[str, str, str] | None: ...

    def note_worker_recreation(self) -> None: ...

    def note_controller_runtime_change(self) -> None: ...

    def record_controller_runtime_after(
        self,
        api_runtime: ContainerRuntimeObservation,
        proxy_runtime: ContainerRuntimeObservation,
    ) -> None: ...

    def record_worker_runtime_after(self, runtime: ContainerRuntimeObservation) -> None: ...

    def transaction_profile(self) -> DeploymentProfile: ...

    def transaction_runtime_after(self) -> tuple[ContainerRuntimeObservation, ...] | None: ...

    def receipt(self) -> MutationReceipt: ...

    def tls_probe_material(self) -> tuple[bytes, str] | None: ...

    def commit_evidence(self, evidence: bytes, attestation: bytes) -> None: ...

    def commit_controller_offer(self, offer: bytes, attestation: bytes) -> None: ...

    def load_controller_offer(self) -> tuple[bytes, bytes] | None: ...

    def commit_worker_result(self, result: bytes, attestation: bytes) -> None: ...

    def load_worker_result(self) -> tuple[bytes, bytes] | None: ...

    def load_worker_controller_offer_inbox(self) -> tuple[bytes, bytes] | None: ...

    def load_controller_worker_result_inbox(self) -> tuple[bytes, bytes] | None: ...

    def object_classifications(self) -> tuple[tuple[str, str], ...]: ...

    def load_evidence(self) -> tuple[bytes, bytes] | None: ...

    def restore_artifacts(self, receipt: MutationReceipt) -> RollbackContext: ...

    def finish_rollback(self, *, proven: bool) -> None: ...


class TLSHandshakeProbe(Protocol):
    def verify(
        self,
        profile: DeploymentProfile,
        *,
        ca_certificate_pem: bytes,
        expected_server_fingerprint: str,
    ) -> bool: ...

    def verify_route(
        self,
        profile: DeploymentProfile,
        *,
        ca_certificate_pem: bytes,
        expected_server_fingerprint: str,
    ) -> bool: ...


class _DirectHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection with a reviewed connect address and independent DNS SNI identity."""

    def __init__(
        self,
        *,
        connect_host: str,
        server_hostname: str,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(server_hostname, port, timeout=timeout, context=context)
        self._connect_host = connect_host
        self._server_hostname = server_hostname
        self._direct_context = context

    def connect(self) -> None:
        raw = socket.create_connection((self._connect_host, self.port), timeout=self.timeout)
        try:
            self.sock = self._direct_context.wrap_socket(raw, server_hostname=self._server_hostname)
        except BaseException:
            raw.close()
            raise


class StrictTLSHandshakeProbe:
    """One bounded TLS handshake using only the explicitly installed CA.

    ``SSLContext(PROTOCOL_TLS_CLIENT)`` begins with no system roots.  No HTTP request is made, so
    redirects and ambient HTTP proxy variables are structurally irrelevant.  The verified peer
    certificate is additionally pinned to the installed server certificate fingerprint.
    """

    def verify(
        self,
        profile: DeploymentProfile,
        *,
        ca_certificate_pem: bytes,
        expected_server_fingerprint: str,
    ) -> bool:
        try:
            _endpoint, dns_identity, endpoint_port = parse_https_endpoint(
                profile.admission_endpoint
            )
            listener_host, listener_port = parse_private_listener(profile.admission_listener_bind)
            if endpoint_port != listener_port:
                return False
            if not _SHA256.fullmatch(expected_server_fingerprint):
                return False
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_verify_locations(cadata=ca_certificate_pem.decode("ascii"))
            with socket.create_connection(
                (listener_host, listener_port), timeout=_TLS_TIMEOUT_SECONDS
            ) as raw:
                raw.settimeout(_TLS_TIMEOUT_SECONDS)
                with context.wrap_socket(raw, server_hostname=dns_identity) as secured:
                    peer = secured.getpeercert(binary_form=True)
                    version = secured.version()
            return bool(
                peer
                and version in {"TLSv1.2", "TLSv1.3"}
                and _digest(peer) == expected_server_fingerprint
            )
        except Exception:
            return False

    def verify_route(
        self,
        profile: DeploymentProfile,
        *,
        ca_certificate_pem: bytes,
        expected_server_fingerprint: str,
    ) -> bool:
        """Make one non-mutating, schema-valid request through the dedicated route.

        The nil identifiers cannot name a production object, so a gated, enabled API returns the
        closed worker-admission refusal.  A TLS-only listener, missing route, disabled API route,
        broken proxy, or rejected origin-gate header cannot satisfy this proof.
        """

        connection: http.client.HTTPSConnection | None = None
        try:
            _endpoint, dns_identity, endpoint_port = parse_https_endpoint(
                profile.admission_endpoint
            )
            listener_host, listener_port = parse_private_listener(profile.admission_listener_bind)
            if endpoint_port != listener_port:
                return False
            if not _SHA256.fullmatch(expected_server_fingerprint):
                return False
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_verify_locations(cadata=ca_certificate_pem.decode("ascii"))
            connection = _DirectHTTPSConnection(
                connect_host=listener_host,
                server_hostname=dns_identity,
                port=listener_port,
                timeout=ADMISSION_REQUEST_TIMEOUT_SECONDS,
                context=context,
            )
            connection.connect()
            if connection.sock is None:
                return False
            peer = connection.sock.getpeercert(binary_form=True)
            if not peer or _digest(peer) != expected_server_fingerprint:
                return False
            body = json.dumps(
                {
                    "authorization_id": "00000000-0000-0000-0000-000000000000",
                    "authorization_version": 1,
                    "discovery_job_id": "00000000-0000-0000-0000-000000000000",
                    "endpoint_binding_hash": "sha256:" + "0" * 64,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            connection.request(
                "POST",
                ADMISSION_ROUTES[0],
                body=body,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                },
            )
            response = connection.getresponse()
            content_type = response.getheader("content-type", "").split(";", 1)[0].lower()
            payload = response.read(MAX_ADMISSION_RESPONSE_BYTES + 1)
            if (
                response.status != 403
                or content_type != "application/json"
                or len(payload) > MAX_ADMISSION_RESPONSE_BYTES
            ):
                return False
            decoded = json.loads(payload.decode("utf-8"))
            return bool(
                isinstance(decoded, dict)
                and isinstance(decoded.get("detail"), dict)
                and decoded["detail"].get("code") == "worker_admission_refused"
            )
        except Exception:
            return False
        finally:
            if connection is not None:
                connection.close()


class LocalHostRole(str, Enum):
    """The one physical host a local adapter instance is allowed to mutate."""

    controller = "controller"
    worker = "worker"


@dataclass(frozen=True)
class _ContainerSnapshot:
    present: bool
    container_id: str = ""
    image_digest: str = ""
    running: bool = False
    healthy: bool = False
    restart_count: int = 0
    started_at: str = ""

    def generation(self) -> WorkerGeneration | None:
        if not self.present:
            return None
        try:
            return WorkerGeneration(
                container_id=self.container_id,
                restart_count=self.restart_count,
                started_at=self.started_at,
            )
        except Exception:
            _closed("worker_generation_invalid")


@dataclass(frozen=True)
class _RuntimeProjection:
    snapshot: _ContainerSnapshot
    configuration_digest: str
    private_configuration_binding: str | None = field(repr=False, compare=False)
    mounts: tuple[tuple[str, str, str, bool, str], ...]
    mounts_digest: str
    networks: tuple[str, ...]
    networks_digest: str
    compose_project: str
    compose_service: str
    user: str
    read_only: bool
    privileged: bool
    cap_add: tuple[str, ...]
    cap_drop: tuple[str, ...]
    security_options: tuple[str, ...]
    extra_hosts: tuple[str, ...]

    def public(
        self,
        *,
        expected_image_digest: str,
        hardening_verified: bool,
        mounts_verified: bool,
        endpoint_binding_verified: bool = False,
    ) -> ContainerRuntimeObservation:
        return ContainerRuntimeObservation(
            present=self.snapshot.present,
            generation=self.snapshot.generation(),
            image_digest=self.snapshot.image_digest or None,
            configuration_digest=self.configuration_digest,
            private_configuration_binding=self.private_configuration_binding,
            mounts_digest=self.mounts_digest,
            networks_digest=self.networks_digest,
            compose_project=self.compose_project,
            compose_service=self.compose_service,
            expected_image=self.snapshot.image_digest == expected_image_digest,
            hardening_verified=hardening_verified,
            mounts_verified=mounts_verified,
            endpoint_binding_verified=endpoint_binding_verified,
        )


@dataclass(frozen=True)
class _MountObservation:
    coherent: bool
    state_read_write_only_worker: bool
    ca_read_only_worker: bool
    overlay_read_only_worker: bool
    discovery_absent_from_others: bool


@dataclass(frozen=True)
class _ActivationProbeResult:
    available: bool = False
    controlled: bool = False
    managed: bool = False
    runtime_overlay_loaded: bool = False
    runtime_overlay_sha256: str | None = None
    fixed_paths: bool = False
    queue_exact: bool = False
    health_ready: bool = False
    bundle_prep_loop_started: bool = False
    key_metadata_safe: bool = False
    public_node_matches_local_keys: bool = False
    seals_valid: bool = False
    operator_registration_absent: bool = False
    operator_queue_absent: bool = False
    public_node: WorkerPublicObservation | None = None
    bootstrap_status: str | None = None
    worker_identity_approved: bool = False
    live_read_authorization_approved: bool = False
    bundle_available: bool = False
    discovery_contacted: bool = False
    candidate_executable: bool | None = None


@dataclass(frozen=True)
class _WorkerTLSProbeResult:
    ok: bool
    ca_certificate_fingerprint: str
    server_certificate_fingerprint: str
    server_dns_identity: str


class LocalActivationAdapter:
    """Concrete fixed-topology adapter implementing the closed ``ActivationAdapter`` protocol."""

    def __init__(
        self,
        *,
        host_role: LocalHostRole,
        command_runner: CommandRunner | None = None,
        artifact_store: ActivationArtifactStore | None = None,
        state_backend: WorkerStateBackend | None = None,
        tls_probe: TLSHandshakeProbe | None = None,
        mount_source_identity_resolver: MountSourceIdentityResolver | None = None,
        runtime_configuration_binder: Callable[[bytes], str] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        publication_timeout_seconds: int = _PUBLICATION_TIMEOUT_SECONDS,
        publication_poll_seconds: float = _PUBLICATION_POLL_SECONDS,
    ) -> None:
        if type(host_role) is not LocalHostRole:
            _closed("local_host_role_invalid")
        if not (
            isinstance(publication_timeout_seconds, int)
            and 1 <= publication_timeout_seconds <= _PUBLICATION_TIMEOUT_SECONDS
            and isinstance(publication_poll_seconds, (int, float))
            and 0 < publication_poll_seconds <= 10
        ):
            _closed("publication_bounds_invalid")
        if runtime_configuration_binder is not None and not callable(runtime_configuration_binder):
            _closed("runtime_configuration_binder_invalid")
        if mount_source_identity_resolver is not None and not callable(
            getattr(mount_source_identity_resolver, "classify", None)
        ):
            _closed("mount_source_identity_resolver_invalid")
        self._runner = command_runner if command_runner is not None else RealCommandRunner()
        self._host_role = host_role
        self._store = (
            artifact_store
            if artifact_store is not None
            else PosixActivationArtifactStore(host_role)
        )
        self._state = (
            state_backend
            if state_backend is not None
            else RealWorkerStateFilesystem()
            if host_role is LocalHostRole.worker
            else None
        )
        self._tls_probe = tls_probe if tls_probe is not None else StrictTLSHandshakeProbe()
        self._mount_source_identity_resolver = (
            mount_source_identity_resolver
            if mount_source_identity_resolver is not None
            else PosixMountSourceIdentityResolver()
        )
        self._runtime_configuration_binder = runtime_configuration_binder
        self._monotonic = monotonic
        self._publication_timeout = publication_timeout_seconds
        self._publication_poll = float(publication_poll_seconds)
        # A process restart during a staged mutation intentionally loses this capability and
        # forces the durable journal down the explicit recovery/rollback path.
        self._staged_worker_generation: WorkerGeneration | None = None
        self._staged_controller_api_generation: WorkerGeneration | None = None

    @staticmethod
    def _container_pin(profile: DeploymentProfile) -> ExecutablePin:
        return ExecutablePin(
            profile.container_runtime_executable,
            profile.container_runtime_executable_digest,
        )

    @staticmethod
    def _compose_pin(profile: DeploymentProfile) -> ExecutablePin:
        return ExecutablePin(profile.compose_executable, profile.compose_executable_digest)

    def _command(
        self,
        pin: ExecutablePin,
        argv: tuple[str, ...],
        *,
        timeout: int = _COMMAND_TIMEOUT_SECONDS,
        output: int = _MAX_COMMAND_OUTPUT,
    ) -> CommandResult:
        try:
            return self._runner.run(
                pin,
                argv,
                timeout_seconds=timeout,
                max_output_bytes=output,
            )
        except Exception:
            _closed("host_command_failed")

    def _assert_transaction_base_compose(self) -> FixedInputBinding:
        expected = self._store.transaction_base_compose_binding()
        self._store.assert_base_compose_unchanged(self._host_role, expected)
        return expected

    def _assert_transaction_controller_env(self) -> FixedInputBinding:
        """Prove the fixed controller environment file still matches the staged binding and still
        covers every base-Compose variable, immediately before a controller Compose mutation."""
        expected = self._store.transaction_controller_env_binding()
        self._store.assert_controller_env_unchanged(expected)
        return expected

    def _container_snapshot(
        self, pin: ExecutablePin, identifier: str, *, reason: str
    ) -> _ContainerSnapshot:
        result = self._command(pin, ("inspect", "--format", _WORKER_FORMAT, identifier))
        if result.exit_code != 0:
            return _ContainerSnapshot(present=False)
        raw = result.stdout.removesuffix("\n")
        if "\n" in raw:
            _closed(reason)
        fields = raw.split("|")
        if len(fields) != 6:
            _closed(reason)
        container_id, image, running, health, restart, started = fields
        if (
            not _HEX64.fullmatch(container_id)
            or not _SHA256.fullmatch(image)
            or running not in {"true", "false"}
            or health not in {"healthy", "unhealthy", "starting", "none"}
            or not restart.isdecimal()
            or len(restart) > 9
            or not _TIMESTAMP.fullmatch(started)
        ):
            _closed(reason)
        return _ContainerSnapshot(
            present=True,
            container_id=container_id,
            image_digest=image,
            running=running == "true",
            healthy=health == "healthy",
            restart_count=int(restart),
            started_at=started,
        )

    def _worker_snapshot(self, pin: ExecutablePin) -> _ContainerSnapshot:
        return self._container_snapshot(
            pin, ORDINARY_WORKER_CONTAINER, reason="worker_inspect_malformed"
        )

    def _proxy_snapshot(self, pin: ExecutablePin) -> _ContainerSnapshot:
        return self._container_snapshot(
            pin, ADMISSION_PROXY_CONTAINER, reason="proxy_inspect_malformed"
        )

    def _proxy_running(self, pin: ExecutablePin) -> bool:
        return self._proxy_snapshot(pin).running

    def _runtime_projection(
        self,
        pin: ExecutablePin,
        identifier: str,
        snapshot: _ContainerSnapshot,
        *,
        reason: str,
    ) -> _RuntimeProjection | None:
        if not snapshot.present:
            return None
        result = self._command(
            pin,
            ("inspect", "--format", _RUNTIME_FORMAT, identifier),
            output=_MAX_COMMAND_OUTPUT,
        )
        if result.exit_code != 0:
            _closed(reason)
        lines = result.stdout.removesuffix("\n").splitlines()
        if len(lines) != 2:
            _closed(reason)
        try:
            values = [json.loads(line, object_pairs_hook=_reject_duplicates) for line in lines]
        except (TypeError, ValueError):
            _closed(reason)
        config, host_config = values
        if not isinstance(config, dict) or not isinstance(host_config, dict):
            _closed(reason)
        environment_raw = config.get("Env")
        working_directory = config.get("WorkingDir")
        user = config.get("User")
        labels = config.get("Labels")
        read_only = host_config.get("ReadonlyRootfs")
        privileged = host_config.get("Privileged")
        cap_add_raw = host_config.get("CapAdd")
        cap_drop_raw = host_config.get("CapDrop")
        security_raw = host_config.get("SecurityOpt")
        extra_hosts_raw = host_config.get("ExtraHosts")
        network_mode = host_config.get("NetworkMode")

        def string_tuple(raw: object, *, maximum: int = 64) -> tuple[str, ...]:
            if raw is None:
                return ()
            if not isinstance(raw, list) or len(raw) > maximum:
                raise ValueError
            parsed = tuple(raw)
            if any(
                not isinstance(item, str) or not item or len(item) > 512 or "\x00" in item
                for item in parsed
            ):
                raise ValueError
            return tuple(sorted(parsed))

        try:
            cap_add = string_tuple(cap_add_raw)
            cap_drop = string_tuple(cap_drop_raw)
            security_options = string_tuple(security_raw)
            extra_hosts = string_tuple(extra_hosts_raw)
            # Environment values can contain database passwords and other credentials. Validate
            # the complete entries for the private binding, but expose only unique variable names
            # in the public projection.
            environment = string_tuple(environment_raw, maximum=512)
            environment_names: list[str] = []
            for item in environment:
                name, separator, _value = item.partition("=")
                if not separator or _ENVIRONMENT_NAME.fullmatch(name) is None:
                    raise ValueError
                environment_names.append(name)
            if len(environment_names) != len(set(environment_names)):
                raise ValueError
            if (
                not isinstance(user, str)
                or len(user) > 128
                or "\x00" in user
                or not isinstance(working_directory, str)
                or len(working_directory) > 4096
                or "\x00" in working_directory
                or type(read_only) is not bool
                or type(privileged) is not bool
                or not isinstance(network_mode, str)
                or not network_mode
                or len(network_mode) > 128
                or not isinstance(labels, dict)
                or len(labels) > 512
                or any(
                    not isinstance(key, str)
                    or not isinstance(value, str)
                    or not key
                    or len(key) > 512
                    or len(value) > 4096
                    or "\x00" in key
                    or "\x00" in value
                    for key, value in labels.items()
                )
                or not isinstance(labels.get("com.docker.compose.project"), str)
                or not isinstance(labels.get("com.docker.compose.service"), str)
            ):
                raise ValueError
            compose_project = labels["com.docker.compose.project"]
            compose_service = labels["com.docker.compose.service"]
            if not _CONTAINER_NAME.fullmatch(compose_project) or not _CONTAINER_NAME.fullmatch(
                compose_service
            ):
                raise ValueError
            public_canonical = json.dumps(
                {
                    "schema": "secp.discovery-activation.public-runtime/v1",
                    "host_role": self._host_role.value,
                    "compose": {
                        "project": compose_project,
                        "service": compose_service,
                    },
                    "configuration_shape": {
                        "command_configured": config.get("Cmd") is not None,
                        "entrypoint_configured": config.get("Entrypoint") is not None,
                        "environment_names": sorted(environment_names),
                        "healthcheck_configured": config.get("Healthcheck") is not None,
                        "user_configured": bool(user),
                        "working_directory_configured": bool(working_directory),
                    },
                    "host_posture": {
                        "cap_add_empty": not cap_add,
                        "cap_drop_all": cap_drop == ("ALL",),
                        "extra_hosts_count": len(extra_hosts),
                        "network_mode_configured": bool(network_mode),
                        "no_new_privileges": security_options
                        in {("no-new-privileges",), ("no-new-privileges:true",)},
                        "privileged": privileged,
                        "read_only": read_only,
                    },
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
            private_canonical = json.dumps(
                {
                    "schema": "secp.discovery-activation.private-runtime-binding/v1",
                    "host_role": self._host_role.value,
                    "container_id": snapshot.container_id,
                    "Config": config,
                    "HostConfig": host_config,
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
        except (TypeError, ValueError):
            _closed(reason)

        private_binding: str | None = None
        if self._runtime_configuration_binder is not None:
            try:
                private_binding = self._runtime_configuration_binder(private_canonical)
            except Exception:
                _closed("runtime_configuration_binding_failed")
            if (
                not isinstance(private_binding, str)
                or _HMAC_SHA256.fullmatch(private_binding) is None
            ):
                _closed("runtime_configuration_binding_failed")

        mounts = self._container_mount_snapshot(pin, identifier, reason=reason)
        networks_result = self._command(
            pin,
            ("inspect", "--format", _NETWORKS_FORMAT, identifier),
            output=4096,
        )
        if networks_result.exit_code != 0:
            _closed(reason)
        networks = tuple(sorted(_parse_names(networks_result.stdout, reason)))
        if not networks:
            _closed(reason)
        return _RuntimeProjection(
            snapshot=snapshot,
            configuration_digest=_digest(public_canonical),
            private_configuration_binding=private_binding,
            mounts=mounts,
            mounts_digest=_digest(
                json.dumps(mounts, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            ),
            networks=networks,
            networks_digest=_digest(
                json.dumps(networks, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            ),
            compose_project=compose_project,
            compose_service=compose_service,
            user=user,
            read_only=read_only,
            privileged=privileged,
            cap_add=cap_add,
            cap_drop=cap_drop,
            security_options=security_options,
            extra_hosts=extra_hosts,
        )

    def _container_mount_snapshot(
        self, pin: ExecutablePin, identifier: str, *, reason: str
    ) -> tuple[tuple[str, str, str, bool, str], ...]:
        result = self._command(
            pin,
            ("inspect", "--format", _MOUNTS_FORMAT, identifier),
            output=8192,
        )
        if result.exit_code != 0:
            _closed(reason)
        parsed: list[tuple[str, str, str, bool, str]] = []
        for line in result.stdout.splitlines():
            fields = line.split("|")
            if len(fields) != 5 or fields[3] not in {"true", "false"}:
                _closed(reason)
            mount_type, source, destination, read_write, propagation = fields
            source_valid = source.startswith("/") or (mount_type == "tmpfs" and source == "")
            if (
                mount_type not in {"bind", "volume", "tmpfs"}
                or not source_valid
                or not destination.startswith("/")
                or any(segment in {".", ".."} for segment in source.split("/"))
                or any(segment in {".", ".."} for segment in destination.split("/"))
                or propagation
                not in {"", "private", "rprivate", "shared", "rshared", "slave", "rslave"}
            ):
                _closed(reason)
            parsed.append((mount_type, source, destination, read_write == "true", propagation))
        return tuple(sorted(parsed))

    def _proxy_listener_exact(self, pin: ExecutablePin, profile: DeploymentProfile) -> bool:
        """Prove the proxy publishes exactly the reviewed private host listener."""

        result = self._command(
            pin,
            (
                "port",
                ADMISSION_PROXY_CONTAINER,
                f"{ADMISSION_PROXY_CONTAINER_PORT}/tcp",
            ),
            output=1024,
        )
        if result.exit_code != 0:
            return False
        raw = result.stdout.removesuffix("\n")
        if not raw or "\n" in raw or "\r" in raw:
            _closed("proxy_listener_observation_malformed")
        try:
            host, port = parse_private_listener(raw)
            expected_host, expected_port = parse_private_listener(profile.admission_listener_bind)
        except ValueError:
            _closed("proxy_listener_observation_malformed")
        return (host, port) == (expected_host, expected_port)

    def _controller_api_running(self, profile: DeploymentProfile) -> bool:
        result = self._command(
            self._compose_pin(profile),
            (
                "--project-name",
                profile.controller_compose_project,
                "--file",
                CONTROLLER_BASE_COMPOSE_PATH,
                "ps",
                "--services",
                "--filter",
                "status=running",
                "api",
            ),
        )
        if result.exit_code != 0:
            _closed("controller_api_observation_failed")
        if result.stdout in {"api", "api\n"}:
            return True
        if result.stdout == "":
            return False
        _closed("controller_api_observation_malformed")

    def _controller_api_identifier(self, profile: DeploymentProfile) -> str | None:
        result = self._command(
            self._compose_pin(profile),
            (
                "--project-name",
                profile.controller_compose_project,
                "--file",
                CONTROLLER_BASE_COMPOSE_PATH,
                "ps",
                "--quiet",
                CONTROLLER_API_SERVICE,
            ),
            output=1024,
        )
        if result.exit_code != 0:
            _closed("controller_api_identity_observation_failed")
        values = result.stdout.splitlines()
        if not values:
            return None
        if len(values) != 1 or not _HEX64.fullmatch(values[0]):
            _closed("controller_api_identity_observation_malformed")
        return values[0]

    def _migration_head(self, pin: ExecutablePin, api_identifier: str | None) -> str | None:
        if api_identifier is None:
            return None
        result = self._command(
            pin,
            (
                "exec",
                "--workdir",
                _API_ALEMBIC_WORKDIR,
                api_identifier,
                *_API_MIGRATION_PROBE,
            ),
            output=1024,
        )
        if result.exit_code != 0:
            return None
        raw = result.stdout.strip()
        for recognized_head in (_API_BASELINE_MIGRATION_HEAD, *_API_ACCEPTED_MIGRATION_HEADS):
            if raw == recognized_head or raw == f"{recognized_head} (head)":
                return recognized_head
        if not raw or len(raw) > 128 or "\n" in raw or "\r" in raw:
            _closed("controller_migration_head_observation_malformed")
        return None

    def _container_names(self, pin: ExecutablePin) -> tuple[str, ...]:
        result = self._command(
            pin,
            (
                "ps",
                "--all",
                "--format",
                _NAMES_FORMAT,
            ),
        )
        if result.exit_code != 0:
            _closed("container_inventory_failed")
        return _parse_names(result.stdout, "container_inventory_malformed")

    def _container_name(self, pin: ExecutablePin, identifier: str) -> str:
        result = self._command(pin, ("inspect", "--format", _NAME_FORMAT, identifier))
        if result.exit_code != 0:
            _closed("container_name_observation_failed")
        name = result.stdout.strip().removeprefix("/")
        if not _CONTAINER_NAME.fullmatch(name):
            _closed("container_name_observation_malformed")
        return name

    def _controller_secret_mounts_isolated(self, pin: ExecutablePin, api_identifier: str) -> bool:
        """Prove no local container gains a parent/alias mount over controller secrets."""

        api_name = self._container_name(pin, api_identifier)
        protected_paths = (
            PRODUCTION_LAYOUT.proxy_contract_path,
            PRODUCTION_LAYOUT.ca_certificate_path,
            PRODUCTION_LAYOUT.server_certificate_path,
            PRODUCTION_LAYOUT.server_private_key_path,
            PRODUCTION_LAYOUT.admission_proxy_gate_path,
        )
        names_before = self._container_names(pin)
        first = self._mount_identity_snapshot(pin, names_before, protected_paths)
        names_after = self._container_names(pin)
        second = self._mount_identity_snapshot(pin, names_after, protected_paths)

        protected = {
            PRODUCTION_LAYOUT.proxy_contract_path: {
                (
                    ADMISSION_PROXY_CONTAINER,
                    "bind",
                    PRODUCTION_LAYOUT.proxy_contract_path,
                    PRODUCTION_LAYOUT.proxy_contract_container_path,
                    False,
                    "rprivate",
                )
            },
            PRODUCTION_LAYOUT.ca_certificate_path: {
                (
                    ADMISSION_PROXY_CONTAINER,
                    "bind",
                    PRODUCTION_LAYOUT.ca_certificate_path,
                    PRODUCTION_LAYOUT.proxy_ca_certificate_container_path,
                    False,
                    "rprivate",
                )
            },
            PRODUCTION_LAYOUT.server_certificate_path: {
                (
                    ADMISSION_PROXY_CONTAINER,
                    "bind",
                    PRODUCTION_LAYOUT.server_certificate_path,
                    PRODUCTION_LAYOUT.proxy_server_certificate_container_path,
                    False,
                    "rprivate",
                )
            },
            PRODUCTION_LAYOUT.server_private_key_path: {
                (
                    ADMISSION_PROXY_CONTAINER,
                    "bind",
                    PRODUCTION_LAYOUT.server_private_key_path,
                    PRODUCTION_LAYOUT.proxy_server_private_key_container_path,
                    False,
                    "rprivate",
                )
            },
            PRODUCTION_LAYOUT.admission_proxy_gate_path: {
                (
                    ADMISSION_PROXY_CONTAINER,
                    "bind",
                    PRODUCTION_LAYOUT.admission_proxy_gate_path,
                    PRODUCTION_LAYOUT.admission_proxy_gate_container_path,
                    False,
                    "rprivate",
                ),
                (
                    api_name,
                    "bind",
                    PRODUCTION_LAYOUT.admission_proxy_gate_path,
                    PRODUCTION_LAYOUT.admission_proxy_gate_container_path,
                    False,
                    "rprivate",
                ),
            },
        }
        allowed = set().union(*protected.values())
        protected_destinations = {item[3] for expected in protected.values() for item in expected}
        relevant = {
            item
            for item, identity in second
            if (identity is not None and any(identity.overlaps))
            or any(
                _lexical_path_overlap(item[3], destination)
                for destination in protected_destinations
            )
        }
        return bool(names_before == names_after and first == second and relevant <= allowed)

    def _mount_observation(self, pin: ExecutablePin) -> _MountObservation:
        """Scan every local mount, then retain only paths overlapping PR5F-owned topology."""

        protected_paths = (
            PRODUCTION_LAYOUT.worker_state_host_path,
            PRODUCTION_LAYOUT.ca_certificate_path,
            PRODUCTION_LAYOUT.worker_runtime_overlay_path,
        )
        names_before = self._container_names(pin)
        first = self._mount_identity_snapshot(pin, names_before, protected_paths)
        names_after = self._container_names(pin)
        second = self._mount_identity_snapshot(pin, names_after, protected_paths)
        state_expected = (
            ORDINARY_WORKER_CONTAINER,
            "bind",
            PRODUCTION_LAYOUT.worker_state_host_path,
            PRODUCTION_LAYOUT.worker_state_container_path,
            True,
            "rprivate",
        )
        ca_expected = (
            ORDINARY_WORKER_CONTAINER,
            "bind",
            PRODUCTION_LAYOUT.ca_certificate_path,
            PRODUCTION_LAYOUT.worker_ca_container_path,
            False,
            "rprivate",
        )
        proxy_ca_expected = (
            ADMISSION_PROXY_CONTAINER,
            "bind",
            PRODUCTION_LAYOUT.ca_certificate_path,
            PRODUCTION_LAYOUT.proxy_ca_certificate_container_path,
            False,
            "rprivate",
        )
        overlay_expected = (
            ORDINARY_WORKER_CONTAINER,
            "bind",
            PRODUCTION_LAYOUT.worker_runtime_overlay_path,
            PRODUCTION_LAYOUT.worker_runtime_overlay_container_path,
            False,
            "rprivate",
        )

        state = tuple(
            item
            for item, identity in second
            if (identity is not None and identity.overlaps[0])
            or _lexical_path_overlap(item[3], PRODUCTION_LAYOUT.worker_state_container_path)
        )
        ca = tuple(
            item
            for item, identity in second
            if (identity is not None and identity.overlaps[1])
            or _lexical_path_overlap(item[3], PRODUCTION_LAYOUT.worker_ca_container_path)
        )
        overlay = tuple(
            item
            for item, identity in second
            if (identity is not None and identity.overlaps[2])
            or _lexical_path_overlap(
                item[3], PRODUCTION_LAYOUT.worker_runtime_overlay_container_path
            )
        )
        relevant = {*state, *ca, *overlay}
        isolated = all(
            item in {state_expected, ca_expected, proxy_ca_expected, overlay_expected}
            for item in relevant
        )
        return _MountObservation(
            coherent=names_before == names_after and first == second,
            state_read_write_only_worker=state == (state_expected,),
            ca_read_only_worker=ca
            in {
                (ca_expected,),
                tuple(sorted((ca_expected, proxy_ca_expected))),
            },
            overlay_read_only_worker=overlay == (overlay_expected,),
            discovery_absent_from_others=isolated,
        )

    def _mount_snapshot(
        self, pin: ExecutablePin, names: tuple[str, ...]
    ) -> tuple[_MountInventoryItem, ...]:
        candidates: list[_MountInventoryItem] = []
        for name in names:
            mounts = self._container_mount_snapshot(
                pin, name, reason="container_mount_observation_malformed"
            )
            candidates.extend((name, *mount) for mount in mounts)
        return tuple(candidates)

    def _mount_identity_snapshot(
        self,
        pin: ExecutablePin,
        names: tuple[str, ...],
        protected_paths: tuple[str, ...],
    ) -> tuple[_ClassifiedMountInventoryItem, ...]:
        """Bind every mounted source and every protected host object to filesystem identity."""

        mounts = self._mount_snapshot(pin, names)
        sources = tuple(sorted({item[2] for item in mounts if item[2]}))
        if not sources:
            return tuple((item, None) for item in mounts)
        try:
            classified = self._mount_source_identity_resolver.classify(
                source_paths=sources,
                protected_paths=protected_paths,
            )
        except ActivationAdapterError:
            raise
        except Exception:
            _closed("mount_source_identity_observation_failed")
        if (
            type(classified) is not tuple
            or len(classified) != len(sources)
            or any(
                type(item) is not MountSourceIdentityClassification
                or len(item.overlaps) != len(protected_paths)
                or len(item.protected_bindings) != len(protected_paths)
                for item in classified
            )
        ):
            _closed("mount_source_identity_observation_malformed")
        by_source = dict(zip(sources, classified, strict=True))
        return tuple((item, by_source.get(item[2])) for item in mounts)

    def _operator_containers(self, pin: ExecutablePin) -> tuple[str, ...]:
        """Inventory every container and identify operator or duplicate-worker workloads.

        Container names alone are not an identity boundary: Compose's ``container_name`` can be
        changed while the process, queue, and service stay the same.  Inspect the effective process
        metadata for every local container and sample the complete inventory twice so a rename or
        replacement during the observation fails closed.  Environment values are parsed only in
        memory and are neither retained nor included in an error/repr.
        """

        def sample() -> tuple[tuple[str, str, bool], ...]:
            observed: list[tuple[str, str, bool]] = []
            for name in self._container_names(pin):
                result = self._command(
                    pin,
                    ("inspect", "--format", _WORKLOAD_IDENTITY_FORMAT, name),
                )
                if result.exit_code != 0:
                    _closed("operator_container_observation_failed")
                container_id, forbidden = _parse_workload_identity(
                    result.stdout,
                    name=name,
                    host_role=self._host_role,
                )
                observed.append((name, container_id, forbidden))
            return tuple(observed)

        first = sample()
        second = sample()
        if first != second:
            _closed("operator_container_observation_incoherent")
        return tuple(name for name, _container_id, forbidden in second if forbidden)

    def _activation_probe(
        self, pin: ExecutablePin, *, identifier: str, running: bool
    ) -> _ActivationProbeResult:
        if not running:
            return _ActivationProbeResult()
        result = self._command(
            pin,
            ("exec", identifier, *_ACTIVATION_PROBE),
            output=_MAX_PROBE_OUTPUT,
        )
        # A disabled configuration or an as-yet-unpublished node intentionally exits one.  Its
        # fixed JSON projection remains useful; all other exit codes are refused.
        if result.exit_code not in {0, 1}:
            _closed("activation_probe_failed")
        return _parse_activation_probe(result.stdout)

    def _worker_tls_handshake(
        self,
        pin: ExecutablePin,
        *,
        identifier: str,
        running: bool,
        expected_ca_fingerprint: str,
        expected_server_fingerprint: str,
        expected_server_dns_identity: str,
    ) -> bool:
        if not running:
            return False
        result = self._command(
            pin,
            ("exec", identifier, *_WORKER_TLS_PROBE),
            output=_MAX_PROBE_OUTPUT,
        )
        if result.exit_code not in {0, 1}:
            _closed("worker_tls_probe_failed")
        observed = _parse_worker_tls_probe(result.stdout)
        return bool(
            result.exit_code == 0
            and observed.ok
            and observed.ca_certificate_fingerprint == expected_ca_fingerprint
            and observed.server_certificate_fingerprint == expected_server_fingerprint
            and observed.server_dns_identity == expected_server_dns_identity
        )

    def _readiness(self, pin: ExecutablePin, *, identifier: str, running: bool) -> bool:
        if not running:
            return False
        result = self._command(
            pin,
            ("exec", identifier, *_HEALTH_PROBE),
            output=1024,
        )
        if result.stdout not in {"", "\n"}:
            _closed("worker_health_output_malformed")
        return result.exit_code == 0

    def observe(self, profile: DeploymentProfile) -> HostObservation:
        if type(profile) is not DeploymentProfile:
            _closed("profile_type_invalid")
        if self._host_role is not LocalHostRole.worker:
            _closed("split_host_worker_observation_required")
        pin = self._container_pin(profile)
        try:
            first = self._worker_snapshot(pin)
            runtime_first = self._runtime_projection(
                pin,
                ORDINARY_WORKER_CONTAINER,
                first,
                reason="worker_runtime_observation_malformed",
            )
            mounts = self._mount_observation(pin)
            operator_containers = self._operator_containers(pin)
            readiness = self._readiness(pin, identifier=first.container_id, running=first.running)
            probe = self._activation_probe(
                pin, identifier=first.container_id, running=first.running
            )
            artifacts = self._store.posture(LocalHostRole.worker)
            if artifacts.base_compose_binding is None:
                _closed("worker_base_compose_unbound")
            if artifacts.worker_config_installed and (
                profile.worker_runtime_overlay_digest is None
                or dict(artifacts.configuration_artifact_digests).get(ROLE_WORKER_RUNTIME_OVERLAY)
                != profile.worker_runtime_overlay_digest
            ):
                _closed("worker_runtime_overlay_drift")
            tls_proof = self._store.worker_tls_proof()
            tls_ready = False
            if tls_proof is not None:
                ca_fingerprint, expected_fingerprint, expected_identity = tls_proof
                if expected_identity == profile.admission_certificate_dns_name:
                    tls_ready = self._worker_tls_handshake(
                        pin,
                        identifier=first.container_id,
                        running=first.running,
                        expected_ca_fingerprint=ca_fingerprint,
                        expected_server_fingerprint=expected_fingerprint,
                        expected_server_dns_identity=expected_identity,
                    )
            if self._state is None:
                _closed("worker_state_backend_unavailable")
            state = self._state.inspect(
                uid=profile.ordinary_runtime_uid, gid=profile.ordinary_runtime_gid
            )
            operator_service = self._store.operator_service_present()
            second = self._worker_snapshot(pin)
            runtime_second = self._runtime_projection(
                pin,
                ORDINARY_WORKER_CONTAINER,
                second,
                reason="worker_runtime_observation_malformed",
            )
        except ActivationAdapterError:
            raise
        except Exception:
            _closed("host_observation_failed")

        coherent = bool(
            first == second
            and _same_runtime_projection(runtime_first, runtime_second)
            and mounts.coherent
        )
        generation = second.generation() if coherent else None
        operator_absent = not operator_containers and not operator_service
        queue_exact = probe.queue_exact and readiness
        listener_host, _listener_port = parse_private_listener(profile.admission_listener_bind)
        endpoint_binding_verified = bool(
            runtime_second
            and runtime_second.extra_hosts
            == (f"{profile.admission_certificate_dns_name}:{listener_host}",)
        )
        worker_mounts_verified = bool(
            runtime_second
            and mounts.discovery_absent_from_others
            and mounts.state_read_write_only_worker
            and mounts.ca_read_only_worker
            and mounts.overlay_read_only_worker
            and _has_mount(
                runtime_second,
                source=PRODUCTION_LAYOUT.worker_state_host_path,
                destination=PRODUCTION_LAYOUT.worker_state_container_path,
                read_write=True,
            )
            and _has_mount(
                runtime_second,
                source=PRODUCTION_LAYOUT.ca_certificate_path,
                destination=PRODUCTION_LAYOUT.worker_ca_container_path,
                read_write=False,
            )
            and _has_mount(
                runtime_second,
                source=PRODUCTION_LAYOUT.worker_runtime_overlay_path,
                destination=PRODUCTION_LAYOUT.worker_runtime_overlay_container_path,
                read_write=False,
            )
        )
        worker_hardening = bool(
            runtime_second
            and runtime_second.compose_service == ORDINARY_WORKER_SERVICE
            and _security_hardened(
                runtime_second,
                expected_user=f"{profile.ordinary_runtime_uid}:{profile.ordinary_runtime_gid}",
            )
        )
        worker_runtime = (
            runtime_second.public(
                expected_image_digest=profile.ordinary_worker_image_digest,
                hardening_verified=worker_hardening,
                mounts_verified=worker_mounts_verified,
                endpoint_binding_verified=endpoint_binding_verified,
            )
            if runtime_second is not None
            else None
        )
        runtime_overlay_active = bool(
            probe.runtime_overlay_loaded
            and probe.runtime_overlay_sha256 is not None
            and probe.runtime_overlay_sha256 == profile.worker_runtime_overlay_digest
        )
        activation_runtime_ready = bool(
            not artifacts.worker_config_installed
            or (
                worker_runtime is not None
                and worker_runtime.verified()
                and worker_runtime.endpoint_binding_verified
                and runtime_overlay_active
            )
        )
        return HostObservation(
            inspected=True,
            coherent=coherent,
            recovery_required=artifacts.recovery_required,
            worker_present=second.present,
            worker_generation=generation,
            worker_image_digest=second.image_digest or None,
            base_compose_binding=artifacts.base_compose_binding,
            worker_runtime=worker_runtime,
            worker_running=coherent and second.running and readiness and activation_runtime_ready,
            worker_healthy=coherent and second.healthy and readiness and activation_runtime_ready,
            ordinary_queues=(ORDINARY_TASK_QUEUE,) if queue_exact else (),
            controlled_integration_enabled=probe.controlled,
            worker_managed_bundle_enabled=probe.managed,
            fixed_worker_paths=probe.fixed_paths and runtime_overlay_active,
            state_mount_read_write_only_worker=mounts.state_read_write_only_worker,
            ca_mount_read_only_worker=mounts.ca_read_only_worker,
            discovery_mount_absent_from_other_containers=(mounts.discovery_absent_from_others),
            bundle_prep_loop_started=(
                probe.bundle_prep_loop_started
                and runtime_overlay_active
                and probe.key_metadata_safe
                and probe.public_node_matches_local_keys
            ),
            operator_service_present=operator_service,
            operator_container_present=bool(operator_containers),
            operator_registration_present=not (
                operator_absent and probe.operator_registration_absent
            ),
            operator_queue_polled=not (operator_absent and probe.operator_queue_absent),
            generic_activation_subprocess_sealed=probe.seals_valid,
            generic_executor_subprocess_sealed=probe.seals_valid,
            plan_only_process_sealed=not probe.seals_valid,
            real_provisioning_enabled=not probe.seals_valid,
            # The proof parameters are durable transaction-local facts authenticated by the
            # controller offer.  Observation still performs a fresh live pinned handshake.
            tls_ready=coherent and tls_ready,
            artifacts_prepared=artifacts.artifacts_prepared and state.prepared,
            worker_config_installed=artifacts.worker_config_installed,
            worker_recreation_required=bool(
                artifacts.worker_config_installed and not probe.controlled
            ),
            worker_generation_changed=bool(artifacts.worker_config_installed and probe.controlled),
            configuration_artifact_digests=artifacts.configuration_artifact_digests,
            keys_generated=state.keys_generated,
            key_metadata_safe=(
                state.prepared and probe.key_metadata_safe and probe.public_node_matches_local_keys
            ),
            worker_public=probe.public_node,
            publication_recorded=bool(probe.public_node and probe.public_node_matches_local_keys),
            database_private_material_absent=bool(
                probe.public_node
                and probe.public_node.public_material_only
                and probe.public_node_matches_local_keys
            ),
            bootstrap_status=probe.bootstrap_status,
            worker_identity_approved=probe.worker_identity_approved,
            live_read_authorization_approved=probe.live_read_authorization_approved,
            bundle_ready=probe.bundle_available,
            discovery_contacted=probe.discovery_contacted,
            candidate_executable=probe.candidate_executable,
        )

    def observe_controller(self, profile: DeploymentProfile) -> ControllerObservation:
        """Observe only controller-local state; never probes the worker or a remote daemon."""

        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        if type(profile) is not DeploymentProfile:
            _closed("profile_type_invalid")
        pin = self._container_pin(profile)
        try:
            artifacts = self._store.posture(LocalHostRole.controller)
            if artifacts.base_compose_binding is None:
                _closed("controller_base_compose_unbound")
            api_identifier_before = self._controller_api_identifier(profile)
            api_snapshot_before = (
                self._container_snapshot(
                    pin,
                    api_identifier_before,
                    reason="controller_api_inspect_malformed",
                )
                if api_identifier_before is not None
                else _ContainerSnapshot(present=False)
            )
            api_runtime_before = self._runtime_projection(
                pin,
                api_identifier_before or "",
                api_snapshot_before,
                reason="controller_api_runtime_observation_malformed",
            )
            proxy_snapshot_before = self._proxy_snapshot(pin)
            proxy_runtime_before = self._runtime_projection(
                pin,
                ADMISSION_PROXY_CONTAINER,
                proxy_snapshot_before,
                reason="proxy_runtime_observation_malformed",
            )
            listener_before = (
                self._proxy_listener_exact(pin, profile) if proxy_snapshot_before.running else False
            )
            operator_service = self._store.operator_service_present()
            operator_containers = self._operator_containers(pin)
            secret_mounts_isolated = bool(
                api_identifier_before is not None
                and self._controller_secret_mounts_isolated(pin, api_identifier_before)
            )

            expected_api_image = profile.controller_api_runtime_image_digest
            expected_proxy_image = profile.admission_proxy_runtime_image_digest
            reviewed_api_images = {
                image
                for image in (
                    expected_api_image,
                    profile.controller_api_baseline_image_digest,
                )
                if image is not None
            }
            proxy_project_matches = bool(
                proxy_runtime_before
                and api_runtime_before
                and proxy_runtime_before.compose_project == api_runtime_before.compose_project
                and proxy_runtime_before.compose_project == profile.controller_compose_project
            )
            proxy_mounts_verified = False
            proxy_hardening = False
            if proxy_runtime_before is not None:
                expected_proxy_binds = {
                    (
                        "bind",
                        PRODUCTION_LAYOUT.proxy_contract_path,
                        PRODUCTION_LAYOUT.proxy_contract_container_path,
                        False,
                        "rprivate",
                    ),
                    (
                        "bind",
                        PRODUCTION_LAYOUT.ca_certificate_path,
                        PRODUCTION_LAYOUT.proxy_ca_certificate_container_path,
                        False,
                        "rprivate",
                    ),
                    (
                        "bind",
                        PRODUCTION_LAYOUT.server_certificate_path,
                        PRODUCTION_LAYOUT.proxy_server_certificate_container_path,
                        False,
                        "rprivate",
                    ),
                    (
                        "bind",
                        PRODUCTION_LAYOUT.server_private_key_path,
                        PRODUCTION_LAYOUT.proxy_server_private_key_container_path,
                        False,
                        "rprivate",
                    ),
                    (
                        "bind",
                        PRODUCTION_LAYOUT.admission_proxy_gate_path,
                        PRODUCTION_LAYOUT.admission_proxy_gate_container_path,
                        False,
                        "rprivate",
                    ),
                }
                expected_proxy_mounts = tuple(
                    sorted(
                        {
                            *expected_proxy_binds,
                            ("tmpfs", "", "/tmp", True, ""),
                        }
                    )
                )
                proxy_mounts_verified = proxy_runtime_before.mounts == expected_proxy_mounts
                proxy_hardening = bool(
                    proxy_runtime_before.compose_service == ADMISSION_PROXY_SERVICE
                    and proxy_project_matches
                    and _security_hardened(
                        proxy_runtime_before,
                        expected_user=(
                            f"{profile.admission_proxy_runtime_uid}:"
                            f"{profile.admission_proxy_runtime_gid}"
                        ),
                    )
                )
            api_mounts_verified = bool(
                api_runtime_before
                and _has_mount(
                    api_runtime_before,
                    source=PRODUCTION_LAYOUT.admission_proxy_gate_path,
                    destination=PRODUCTION_LAYOUT.admission_proxy_gate_container_path,
                    read_write=False,
                )
            )
            api_hardening = bool(
                api_runtime_before
                and api_runtime_before.compose_service == CONTROLLER_API_SERVICE
                and api_runtime_before.compose_project == profile.controller_compose_project
                and _security_hardened(api_runtime_before, expected_user=None)
            )
            proxy_public = (
                proxy_runtime_before.public(
                    expected_image_digest=expected_proxy_image or "",
                    hardening_verified=proxy_hardening,
                    mounts_verified=proxy_mounts_verified,
                )
                if proxy_runtime_before is not None
                else None
            )
            api_public = (
                api_runtime_before.public(
                    expected_image_digest=(
                        api_runtime_before.snapshot.image_digest
                        if api_runtime_before.snapshot.image_digest in reviewed_api_images
                        else expected_api_image or ""
                    ),
                    hardening_verified=api_hardening,
                    mounts_verified=api_mounts_verified,
                )
                if api_runtime_before is not None
                else None
            )
            tls_ready = False
            route_ready = False
            migration_head = self._migration_head(pin, api_identifier_before)
            migration_ready = migration_head in _API_ACCEPTED_MIGRATION_HEADS
            controller_runtime_ready = bool(
                proxy_public is not None
                and proxy_public.verified()
                and api_public is not None
                and api_public.verified()
                and migration_ready
                and artifacts.artifacts_prepared
                and secret_mounts_isolated
            )
            probe_material = self._store.tls_probe_material() if controller_runtime_ready else None
            if probe_material is not None and listener_before:
                ca_pem, fingerprint = probe_material
                tls_ready = self._tls_probe.verify(
                    profile,
                    ca_certificate_pem=ca_pem,
                    expected_server_fingerprint=fingerprint,
                )
                if tls_ready:
                    route_ready = self._tls_probe.verify_route(
                        profile,
                        ca_certificate_pem=ca_pem,
                        expected_server_fingerprint=fingerprint,
                    )
            api_identifier_after = self._controller_api_identifier(profile)
            api_snapshot_after = (
                self._container_snapshot(
                    pin,
                    api_identifier_after,
                    reason="controller_api_inspect_malformed",
                )
                if api_identifier_after is not None
                else _ContainerSnapshot(present=False)
            )
            api_runtime_after = self._runtime_projection(
                pin,
                api_identifier_after or "",
                api_snapshot_after,
                reason="controller_api_runtime_observation_malformed",
            )
            proxy_snapshot_after = self._proxy_snapshot(pin)
            proxy_runtime_after = self._runtime_projection(
                pin,
                ADMISSION_PROXY_CONTAINER,
                proxy_snapshot_after,
                reason="proxy_runtime_observation_malformed",
            )
            listener_after = (
                self._proxy_listener_exact(pin, profile) if proxy_snapshot_after.running else False
            )
        except ActivationAdapterError:
            raise
        except Exception:
            _closed("controller_observation_failed")
        if operator_service or operator_containers:
            _closed("operator_presence_detected")
        coherent = bool(
            api_identifier_before == api_identifier_after
            and _same_runtime_projection(api_runtime_before, api_runtime_after)
            and _same_runtime_projection(proxy_runtime_before, proxy_runtime_after)
            and listener_before == listener_after
            and secret_mounts_isolated
        )
        return ControllerObservation(
            inspected=True,
            coherent=coherent,
            recovery_required=artifacts.recovery_required,
            controller_config_installed=artifacts.artifacts_prepared,
            proxy_running=proxy_snapshot_after.running,
            proxy_healthy=bool(
                coherent and proxy_public and proxy_public.verified() and route_ready
            ),
            private_listener_only=proxy_snapshot_after.running and listener_after,
            activation_route_enabled=coherent and route_ready,
            tls_ready=coherent and tls_ready,
            base_compose_binding=artifacts.base_compose_binding,
            api_runtime=api_public,
            proxy_runtime=proxy_public,
            migration_head=migration_head,
            migration_head_ready=migration_ready,
            configuration_artifact_digests=artifacts.configuration_artifact_digests,
        )

    def observe_worker(self, profile: DeploymentProfile) -> WorkerObservation:
        observed = self.observe(profile)
        public = observed.worker_public
        return WorkerObservation(
            inspected=observed.inspected,
            coherent=observed.coherent,
            recovery_required=observed.recovery_required,
            artifacts_prepared=observed.artifacts_prepared,
            worker_config_installed=observed.worker_config_installed,
            worker_recreation_required=observed.worker_recreation_required,
            worker_generation_changed=observed.worker_generation_changed,
            worker_present=observed.worker_present,
            worker_generation=observed.worker_generation,
            worker_image_digest=observed.worker_image_digest,
            base_compose_binding=observed.base_compose_binding,
            worker_runtime=observed.worker_runtime,
            worker_running=observed.worker_running,
            worker_healthy=observed.worker_healthy,
            ordinary_queues=observed.ordinary_queues,
            controlled_integration_enabled=observed.controlled_integration_enabled,
            worker_managed_bundle_enabled=observed.worker_managed_bundle_enabled,
            fixed_worker_paths=observed.fixed_worker_paths,
            state_mount_read_write_only_worker=observed.state_mount_read_write_only_worker,
            ca_mount_read_only_worker=observed.ca_mount_read_only_worker,
            discovery_mount_absent_from_other_containers=(
                observed.discovery_mount_absent_from_other_containers
            ),
            bundle_prep_loop_started=observed.bundle_prep_loop_started,
            operator_service_present=observed.operator_service_present,
            operator_container_present=observed.operator_container_present,
            operator_registration_present=observed.operator_registration_present,
            operator_queue_polled=observed.operator_queue_polled,
            generic_activation_subprocess_sealed=(observed.generic_activation_subprocess_sealed),
            generic_executor_subprocess_sealed=observed.generic_executor_subprocess_sealed,
            plan_only_process_sealed=observed.plan_only_process_sealed,
            real_provisioning_enabled=observed.real_provisioning_enabled,
            tls_ready=observed.tls_ready,
            keys_generated=observed.keys_generated,
            key_metadata_safe=observed.key_metadata_safe,
            worker_public=(
                WorkerNodeObservation(
                    node_id=public.node_id,
                    revision=public.revision,
                    ssh_public_fingerprint=public.ssh_public_fingerprint,
                    admission_anchor_fingerprint=public.admission_anchor_fingerprint,
                    public_material_only=public.public_material_only,
                )
                if public is not None
                else None
            ),
            publication_recorded=observed.publication_recorded,
            database_private_material_absent=observed.database_private_material_absent,
            bootstrap_status=observed.bootstrap_status,
            worker_identity_approved=observed.worker_identity_approved,
            live_read_authorization_approved=observed.live_read_authorization_approved,
            bundle_ready=observed.bundle_ready,
            discovery_contacted=observed.discovery_contacted,
            candidate_executable=observed.candidate_executable,
            configuration_artifact_digests=observed.configuration_artifact_digests,
        )

    def stage_rollback(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        before: HostObservation,
        *,
        state_receipt: dict[str, object],
    ) -> MutationReceipt:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        if type(profile) is not DeploymentProfile or type(rendered) is not ActivationRender:
            _closed("activation_input_type_invalid")
        if type(before) is not HostObservation or not (
            before.inspected
            and before.coherent
            and before.worker_present
            and before.worker_generation is not None
        ):
            _closed("rollback_observation_incomplete")
        self._require_worker_recreation_baseline(profile, before)
        transaction_id = str(uuid.uuid4())
        receipt = self._store.stage(
            profile,
            _worker_override_from_render(rendered),
            before,
            host_role=LocalHostRole.worker,
            transaction_id=transaction_id,
            state_receipt=state_receipt,
        )
        self._staged_worker_generation = before.worker_generation
        return receipt

    @staticmethod
    def _require_worker_recreation_baseline(
        profile: DeploymentProfile, before: HostObservation | WorkerObservation
    ) -> None:
        if not (
            before.inspected
            and before.coherent
            and not before.recovery_required
            and before.worker_present
            and before.worker_generation is not None
            and before.worker_image_digest == profile.ordinary_worker_image_digest
            and before.worker_running
            and before.worker_healthy
            and before.ordinary_queues == (ORDINARY_TASK_QUEUE,)
            and before.base_compose_binding is not None
            and before.worker_runtime is not None
            and before.worker_runtime.present
            and before.worker_runtime.expected_image
            and before.worker_runtime.hardening_verified
            and before.worker_runtime.compose_service == ORDINARY_WORKER_SERVICE
            and before.worker_runtime.compose_project == profile.worker_compose_project
            and before.operator_absent()
            and before.safety_seals_valid()
        ):
            _closed("worker_recreation_precondition_invalid")

    def stage_controller_rollback(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        before: ControllerObservation,
    ) -> ControllerReceipt:
        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        if type(profile) is not DeploymentProfile or type(rendered) is not ActivationRender:
            _closed("activation_input_type_invalid")
        if type(before) is not ControllerObservation or not (
            before.inspected
            and before.coherent
            and not before.recovery_required
            and before.base_compose_binding is not None
            and before.api_runtime is not None
            and before.api_runtime.present
            and before.api_runtime.expected_image
            and before.api_runtime.hardening_verified
            and before.api_runtime.compose_service == CONTROLLER_API_SERVICE
            and before.api_runtime.compose_project == profile.controller_compose_project
            and before.api_runtime.image_digest == profile.controller_api_baseline_image_digest
            and before.migration_head == _API_BASELINE_MIGRATION_HEAD
            and not before.migration_head_ready
            and not before.controller_config_installed
            and not before.proxy_running
            and before.proxy_runtime is None
        ):
            _closed("controller_rollback_observation_incomplete")
        self._store.stage_controller(
            profile,
            rendered,
            before,
            transaction_id=str(uuid.uuid4()),
        )
        self._staged_controller_api_generation = before.api_runtime.generation
        return self.controller_receipt()

    def stage_worker_rollback(
        self,
        profile: DeploymentProfile,
        worker_override: RenderedArtifact,
        before: WorkerObservation,
        *,
        state_receipt: PreparedStateReceipt,
    ) -> WorkerReceipt:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        if type(profile) is not DeploymentProfile or type(worker_override) is not RenderedArtifact:
            _closed("activation_input_type_invalid")
        if type(before) is not WorkerObservation:
            _closed("rollback_observation_incomplete")
        self._require_worker_recreation_baseline(profile, before)
        if type(state_receipt) is not PreparedStateReceipt:
            _closed("worker_state_receipt_invalid")
        legacy = HostObservation(
            inspected=before.inspected,
            coherent=before.coherent,
            worker_present=before.worker_present,
            worker_generation=before.worker_generation,
            worker_image_digest=before.worker_image_digest,
            base_compose_binding=before.base_compose_binding,
            worker_runtime=before.worker_runtime,
            worker_running=before.worker_running,
            worker_healthy=before.worker_healthy,
            ordinary_queues=before.ordinary_queues,
            controlled_integration_enabled=before.controlled_integration_enabled,
            worker_managed_bundle_enabled=before.worker_managed_bundle_enabled,
            fixed_worker_paths=before.fixed_worker_paths,
            state_mount_read_write_only_worker=before.state_mount_read_write_only_worker,
            ca_mount_read_only_worker=before.ca_mount_read_only_worker,
            discovery_mount_absent_from_other_containers=(
                before.discovery_mount_absent_from_other_containers
            ),
            operator_service_present=before.operator_service_present,
            operator_container_present=before.operator_container_present,
            operator_registration_present=before.operator_registration_present,
            operator_queue_polled=before.operator_queue_polled,
            generic_activation_subprocess_sealed=(before.generic_activation_subprocess_sealed),
            generic_executor_subprocess_sealed=before.generic_executor_subprocess_sealed,
            plan_only_process_sealed=before.plan_only_process_sealed,
            real_provisioning_enabled=before.real_provisioning_enabled,
            artifacts_prepared=before.artifacts_prepared,
            worker_config_installed=before.worker_config_installed,
            worker_recreation_required=before.worker_recreation_required,
            worker_generation_changed=before.worker_generation_changed,
            configuration_artifact_digests=before.configuration_artifact_digests,
            recovery_required=before.recovery_required,
        )
        self._store.stage(
            profile,
            worker_override,
            legacy,
            host_role=LocalHostRole.worker,
            transaction_id=str(uuid.uuid4()),
            state_receipt=state_receipt.canonical(),
        )
        self._staged_worker_generation = before.worker_generation
        return self.worker_receipt()

    def install_controller(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        tls_material: ValidatedTLSMaterial,
    ) -> None:
        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        self._assert_transaction_base_compose()
        self._assert_transaction_controller_env()
        self._store.install_controller(rendered, tls_material)
        self._assert_transaction_base_compose()
        # Prove the fixed base Compose file AND its fixed environment file are byte-identical to the
        # staged bindings (and still fully cover interpolation) immediately before the mutation.
        self._assert_transaction_controller_env()
        # Mark before Compose: a timeout or runner failure has unknown runtime effects and must
        # require the database compatibility gate before any attempted image rollback.
        self._store.note_controller_runtime_change()
        result = self._command(
            self._compose_pin(profile),
            _controller_compose_args(
                with_override=True, project_name=profile.controller_compose_project
            ),
            timeout=_COMPOSE_TIMEOUT_SECONDS,
        )
        if result.exit_code != 0:
            _closed("controller_compose_failed")
        api_runtime_after, proxy_runtime_after = self._capture_controller_runtime_after(profile)
        self._store.record_controller_runtime_after(api_runtime_after, proxy_runtime_after)
        after = self.observe_controller(profile)
        api_runtime = after.api_runtime
        proxy_runtime = after.proxy_runtime
        if (
            not after.coherent
            or type(api_runtime) is not ContainerRuntimeObservation
            or type(proxy_runtime) is not ContainerRuntimeObservation
            or not api_runtime.verified()
            or not proxy_runtime.verified()
            or api_runtime.generation is None
            or proxy_runtime.generation is None
            or api_runtime.generation == self._staged_controller_api_generation
            or api_runtime.image_digest != profile.controller_api_runtime_image_digest
            or proxy_runtime.image_digest != profile.admission_proxy_runtime_image_digest
            or not _same_runtime_binding(api_runtime, api_runtime_after)
            or not _same_runtime_binding(proxy_runtime, proxy_runtime_after)
        ):
            _closed("controller_runtime_after_unverified")
        self._staged_controller_api_generation = None

    def _capture_controller_runtime_after(
        self, profile: DeploymentProfile
    ) -> tuple[ContainerRuntimeObservation, ContainerRuntimeObservation]:
        """Capture the Compose-created generations using Docker inspect only."""

        pin = self._container_pin(profile)

        def sample() -> tuple[
            str,
            _ContainerSnapshot,
            _RuntimeProjection | None,
            _ContainerSnapshot,
            _RuntimeProjection | None,
        ]:
            api_identifier = self._controller_api_identifier(profile)
            if api_identifier is None:
                _closed("controller_runtime_after_unverified")
            api_snapshot = self._container_snapshot(
                pin, api_identifier, reason="controller_api_inspect_malformed"
            )
            api_projection = self._runtime_projection(
                pin,
                api_snapshot.container_id,
                api_snapshot,
                reason="controller_api_runtime_observation_malformed",
            )
            proxy_snapshot = self._proxy_snapshot(pin)
            proxy_projection = self._runtime_projection(
                pin,
                proxy_snapshot.container_id,
                proxy_snapshot,
                reason="proxy_runtime_observation_malformed",
            )
            return (
                api_identifier,
                api_snapshot,
                api_projection,
                proxy_snapshot,
                proxy_projection,
            )

        first = sample()
        second = sample()
        if not _same_controller_runtime_sample(first, second):
            _closed("controller_runtime_after_unverified")
        api_identifier, api_snapshot, api_projection, proxy_snapshot, proxy_projection = second
        if (
            api_projection is None
            or proxy_projection is None
            or api_identifier != api_snapshot.container_id
            or api_snapshot.generation() == self._staged_controller_api_generation
            or api_snapshot.image_digest != profile.controller_api_runtime_image_digest
            or proxy_snapshot.image_digest != profile.admission_proxy_runtime_image_digest
            or api_projection.compose_service != CONTROLLER_API_SERVICE
            or proxy_projection.compose_service != ADMISSION_PROXY_SERVICE
            or api_projection.compose_project != profile.controller_compose_project
            or proxy_projection.compose_project != profile.controller_compose_project
        ):
            _closed("controller_runtime_after_unverified")
        return (
            api_projection.public(
                expected_image_digest=profile.controller_api_runtime_image_digest or "",
                hardening_verified=False,
                mounts_verified=False,
            ),
            proxy_projection.public(
                expected_image_digest=profile.admission_proxy_runtime_image_digest,
                hardening_verified=False,
                mounts_verified=False,
            ),
        )

    def verify_internal_tls(
        self, profile: DeploymentProfile, tls_material: ValidatedTLSMaterial
    ) -> bool:
        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        if not self._proxy_running(self._container_pin(profile)):
            return False
        material = self._store.tls_probe_material()
        if material is None:
            return False
        ca_pem, expected_server_fingerprint = material
        if (
            _digest(tls_material.ca_certificate_pem()) != _digest(ca_pem)
            or expected_server_fingerprint != tls_material.metadata.server_certificate_fingerprint
        ):
            return False
        return self._tls_probe.verify(
            profile,
            ca_certificate_pem=ca_pem,
            expected_server_fingerprint=expected_server_fingerprint,
        )

    def verify_controller_tls(
        self, profile: DeploymentProfile, tls_material: ValidatedTLSMaterial
    ) -> bool:
        return self.verify_internal_tls(profile, tls_material)

    def install_worker(
        self,
        profile: DeploymentProfile,
        worker_override: RenderedArtifact,
        ca_certificate: ValidatedAdmissionCA,
    ) -> None:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        if (
            type(profile) is not DeploymentProfile
            or type(worker_override) is not RenderedArtifact
            or type(ca_certificate) is not ValidatedAdmissionCA
        ):
            _closed("worker_install_input_invalid")
        if profile.worker_runtime_overlay_digest is None:
            _closed("worker_runtime_overlay_pin_missing")
        self._assert_transaction_base_compose()
        runtime_overlay = self._store.validated_runtime_overlay(
            profile.worker_runtime_overlay_digest
        )
        self._store.install_worker(worker_override, ca_certificate, runtime_overlay)

    def recreate_worker(self, profile: DeploymentProfile) -> None:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        expected_generation = self._staged_worker_generation
        if expected_generation is None:
            _closed("worker_recreation_not_staged")
        current = self.observe_worker(profile)
        self._require_worker_recreation_baseline(profile, current)
        if current.worker_generation != expected_generation:
            _closed("worker_generation_changed_before_recreation")
        # Mark the effect before invoking Compose: a timeout/runner failure has unknown effects and
        # must never be interpreted as no-op.
        self._assert_transaction_base_compose()
        self._store.note_worker_recreation()
        result = self._command(
            self._compose_pin(profile),
            _worker_compose_args(with_override=True, project_name=profile.worker_compose_project),
            timeout=_COMPOSE_TIMEOUT_SECONDS,
        )
        if result.exit_code != 0:
            _closed("worker_recreation_failed")
        runtime_after = self._capture_worker_runtime_after(profile)
        self._store.record_worker_runtime_after(runtime_after)
        after = self.observe_worker(profile)
        runtime = after.worker_runtime
        if (
            not after.coherent
            or not after.worker_running
            or not after.worker_healthy
            or type(runtime) is not ContainerRuntimeObservation
            or not runtime.verified()
            or not runtime.endpoint_binding_verified
            or runtime.generation is None
            or runtime.generation == expected_generation
            or runtime.image_digest != profile.ordinary_worker_image_digest
            or not _same_runtime_binding(runtime, runtime_after)
        ):
            _closed("worker_runtime_after_unverified")
        self._staged_worker_generation = None

    def _capture_worker_runtime_after(
        self, profile: DeploymentProfile
    ) -> ContainerRuntimeObservation:
        """Capture an owned new worker generation before running any in-container probe."""

        pin = self._container_pin(profile)

        def sample() -> tuple[_ContainerSnapshot, _RuntimeProjection | None]:
            snapshot = self._worker_snapshot(pin)
            projection = self._runtime_projection(
                pin,
                snapshot.container_id,
                snapshot,
                reason="worker_runtime_observation_malformed",
            )
            return snapshot, projection

        first = sample()
        second = sample()
        snapshot, projection = second
        if (
            not _same_worker_runtime_sample(first, second)
            or projection is None
            or snapshot.generation() == self._staged_worker_generation
            or snapshot.image_digest != profile.ordinary_worker_image_digest
            or projection.compose_service != ORDINARY_WORKER_SERVICE
            or projection.compose_project != profile.worker_compose_project
        ):
            _closed("worker_runtime_after_unverified")
        return projection.public(
            expected_image_digest=profile.ordinary_worker_image_digest,
            hardening_verified=False,
            mounts_verified=False,
            endpoint_binding_verified=False,
        )

    def recreate_ordinary_worker(self, profile: DeploymentProfile) -> None:
        self.recreate_worker(profile)

    def verify_live_admission_tls(
        self,
        profile: DeploymentProfile,
        ca_certificate: ValidatedAdmissionCA,
        *,
        expected_server_certificate_fingerprint: str,
        expected_server_dns_identity: str,
    ) -> bool:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        if (
            type(profile) is not DeploymentProfile
            or type(ca_certificate) is not ValidatedAdmissionCA
            or not _SHA256.fullmatch(expected_server_certificate_fingerprint)
            or expected_server_dns_identity != profile.admission_certificate_dns_name
        ):
            _closed("worker_tls_binding_invalid")
        # This gate runs before recreation, when the current worker deliberately lacks the new
        # CA mount and B8 settings.  Verify from the host with only the newly staged CA.  The
        # in-container admission probe remains mandatory in the post-recreation observation.
        verified = self._tls_probe.verify(
            profile,
            ca_certificate_pem=ca_certificate.ca_certificate_pem(),
            expected_server_fingerprint=expected_server_certificate_fingerprint,
        )
        if verified:
            self._store.record_worker_tls_proof(
                ca_certificate_fingerprint=ca_certificate.ca_certificate_fingerprint,
                expected_server_certificate_fingerprint=(expected_server_certificate_fingerprint),
                expected_server_dns_identity=expected_server_dns_identity,
            )
        return verified

    def await_worker_publication(
        self, profile: DeploymentProfile, *, previous_generation: WorkerGeneration
    ) -> WorkerObservation:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        if type(previous_generation) is not WorkerGeneration:
            _closed("previous_generation_invalid")
        deadline = self._monotonic() + self._publication_timeout
        latest = WorkerObservation()
        while self._monotonic() <= deadline:
            latest = self.observe_worker(profile)
            if (
                latest.coherent
                and latest.worker_generation is not None
                and latest.worker_generation != previous_generation
                and latest.worker_running
                and latest.worker_healthy
                and latest.tls_ready
                and latest.worker_public is not None
            ):
                return latest
            # Event.wait gives tests a non-blocking injectable clock route while avoiding a raw
            # long sleep in production.  The default interval is short and bounded.
            import threading

            threading.Event().wait(self._publication_poll)
        return latest

    def receipt(self) -> MutationReceipt:
        return self._store.receipt()

    def controller_receipt(self) -> ControllerReceipt:
        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        receipt = self._store.receipt()
        return ControllerReceipt(
            transaction_id=receipt.transaction_id,
            journal_present=receipt.journal_present,
            effects_started=receipt.effects_started,
            controller_changed=receipt.controller_changed,
            controller_runtime_changed=receipt.controller_runtime_changed,
            offer_emitted=self._store.load_controller_offer() is not None,
            evidence_committed=receipt.evidence_committed,
            operation_count=receipt.operation_count,
            object_classifications=self._store.object_classifications(),
        )

    def worker_receipt(self) -> WorkerReceipt:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        receipt = self._store.receipt()
        return WorkerReceipt(
            transaction_id=receipt.transaction_id,
            journal_present=receipt.journal_present,
            effects_started=receipt.effects_started,
            worker_config_changed=receipt.worker_config_changed,
            worker_recreated=receipt.worker_recreated,
            result_emitted=self._store.load_worker_result() is not None,
            operation_count=receipt.operation_count,
            object_classifications=self._store.object_classifications(),
        )

    def compensate(self, receipt: MutationReceipt) -> CompensationResult:
        try:
            current = self.receipt()
            if type(receipt) is not MutationReceipt or receipt != current:
                _closed("transaction_receipt_mismatch")
            if receipt.controller_runtime_changed or receipt.worker_recreated:
                profile, runtime_identifier = self._assert_transaction_runtime_current(receipt)
                if runtime_identifier is None:
                    _closed("transaction_runtime_after_missing")
                if (
                    receipt.controller_runtime_changed
                    and self._migration_head(self._container_pin(profile), runtime_identifier)
                    not in _API_ACCEPTED_MIGRATION_HEADS
                ):
                    _closed("controller_migration_after_drift")
                compatible = self._rollback_compatibility_probe(
                    profile, runtime_identifier=runtime_identifier
                )
                if not compatible:
                    _closed("api_rollback_incompatible_state")
                # Rebind immediately before the first journal/artifact mutation.  The database
                # probe is intentionally not accepted as proof that the named runtime remained
                # the transaction-owned generation while it executed.
                rebound_profile, rebound_identifier = self._assert_transaction_runtime_current(
                    receipt
                )
                if receipt.controller_runtime_changed and (
                    rebound_identifier is None
                    or self._migration_head(
                        self._container_pin(rebound_profile), rebound_identifier
                    )
                    not in _API_ACCEPTED_MIGRATION_HEADS
                ):
                    _closed("controller_migration_after_drift")
                if rebound_identifier is None:
                    _closed("transaction_runtime_after_missing")
                # The first split-engine gate has already engaged this durable database fence.
                # Repeat the fixed operation against the freshly rebound, transaction-owned
                # generation immediately before the first rollback mutation.  The operation is
                # idempotent and serializes against database writers.
                self._api_rollback_fence(
                    rebound_profile,
                    runtime_identifier=rebound_identifier,
                    action="engage",
                )
            context = self._store.restore_artifacts(receipt)
            runtime_ok = self._restore_runtime(context)
            self._store.finish_rollback(proven=runtime_ok)
            return CompensationResult(
                proven=runtime_ok,
                previous_worker_restored=runtime_ok,
                previous_artifacts_restored=True,
                residual_worker_state=True,
                reason_code=None if runtime_ok else "rollback_runtime_unproven",
            )
        except Exception:
            try:
                self._store.finish_rollback(proven=False)
            except Exception:
                pass
            return CompensationResult(
                proven=False,
                previous_worker_restored=False,
                previous_artifacts_restored=False,
                residual_worker_state=True,
                reason_code="rollback_recovery_required",
            )

    def _assert_transaction_runtime_current(
        self, receipt: MutationReceipt
    ) -> tuple[DeploymentProfile, str | None]:
        """Bind the live runtime to the journal using inspect-only Docker operations.

        No code in a container is executed here.  This check therefore precedes both the
        compatibility probe and every rollback mutation, and a missing after-image after an
        uncertain Compose result is a recovery-required refusal.
        """

        profile = self._store.transaction_profile()
        expected = self._store.transaction_runtime_after()
        if receipt.controller_runtime_changed:
            if (
                self._host_role is not LocalHostRole.controller
                or receipt.worker_recreated
                or expected is None
                or len(expected) != 2
            ):
                _closed("transaction_runtime_after_missing")
            expected_api, expected_proxy = expected
            if not (
                _runtime_binding_complete(expected_api)
                and _runtime_binding_complete(expected_proxy)
            ):
                _closed("transaction_runtime_after_invalid")
            expected_api_generation = expected_api.generation
            if expected_api_generation is None:
                _closed("transaction_runtime_after_invalid")
            pin = self._container_pin(profile)

            def sample() -> tuple[
                str,
                _ContainerSnapshot,
                _RuntimeProjection | None,
                _ContainerSnapshot,
                _RuntimeProjection | None,
            ]:
                api_identifier = self._controller_api_identifier(profile)
                if api_identifier is None:
                    _closed("transaction_runtime_after_drift")
                api_snapshot = self._container_snapshot(
                    pin, api_identifier, reason="controller_api_inspect_malformed"
                )
                api_projection = self._runtime_projection(
                    pin,
                    api_snapshot.container_id,
                    api_snapshot,
                    reason="controller_api_runtime_observation_malformed",
                )
                proxy_snapshot = self._proxy_snapshot(pin)
                proxy_projection = self._runtime_projection(
                    pin,
                    proxy_snapshot.container_id,
                    proxy_snapshot,
                    reason="proxy_runtime_observation_malformed",
                )
                return (
                    api_identifier,
                    api_snapshot,
                    api_projection,
                    proxy_snapshot,
                    proxy_projection,
                )

            first = sample()
            second = sample()
            if not _same_controller_runtime_sample(first, second):
                _closed("transaction_runtime_after_drift")
            api_identifier, api_snapshot, api_projection, proxy_snapshot, proxy_projection = second
            if (
                api_identifier != expected_api_generation.container_id
                or not _projection_matches_runtime(api_snapshot, api_projection, expected_api)
                or not _projection_matches_runtime(proxy_snapshot, proxy_projection, expected_proxy)
            ):
                _closed("transaction_runtime_after_drift")
            return profile, api_identifier

        if receipt.worker_recreated:
            if (
                self._host_role is not LocalHostRole.worker
                or expected is None
                or len(expected) != 1
            ):
                _closed("transaction_runtime_after_missing")
            expected_worker = expected[0]
            if not _runtime_binding_complete(expected_worker):
                _closed("transaction_runtime_after_invalid")
            expected_worker_generation = expected_worker.generation
            if expected_worker_generation is None:
                _closed("transaction_runtime_after_invalid")
            pin = self._container_pin(profile)

            def worker_sample() -> tuple[_ContainerSnapshot, _RuntimeProjection | None]:
                snapshot = self._worker_snapshot(pin)
                projection = self._runtime_projection(
                    pin,
                    snapshot.container_id,
                    snapshot,
                    reason="worker_runtime_observation_malformed",
                )
                return snapshot, projection

            first_worker = worker_sample()
            second_worker = worker_sample()
            if not _same_worker_runtime_sample(
                first_worker, second_worker
            ) or not _projection_matches_runtime(
                second_worker[0], second_worker[1], expected_worker
            ):
                _closed("transaction_runtime_after_drift")
            return profile, expected_worker_generation.container_id

        if expected is not None:
            _closed("transaction_runtime_after_without_effect")
        return profile, None

    def _rollback_compatibility_probe(
        self, profile: DeploymentProfile, *, runtime_identifier: str
    ) -> bool:
        result = self._command(
            self._container_pin(profile),
            ("exec", runtime_identifier, *_API_ROLLBACK_COMPATIBILITY_PROBE),
            output=256,
        )
        if result.exit_code != 0:
            _closed("api_rollback_compatibility_unverified")
        payload = result.stdout.strip()
        if payload == '{"observation_complete":true,"rollback_compatible":true}':
            return True
        if payload == '{"observation_complete":true,"rollback_compatible":false}':
            return False
        _closed("api_rollback_compatibility_unverified")

    def _api_rollback_fence(
        self,
        profile: DeploymentProfile,
        *,
        runtime_identifier: str,
        action: str,
    ) -> ApiRollbackFenceState:
        """Run one fixed fence action and accept only exact canonical closed output."""

        if action not in {"engage", "observe", "release"} or not _HEX64.fullmatch(
            runtime_identifier
        ):
            _closed("api_rollback_fence_unverified")
        result = self._command(
            self._container_pin(profile),
            ("exec", runtime_identifier, *_API_ROLLBACK_FENCE_COMMAND, action),
            output=256,
        )
        if action == "observe":
            if result.exit_code == 0:
                observed = _API_ROLLBACK_FENCE_OBSERVE_OUTPUT.get(result.stdout)
                if observed is not None:
                    return observed
            return "unverified"
        expected = _API_ROLLBACK_FENCE_OUTPUT[action]
        if result.exit_code != 0 or result.stdout != expected:
            _closed("api_rollback_fence_unverified")
        return "engaged" if action == "engage" else "released"

    def compensate_controller(self, receipt: ControllerReceipt) -> ControllerCompensation:
        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        if type(receipt) is not ControllerReceipt:
            _closed("transaction_receipt_invalid")
        current = self.receipt()
        if receipt.transaction_id != current.transaction_id:
            _closed("transaction_receipt_mismatch")
        outcome = self.compensate(current)
        return ControllerCompensation(
            proven=outcome.proven,
            previous_artifacts_restored=outcome.previous_artifacts_restored,
            residual_controller_state=not outcome.proven,
            reason_code=outcome.reason_code,
        )

    def compensate_worker(self, receipt: WorkerReceipt) -> WorkerCompensation:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        if type(receipt) is not WorkerReceipt:
            _closed("transaction_receipt_invalid")
        current = self.receipt()
        if receipt.transaction_id != current.transaction_id:
            _closed("transaction_receipt_mismatch")
        outcome = self.compensate(current)
        return WorkerCompensation(
            proven=outcome.proven,
            previous_worker_restored=outcome.previous_worker_restored,
            previous_artifacts_restored=outcome.previous_artifacts_restored,
            residual_worker_state=outcome.residual_worker_state,
            reason_code=outcome.reason_code,
        )

    def _restore_runtime(self, context: RollbackContext) -> bool:
        try:
            if context.worker_recreated:
                if context.base_compose_binding is None or context.profile is None:
                    return False
                self._store.assert_base_compose_unchanged(
                    LocalHostRole.worker, context.base_compose_binding
                )
                result = self._command(
                    context.compose_runtime,
                    # The admitted baseline proves the override was not active, even when an
                    # identical dormant file pre-existed.  Restore that runtime posture exactly.
                    _worker_compose_args(
                        with_override=False,
                        project_name=context.profile.worker_compose_project,
                    ),
                    timeout=_COMPOSE_TIMEOUT_SECONDS,
                )
                if result.exit_code != 0:
                    return False
            if context.controller_runtime_changed:
                if (
                    context.base_compose_binding is None
                    or context.profile is None
                    or context.controller_env_binding is None
                ):
                    return False
                controller_env_binding = context.controller_env_binding
                self._store.assert_base_compose_unchanged(
                    LocalHostRole.controller, context.base_compose_binding
                )
                runtimes = self._store.transaction_runtime_after()
                if runtimes is None or len(runtimes) != 2:
                    return False
                api_runtime, proxy_runtime = runtimes
                if api_runtime.generation is None or proxy_runtime.generation is None:
                    return False
                downgraded = self._command(
                    context.container_runtime,
                    (
                        "exec",
                        "--workdir",
                        _API_ALEMBIC_WORKDIR,
                        api_runtime.generation.container_id,
                        *_API_MIGRATION_DOWNGRADE,
                    ),
                    timeout=_COMPOSE_TIMEOUT_SECONDS,
                )
                if downgraded.exit_code != 0:
                    return False
                if (
                    self._migration_head(
                        context.container_runtime, api_runtime.generation.container_id
                    )
                    != _API_BASELINE_MIGRATION_HEAD
                ):
                    return False
                removed = self._command(
                    context.container_runtime,
                    ("rm", "--force", proxy_runtime.generation.container_id),
                )
                if removed.exit_code not in {0, 1}:
                    return False
                # Prove the fixed environment file is byte-identical to the staged binding and still
                # covers interpolation immediately before the rollback Compose runs it.
                self._store.assert_controller_env_unchanged(controller_env_binding)
                result = self._command(
                    context.compose_runtime,
                    # The controller baseline has no proxy and does not apply the dormant
                    # override, regardless of whether that file existed before activation.
                    _controller_compose_args(
                        with_override=False,
                        project_name=context.profile.controller_compose_project,
                    ),
                    timeout=_COMPOSE_TIMEOUT_SECONDS,
                )
                if result.exit_code != 0:
                    return False
            if self._host_role is LocalHostRole.controller:
                baseline = context.before_controller_observation
                if context.profile is None or baseline is None:
                    # Backward-compatible adapter seam for legacy test doubles; the production
                    # store always supplies a profile-bound full observation.  A pre-existing
                    # override is only a file classification; the admitted baseline runtime has
                    # no proxy and rollback must not activate that dormant file.
                    proxy_running = self._proxy_running(context.container_runtime)
                    return not proxy_running
                observed_controller = self.observe_controller(context.profile)
                return bool(
                    observed_controller.inspected
                    and observed_controller.coherent
                    and not observed_controller.recovery_required
                    and observed_controller.controller_config_installed
                    == baseline.controller_config_installed
                    and observed_controller.proxy_running == baseline.proxy_running
                    and observed_controller.proxy_healthy == baseline.proxy_healthy
                    and observed_controller.private_listener_only == baseline.private_listener_only
                    and observed_controller.activation_route_enabled
                    == baseline.activation_route_enabled
                    and observed_controller.tls_ready == baseline.tls_ready
                    and observed_controller.configuration_artifact_digests
                    == baseline.configuration_artifact_digests
                    and observed_controller.base_compose_binding == baseline.base_compose_binding
                    and _same_runtime_posture(observed_controller.api_runtime, baseline.api_runtime)
                    and _same_runtime_posture(
                        observed_controller.proxy_runtime, baseline.proxy_runtime
                    )
                    and observed_controller.migration_head == baseline.migration_head
                    and observed_controller.migration_head_ready == baseline.migration_head_ready
                )
            baseline_worker = context.before_worker_observation
            if context.profile is None or baseline_worker is None:
                worker_snapshot = self._worker_snapshot(context.container_runtime)
                healthy = self._readiness(
                    context.container_runtime,
                    identifier=worker_snapshot.container_id,
                    running=worker_snapshot.running,
                )
                return bool(
                    worker_snapshot.present == context.before_worker_present
                    and worker_snapshot.image_digest == context.before_worker_image_digest
                    and worker_snapshot.running == context.before_worker_running
                    and (worker_snapshot.healthy and healthy) == context.before_worker_healthy
                )
            observed_worker = self.observe(context.profile)
            generation = observed_worker.worker_generation
            if generation is None or context.before_worker_generation_digest is None:
                return False
            generation_matches = generation.digest() == context.before_worker_generation_digest
            if context.worker_recreated:
                generation_matches = not generation_matches
            return bool(
                observed_worker.inspected
                and observed_worker.coherent
                and not observed_worker.recovery_required
                and generation_matches
                and observed_worker.worker_present == baseline_worker.worker_present
                and observed_worker.worker_image_digest == baseline_worker.worker_image_digest
                and observed_worker.worker_running == baseline_worker.worker_running
                and observed_worker.worker_healthy == baseline_worker.worker_healthy
                and observed_worker.ordinary_queues == baseline_worker.ordinary_queues
                and observed_worker.controlled_integration_enabled
                == baseline_worker.controlled_integration_enabled
                and observed_worker.worker_managed_bundle_enabled
                == baseline_worker.worker_managed_bundle_enabled
                and observed_worker.fixed_worker_paths == baseline_worker.fixed_worker_paths
                and observed_worker.state_mount_read_write_only_worker
                == baseline_worker.state_mount_read_write_only_worker
                and observed_worker.ca_mount_read_only_worker
                == baseline_worker.ca_mount_read_only_worker
                and observed_worker.discovery_mount_absent_from_other_containers
                == baseline_worker.discovery_mount_absent_from_other_containers
                and observed_worker.bundle_prep_loop_started
                == baseline_worker.bundle_prep_loop_started
                and observed_worker.operator_service_present
                == baseline_worker.operator_service_present
                and observed_worker.operator_container_present
                == baseline_worker.operator_container_present
                and observed_worker.operator_registration_present
                == baseline_worker.operator_registration_present
                and observed_worker.operator_queue_polled == baseline_worker.operator_queue_polled
                and observed_worker.generic_activation_subprocess_sealed
                == baseline_worker.generic_activation_subprocess_sealed
                and observed_worker.generic_executor_subprocess_sealed
                == baseline_worker.generic_executor_subprocess_sealed
                and observed_worker.plan_only_process_sealed
                == baseline_worker.plan_only_process_sealed
                and observed_worker.real_provisioning_enabled
                == baseline_worker.real_provisioning_enabled
                and observed_worker.artifacts_prepared == baseline_worker.artifacts_prepared
                and observed_worker.worker_config_installed
                == baseline_worker.worker_config_installed
                and observed_worker.configuration_artifact_digests
                == baseline_worker.configuration_artifact_digests
                and observed_worker.base_compose_binding == baseline_worker.base_compose_binding
                and _same_runtime_posture(
                    observed_worker.worker_runtime, baseline_worker.worker_runtime
                )
            )
        except Exception:
            return False

    def commit_evidence(self, evidence: bytes, attestation: bytes) -> None:
        self._store.commit_evidence(evidence, attestation)

    def load_evidence(self) -> tuple[bytes, bytes] | None:
        return self._store.load_evidence()

    def commit_activation_evidence(self, evidence: bytes, attestation: bytes) -> None:
        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        self._store.commit_evidence(evidence, attestation)

    def load_activation_evidence(self) -> tuple[bytes, bytes] | None:
        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        return self._store.load_evidence()

    def observe_api_rollback_fence(self, profile: DeploymentProfile) -> ApiRollbackFenceObservation:
        """Observe the fence through one exact journal-bound API generation."""

        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        if type(profile) is not DeploymentProfile:
            _closed("profile_type_invalid")
        try:
            current = self.receipt()
            bound_profile, api_identifier = self._assert_transaction_runtime_current(current)
            if bound_profile != profile or api_identifier is None:
                _closed("api_rollback_fence_unverified")
            migration_head = self._migration_head(
                self._container_pin(bound_profile), api_identifier
            )
            if migration_head != _API_MIGRATION_HEAD:
                _closed("api_rollback_fence_unverified")
            state = self._api_rollback_fence(
                bound_profile,
                runtime_identifier=api_identifier,
                action="observe",
            )
            rebound_profile, rebound_identifier = self._assert_transaction_runtime_current(current)
            rebound_head = (
                None
                if rebound_identifier is None
                else self._migration_head(self._container_pin(rebound_profile), rebound_identifier)
            )
            if (
                rebound_profile != profile
                or rebound_identifier != api_identifier
                or rebound_head != migration_head
            ):
                _closed("api_rollback_fence_unverified")
        except Exception:
            _closed("api_rollback_fence_unverified")
        return ApiRollbackFenceObservation(
            observation_complete=state in {"engaged", "released"},
            state=state,
            api_container_id=api_identifier,
            migration_head=migration_head,
        )

    def controller_api_rollback_compatible(self, profile: DeploymentProfile) -> bool:
        """Prove compatibility and durably fence new incompatible writes before rollback."""

        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        if type(profile) is not DeploymentProfile:
            _closed("profile_type_invalid")
        current = self.receipt()
        bound_profile, api_identifier = self._assert_transaction_runtime_current(current)
        if bound_profile != profile or api_identifier is None:
            _closed("controller_api_rollback_compatibility_unverified")
        if (
            self._migration_head(self._container_pin(bound_profile), api_identifier)
            != _API_MIGRATION_HEAD
        ):
            _closed("controller_api_rollback_compatibility_unverified")
        compatible = self._rollback_compatibility_probe(
            bound_profile, runtime_identifier=api_identifier
        )
        if compatible:
            rebound_profile, rebound_identifier = self._assert_transaction_runtime_current(current)
            if (
                rebound_profile != profile
                or rebound_identifier != api_identifier
                or self._migration_head(self._container_pin(rebound_profile), rebound_identifier)
                != _API_MIGRATION_HEAD
            ):
                _closed("controller_api_rollback_compatibility_unverified")
            self._api_rollback_fence(
                rebound_profile,
                runtime_identifier=rebound_identifier,
                action="engage",
            )
        return compatible

    def worker_api_rollback_compatible(self, profile: DeploymentProfile) -> bool:
        """Prove compatibility and engage the fence through the owned worker overlay."""

        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        if type(profile) is not DeploymentProfile:
            _closed("profile_type_invalid")
        current = self.receipt()
        bound_profile, worker_identifier = self._assert_transaction_runtime_current(current)
        if bound_profile != profile or worker_identifier is None:
            _closed("worker_api_rollback_compatibility_unverified")
        compatible = self._rollback_compatibility_probe(
            bound_profile, runtime_identifier=worker_identifier
        )
        if compatible:
            rebound_profile, rebound_identifier = self._assert_transaction_runtime_current(current)
            if rebound_profile != profile or rebound_identifier != worker_identifier:
                _closed("worker_api_rollback_compatibility_unverified")
            self._api_rollback_fence(
                rebound_profile,
                runtime_identifier=rebound_identifier,
                action="engage",
            )
        return compatible

    def release_api_rollback_fence(self, profile: DeploymentProfile) -> None:
        """Release the split-activation fence through the exact current PR5F API generation."""

        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        if type(profile) is not DeploymentProfile:
            _closed("profile_type_invalid")
        current = self.receipt()
        if not current.evidence_committed or self._store.load_evidence() is None:
            _closed("activation_evidence_unavailable_for_fence_release")
        bound_profile, api_identifier = self._assert_transaction_runtime_current(current)
        if bound_profile != profile or api_identifier is None:
            _closed("api_rollback_fence_unverified")
        if (
            self._migration_head(self._container_pin(bound_profile), api_identifier)
            != _API_MIGRATION_HEAD
        ):
            _closed("api_rollback_fence_unverified")
        rebound_profile, rebound_identifier = self._assert_transaction_runtime_current(current)
        if (
            rebound_profile != profile
            or rebound_identifier != api_identifier
            or self._migration_head(self._container_pin(rebound_profile), rebound_identifier)
            != _API_MIGRATION_HEAD
        ):
            _closed("api_rollback_fence_unverified")
        self._api_rollback_fence(
            rebound_profile,
            runtime_identifier=rebound_identifier,
            action="release",
        )

    def emit_fixed_controller_offer(self, offer: bytes, attestation: bytes) -> None:
        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        self._store.commit_controller_offer(offer, attestation)

    def load_fixed_controller_offer(self) -> tuple[bytes, bytes] | None:
        return self.load_controller_offer()

    def load_fixed_worker_result_inbox(self) -> tuple[bytes, bytes] | None:
        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        return self._store.load_controller_worker_result_inbox()

    def load_fixed_controller_offer_inbox(self) -> tuple[bytes, bytes] | None:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        return self._store.load_worker_controller_offer_inbox()

    def load_fixed_worker_result(self) -> tuple[bytes, bytes] | None:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        return self._store.load_worker_result()

    def emit_fixed_worker_result(self, result: bytes, attestation: bytes) -> None:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        self._store.commit_worker_result(result, attestation)

    def emit_controller_offer(
        self, offer: ControllerOffer, attestation: HandoffAttestation
    ) -> tuple[bytes, bytes]:
        """Serialize an already constructed and signed controller offer for fixed-path storage."""
        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        receipt = self.receipt()
        if (
            not receipt.controller_changed
            or not receipt.controller_runtime_changed
            or receipt.worker_config_changed
            or receipt.worker_recreated
        ):
            _closed("controller_transaction_incomplete")
        if type(offer) is not ControllerOffer or type(attestation) is not HandoffAttestation:
            _closed("controller_offer_type_invalid")
        if offer.transaction_id != receipt.transaction_id:
            _closed("controller_offer_transaction_mismatch")
        return handoff_bytes(offer), handoff_attestation_bytes(attestation)

    def store_controller_offer(
        self, offer: ControllerOffer, attestation: HandoffAttestation
    ) -> None:
        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        offer_raw, attestation_raw = self.emit_controller_offer(offer, attestation)
        self._store.commit_controller_offer(offer_raw, attestation_raw)

    def load_controller_offer(self) -> tuple[bytes, bytes] | None:
        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        return self._store.load_controller_offer()

    def store_worker_result(self, result: WorkerResult, attestation: HandoffAttestation) -> None:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        if type(result) is not WorkerResult or type(attestation) is not HandoffAttestation:
            _closed("worker_result_type_invalid")
        receipt = self.receipt()
        if result.worker_transaction_id != receipt.transaction_id:
            _closed("worker_result_transaction_mismatch")
        self._store.commit_worker_result(
            handoff_bytes(result), handoff_attestation_bytes(attestation)
        )

    def load_worker_result(self) -> tuple[bytes, bytes] | None:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        return self._store.load_worker_result()

    def rollback_committed(
        self, evidence: ActivationEvidence, receipt: MutationReceipt
    ) -> CompensationResult:
        if type(evidence) is not ActivationEvidence:
            _closed("authenticated_evidence_required")
        return self.compensate(receipt)

    def rollback_controller_committed(
        self, evidence: ActivationEvidence, receipt: ControllerReceipt
    ) -> ControllerCompensation:
        if type(evidence) is not ActivationEvidence:
            _closed("authenticated_evidence_required")
        return self.compensate_controller(receipt)

    def rollback_worker_committed(self, receipt: WorkerReceipt) -> WorkerCompensation:
        return self.compensate_worker(receipt)


def _worker_compose_args(*, with_override: bool, project_name: str) -> tuple[str, ...]:
    if not _CONTAINER_NAME.fullmatch(project_name):
        _closed("compose_project_invalid")
    files: tuple[str, ...] = (
        "--project-name",
        project_name,
        "--file",
        WORKER_BASE_COMPOSE_PATH,
    )
    if with_override:
        files += ("--file", PRODUCTION_LAYOUT.worker_compose_override_path)
    return files + (
        "up",
        "--detach",
        "--no-deps",
        "--force-recreate",
        "--no-build",
        "--pull",
        "never",
        "worker",
    )


def _controller_compose_args(*, with_override: bool, project_name: str) -> tuple[str, ...]:
    if not _CONTAINER_NAME.fullmatch(project_name):
        _closed("compose_project_invalid")
    # Always supply the code-owned fixed controller environment file so ${SECP_*} interpolation is
    # deterministic regardless of the fixed child environment and the process working directory.
    # The worker compose args deliberately omit it: the worker uses its own service-level env_file.
    files: tuple[str, ...] = (
        "--env-file",
        CONTROLLER_ENV_FILE_PATH,
        "--project-name",
        project_name,
        "--file",
        CONTROLLER_BASE_COMPOSE_PATH,
    )
    services: tuple[str, ...] = ("api",)
    if with_override:
        files += ("--file", PRODUCTION_LAYOUT.controller_compose_override_path)
        services += ("discovery-admission-proxy",)
    return files + (
        "up",
        "--detach",
        "--no-deps",
        "--no-build",
        "--pull",
        "never",
        *services,
    )


def _parse_names(raw: str, reason: str) -> tuple[str, ...]:
    lines = raw.splitlines()
    if len(lines) != len(set(lines)) or any(not _CONTAINER_NAME.fullmatch(v) for v in lines):
        _closed(reason)
    return tuple(sorted(lines))


def _parse_workload_identity(
    raw: str,
    *,
    name: str,
    host_role: LocalHostRole,
) -> tuple[str, bool]:
    """Return the container ID and whether its effective metadata identifies a forbidden worker."""

    try:
        if not (1 <= len(raw.encode("utf-8")) <= _MAX_COMMAND_OUTPUT):
            raise ValueError
        lines = raw.removesuffix("\n").splitlines()
        if len(lines) != 4:
            raise ValueError
        (
            container_id,
            executable,
            arguments_raw,
            config,
        ) = [json.loads(line, object_pairs_hook=_reject_duplicates) for line in lines]
        if not isinstance(config, dict):
            raise ValueError
        image = config.get("Image")
        entrypoint_raw = config.get("Entrypoint")
        command_raw = config.get("Cmd")
        environment_raw = config.get("Env")
        labels_raw = config.get("Labels")

        def string_sequence(
            value: object,
            *,
            maximum_items: int,
            maximum_length: int,
        ) -> tuple[str, ...]:
            if value is None:
                return ()
            if not isinstance(value, list) or len(value) > maximum_items:
                raise ValueError
            parsed = tuple(value)
            if any(
                not isinstance(item, str) or len(item) > maximum_length or "\x00" in item
                for item in parsed
            ):
                raise ValueError
            return parsed

        arguments = string_sequence(
            arguments_raw,
            maximum_items=128,
            maximum_length=4096,
        )
        entrypoint = string_sequence(
            entrypoint_raw,
            maximum_items=64,
            maximum_length=4096,
        )
        command = string_sequence(
            command_raw,
            maximum_items=128,
            maximum_length=4096,
        )
        environment = string_sequence(
            environment_raw,
            maximum_items=512,
            maximum_length=4096,
        )
        labels = {} if labels_raw is None else labels_raw
        if (
            not _CONTAINER_NAME.fullmatch(name)
            or not isinstance(container_id, str)
            or not _HEX64.fullmatch(container_id)
            or not isinstance(executable, str)
            or not executable
            or len(executable) > 4096
            or "\x00" in executable
            or not isinstance(image, str)
            or not image
            or len(image) > 4096
            or "\x00" in image
            or not isinstance(labels, dict)
            or len(labels) > 512
            or any(
                not isinstance(key, str)
                or not isinstance(value, str)
                or not key
                or len(key) > 512
                or len(value) > 4096
                or "\x00" in key
                or "\x00" in value
                for key, value in labels.items()
            )
        ):
            raise ValueError

        def operator_marker(value: str) -> bool:
            folded = value.casefold()
            return bool(
                _OPERATOR_TOKEN.search(folded)
                or "controlled-live" in folded
                or "controlled_live" in folded
            )

        def worker_marker(value: str) -> bool:
            folded = value.casefold()
            return bool(
                _WORKER_TOKEN.search(folded) or "secp_worker" in folded or "secp-worker" in folded
            )

        compose_service = labels.get("com.docker.compose.service", "")
        role_labels = tuple(
            value
            for key, value in labels.items()
            if key.casefold().startswith("secp.")
            or key.casefold().endswith((".role", ".service", ".component", ".workload"))
        )
        process_identity = (
            name,
            image,
            executable,
            *arguments,
            *entrypoint,
            *command,
            compose_service,
            *role_labels,
        )
        operator_identified = bool(
            name in _OPERATOR_CONTAINER_NAMES
            or any(operator_marker(value) for value in process_identity)
        )
        queue_keys = {
            item.partition("=")[0]
            for item in environment
            if item.partition("=")[0] in _TEMPORAL_QUEUE_ENV_KEYS
        }
        unexpected_queue_configuration = bool(
            host_role is LocalHostRole.worker
            and (
                (name != ORDINARY_WORKER_CONTAINER and queue_keys)
                or _OPERATOR_QUEUE_ENV_KEY in queue_keys
            )
        )
        duplicate_worker = bool(
            name != ORDINARY_WORKER_CONTAINER
            and (
                compose_service.casefold() == ORDINARY_WORKER_SERVICE.casefold()
                or any(worker_marker(value) for value in process_identity)
            )
        )
        return container_id, bool(
            operator_identified or duplicate_worker or unexpected_queue_configuration
        )
    except Exception:
        _closed("operator_container_observation_malformed")


def _parse_activation_probe(raw: str) -> _ActivationProbeResult:
    try:
        if not (1 <= len(raw.encode("utf-8")) <= _MAX_PROBE_OUTPUT):
            raise ValueError
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
        if not isinstance(value, dict) or value.get("contract_version") != (
            "secp.worker.activation-probe/v1"
        ):
            raise ValueError
        expected = {
            "contract_version",
            "ok",
            "reason_code",
            "ordinary_task_queue",
            "configuration",
            "fixed_paths",
            "health",
            "safety_seals",
            "worker_keys",
            "worker_node",
            "lifecycle",
            "runtime_overlay_sha256",
            "probe_effects",
        }
        if set(value) != expected:
            raise ValueError
        config = value["configuration"]
        fixed_paths = value["fixed_paths"]
        health = value["health"]
        seals = value["safety_seals"]
        worker_keys = value["worker_keys"]
        effects = value["probe_effects"]
        lifecycle = value["lifecycle"]
        if not all(
            isinstance(item, dict)
            for item in (
                config,
                fixed_paths,
                health,
                seals,
                worker_keys,
                effects,
                lifecycle,
            )
        ):
            raise ValueError
        if set(config) != {
            "controlled_integration_enabled",
            "worker_managed_bundle",
            "fixed_paths_valid",
            "admission_configured",
            "runtime_overlay_loaded",
        }:
            raise ValueError
        if set(health) != {"ready", "ordinary_queue", "bundle_prep_loop_started"}:
            raise ValueError
        if set(worker_keys) != {"metadata_safe", "public_node_matches_local_keys"}:
            raise ValueError
        if fixed_paths != {
            "worker_state": "/var/run/secp",
            "worker_keys": "/var/run/secp/worker-keys",
            "discovery_bundle": "/var/run/secp/discovery-bundle",
            "worker_identity_key": "/var/run/secp/worker-keys/admission_key",
            "worker_identity_anchor": "/var/run/secp/worker-keys/admission_anchor",
            "admission_ca": "/etc/secp/admission-ca.pem",
            "runtime_overlay": "/opt/secp/secp-pr5f-runtime-overlay.zip",
            "health_marker": "/tmp/secp-worker.ready",
        }:
            raise ValueError
        expected_seals = {
            "generic_activation_subprocess_sealed": True,
            "generic_executor_subprocess_sealed": True,
            "plan_only_process_sealed": False,
            "real_provisioning_disabled": True,
        }
        expected_effects = {
            "operator_registered",
            "operator_queue_polled",
            "workflow_submitted",
            "run_plan_generation_called",
            "opentofu_executed",
            "proxmox_contacted",
        }
        if set(seals) != set(expected_seals) or set(effects) != expected_effects:
            raise ValueError
        if set(lifecycle) != {
            "bootstrap_status",
            "worker_identity_approved",
            "worker_identity_current",
            "live_read_authorization_approved",
            "live_read_authorization_current",
            "bundle_available",
            "discovery_contacted",
            "candidate_executable",
        }:
            raise ValueError
        bootstrap_status = lifecycle["bootstrap_status"]
        candidate_executable = lifecycle["candidate_executable"]
        if bootstrap_status is not None and bootstrap_status not in {
            "pending",
            "completed",
            "bound",
            "superseded",
            "refused",
        }:
            raise ValueError
        lifecycle_bool_keys = (
            "worker_identity_approved",
            "worker_identity_current",
            "live_read_authorization_approved",
            "live_read_authorization_current",
            "bundle_available",
            "discovery_contacted",
        )
        if any(type(lifecycle[key]) is not bool for key in lifecycle_bool_keys) or (
            candidate_executable is not None and type(candidate_executable) is not bool
        ):
            raise ValueError
        if (lifecycle["worker_identity_current"] and not lifecycle["worker_identity_approved"]) or (
            lifecycle["live_read_authorization_current"]
            and not lifecycle["live_read_authorization_approved"]
        ):
            raise ValueError
        if lifecycle["discovery_contacted"] and not lifecycle["bundle_available"]:
            raise ValueError
        if candidate_executable is not None and not lifecycle["discovery_contacted"]:
            raise ValueError
        bool_values = [
            value["ok"],
            *config.values(),
            *health.values(),
            *seals.values(),
            *worker_keys.values(),
            *effects.values(),
        ]
        if any(type(item) is not bool for item in bool_values):
            raise ValueError
        overlay_digest = value["runtime_overlay_sha256"]
        if overlay_digest is not None and (
            not isinstance(overlay_digest, str) or not _SHA256.fullmatch(overlay_digest)
        ):
            raise ValueError
        if config["runtime_overlay_loaded"] != (overlay_digest is not None):
            raise ValueError
        if any(effects.values()):
            raise ValueError
        public = _parse_public_node(value["worker_node"])
        return _ActivationProbeResult(
            available=True,
            controlled=config["controlled_integration_enabled"],
            managed=config["worker_managed_bundle"],
            runtime_overlay_loaded=config["runtime_overlay_loaded"],
            runtime_overlay_sha256=overlay_digest,
            fixed_paths=config["fixed_paths_valid"] and config["admission_configured"],
            queue_exact=(
                value["ordinary_task_queue"] == ORDINARY_TASK_QUEUE and health["ordinary_queue"]
            ),
            health_ready=health["ready"],
            bundle_prep_loop_started=health["bundle_prep_loop_started"],
            key_metadata_safe=worker_keys["metadata_safe"],
            public_node_matches_local_keys=worker_keys["public_node_matches_local_keys"],
            seals_valid=seals == expected_seals,
            operator_registration_absent=effects["operator_registered"] is False,
            operator_queue_absent=effects["operator_queue_polled"] is False,
            public_node=public,
            bootstrap_status=bootstrap_status,
            worker_identity_approved=(
                lifecycle["worker_identity_approved"] and lifecycle["worker_identity_current"]
            ),
            live_read_authorization_approved=(
                lifecycle["live_read_authorization_approved"]
                and lifecycle["live_read_authorization_current"]
            ),
            bundle_available=lifecycle["bundle_available"],
            discovery_contacted=lifecycle["discovery_contacted"],
            candidate_executable=candidate_executable,
        )
    except Exception:
        _closed("activation_probe_output_malformed")


def _parse_worker_tls_probe(raw: str) -> _WorkerTLSProbeResult:
    try:
        if not (1 <= len(raw.encode("utf-8")) <= _MAX_PROBE_OUTPUT):
            raise ValueError
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
        if not isinstance(value, dict) or set(value) != {
            "contract_version",
            "ok",
            "ca_certificate_fingerprint",
            "server_certificate_fingerprint",
            "server_dns_identity",
            "tls_version",
            "probe_effects",
        }:
            raise ValueError
        effects = value["probe_effects"]
        if (
            value["contract_version"] != "secp.worker.admission-tls-probe/v1"
            or type(value["ok"]) is not bool
            or not isinstance(value["ca_certificate_fingerprint"], str)
            or not _SHA256.fullmatch(value["ca_certificate_fingerprint"])
            or not isinstance(value["server_certificate_fingerprint"], str)
            or not _SHA256.fullmatch(value["server_certificate_fingerprint"])
            or not isinstance(value["server_dns_identity"], str)
            or value["tls_version"] not in {"TLSv1.2", "TLSv1.3"}
            or not isinstance(effects, dict)
            or effects
            != {
                "http_requested": False,
                "redirect_followed": False,
                "proxy_used": False,
            }
        ):
            raise ValueError
        validate_dns_identity(value["server_dns_identity"])
        return _WorkerTLSProbeResult(
            ok=value["ok"],
            ca_certificate_fingerprint=value["ca_certificate_fingerprint"],
            server_certificate_fingerprint=value["server_certificate_fingerprint"],
            server_dns_identity=value["server_dns_identity"],
        )
    except Exception:
        _closed("worker_tls_probe_output_malformed")


def _parse_public_node(raw: object) -> WorkerPublicObservation | None:
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) != {
        "id",
        "revision",
        "ssh_public_key_fingerprint",
        "admission_anchor_fingerprint",
        "public_material_only",
    }:
        raise ValueError
    if (
        not isinstance(raw["id"], str)
        or not _UUID.fullmatch(raw["id"])
        or type(raw["revision"]) is not int
        or not (1 <= raw["revision"] <= 2**31 - 1)
        or not isinstance(raw["ssh_public_key_fingerprint"], str)
        or not _SSH_FINGERPRINT.fullmatch(raw["ssh_public_key_fingerprint"])
        or not isinstance(raw["admission_anchor_fingerprint"], str)
        or not _SHA256.fullmatch(raw["admission_anchor_fingerprint"])
        or raw["public_material_only"] is not True
    ):
        raise ValueError
    return WorkerPublicObservation(
        node_id=raw["id"],
        revision=raw["revision"],
        ssh_public_fingerprint=raw["ssh_public_key_fingerprint"],
        admission_anchor_fingerprint=raw["admission_anchor_fingerprint"],
        public_material_only=True,
    )


class _DuplicateKey(ValueError):
    pass


def _reject_duplicates(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


class PosixActivationArtifactStore:
    """No-follow, fixed-path, root-controlled artifact journal and rollback store."""

    def __init__(self, host_role: LocalHostRole) -> None:
        # Deliberately no path access here.  Production capability is exercised only by explicit
        # adapter operations.
        if type(host_role) is not LocalHostRole:
            _closed("local_host_role_invalid")
        self._host_role = host_role
        self._journal_path = (
            PRODUCTION_LAYOUT.controller_journal_path
            if host_role is LocalHostRole.controller
            else PRODUCTION_LAYOUT.worker_journal_path
        )

    @staticmethod
    def _require_posix() -> None:
        if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
            _closed("activation_filesystem_requires_posix_root")

    @classmethod
    def _open_parent(cls, path: str, *, create: bool) -> tuple[int, str]:
        """Open a fixed path's parent by directory fd, rejecting symlinked/unsafe ancestors."""

        cls._require_posix()
        if path not in {
            *_ROLE_PATHS.values(),
            *_FIXED_CODE_OWNED_PATHS,
            PRODUCTION_LAYOUT.controller_journal_path,
            PRODUCTION_LAYOUT.worker_journal_path,
        }:
            _closed("activation_path_not_fixed")
        parts = path.split("/")
        if not path.startswith("/") or any(part in {".", ".."} for part in parts):
            _closed("activation_path_invalid")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            current = os.open("/", flags)
        except OSError:
            _closed("activation_root_open_failed")
        try:
            for segment in parts[1:-1]:
                try:
                    child = os.open(segment, flags, dir_fd=current)
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(segment, 0o700, dir_fd=current)
                        os.fsync(current)
                        child = os.open(segment, flags, dir_fd=current)
                    except OSError:
                        _closed("activation_directory_create_failed")
                except OSError:
                    _closed("activation_directory_open_failed")
                child_stat = os.fstat(child)
                if (
                    not stat.S_ISDIR(child_stat.st_mode)
                    or child_stat.st_uid != 0
                    or stat.S_IMODE(child_stat.st_mode) & 0o022
                ):
                    os.close(child)
                    _closed("activation_directory_unsafe")
                os.close(current)
                current = child
            return current, parts[-1]
        except BaseException:
            os.close(current)
            raise

    @classmethod
    def _read_absolute(
        cls,
        path: str,
        *,
        allow_missing: bool,
        max_bytes: int = _MAX_ARTIFACT_BYTES,
        journal: bool = False,
    ) -> _BoundFile | None:
        try:
            parent, leaf = cls._open_parent(path, create=False)
        except FileNotFoundError:
            if allow_missing:
                return None
            _closed("activation_artifact_missing")
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            try:
                fd = os.open(leaf, flags, dir_fd=parent)
            except FileNotFoundError:
                if allow_missing:
                    return None
                _closed("activation_artifact_missing")
            except OSError:
                _closed("activation_artifact_open_failed")
            try:
                before = os.fstat(fd)
                mode = stat.S_IMODE(before.st_mode)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_uid != 0
                    or mode & 0o022
                    or before.st_size < 0
                    or before.st_size > max_bytes
                    or (journal and (before.st_gid != 0 or mode != 0o600))
                ):
                    _closed("activation_artifact_unsafe")
                remaining = before.st_size
                chunks: list[bytes] = []
                while remaining:
                    chunk = os.read(fd, min(remaining, 64 * 1024))
                    if not chunk:
                        _closed("activation_artifact_short_read")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if os.read(fd, 1):
                    _closed("activation_artifact_changed_during_read")
                after = os.fstat(fd)
                if (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                    _closed("activation_artifact_changed_during_read")
                content = b"".join(chunks)
                return _BoundFile(content, _digest(content), before.st_uid, before.st_gid, mode)
            finally:
                os.close(fd)
        finally:
            os.close(parent)

    @classmethod
    def _read_role(cls, role: str, *, allow_missing: bool = True) -> _BoundFile | None:
        if role not in _ROLE_PATHS:
            _closed("activation_artifact_role_invalid")
        return cls._read_absolute(
            _ROLE_PATHS[role],
            allow_missing=allow_missing,
            max_bytes=(
                MAX_RUNTIME_OVERLAY_BYTES
                if role == ROLE_WORKER_RUNTIME_OVERLAY
                else _MAX_ARTIFACT_BYTES
            ),
        )

    @classmethod
    def _write_absolute(
        cls,
        path: str,
        desired: _BoundFile,
        *,
        expected: _BoundFile | None,
        journal: bool = False,
        max_bytes: int = _MAX_ARTIFACT_BYTES,
    ) -> None:
        parent, leaf = cls._open_parent(path, create=True)
        temp = ".secp-pr5f-" + uuid.uuid4().hex + ".tmp"
        temp_created = False
        try:
            try:
                import fcntl

                fcntl.flock(parent, fcntl.LOCK_EX)  # type: ignore[attr-defined]
            except (ImportError, OSError):
                _closed("activation_filesystem_lock_failed")
            current = cls._read_absolute(
                path,
                allow_missing=True,
                max_bytes=_MAX_JOURNAL_BYTES if journal else max_bytes,
                journal=journal,
            )
            if current != expected:
                _closed("activation_artifact_drift")
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            try:
                fd = os.open(temp, flags, desired.mode, dir_fd=parent)
                temp_created = True
            except OSError:
                _closed("activation_artifact_stage_failed")
            try:
                fchmod: Any = getattr(os, "fchmod", None)
                fchown: Any = getattr(os, "fchown", None)
                if not callable(fchmod) or not callable(fchown):
                    _closed("activation_filesystem_requires_posix_root")
                fchmod(fd, desired.mode)
                fchown(fd, desired.uid, desired.gid)
                view = memoryview(desired.content)
                written = 0
                while written < len(view):
                    count = os.write(fd, view[written:])
                    if count <= 0:
                        _closed("activation_artifact_write_failed")
                    written += count
                os.fsync(fd)
                staged = os.fstat(fd)
                if (
                    not stat.S_ISREG(staged.st_mode)
                    or staged.st_nlink != 1
                    or staged.st_uid != desired.uid
                    or staged.st_gid != desired.gid
                    or stat.S_IMODE(staged.st_mode) != desired.mode
                    or staged.st_size != len(desired.content)
                ):
                    _closed("activation_artifact_stage_invalid")
            finally:
                os.close(fd)
            try:
                # Revalidate under the parent-directory lock immediately before committing.  All
                # package writes/removals take the same lock, preventing stale check/replace races.
                latest = cls._read_absolute(
                    path,
                    allow_missing=True,
                    max_bytes=_MAX_JOURNAL_BYTES if journal else max_bytes,
                    journal=journal,
                )
                if latest != expected:
                    _closed("activation_artifact_drift")
                os.replace(temp, leaf, src_dir_fd=parent, dst_dir_fd=parent)
                temp_created = False
                os.fsync(parent)
            except OSError:
                _closed("activation_artifact_commit_failed")
        finally:
            if temp_created:
                try:
                    os.unlink(temp, dir_fd=parent)
                except OSError:
                    pass
            os.close(parent)

    @classmethod
    def _write_role(cls, role: str, desired: _BoundFile, *, expected: _BoundFile | None) -> None:
        if role not in _ROLE_PATHS:
            _closed("activation_artifact_role_invalid")
        cls._write_absolute(
            _ROLE_PATHS[role],
            desired,
            expected=expected,
            max_bytes=(
                MAX_RUNTIME_OVERLAY_BYTES
                if role == ROLE_WORKER_RUNTIME_OVERLAY
                else _MAX_ARTIFACT_BYTES
            ),
        )

    @classmethod
    def _remove_role(cls, role: str, *, expected: _BoundFile) -> None:
        if role not in _ROLE_PATHS:
            _closed("activation_artifact_role_invalid")
        cls._remove_absolute(
            _ROLE_PATHS[role],
            expected=expected,
            max_bytes=(
                MAX_RUNTIME_OVERLAY_BYTES
                if role == ROLE_WORKER_RUNTIME_OVERLAY
                else _MAX_ARTIFACT_BYTES
            ),
        )

    @classmethod
    def _remove_absolute(
        cls,
        path: str,
        *,
        expected: _BoundFile,
        journal: bool = False,
        max_bytes: int = _MAX_ARTIFACT_BYTES,
    ) -> None:
        parent, leaf = cls._open_parent(path, create=False)
        fd: int | None = None
        try:
            try:
                import fcntl

                fcntl.flock(parent, fcntl.LOCK_EX)  # type: ignore[attr-defined]
            except (ImportError, OSError):
                _closed("activation_filesystem_lock_failed")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(leaf, flags, dir_fd=parent)
            opened = os.fstat(fd)
            max_bytes = _MAX_JOURNAL_BYTES if journal else max_bytes
            mode = stat.S_IMODE(opened.st_mode)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_uid != expected.uid
                or opened.st_gid != expected.gid
                or mode != expected.mode
                or opened.st_size != len(expected.content)
                or opened.st_size > max_bytes
            ):
                _closed("rollback_content_or_metadata_drift")
            content = bytearray()
            while len(content) < opened.st_size:
                chunk = os.read(fd, min(64 * 1024, opened.st_size - len(content)))
                if not chunk:
                    _closed("rollback_content_or_metadata_drift")
                content.extend(chunk)
            if bytes(content) != expected.content or _digest(bytes(content)) != expected.digest:
                _closed("rollback_content_or_metadata_drift")
            entry = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino):
                _closed("rollback_content_or_metadata_drift")
            os.unlink(leaf, dir_fd=parent)
            os.fsync(parent)
        except OSError:
            _closed("rollback_artifact_remove_failed")
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)

    def _journal_bound(self) -> _BoundFile | None:
        return self._read_absolute(
            self._journal_path,
            allow_missing=True,
            max_bytes=_MAX_JOURNAL_BYTES,
            journal=True,
        )

    def _write_journal(self, value: dict[str, object], *, expected: _BoundFile | None) -> None:
        try:
            raw = (
                json.dumps(
                    value,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ).encode("ascii")
                + b"\n"
            )
        except (TypeError, ValueError):
            _closed("transaction_journal_serialization_failed")
        if not (1 <= len(raw) <= _MAX_JOURNAL_BYTES):
            _closed("transaction_journal_size_invalid")
        self._write_absolute(
            self._journal_path,
            _BoundFile(raw, _digest(raw), 0, 0, 0o600),
            expected=expected,
            journal=True,
        )

    def _load_journal(self) -> tuple[dict[str, Any], _BoundFile]:
        bound = self._journal_bound()
        if bound is None:
            _closed("transaction_journal_missing")
        try:
            value = json.loads(bound.content.decode("ascii"), object_pairs_hook=_reject_duplicates)
        except (UnicodeDecodeError, ValueError):
            _closed("transaction_journal_malformed")
        if not isinstance(value, dict):
            _closed("transaction_journal_malformed")
        _validate_journal(value)
        if value["host_role"] != self._host_role.value:
            _closed("transaction_journal_role_mismatch")
        return value, bound

    def _update_journal(self, value: dict[str, Any], previous: _BoundFile) -> _BoundFile:
        self._write_journal(value, expected=previous)
        updated = self._journal_bound()
        if updated is None:
            _closed("transaction_journal_commit_unproven")
        return updated

    @classmethod
    def _base_compose_record(cls, host_role: LocalHostRole) -> _BoundFile:
        record = cls._read_absolute(
            _base_compose_path(host_role),
            allow_missing=False,
            max_bytes=_MAX_ARTIFACT_BYTES,
        )
        if record is None or not record.content:
            _closed("base_compose_missing_or_empty")
        if record.uid != 0 or record.mode not in {0o600, 0o640, 0o644}:
            _closed("base_compose_metadata_unsafe")
        return record

    def assert_base_compose_unchanged(
        self, host_role: LocalHostRole, expected: FixedInputBinding
    ) -> None:
        if host_role is not self._host_role or type(expected) is not FixedInputBinding:
            _closed("base_compose_binding_invalid")
        if self._base_compose_record(host_role).fixed_input() != expected:
            _closed("base_compose_drift")

    def transaction_base_compose_binding(self) -> FixedInputBinding:
        journal, _bound = self._load_journal()
        return _fixed_input_from_journal(journal["base_compose"])

    @classmethod
    def _controller_env_record(cls) -> _BoundFile:
        """Read the code-owned fixed controller environment file as a private content+metadata
        binding.  The hardened trusted-ancestor read already enforces a real regular file, no
        symlink, single hard link, a root-controlled ancestor chain, and bounded size; here we add
        the secret-bearing owner/mode policy (root-owned, never world-accessible: 0600 or 0640)."""
        record = cls._read_absolute(
            CONTROLLER_ENV_FILE_PATH,
            allow_missing=True,
            max_bytes=_MAX_CONTROLLER_ENV_BYTES,
        )
        if record is None:
            _closed("controller_env_missing")
        if not record.content:
            _closed("controller_env_missing_or_empty")
        if record.uid != 0 or record.mode not in {0o600, 0o640}:
            _closed("controller_env_metadata_unsafe")
        return record

    def assert_controller_env_unchanged(self, expected: FixedInputBinding) -> None:
        """Re-read the fixed controller environment file, prove it is byte-identical to the staged
        binding, and re-prove it still covers every base-Compose interpolation variable.  Any
        disappearance, replacement, symlink, hardlink, owner/mode/content drift refuses closed.
        The file bytes are never returned or logged — only its private binding + name coverage."""
        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        if type(expected) is not FixedInputBinding:
            _closed("controller_env_binding_invalid")
        record = self._controller_env_record()
        if record.fixed_input() != expected:
            _closed("controller_env_drift")
        _assert_controller_env_coverage(
            self._base_compose_record(LocalHostRole.controller).content, record.content
        )

    def transaction_controller_env_binding(self) -> FixedInputBinding:
        journal, _bound = self._load_journal()
        if (
            journal["host_role"] != LocalHostRole.controller.value
            or "controller_env" not in journal
        ):
            _closed("controller_env_binding_missing")
        return _fixed_input_from_journal(journal["controller_env"])

    def transaction_profile(self) -> DeploymentProfile:
        journal, _bound = self._load_journal()
        profile_record = self._read_role(ROLE_PROFILE, allow_missing=False)
        if profile_record is None or profile_record.digest != journal["profile_content_digest"]:
            _closed("rollback_profile_drift")
        try:
            return parse_profile_bytes(profile_record.content)
        except Exception:
            _closed("rollback_profile_drift")

    def transaction_runtime_after(self) -> tuple[ContainerRuntimeObservation, ...] | None:
        journal, _bound = self._load_journal()
        raw = journal["runtime_after"]
        if raw is None:
            return None
        assert isinstance(raw, dict)
        if self._host_role is LocalHostRole.controller:
            return (
                _runtime_identity_from_journal(raw["api"]),
                _runtime_identity_from_journal(raw["proxy"]),
            )
        return (_runtime_identity_from_journal(raw["worker"]),)

    @classmethod
    def validated_runtime_overlay(cls, expected_digest: str) -> _BoundFile:
        record = cls._read_absolute(
            PRODUCTION_LAYOUT.worker_runtime_overlay_import_path,
            allow_missing=False,
            max_bytes=MAX_RUNTIME_OVERLAY_BYTES,
        )
        if record is None or record.uid != 0 or record.gid != 0 or record.mode != 0o644:
            _closed("worker_runtime_overlay_import_unsafe")
        try:
            validated = import_runtime_overlay(record.content, expected_sha256=expected_digest)
        except Exception:
            _closed("worker_runtime_overlay_invalid")
        return _BoundFile(bytes(validated), validated.sha256, 0, 0, 0o644)

    def posture(self, host_role: LocalHostRole) -> ArtifactPosture:
        roles = _roles_for(host_role)
        observed_roles = {ROLE_PROFILE, *roles}
        records = {role: self._read_role(role) for role in observed_roles}
        digest_roles = (
            (
                ROLE_PROFILE,
                ROLE_WORKER_OVERRIDE,
                ROLE_WORKER_RUNTIME_OVERLAY,
                ROLE_ADMISSION_CA,
            )
            if host_role is LocalHostRole.worker
            else (
                ROLE_PROFILE,
                ROLE_CONTROLLER_OVERRIDE,
                ROLE_PROXY_CONTRACT,
                ROLE_ADMISSION_CA,
                ROLE_ADMISSION_SERVER_CERTIFICATE,
            )
        )
        digests = tuple(
            (role, record.digest) for role in digest_roles if (record := records[role]) is not None
        )
        prepared_roles = (
            {ROLE_WORKER_OVERRIDE, ROLE_WORKER_RUNTIME_OVERLAY, ROLE_ADMISSION_CA}
            if host_role is LocalHostRole.worker
            else {
                ROLE_PROXY_CONTRACT,
                ROLE_CONTROLLER_OVERRIDE,
                ROLE_ADMISSION_CA,
                ROLE_ADMISSION_SERVER_CERTIFICATE,
                ROLE_ADMISSION_SERVER_KEY,
                ROLE_ADMISSION_PROXY_GATE,
            }
        )
        gate = records.get(ROLE_ADMISSION_PROXY_GATE)
        if host_role is LocalHostRole.controller and gate is not None:
            profile_record = records.get(ROLE_PROFILE)
            if profile_record is None:
                _closed("activation_profile_missing")
            try:
                profile = parse_profile_bytes(profile_record.content)
            except Exception:
                _closed("activation_profile_invalid")
            if (
                gate.uid != 0
                or gate.gid != profile.admission_proxy_runtime_gid
                or gate.mode != 0o640
                or _PROXY_GATE_SECRET.fullmatch(gate.content) is None
            ):
                _closed("admission_proxy_gate_invalid")
            ca = records.get(ROLE_ADMISSION_CA)
            server = records.get(ROLE_ADMISSION_SERVER_CERTIFICATE)
            key = records.get(ROLE_ADMISSION_SERVER_KEY)
            if ca is not None or server is not None or key is not None:
                if ca is None or server is None or key is None:
                    _closed("tls_artifact_set_incomplete")
                if not (
                    ca.uid == 0
                    and ca.gid == 0
                    and ca.mode == 0o644
                    and server.uid == 0
                    and server.gid == 0
                    and server.mode == 0o644
                    and key.uid == 0
                    and key.gid == profile.admission_proxy_runtime_gid
                    and key.mode == 0o640
                ):
                    _closed("tls_artifact_metadata_invalid")
                try:
                    validated_tls = import_tls_material(
                        ca_certificate_pem=ca.content,
                        server_certificate_pem=server.content,
                        server_private_key_pem=key.content,
                        expected_dns_identity=profile.admission_certificate_dns_name,
                    )
                except Exception:
                    _closed("tls_artifact_set_invalid")
                if (
                    validated_tls.ca_certificate_pem() != ca.content
                    or validated_tls.server_certificate_pem() != server.content
                    or validated_tls.server_private_key_pem() != key.content
                ):
                    _closed("tls_artifact_set_noncanonical")
        overlay = records.get(ROLE_WORKER_RUNTIME_OVERLAY)
        if host_role is LocalHostRole.worker and overlay is not None:
            if overlay.uid != 0 or overlay.gid != 0 or overlay.mode != 0o644:
                _closed("worker_runtime_overlay_installed_unsafe")
        recovery_required = False
        if self._journal_bound() is not None:
            journal, _journal_bound = self._load_journal()
            recovery_required = journal["status"] == "recovery_required"
        return ArtifactPosture(
            artifacts_prepared=all(records[role] is not None for role in prepared_roles),
            worker_config_installed=(
                host_role is LocalHostRole.worker and records[ROLE_WORKER_OVERRIDE] is not None
            ),
            configuration_artifact_digests=digests,
            base_compose_binding=self._base_compose_record(host_role).fixed_input(),
            recovery_required=recovery_required,
        )

    def operator_service_present(self) -> bool:
        self._require_posix()
        for path in _OPERATOR_UNIT_PATHS:
            try:
                os.lstat(path)
            except FileNotFoundError:
                continue
            except OSError:
                return True
            return True
        return False

    def stage(
        self,
        profile: DeploymentProfile,
        worker_override: RenderedArtifact,
        before: HostObservation,
        *,
        host_role: LocalHostRole,
        transaction_id: str,
        state_receipt: dict[str, object],
    ) -> MutationReceipt:
        if host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        return self._stage_transaction(
            profile,
            worker_override,
            transaction_id=transaction_id,
            host_role=host_role,
            before_worker=before,
            before_controller=None,
            state_receipt=state_receipt,
        )

    def stage_controller(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        before: ControllerObservation,
        *,
        transaction_id: str,
    ) -> MutationReceipt:
        return self._stage_transaction(
            profile,
            rendered,
            transaction_id=transaction_id,
            host_role=LocalHostRole.controller,
            before_worker=None,
            before_controller=before,
            state_receipt=None,
        )

    def _stage_transaction(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender | RenderedArtifact,
        *,
        transaction_id: str,
        host_role: LocalHostRole,
        before_worker: HostObservation | None,
        before_controller: ControllerObservation | None,
        state_receipt: dict[str, object] | None,
    ) -> MutationReceipt:
        if host_role is not self._host_role:
            _closed("local_host_role_mismatch")
        existing_journal = self._journal_bound()
        if existing_journal is not None:
            existing, bound = self._load_journal()
            if existing["status"] != "compensated":
                _closed("transaction_already_present")
            # A compensated journal is authoritative proof that both artifact and runtime
            # restoration completed.  Remove that exact bound object before beginning a new
            # transaction; drift/substitution fails closed.
            self._remove_absolute(self._journal_path, expected=bound, journal=True)
        try:
            parsed_id = uuid.UUID(transaction_id)
        except (ValueError, AttributeError):
            _closed("transaction_id_invalid")
        if str(parsed_id) != transaction_id or parsed_id.version != 4:
            _closed("transaction_id_invalid")
        if host_role is LocalHostRole.worker:
            if type(rendered) is not RenderedArtifact:
                _closed("worker_override_invalid")
            _validate_worker_override(rendered)
            render_binding = rendered.sha256
        else:
            if type(rendered) is not ActivationRender:
                _closed("rendered_artifact_set_invalid")
            artifacts = _rendered_by_role(rendered)
            if set(artifacts) != {
                ROLE_WORKER_OVERRIDE,
                ROLE_PROXY_CONTRACT,
                ROLE_CONTROLLER_OVERRIDE,
            }:
                _closed("rendered_artifact_set_invalid")
            render_binding = rendered.manifest.sha256
        roles = _roles_for(host_role)
        before_files = {role: self._read_role(role) for role in roles}
        # Private keys are never copied into the JSON rollback journal.  A controller host with
        # an existing server key requires an explicit out-of-band recovery/adoption procedure.
        if (
            host_role is LocalHostRole.controller
            and before_files[ROLE_ADMISSION_SERVER_KEY] is not None
        ):
            _closed("preexisting_server_key_adoption_forbidden")
        # Never copy an adopted credential into the JSON before-image or overwrite a credential
        # owned by an earlier/foreign deployment.  The gate is generated only after this durable
        # journal has proven that its fixed path is absent.
        if (
            host_role is LocalHostRole.controller
            and before_files[ROLE_ADMISSION_PROXY_GATE] is not None
        ):
            _closed("preexisting_proxy_gate_adoption_forbidden")
        if (
            host_role is LocalHostRole.worker
            and before_files[ROLE_WORKER_RUNTIME_OVERLAY] is not None
        ):
            _closed("preexisting_worker_runtime_overlay_adoption_forbidden")
        # The fixed profile must itself still be a safe root-controlled regular file before the
        # journal can confer any rollback authority.
        profile_record = self._read_role(ROLE_PROFILE)
        if profile_record is None:
            _closed("activation_profile_missing")
        base_compose_record = self._base_compose_record(host_role)
        observed_base = (
            before_worker.base_compose_binding
            if before_worker is not None
            else before_controller.base_compose_binding
            if before_controller is not None
            else None
        )
        if observed_base is None or observed_base != base_compose_record.fixed_input():
            _closed("base_compose_changed_before_staging")
        # Controller only: bind the code-owned fixed environment file and prove — before any host
        # mutation — that it defines every ${SECP_*} variable the base Compose file interpolates.
        # Only a private digest/owner/mode binding is journaled, never the bytes; the worker never
        # receives it.  Missing coverage or an unsafe/absent file refuses here, before staging.
        controller_env_journal: dict[str, object] | None = None
        if host_role is LocalHostRole.controller:
            controller_env_record = self._controller_env_record()
            _assert_controller_env_coverage(
                base_compose_record.content, controller_env_record.content
            )
            controller_env_journal = controller_env_record.safe()
        if host_role is LocalHostRole.worker:
            if not _valid_state_receipt(state_receipt) or before_worker is None:
                _closed("worker_state_receipt_invalid")
            generation = before_worker.worker_generation
            if generation is None:
                _closed("rollback_observation_incomplete")
            before_worker_value: dict[str, object] | None = {
                "present": before_worker.worker_present,
                "image_digest": before_worker.worker_image_digest,
                "running": before_worker.worker_running,
                "healthy": before_worker.worker_healthy,
                "generation_digest": generation.digest(),
                "ordinary_queues": list(before_worker.ordinary_queues),
                "controlled_integration_enabled": (before_worker.controlled_integration_enabled),
                "worker_managed_bundle_enabled": (before_worker.worker_managed_bundle_enabled),
                "fixed_worker_paths": before_worker.fixed_worker_paths,
                "state_mount_read_write_only_worker": (
                    before_worker.state_mount_read_write_only_worker
                ),
                "ca_mount_read_only_worker": before_worker.ca_mount_read_only_worker,
                "discovery_mount_absent_from_other_containers": (
                    before_worker.discovery_mount_absent_from_other_containers
                ),
                "bundle_prep_loop_started": before_worker.bundle_prep_loop_started,
                "operator_service_present": before_worker.operator_service_present,
                "operator_container_present": before_worker.operator_container_present,
                "operator_registration_present": before_worker.operator_registration_present,
                "operator_queue_polled": before_worker.operator_queue_polled,
                "generic_activation_subprocess_sealed": (
                    before_worker.generic_activation_subprocess_sealed
                ),
                "generic_executor_subprocess_sealed": (
                    before_worker.generic_executor_subprocess_sealed
                ),
                "plan_only_process_sealed": before_worker.plan_only_process_sealed,
                "real_provisioning_enabled": before_worker.real_provisioning_enabled,
                "artifacts_prepared": before_worker.artifacts_prepared,
                "worker_config_installed": before_worker.worker_config_installed,
                "worker_recreation_required": before_worker.worker_recreation_required,
                "worker_generation_changed": before_worker.worker_generation_changed,
                "configuration_artifact_digests": [
                    list(item) for item in before_worker.configuration_artifact_digests
                ],
                "runtime": _runtime_to_journal(before_worker.worker_runtime),
            }
            before_controller_value: dict[str, object] | None = None
        else:
            if before_controller is None or state_receipt is not None:
                _closed("controller_rollback_observation_incomplete")
            before_worker_value = None
            before_controller_value = {
                "controller_config_installed": before_controller.controller_config_installed,
                "proxy_running": before_controller.proxy_running,
                "proxy_healthy": before_controller.proxy_healthy,
                "private_listener_only": before_controller.private_listener_only,
                "tls_ready": before_controller.tls_ready,
                "activation_route_enabled": before_controller.activation_route_enabled,
                "configuration_artifact_digests": [
                    list(item) for item in before_controller.configuration_artifact_digests
                ],
                "api_runtime": _runtime_to_journal(before_controller.api_runtime),
                "proxy_runtime": _runtime_to_journal(before_controller.proxy_runtime),
                "migration_head": before_controller.migration_head,
                "migration_head_ready": before_controller.migration_head_ready,
            }
        journal: dict[str, object] = {
            "schema": _JOURNAL_SCHEMA,
            "transaction_id": transaction_id,
            "host_role": host_role.value,
            "status": "staged",
            "render_manifest_sha256": render_binding,
            "profile_content_digest": profile_record.digest,
            "base_compose": base_compose_record.safe(),
            "before": {
                role: record.journal() if record is not None else None
                for role, record in before_files.items()
            },
            "after": {role: None for role in roles},
            "effects": {
                "effects_started": False,
                "controller_changed": False,
                "controller_runtime_changed": False,
                "worker_config_changed": False,
                "worker_recreated": False,
                "evidence_committed": False,
            },
            "operation_count": 0,
            "state_receipt": dict(state_receipt) if state_receipt is not None else None,
            "execution": {
                "container_path": profile.container_runtime_executable,
                "container_digest": profile.container_runtime_executable_digest,
                "compose_path": profile.compose_executable,
                "compose_digest": profile.compose_executable_digest,
            },
            "before_worker": before_worker_value,
            "before_controller": before_controller_value,
            "runtime_after": None,
            "worker_tls_proof": None,
        }
        # Controller journals bind the fixed environment file (private digest/owner/mode only, never
        # its bytes); worker journals deliberately never claim or require this controller binding.
        if controller_env_journal is not None:
            journal["controller_env"] = controller_env_journal
        self._write_journal(journal, expected=None)
        return self.receipt()

    @staticmethod
    def _set_effect(journal: dict[str, Any], name: str) -> None:
        effects = journal["effects"]
        assert isinstance(effects, dict)
        effects["effects_started"] = True
        effects[name] = True
        journal["operation_count"] += 1

    def _plan_writes(
        self,
        writes: Mapping[str, _BoundFile],
        *,
        effect: str,
    ) -> tuple[dict[str, Any], _BoundFile]:
        journal, bound = self._load_journal()
        if journal["status"] not in {"staged", "mutating"}:
            _closed("transaction_state_invalid")
        roles = _roles_for(LocalHostRole(journal["host_role"]))
        after = journal["after"]
        assert isinstance(after, dict)
        for role, desired in writes.items():
            if role not in roles:
                _closed("activation_artifact_role_invalid")
            previous = after[role]
            safe = desired.safe()
            if previous is not None and previous != safe:
                _closed("transaction_after_image_changed")
            after[role] = safe
        journal["status"] = "mutating"
        self._set_effect(journal, effect)
        bound = self._update_journal(journal, bound)
        return journal, bound

    def _apply_writes(self, writes: Mapping[str, _BoundFile], effect: str) -> None:
        journal, journal_bound = self._plan_writes(writes, effect=effect)
        before = journal["before"]
        after = journal["after"]
        assert isinstance(before, dict) and isinstance(after, dict)
        for role, desired in writes.items():
            current = self._read_role(role)
            original = _bound_from_journal(before[role], content=True)
            expected_after = _bound_from_journal(after[role], content=False)
            if (
                current is not None
                and expected_after is not None
                and _same_binding(current, expected_after)
            ):
                continue
            if not _same_optional_binding(current, original):
                _closed("activation_artifact_drift")
            self._write_role(role, desired, expected=current)
        # Re-read every installed object and bind journal completion to the actual content+metadata.
        for role, desired in writes.items():
            if self_record := self._read_role(role):
                if self_record != desired:
                    _closed("activation_artifact_commit_unproven")
            else:
                _closed("activation_artifact_commit_unproven")
        self._update_journal(journal, journal_bound)

    def install_controller(
        self, rendered: ActivationRender, tls_material: ValidatedTLSMaterial
    ) -> None:
        artifacts = _rendered_by_role(rendered)
        try:
            journal, _bound = self._load_journal()
            if journal["host_role"] != LocalHostRole.controller.value:
                _closed("controller_host_role_required")
            proxy_gid = int(_bound_from_render(artifacts[ROLE_PROXY_CONTRACT]).gid)
        except Exception:
            _closed("controller_artifact_invalid")
        writes: dict[str, _BoundFile] = {
            ROLE_PROXY_CONTRACT: _bound_from_render(artifacts[ROLE_PROXY_CONTRACT]),
            ROLE_CONTROLLER_OVERRIDE: _bound_from_render(artifacts[ROLE_CONTROLLER_OVERRIDE]),
            ROLE_ADMISSION_CA: _BoundFile(
                tls_material.ca_certificate_pem(),
                _digest(tls_material.ca_certificate_pem()),
                0,
                0,
                0o644,
            ),
            ROLE_ADMISSION_SERVER_CERTIFICATE: _BoundFile(
                tls_material.server_certificate_pem(),
                _digest(tls_material.server_certificate_pem()),
                0,
                0,
                0o644,
            ),
            # The proxy is deliberately non-root.  Group-read by its dedicated deployment-local
            # gid is the narrow access it needs; the worker has neither this gid nor this mount.
            ROLE_ADMISSION_SERVER_KEY: _BoundFile(
                tls_material.server_private_key_pem(),
                _digest(tls_material.server_private_key_pem()),
                0,
                proxy_gid,
                0o640,
            ),
        }
        gate_content = secrets.token_hex(32).encode("ascii") + b"\n"
        writes[ROLE_ADMISSION_PROXY_GATE] = _BoundFile(
            gate_content,
            _digest(gate_content),
            0,
            proxy_gid,
            0o640,
        )
        if journal["render_manifest_sha256"] != rendered.manifest.sha256:
            _closed("render_manifest_changed")
        self._apply_writes(writes, "controller_changed")

    def install_worker(
        self,
        worker_override: RenderedArtifact,
        ca_certificate: ValidatedAdmissionCA,
        runtime_overlay: _BoundFile,
    ) -> None:
        override = _validate_worker_override(worker_override)
        if type(ca_certificate) is not ValidatedAdmissionCA:
            _closed("worker_ca_certificate_required")
        if (
            type(runtime_overlay) is not _BoundFile
            or runtime_overlay.uid != 0
            or runtime_overlay.gid != 0
            or runtime_overlay.mode != 0o644
            or not runtime_overlay.content
        ):
            _closed("worker_runtime_overlay_required")
        journal, _bound = self._load_journal()
        if journal["host_role"] != LocalHostRole.worker.value:
            _closed("worker_host_role_required")
        if journal["render_manifest_sha256"] != worker_override.sha256:
            _closed("worker_override_changed")
        ca_pem = ca_certificate.ca_certificate_pem()
        if _digest(ca_pem) != ca_certificate.ca_certificate_content_digest:
            _closed("worker_ca_content_digest_mismatch")
        self._apply_writes(
            {
                ROLE_WORKER_OVERRIDE: override,
                ROLE_WORKER_RUNTIME_OVERLAY: runtime_overlay,
                ROLE_ADMISSION_CA: _BoundFile(
                    ca_pem,
                    ca_certificate.ca_certificate_content_digest,
                    0,
                    0,
                    0o644,
                ),
            },
            "worker_config_changed",
        )

    def record_worker_tls_proof(
        self,
        *,
        ca_certificate_fingerprint: str,
        expected_server_certificate_fingerprint: str,
        expected_server_dns_identity: str,
    ) -> None:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        if not _SHA256.fullmatch(ca_certificate_fingerprint) or not _SHA256.fullmatch(
            expected_server_certificate_fingerprint
        ):
            _closed("worker_tls_proof_invalid")
        try:
            validate_dns_identity(expected_server_dns_identity)
        except ValueError:
            _closed("worker_tls_proof_invalid")
        ca = self._read_role(ROLE_ADMISSION_CA)
        if ca is None:
            _closed("worker_ca_certificate_missing")
        try:
            der = ssl.PEM_cert_to_DER_cert(ca.content.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            _closed("worker_ca_certificate_malformed")
        if _digest(der) != ca_certificate_fingerprint:
            _closed("worker_tls_ca_fingerprint_mismatch")
        proof = {
            "ca_certificate_fingerprint": ca_certificate_fingerprint,
            "expected_server_certificate_fingerprint": (expected_server_certificate_fingerprint),
            "expected_server_dns_identity": expected_server_dns_identity,
        }
        journal, bound = self._load_journal()
        if journal["status"] not in {"mutating", "committed"}:
            _closed("transaction_state_invalid")
        previous = journal["worker_tls_proof"]
        if previous is not None and previous != proof:
            _closed("worker_tls_proof_changed")
        journal["worker_tls_proof"] = proof
        journal["operation_count"] += 1
        self._update_journal(journal, bound)

    def worker_tls_proof(self) -> tuple[str, str, str] | None:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        if self._journal_bound() is None:
            return None
        journal, _bound = self._load_journal()
        if journal["status"] not in {"mutating", "committed"}:
            return None
        proof = journal["worker_tls_proof"]
        if proof is None:
            return None
        assert isinstance(proof, dict)
        return (
            proof["ca_certificate_fingerprint"],
            proof["expected_server_certificate_fingerprint"],
            proof["expected_server_dns_identity"],
        )

    def note_worker_recreation(self) -> None:
        journal, bound = self._load_journal()
        if journal["status"] not in {"mutating", "staged"}:
            _closed("transaction_state_invalid")
        journal["status"] = "mutating"
        self._set_effect(journal, "worker_recreated")
        self._update_journal(journal, bound)

    def note_controller_runtime_change(self) -> None:
        journal, bound = self._load_journal()
        if journal["host_role"] != LocalHostRole.controller.value or journal["status"] not in {
            "mutating",
            "staged",
        }:
            _closed("transaction_state_invalid")
        journal["status"] = "mutating"
        self._set_effect(journal, "controller_runtime_changed")
        self._update_journal(journal, bound)

    def _record_runtime_after(self, value: dict[str, object], *, role: LocalHostRole) -> None:
        journal, bound = self._load_journal()
        if (
            self._host_role is not role
            or journal["host_role"] != role.value
            or journal["status"] != "mutating"
        ):
            _closed("transaction_state_invalid")
        required_effect = (
            "controller_runtime_changed" if role is LocalHostRole.controller else "worker_recreated"
        )
        effects = journal["effects"]
        assert isinstance(effects, dict)
        if effects[required_effect] is not True:
            _closed("transaction_runtime_effect_missing")
        previous = journal["runtime_after"]
        if previous is not None and previous != value:
            _closed("transaction_runtime_after_changed")
        journal["runtime_after"] = value
        journal["operation_count"] += 1
        self._update_journal(journal, bound)

    def record_controller_runtime_after(
        self,
        api_runtime: ContainerRuntimeObservation,
        proxy_runtime: ContainerRuntimeObservation,
    ) -> None:
        self._record_runtime_after(
            {
                "api": _runtime_identity_to_journal(api_runtime),
                "proxy": _runtime_identity_to_journal(proxy_runtime),
            },
            role=LocalHostRole.controller,
        )

    def record_worker_runtime_after(self, runtime: ContainerRuntimeObservation) -> None:
        self._record_runtime_after(
            {"worker": _runtime_identity_to_journal(runtime)},
            role=LocalHostRole.worker,
        )

    def receipt(self) -> MutationReceipt:
        journal, _bound = self._load_journal()
        effects = journal["effects"]
        assert isinstance(effects, dict)
        return MutationReceipt(
            transaction_id=journal["transaction_id"],
            journal_present=True,
            effects_started=effects["effects_started"],
            controller_changed=effects["controller_changed"],
            worker_config_changed=effects["worker_config_changed"],
            worker_recreated=effects["worker_recreated"],
            evidence_committed=effects["evidence_committed"],
            operation_count=journal["operation_count"],
            controller_runtime_changed=effects["controller_runtime_changed"],
        )

    def tls_probe_material(self) -> tuple[bytes, str] | None:
        ca = self._read_role(ROLE_ADMISSION_CA)
        server = self._read_role(ROLE_ADMISSION_SERVER_CERTIFICATE)
        key = self._read_role(ROLE_ADMISSION_SERVER_KEY)
        if ca is None and server is None and key is None:
            return None
        if ca is None or server is None or key is None:
            _closed("tls_artifact_set_incomplete")
        try:
            profile = self.transaction_profile()
            validated = import_tls_material(
                ca_certificate_pem=ca.content,
                server_certificate_pem=server.content,
                server_private_key_pem=key.content,
                expected_dns_identity=profile.admission_certificate_dns_name,
            )
        except Exception:
            _closed("tls_artifact_set_invalid")
        if not (
            ca.uid == 0
            and ca.gid == 0
            and ca.mode == 0o644
            and server.uid == 0
            and server.gid == 0
            and server.mode == 0o644
            and key.uid == 0
            and key.gid == profile.admission_proxy_runtime_gid
            and key.mode == 0o640
            and validated.ca_certificate_pem() == ca.content
            and validated.server_certificate_pem() == server.content
            and validated.server_private_key_pem() == key.content
        ):
            _closed("tls_artifact_set_invalid")
        return ca.content, validated.metadata.server_certificate_fingerprint

    def commit_evidence(self, evidence: bytes, attestation: bytes) -> None:
        if (
            not isinstance(evidence, bytes)
            or not isinstance(attestation, bytes)
            or not evidence
            or not attestation
            or len(evidence) > _MAX_ARTIFACT_BYTES
            or len(attestation) > 16 * 1024
        ):
            _closed("evidence_artifact_invalid")
        writes = {
            "activation_evidence": _BoundFile(evidence, _digest(evidence), 0, 0, 0o640),
            "activation_evidence_attestation": _BoundFile(
                attestation, _digest(attestation), 0, 0, 0o640
            ),
        }
        self._apply_writes(writes, "evidence_committed")
        journal, bound = self._load_journal()
        journal["status"] = "committed"
        self._update_journal(journal, bound)

    def commit_controller_offer(self, offer: bytes, attestation: bytes) -> None:
        journal, _bound = self._load_journal()
        if journal["host_role"] != LocalHostRole.controller.value:
            _closed("controller_host_role_required")
        if (
            not isinstance(offer, bytes)
            or not isinstance(attestation, bytes)
            or not offer
            or not attestation
            or len(offer) > _MAX_ARTIFACT_BYTES
            or len(attestation) > 16 * 1024
        ):
            _closed("controller_offer_artifact_invalid")
        self._apply_writes(
            {
                "controller_offer": _BoundFile(offer, _digest(offer), 0, 0, 0o640),
                "controller_offer_attestation": _BoundFile(
                    attestation, _digest(attestation), 0, 0, 0o640
                ),
            },
            "controller_changed",
        )

    def load_controller_offer(self) -> tuple[bytes, bytes] | None:
        offer = self._read_role("controller_offer")
        attestation = self._read_role("controller_offer_attestation")
        if offer is None and attestation is None:
            return None
        if offer is None or attestation is None:
            _closed("controller_offer_artifact_set_incomplete")
        return offer.content, attestation.content

    def commit_worker_result(self, result: bytes, attestation: bytes) -> None:
        journal, _bound = self._load_journal()
        if journal["host_role"] != LocalHostRole.worker.value:
            _closed("worker_host_role_required")
        if (
            not isinstance(result, bytes)
            or not isinstance(attestation, bytes)
            or not result
            or not attestation
            or len(result) > _MAX_ARTIFACT_BYTES
            or len(attestation) > 16 * 1024
        ):
            _closed("worker_result_artifact_invalid")
        self._apply_writes(
            {
                "worker_result": _BoundFile(result, _digest(result), 0, 0, 0o640),
                "worker_result_attestation": _BoundFile(
                    attestation, _digest(attestation), 0, 0, 0o640
                ),
            },
            "worker_config_changed",
        )
        journal, bound = self._load_journal()
        journal["status"] = "committed"
        self._update_journal(journal, bound)

    def load_worker_result(self) -> tuple[bytes, bytes] | None:
        result = self._read_role("worker_result")
        attestation = self._read_role("worker_result_attestation")
        if result is None and attestation is None:
            return None
        if result is None or attestation is None:
            _closed("worker_result_artifact_set_incomplete")
        return result.content, attestation.content

    def load_worker_controller_offer_inbox(self) -> tuple[bytes, bytes] | None:
        if self._host_role is not LocalHostRole.worker:
            _closed("worker_host_role_required")
        return self._load_fixed_pair(
            "worker_controller_offer_inbox",
            "worker_controller_offer_inbox_attestation",
            "controller_offer_inbox",
        )

    def load_controller_worker_result_inbox(self) -> tuple[bytes, bytes] | None:
        if self._host_role is not LocalHostRole.controller:
            _closed("controller_host_role_required")
        return self._load_fixed_pair(
            "controller_worker_result_inbox",
            "controller_worker_result_inbox_attestation",
            "worker_result_inbox",
        )

    def _load_fixed_pair(
        self, payload_role: str, attestation_role: str, reason_prefix: str
    ) -> tuple[bytes, bytes] | None:
        payload = self._read_role(payload_role)
        attestation = self._read_role(attestation_role)
        if payload is None and attestation is None:
            return None
        if payload is None or attestation is None:
            _closed(reason_prefix + "_artifact_set_incomplete")
        return payload.content, attestation.content

    def object_classifications(self) -> tuple[tuple[str, str], ...]:
        journal, _bound = self._load_journal()
        before = journal["before"]
        assert isinstance(before, dict)
        if self._host_role is LocalHostRole.controller:
            roles = (
                ROLE_PROFILE,
                ROLE_CONTROLLER_OVERRIDE,
                ROLE_PROXY_CONTRACT,
                ROLE_ADMISSION_CA,
                ROLE_ADMISSION_SERVER_CERTIFICATE,
                ROLE_ADMISSION_SERVER_KEY,
                ROLE_ADMISSION_PROXY_GATE,
            )
            return tuple(
                (
                    role,
                    "adopted"
                    if role == ROLE_PROFILE or before.get(role) is not None
                    else "created",
                )
                for role in roles
            )
        state_receipt = journal["state_receipt"]
        assert isinstance(state_receipt, dict)
        return (
            (
                ROLE_WORKER_OVERRIDE,
                "adopted" if before.get(ROLE_WORKER_OVERRIDE) is not None else "created",
            ),
            (
                ROLE_WORKER_RUNTIME_OVERLAY,
                "adopted" if before.get(ROLE_WORKER_RUNTIME_OVERLAY) is not None else "created",
            ),
            (ROLE_WORKER_STATE, state_receipt["classification"]),
        )

    def load_evidence(self) -> tuple[bytes, bytes] | None:
        evidence = self._read_role("activation_evidence")
        attestation = self._read_role("activation_evidence_attestation")
        if evidence is None and attestation is None:
            return None
        if evidence is None or attestation is None:
            _closed("evidence_artifact_set_incomplete")
        return evidence.content, attestation.content

    def restore_artifacts(self, receipt: MutationReceipt) -> RollbackContext:
        if type(receipt) is not MutationReceipt or not receipt.journal_present:
            _closed("transaction_receipt_invalid")
        journal, journal_bound = self._load_journal()
        if receipt != self.receipt():
            _closed("transaction_receipt_mismatch")
        if journal["status"] not in {"staged", "mutating", "committed", "recovery_required"}:
            _closed("transaction_state_invalid")
        journal["status"] = "recovery_required"
        journal_bound = self._update_journal(journal, journal_bound)
        before = journal["before"]
        after = journal["after"]
        assert isinstance(before, dict) and isinstance(after, dict)
        host_role = LocalHostRole(journal["host_role"])
        execution = journal["execution"]
        previous_worker = journal["before_worker"]
        previous_controller = journal["before_controller"]
        effects = journal["effects"]
        assert isinstance(execution, dict)
        assert isinstance(effects, dict)
        base_compose_binding = _fixed_input_from_journal(journal["base_compose"])
        self.assert_base_compose_unchanged(host_role, base_compose_binding)
        # A controller rollback re-binds and re-proves the fixed environment file before any
        # mutation; a drifted/absent file refuses closed here.  Worker journals carry no such
        # binding and never require one.
        controller_env_binding = (
            _fixed_input_from_journal(journal["controller_env"])
            if host_role is LocalHostRole.controller and "controller_env" in journal
            else None
        )
        if controller_env_binding is not None:
            self.assert_controller_env_unchanged(controller_env_binding)
        # Bind every input needed for runtime restoration before changing a single managed
        # artifact.  In particular, profile drift must not be discovered after a partial restore.
        profile_record = self._read_role(ROLE_PROFILE, allow_missing=False)
        if profile_record is None or profile_record.digest != journal["profile_content_digest"]:
            _closed("rollback_profile_drift")
        try:
            profile = parse_profile_bytes(profile_record.content)
            container_runtime = ExecutablePin(
                execution["container_path"], execution["container_digest"]
            )
            compose_runtime = ExecutablePin(execution["compose_path"], execution["compose_digest"])
        except Exception:
            _closed("rollback_profile_or_execution_invalid")
        if (
            profile.container_runtime_executable != container_runtime.path
            or profile.container_runtime_executable_digest != container_runtime.digest
            or profile.compose_executable != compose_runtime.path
            or profile.compose_executable_digest != compose_runtime.digest
        ):
            _closed("rollback_execution_profile_mismatch")
        actions: list[tuple[str, _BoundFile, _BoundFile | None]] = []
        # Validate the complete rollback set before changing any managed artifact.  A late drift
        # must not leave earlier roles partially restored.
        for role in reversed(_roles_for(host_role)):
            original = _bound_from_journal(before[role], content=True)
            expected_after = _bound_from_journal(after[role], content=False)
            current = self._read_role(role)
            if _same_optional_binding(current, original):
                continue
            if expected_after is None or not _same_optional_binding(current, expected_after):
                _closed("rollback_content_or_metadata_drift")
            assert current is not None
            actions.append((role, current, original))
        for role, current, original in actions:
            if original is None:
                self._remove_role(role, expected=current)
            else:
                self._write_role(role, original, expected=current)
        worker_baseline: HostObservation | None = None
        controller_baseline: ControllerObservation | None = None
        worker_generation_digest: str | None = None
        if host_role is LocalHostRole.worker:
            assert isinstance(previous_worker, dict)
            worker_present = previous_worker["present"]
            worker_image = previous_worker["image_digest"]
            worker_running = previous_worker["running"]
            worker_healthy = previous_worker["healthy"]
            worker_generation_digest = previous_worker["generation_digest"]
            worker_baseline = HostObservation(
                inspected=True,
                coherent=True,
                worker_present=worker_present,
                worker_image_digest=worker_image,
                worker_running=worker_running,
                worker_healthy=worker_healthy,
                ordinary_queues=tuple(previous_worker["ordinary_queues"]),
                controlled_integration_enabled=previous_worker["controlled_integration_enabled"],
                worker_managed_bundle_enabled=previous_worker["worker_managed_bundle_enabled"],
                fixed_worker_paths=previous_worker["fixed_worker_paths"],
                state_mount_read_write_only_worker=previous_worker[
                    "state_mount_read_write_only_worker"
                ],
                ca_mount_read_only_worker=previous_worker["ca_mount_read_only_worker"],
                discovery_mount_absent_from_other_containers=previous_worker[
                    "discovery_mount_absent_from_other_containers"
                ],
                bundle_prep_loop_started=previous_worker["bundle_prep_loop_started"],
                operator_service_present=previous_worker["operator_service_present"],
                operator_container_present=previous_worker["operator_container_present"],
                operator_registration_present=previous_worker["operator_registration_present"],
                operator_queue_polled=previous_worker["operator_queue_polled"],
                generic_activation_subprocess_sealed=previous_worker[
                    "generic_activation_subprocess_sealed"
                ],
                generic_executor_subprocess_sealed=previous_worker[
                    "generic_executor_subprocess_sealed"
                ],
                plan_only_process_sealed=previous_worker["plan_only_process_sealed"],
                real_provisioning_enabled=previous_worker["real_provisioning_enabled"],
                artifacts_prepared=previous_worker["artifacts_prepared"],
                worker_config_installed=previous_worker["worker_config_installed"],
                worker_recreation_required=previous_worker["worker_recreation_required"],
                worker_generation_changed=previous_worker["worker_generation_changed"],
                configuration_artifact_digests=tuple(
                    tuple(item) for item in previous_worker["configuration_artifact_digests"]
                ),
                base_compose_binding=base_compose_binding,
                worker_runtime=_runtime_from_journal(previous_worker["runtime"]),
            )
        else:
            worker_present = False
            worker_image = None
            worker_running = False
            worker_healthy = False
            assert isinstance(previous_controller, dict)
            controller_baseline = ControllerObservation(
                inspected=True,
                coherent=True,
                controller_config_installed=previous_controller["controller_config_installed"],
                proxy_running=previous_controller["proxy_running"],
                proxy_healthy=previous_controller["proxy_healthy"],
                private_listener_only=previous_controller["private_listener_only"],
                activation_route_enabled=previous_controller["activation_route_enabled"],
                tls_ready=previous_controller["tls_ready"],
                base_compose_binding=base_compose_binding,
                api_runtime=_runtime_from_journal(previous_controller["api_runtime"]),
                proxy_runtime=_runtime_from_journal(previous_controller["proxy_runtime"]),
                migration_head=previous_controller["migration_head"],
                migration_head_ready=previous_controller["migration_head_ready"],
                configuration_artifact_digests=tuple(
                    tuple(item) for item in previous_controller["configuration_artifact_digests"]
                ),
            )
        return RollbackContext(
            transaction_id=journal["transaction_id"],
            container_runtime=container_runtime,
            compose_runtime=compose_runtime,
            before_worker_present=worker_present,
            before_worker_image_digest=worker_image,
            before_worker_running=worker_running,
            before_worker_healthy=worker_healthy,
            controller_override_preexisting=(before.get(ROLE_CONTROLLER_OVERRIDE) is not None),
            worker_override_preexisting=before.get(ROLE_WORKER_OVERRIDE) is not None,
            controller_changed=effects["controller_changed"],
            controller_runtime_changed=effects["controller_runtime_changed"],
            worker_config_changed=effects["worker_config_changed"],
            worker_recreated=effects["worker_recreated"],
            host_role=host_role,
            profile=profile,
            before_worker_observation=worker_baseline,
            before_controller_observation=controller_baseline,
            before_worker_generation_digest=worker_generation_digest,
            base_compose_binding=base_compose_binding,
            controller_env_binding=controller_env_binding,
        )

    def finish_rollback(self, *, proven: bool) -> None:
        journal, bound = self._load_journal()
        journal["status"] = "compensated" if proven else "recovery_required"
        updated = self._update_journal(journal, bound)
        if proven:
            self._remove_absolute(self._journal_path, expected=updated, journal=True)


def _rendered_by_role(rendered: ActivationRender) -> dict[str, RenderedArtifact]:
    if type(rendered) is not ActivationRender:
        _closed("render_type_invalid")
    mapping: dict[str, RenderedArtifact] = {}
    names = {
        "worker_compose_override": ROLE_WORKER_OVERRIDE,
        "admission_proxy_contract": ROLE_PROXY_CONTRACT,
        "controller_compose_override": ROLE_CONTROLLER_OVERRIDE,
    }
    for artifact in rendered.artifacts:
        role = names.get(artifact.name)
        if role is None or role in mapping or artifact.path != _ROLE_PATHS[role]:
            _closed("rendered_artifact_set_invalid")
        mapping[role] = artifact
    return mapping


def _worker_override_from_render(rendered: ActivationRender) -> RenderedArtifact:
    artifacts = _rendered_by_role(rendered)
    if set(artifacts) != {
        ROLE_WORKER_OVERRIDE,
        ROLE_PROXY_CONTRACT,
        ROLE_CONTROLLER_OVERRIDE,
    }:
        _closed("rendered_artifact_set_invalid")
    return artifacts[ROLE_WORKER_OVERRIDE]


def _validate_worker_override(worker_override: RenderedArtifact) -> _BoundFile:
    if (
        type(worker_override) is not RenderedArtifact
        or worker_override.name != "worker_compose_override"
        or worker_override.path != _ROLE_PATHS[ROLE_WORKER_OVERRIDE]
    ):
        _closed("worker_override_invalid")
    return _bound_from_render(worker_override)


def _bound_from_render(artifact: RenderedArtifact) -> _BoundFile:
    if (
        type(artifact) is not RenderedArtifact
        or artifact.uid != 0
        or artifact.mode not in {0o600, 0o640, 0o644}
        or artifact.gid < 0
        or artifact.sha256 != _digest(artifact.content)
        or not (1 <= len(artifact.content) <= _MAX_ARTIFACT_BYTES)
    ):
        _closed("rendered_artifact_invalid")
    return _BoundFile(
        artifact.content,
        artifact.sha256,
        artifact.uid,
        artifact.gid,
        artifact.mode,
    )


def _same_binding(actual: _BoundFile, expected: _BoundFile) -> bool:
    return actual.safe() == expected.safe()


def _same_optional_binding(actual: _BoundFile | None, expected: _BoundFile | None) -> bool:
    if actual is None or expected is None:
        return actual is expected
    return _same_binding(actual, expected)


def _bound_from_journal(raw: object, *, content: bool) -> _BoundFile | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        _closed("transaction_journal_malformed")
    expected = {"digest", "uid", "gid", "mode"}
    if content:
        expected.add("content_b64")
    # Before-images contain content; after-images deliberately contain bindings only.
    if set(raw) != expected:
        _closed("transaction_journal_malformed")
    digest = raw.get("digest")
    uid = raw.get("uid")
    gid = raw.get("gid")
    mode = raw.get("mode")
    if (
        not isinstance(digest, str)
        or not _SHA256.fullmatch(digest)
        or type(uid) is not int
        or type(gid) is not int
        or type(mode) is not int
        or uid < 0
        or gid < 0
        or mode not in {0o600, 0o640, 0o644}
    ):
        _closed("transaction_journal_malformed")
    data = b""
    if content:
        encoded = raw.get("content_b64")
        if not isinstance(encoded, str):
            _closed("transaction_journal_malformed")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            _closed("transaction_journal_malformed")
        if len(data) > _MAX_ARTIFACT_BYTES or _digest(data) != digest:
            _closed("transaction_journal_malformed")
    return _BoundFile(data, digest, uid, gid, mode)


def _fixed_input_from_journal(raw: object) -> FixedInputBinding:
    bound = _bound_from_journal(raw, content=False)
    if bound is None or bound.uid != 0:
        _closed("transaction_journal_malformed")
    return bound.fixed_input()


def _runtime_to_journal(
    value: ContainerRuntimeObservation | None,
) -> dict[str, object] | None:
    if value is None:
        return None
    return {
        "present": value.present,
        "image_digest": value.image_digest,
        "configuration_digest": value.configuration_digest,
        "private_configuration_binding": value.private_configuration_binding,
        "mounts_digest": value.mounts_digest,
        "networks_digest": value.networks_digest,
        "compose_project": value.compose_project,
        "compose_service": value.compose_service,
        "expected_image": value.expected_image,
        "hardening_verified": value.hardening_verified,
        "mounts_verified": value.mounts_verified,
        "endpoint_binding_verified": value.endpoint_binding_verified,
    }


def _runtime_from_journal(raw: object) -> ContainerRuntimeObservation | None:
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) != {
        "present",
        "image_digest",
        "configuration_digest",
        "private_configuration_binding",
        "mounts_digest",
        "networks_digest",
        "compose_project",
        "compose_service",
        "expected_image",
        "hardening_verified",
        "mounts_verified",
        "endpoint_binding_verified",
    }:
        _closed("transaction_journal_malformed")
    for key in (
        "present",
        "expected_image",
        "hardening_verified",
        "mounts_verified",
        "endpoint_binding_verified",
    ):
        if type(raw[key]) is not bool:
            _closed("transaction_journal_malformed")
    for key in (
        "image_digest",
        "configuration_digest",
        "mounts_digest",
        "networks_digest",
    ):
        if not isinstance(raw[key], str) or _SHA256.fullmatch(raw[key]) is None:
            _closed("transaction_journal_malformed")
    private_binding = raw["private_configuration_binding"]
    if not isinstance(private_binding, str) or _HMAC_SHA256.fullmatch(private_binding) is None:
        _closed("transaction_journal_malformed")
    for key in ("compose_project", "compose_service"):
        if not isinstance(raw[key], str) or _CONTAINER_NAME.fullmatch(raw[key]) is None:
            _closed("transaction_journal_malformed")
    return ContainerRuntimeObservation(
        present=raw["present"],
        image_digest=raw["image_digest"],
        configuration_digest=raw["configuration_digest"],
        private_configuration_binding=private_binding,
        mounts_digest=raw["mounts_digest"],
        networks_digest=raw["networks_digest"],
        compose_project=raw["compose_project"],
        compose_service=raw["compose_service"],
        expected_image=raw["expected_image"],
        hardening_verified=raw["hardening_verified"],
        mounts_verified=raw["mounts_verified"],
        endpoint_binding_verified=raw["endpoint_binding_verified"],
    )


def _runtime_identity_to_journal(value: ContainerRuntimeObservation) -> dict[str, object]:
    if type(value) is not ContainerRuntimeObservation or value.generation is None:
        _closed("transaction_runtime_binding_invalid")
    return {
        "generation": value.generation.model_dump(mode="json"),
        "runtime": _runtime_to_journal(value),
    }


def _runtime_identity_from_journal(raw: object) -> ContainerRuntimeObservation:
    if not isinstance(raw, dict) or set(raw) != {"generation", "runtime"}:
        _closed("transaction_journal_malformed")
    runtime = _runtime_from_journal(raw["runtime"])
    if runtime is None:
        _closed("transaction_journal_malformed")
    try:
        generation = WorkerGeneration.model_validate(raw["generation"])
    except Exception:
        _closed("transaction_journal_malformed")
    return replace(runtime, generation=generation)


def _same_runtime_identity(
    actual: ContainerRuntimeObservation | None,
    expected: ContainerRuntimeObservation | None,
) -> bool:
    if actual is None or expected is None:
        return actual is expected
    return bool(
        actual.generation == expected.generation
        and _runtime_journal_without_private(actual) == _runtime_journal_without_private(expected)
        and _same_private_configuration_binding(actual, expected)
    )


def _same_runtime_projection(
    left: _RuntimeProjection | None,
    right: _RuntimeProjection | None,
) -> bool:
    """Compare a double-sampled projection without ordinary equality on its private MAC."""

    if left is None or right is None:
        return left is right
    private_equal = bool(
        left.private_configuration_binding is None and right.private_configuration_binding is None
    ) or _private_configuration_bindings_equal(
        left.private_configuration_binding,
        right.private_configuration_binding,
    )
    return left == right and private_equal


def _same_worker_runtime_sample(
    left: tuple[_ContainerSnapshot, _RuntimeProjection | None],
    right: tuple[_ContainerSnapshot, _RuntimeProjection | None],
) -> bool:
    return left[0] == right[0] and _same_runtime_projection(left[1], right[1])


def _same_controller_runtime_sample(
    left: tuple[
        str,
        _ContainerSnapshot,
        _RuntimeProjection | None,
        _ContainerSnapshot,
        _RuntimeProjection | None,
    ],
    right: tuple[
        str,
        _ContainerSnapshot,
        _RuntimeProjection | None,
        _ContainerSnapshot,
        _RuntimeProjection | None,
    ],
) -> bool:
    return bool(
        left[0] == right[0]
        and left[1] == right[1]
        and _same_runtime_projection(left[2], right[2])
        and left[3] == right[3]
        and _same_runtime_projection(left[4], right[4])
    )


def _same_private_configuration_binding(
    actual: ContainerRuntimeObservation,
    expected: ContainerRuntimeObservation,
) -> bool:
    return _private_configuration_bindings_equal(
        actual.private_configuration_binding,
        expected.private_configuration_binding,
    )


def _private_configuration_bindings_equal(left: str | None, right: str | None) -> bool:
    return bool(
        isinstance(left, str)
        and isinstance(right, str)
        and _HMAC_SHA256.fullmatch(left) is not None
        and _HMAC_SHA256.fullmatch(right) is not None
        and hmac.compare_digest(left, right)
    )


def _runtime_journal_without_private(value: ContainerRuntimeObservation) -> dict[str, object]:
    raw = _runtime_to_journal(value)
    if raw is None:
        _closed("transaction_runtime_binding_invalid")
    public = dict(raw)
    public.pop("private_configuration_binding")
    return public


def _projection_matches_runtime(
    snapshot: _ContainerSnapshot,
    projection: _RuntimeProjection | None,
    expected: ContainerRuntimeObservation,
) -> bool:
    """Compare only facts obtained by Docker inspect to a journaled runtime after-image."""

    return bool(
        projection is not None
        and snapshot.present
        and expected.present
        and snapshot.generation() == expected.generation
        and snapshot.image_digest == expected.image_digest
        and projection.configuration_digest == expected.configuration_digest
        and _private_configuration_bindings_equal(
            projection.private_configuration_binding,
            expected.private_configuration_binding,
        )
        and projection.mounts_digest == expected.mounts_digest
        and projection.networks_digest == expected.networks_digest
        and projection.compose_project == expected.compose_project
        and projection.compose_service == expected.compose_service
    )


def _runtime_binding_complete(value: ContainerRuntimeObservation) -> bool:
    return bool(
        value.present
        and value.generation is not None
        and value.image_digest is not None
        and value.configuration_digest is not None
        and isinstance(value.private_configuration_binding, str)
        and _HMAC_SHA256.fullmatch(value.private_configuration_binding) is not None
        and value.mounts_digest is not None
        and value.networks_digest is not None
        and value.compose_project is not None
        and value.compose_service is not None
        and value.expected_image
    )


def _same_runtime_binding(
    actual: ContainerRuntimeObservation | None,
    expected: ContainerRuntimeObservation | None,
) -> bool:
    if actual is None or expected is None:
        return actual is expected
    return bool(
        actual.present == expected.present
        and actual.generation == expected.generation
        and actual.image_digest == expected.image_digest
        and actual.configuration_digest == expected.configuration_digest
        and _same_private_configuration_binding(actual, expected)
        and actual.mounts_digest == expected.mounts_digest
        and actual.networks_digest == expected.networks_digest
        and actual.compose_project == expected.compose_project
        and actual.compose_service == expected.compose_service
    )


def _same_runtime_posture(
    actual: ContainerRuntimeObservation | None,
    expected: ContainerRuntimeObservation | None,
) -> bool:
    if actual is None or expected is None:
        return actual is expected
    return bool(
        _runtime_journal_without_private(actual) == _runtime_journal_without_private(expected)
        and _same_private_configuration_binding(actual, expected)
    )


def _valid_state_receipt(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "classification",
        "root_created",
        "keys_created",
        "bundle_created",
        "root_device",
        "root_inode",
        "keys_inode",
        "bundle_inode",
    }:
        return False
    if value["classification"] not in {"created", "adopted"}:
        return False
    bool_keys = ("root_created", "keys_created", "bundle_created")
    int_keys = ("root_device", "root_inode", "keys_inode", "bundle_inode")
    return all(type(value[key]) is bool for key in bool_keys) and all(
        type(value[key]) is int and value[key] >= 0 for key in int_keys
    )


def _roles_for(host_role: LocalHostRole) -> tuple[str, ...]:
    if host_role is LocalHostRole.controller:
        return _CONTROLLER_MUTABLE_ROLES
    if host_role is LocalHostRole.worker:
        return _WORKER_MUTABLE_ROLES
    _closed("local_host_role_invalid")


def _valid_journal_digest_pairs(value: object, allowed_roles: set[str]) -> bool:
    if not isinstance(value, list):
        return False
    parsed: list[tuple[str, str]] = []
    for item in value:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not isinstance(item[0], str)
            or item[0] not in allowed_roles
            or not isinstance(item[1], str)
            or _SHA256.fullmatch(item[1]) is None
        ):
            return False
        parsed.append((item[0], item[1]))
    return len(parsed) == len(set(parsed)) and len({role for role, _digest_value in parsed}) == len(
        parsed
    )


# The base journal key set shared by every role.  A controller journal additionally carries exactly
# one "controller_env" binding (the fixed environment file's private digest/uid/gid/mode); a worker
# journal carries none.  Neither role admits any other key.
_COMMON_JOURNAL_KEYS = frozenset(
    {
        "schema",
        "transaction_id",
        "host_role",
        "status",
        "render_manifest_sha256",
        "profile_content_digest",
        "base_compose",
        "before",
        "after",
        "effects",
        "operation_count",
        "state_receipt",
        "execution",
        "before_worker",
        "before_controller",
        "runtime_after",
        "worker_tls_proof",
    }
)


def _validate_journal(value: dict[str, Any]) -> None:
    if not isinstance(value, dict):
        _closed("transaction_journal_malformed")
    # Determine the host role first so the exact key set is role-dependent: a controller journal
    # MUST carry exactly one controller_env binding, a worker journal MUST NOT carry it at all.
    # This lets the fixed controller environment binding survive staging while keeping the worker
    # schema unchanged; no arbitrary extra key is admitted for either role.
    try:
        host_role = LocalHostRole(value["host_role"])
    except (ValueError, TypeError, KeyError):
        _closed("transaction_journal_malformed")
    expected_keys = set(_COMMON_JOURNAL_KEYS)
    if host_role is LocalHostRole.controller:
        expected_keys.add("controller_env")
    if set(value) != expected_keys:
        _closed("transaction_journal_malformed")
    if value["schema"] != _JOURNAL_SCHEMA or value["status"] not in {
        "staged",
        "mutating",
        "committed",
        "recovery_required",
        "compensated",
    }:
        _closed("transaction_journal_malformed")
    try:
        transaction = uuid.UUID(value["transaction_id"])
    except (ValueError, AttributeError, TypeError):
        _closed("transaction_journal_malformed")
    if str(transaction) != value["transaction_id"] or transaction.version != 4:
        _closed("transaction_journal_malformed")
    if host_role is LocalHostRole.controller:
        # The controller environment binding is a private FixedInputBinding — digest/uid/gid/mode
        # only, never the bytes.  _fixed_input_from_journal rejects any content_b64 or extra field
        # and requires uid 0 with a valid sha256 digest and bounded integer fields; here we pin the
        # secret-bearing mode to exactly 0600 or 0640 (never a world-readable 0644).
        controller_env = _fixed_input_from_journal(value["controller_env"])
        if controller_env.mode not in {0o600, 0o640}:
            _closed("transaction_journal_malformed")
    if not isinstance(value["render_manifest_sha256"], str) or not _SHA256.fullmatch(
        value["render_manifest_sha256"]
    ):
        _closed("transaction_journal_malformed")
    if not isinstance(value["profile_content_digest"], str) or not _SHA256.fullmatch(
        value["profile_content_digest"]
    ):
        _closed("transaction_journal_malformed")
    _fixed_input_from_journal(value["base_compose"])
    before = value["before"]
    after = value["after"]
    if (
        not isinstance(before, dict)
        or not isinstance(after, dict)
        or set(before) != set(_roles_for(host_role))
        or set(after) != set(_roles_for(host_role))
    ):
        _closed("transaction_journal_malformed")
    for role in _roles_for(host_role):
        if (
            host_role is LocalHostRole.controller
            and role in {ROLE_ADMISSION_SERVER_KEY, ROLE_ADMISSION_PROXY_GATE}
            and before[role] is not None
        ):
            _closed("transaction_journal_malformed")
        _bound_from_journal(before[role], content=True)
        _bound_from_journal(after[role], content=False)
    effects = value["effects"]
    if (
        not isinstance(effects, dict)
        or set(effects)
        != {
            "effects_started",
            "controller_changed",
            "controller_runtime_changed",
            "worker_config_changed",
            "worker_recreated",
            "evidence_committed",
        }
        or any(type(item) is not bool for item in effects.values())
    ):
        _closed("transaction_journal_malformed")
    if type(value["operation_count"]) is not int or not (0 <= value["operation_count"] <= 100):
        _closed("transaction_journal_malformed")
    runtime_after = value["runtime_after"]
    if runtime_after is not None:
        if not isinstance(runtime_after, dict):
            _closed("transaction_journal_malformed")
        if host_role is LocalHostRole.controller:
            if set(runtime_after) != {"api", "proxy"} or not effects["controller_runtime_changed"]:
                _closed("transaction_journal_malformed")
            _runtime_identity_from_journal(runtime_after["api"])
            _runtime_identity_from_journal(runtime_after["proxy"])
        else:
            if set(runtime_after) != {"worker"} or not effects["worker_recreated"]:
                _closed("transaction_journal_malformed")
            _runtime_identity_from_journal(runtime_after["worker"])
    if host_role is LocalHostRole.worker:
        if not _valid_state_receipt(value["state_receipt"]):
            _closed("transaction_journal_malformed")
    elif value["state_receipt"] is not None:
        _closed("transaction_journal_malformed")
    execution = value["execution"]
    if not isinstance(execution, dict) or set(execution) != {
        "container_path",
        "container_digest",
        "compose_path",
        "compose_digest",
    }:
        _closed("transaction_journal_malformed")
    for key in ("container_path", "compose_path"):
        path = execution[key]
        if not isinstance(path, str) or not path.startswith("/") or ".." in path.split("/"):
            _closed("transaction_journal_malformed")
    for key in ("container_digest", "compose_digest"):
        digest = execution[key]
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            _closed("transaction_journal_malformed")
    worker = value["before_worker"]
    controller = value["before_controller"]
    worker_tls_proof = value["worker_tls_proof"]
    if host_role is LocalHostRole.worker:
        worker_bool_keys = {
            "present",
            "running",
            "healthy",
            "controlled_integration_enabled",
            "worker_managed_bundle_enabled",
            "fixed_worker_paths",
            "state_mount_read_write_only_worker",
            "ca_mount_read_only_worker",
            "discovery_mount_absent_from_other_containers",
            "bundle_prep_loop_started",
            "operator_service_present",
            "operator_container_present",
            "operator_registration_present",
            "operator_queue_polled",
            "generic_activation_subprocess_sealed",
            "generic_executor_subprocess_sealed",
            "plan_only_process_sealed",
            "real_provisioning_enabled",
            "artifacts_prepared",
            "worker_config_installed",
            "worker_recreation_required",
            "worker_generation_changed",
        }
        if not isinstance(worker, dict) or set(worker) != worker_bool_keys | {
            "image_digest",
            "generation_digest",
            "ordinary_queues",
            "configuration_artifact_digests",
            "runtime",
        }:
            _closed("transaction_journal_malformed")
        if any(type(worker[key]) is not bool for key in worker_bool_keys):
            _closed("transaction_journal_malformed")
        if (
            not isinstance(worker["image_digest"], str)
            or not _SHA256.fullmatch(worker["image_digest"])
            or not isinstance(worker["generation_digest"], str)
            or not _SHA256.fullmatch(worker["generation_digest"])
            or worker["ordinary_queues"] != [ORDINARY_TASK_QUEUE]
            or not _valid_journal_digest_pairs(
                worker["configuration_artifact_digests"],
                {
                    ROLE_PROFILE,
                    ROLE_WORKER_OVERRIDE,
                    ROLE_WORKER_RUNTIME_OVERLAY,
                    ROLE_ADMISSION_CA,
                },
            )
            or controller is not None
        ):
            _closed("transaction_journal_malformed")
        if worker_tls_proof is not None:
            if not isinstance(worker_tls_proof, dict) or set(worker_tls_proof) != {
                "ca_certificate_fingerprint",
                "expected_server_certificate_fingerprint",
                "expected_server_dns_identity",
            }:
                _closed("transaction_journal_malformed")
            if not all(
                isinstance(worker_tls_proof[key], str) and _SHA256.fullmatch(worker_tls_proof[key])
                for key in (
                    "ca_certificate_fingerprint",
                    "expected_server_certificate_fingerprint",
                )
            ):
                _closed("transaction_journal_malformed")
            try:
                validate_dns_identity(worker_tls_proof["expected_server_dns_identity"])
            except (TypeError, ValueError):
                _closed("transaction_journal_malformed")
        _runtime_from_journal(worker["runtime"])
    else:
        if (
            worker is not None
            or not isinstance(controller, dict)
            or set(controller)
            != {
                "controller_config_installed",
                "proxy_running",
                "proxy_healthy",
                "private_listener_only",
                "tls_ready",
                "activation_route_enabled",
                "api_runtime",
                "proxy_runtime",
                "migration_head",
                "migration_head_ready",
                "configuration_artifact_digests",
            }
        ):
            _closed("transaction_journal_malformed")
        if any(
            type(controller[key]) is not bool
            for key in (
                "controller_config_installed",
                "proxy_running",
                "proxy_healthy",
                "private_listener_only",
                "tls_ready",
                "activation_route_enabled",
                "migration_head_ready",
            )
        ) or not _valid_journal_digest_pairs(
            controller["configuration_artifact_digests"],
            {
                ROLE_PROFILE,
                ROLE_CONTROLLER_OVERRIDE,
                ROLE_PROXY_CONTRACT,
                ROLE_ADMISSION_CA,
                ROLE_ADMISSION_SERVER_CERTIFICATE,
            },
        ):
            _closed("transaction_journal_malformed")
        if controller["migration_head"] not in {
            None,
            _API_BASELINE_MIGRATION_HEAD,
            _API_MIGRATION_HEAD,
        }:
            _closed("transaction_journal_malformed")
        _runtime_from_journal(controller["api_runtime"])
        _runtime_from_journal(controller["proxy_runtime"])
        if worker_tls_proof is not None:
            _closed("transaction_journal_malformed")


__all__ = [
    "CONTROLLER_BASE_COMPOSE_PATH",
    "WORKER_BASE_COMPOSE_PATH",
    "EVIDENCE_ATTESTATION_PATH",
    "ArtifactPosture",
    "RollbackContext",
    "ActivationArtifactStore",
    "TLSHandshakeProbe",
    "StrictTLSHandshakeProbe",
    "MountSourceIdentityClassification",
    "MountSourceIdentityResolver",
    "PosixMountSourceIdentityResolver",
    "LocalHostRole",
    "LocalActivationAdapter",
    "PosixActivationArtifactStore",
]
