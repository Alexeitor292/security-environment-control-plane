"""Strict, topology-safe, immutable commissioning evidence (SECP-PR5C, ADR-023, defects #3, #5).

Evidence is the auditable proof of the PREPARED (never activated) state. Commissioning contacts no
database, so this is a file-based record — but it is strictly validated (pydantic ``extra="forbid"``
+ ``strict=True``, so JSON ``true``/``false`` only, never ``0``/``1``; closed role vocabulary;
unique
roles; exact digest/queue/version/timestamp shapes) and runs the forbidden-secret scanner on load.

It contains NO raw path and NO topology value: each managed object is a stable ROLE + a
topology-safe
``path_binding`` digest (``sha256`` over role+resolved-path) — status/rollback RE-DERIVE the actual
path from the trusted locations + role and compare the binding. Also stored: contract+tool version;
source revision+tree; the three image content DIGESTS; descriptor/plan/render-manifest/entrypoint-
template digests; per-object content digest + ownership/mode + a ``created`` flag (was this object
created by THIS install — the actual transaction ownership set for rollback); ordinary+operator
queue
NAMES; ``activation_status`` EXACTLY ``not_started`` or ``prepared``; and REAL false seals.
"""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from secp_commissioning import TOOL_VERSION
from secp_commissioning.canonical import is_sha256_digest, sha256_digest
from secp_commissioning.descriptor import CONTRACT_VERSION, scan_forbidden
from secp_commissioning.errors import CommissioningError, reject
from secp_commissioning.locations import (
    OPERATOR_FILE_LAYOUT,
    OPERATOR_ROOT_MODE,
    ROLE_OPERATOR_ROOT,
)
from secp_commissioning.operator_template import entrypoint_template_digest

_HEX_SHA = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_QUEUE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[0-9:+.Z-]{0,12}$")

STATUS_NOT_STARTED = "not_started"
STATUS_PREPARED = "prepared"

_FILE_ROLES = tuple(role for role, _b, _m in OPERATOR_FILE_LAYOUT)
_DIR_ROLES = (ROLE_OPERATOR_ROOT,)
_ROLE_MODE = {role: mode for role, _b, mode in OPERATOR_FILE_LAYOUT}
_MAX_FILES = 32
_MAX_DIRS = 8


class EvidenceError(CommissioningError):
    """An evidence record failed strict validation (bounded reason code; never a value)."""


def path_binding_digest(role: str, abs_path: str) -> str:
    """A topology-safe binding of a role to its resolved path (the raw path is never stored)."""
    return sha256_digest({"v": "secp.commissioning.path/v1", "role": role, "path": abs_path})


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _v_digest(v: str) -> str:
    if not is_sha256_digest(v):
        raise ValueError("expected a sha256:<64-hex> digest")
    return v


class InstalledFileRecord(_Strict):
    role: str
    sha256: str
    path_binding: str
    owner_uid: int
    owner_gid: int
    mode: int
    created: bool

    _vd = field_validator("sha256", "path_binding")(staticmethod(_v_digest))

    @field_validator("role")
    @classmethod
    def _v_role(cls, v: str) -> str:
        if v not in _FILE_ROLES:
            raise ValueError("unknown installed-file role")
        return v


class ManagedDirectoryRecord(_Strict):
    role: str
    path_binding: str
    owner_uid: int
    owner_gid: int
    mode: int
    created: bool

    _vd = field_validator("path_binding")(staticmethod(_v_digest))

    @field_validator("role")
    @classmethod
    def _v_role(cls, v: str) -> str:
        if v not in _DIR_ROLES:
            raise ValueError("unknown managed-directory role")
        return v


class CommissioningEvidence(_Strict):
    """The strict, topology-safe, immutable evidence record."""

    contract_version: str
    tool_version: str
    activation_status: str
    deployment_id: str
    source_sha: str
    source_tree_sha: str
    control_plane_image_digest: str
    ordinary_worker_image_digest: str
    operator_image_digest: str
    descriptor_digest: str
    plan_digest: str
    render_manifest_digest: str
    entrypoint_template_digest: str
    installed_files: list[InstalledFileRecord]
    managed_directories: list[ManagedDirectoryRecord]
    ordinary_task_queue: str
    operator_task_queue: str
    operator_service_enabled: bool
    operator_service_running: bool
    external_contacts_performed: bool
    workflows_submitted: bool
    plan_execution_performed: bool
    recorded_at: str

    _vd = field_validator(
        "control_plane_image_digest",
        "ordinary_worker_image_digest",
        "operator_image_digest",
        "descriptor_digest",
        "plan_digest",
        "render_manifest_digest",
        "entrypoint_template_digest",
    )(staticmethod(_v_digest))

    @field_validator("contract_version")
    @classmethod
    def _v_contract(cls, v: str) -> str:
        if v != CONTRACT_VERSION:
            raise ValueError("unexpected contract version")
        return v

    @field_validator("activation_status")
    @classmethod
    def _v_status(cls, v: str) -> str:
        if v not in (STATUS_NOT_STARTED, STATUS_PREPARED):
            raise ValueError("activation_status must be not_started or prepared")
        return v

    # Format-pin the scalar strings so a tampered on-disk record cannot smuggle a path / URL /
    # endpoint / topology value into an otherwise-free string field.
    @field_validator("tool_version")
    @classmethod
    def _v_tool_version(cls, v: str) -> str:
        # Not merely a semver SHAPE — the record must carry the EXACT current tool version, so a
        # stale record built by a different implementation fails closed on load (defect #5/#7).
        if not _VERSION.match(v) or v != TOOL_VERSION:
            raise ValueError("tool_version is not the current tool version")
        return v

    @field_validator("entrypoint_template_digest")
    @classmethod
    def _v_template_digest(cls, v: str) -> str:
        # EXACT current entrypoint-template digest, not just a sha256 shape.
        if not is_sha256_digest(v) or v != entrypoint_template_digest():
            raise ValueError("entrypoint_template_digest is not the current template digest")
        return v

    @field_validator("source_sha", "source_tree_sha")
    @classmethod
    def _v_sha(cls, v: str) -> str:
        if not _HEX_SHA.match(v):
            raise ValueError("expected a 40/64-char hex git object id")
        return v

    @field_validator("deployment_id")
    @classmethod
    def _v_deployment(cls, v: str) -> str:
        if not _UUID.match(v):
            raise ValueError("deployment_id must be a UUID")
        return v

    @field_validator("ordinary_task_queue", "operator_task_queue")
    @classmethod
    def _v_queue(cls, v: str) -> str:
        if not _QUEUE.match(v):
            raise ValueError("task queue has an invalid shape")
        return v

    @field_validator("recorded_at")
    @classmethod
    def _v_recorded_at(cls, v: str) -> str:
        # Shape-pin THEN actually parse it (defect #5): a regex-only check would accept a
        # syntactically-plausible but invalid instant. It must be a real, timezone-aware ISO-8601
        # instant (explicit UTC ``Z`` or a numeric offset), never a naive local time.
        if not _TIMESTAMP.match(v):
            raise ValueError("recorded_at must be an ISO-8601 timestamp")
        try:
            parsed = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("recorded_at is not a valid ISO-8601 instant") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("recorded_at must be timezone-aware (UTC or an explicit offset)")
        return v

    @field_validator("installed_files")
    @classmethod
    def _v_files(cls, v: list[InstalledFileRecord]) -> list[InstalledFileRecord]:
        if len(v) > _MAX_FILES:
            raise ValueError("too many installed files")
        roles = [f.role for f in v]
        if len(set(roles)) != len(roles):
            raise ValueError("duplicate installed-file role")
        return v

    @field_validator("managed_directories")
    @classmethod
    def _v_dirs(cls, v: list[ManagedDirectoryRecord]) -> list[ManagedDirectoryRecord]:
        if len(v) > _MAX_DIRS:
            raise ValueError("too many managed directories")
        roles = [d.role for d in v]
        if len(set(roles)) != len(roles):
            raise ValueError("duplicate managed-directory role")
        return v

    @field_validator(
        "operator_service_enabled",
        "operator_service_running",
        "external_contacts_performed",
        "workflows_submitted",
        "plan_execution_performed",
    )
    @classmethod
    def _v_seals_false(cls, v: bool) -> bool:
        if v is not False:  # every seal is ALWAYS False in this milestone
            raise ValueError("seal must be false")
        return v

    @model_validator(mode="after")
    def _v_semantic_completeness(self) -> CommissioningEvidence:
        # The ordinary + operator queues are ALWAYS distinct (a shared queue would let the sealed
        # worker pick up controlled-live work — ADR-022 §12).
        if self.ordinary_task_queue == self.operator_task_queue:
            raise ValueError("ordinary and operator task queues must be distinct")
        # A PREPARED record must bind EXACTLY the reviewed role set — no missing, extra, or dup
        # roles — with the exact role-specific root ownership + mode. An incomplete prepared record
        # (e.g. an entrypoint-less bundle) can no longer masquerade as a valid prepared state
        # (defect #5).
        if self.activation_status == STATUS_PREPARED:
            file_roles = {f.role for f in self.installed_files}
            if file_roles != set(_FILE_ROLES):
                raise ValueError("prepared evidence installed-file roles are not exactly complete")
            dir_roles = {d.role for d in self.managed_directories}
            if dir_roles != set(_DIR_ROLES):
                raise ValueError(
                    "prepared evidence managed-directory roles are not exactly complete"
                )
            for f in self.installed_files:
                if f.owner_uid != 0 or f.owner_gid != 0 or f.mode != _ROLE_MODE[f.role]:
                    raise ValueError("prepared installed-file ownership/mode is not exact")
            for d in self.managed_directories:
                if d.owner_uid != 0 or d.owner_gid != 0 or d.mode != OPERATOR_ROOT_MODE:
                    raise ValueError("prepared managed-directory ownership/mode is not exact")
        return self

    def canonical(self) -> dict:
        return self.model_dump(mode="json")

    def digest(self) -> str:
        payload = {k: v for k, v in self.canonical().items() if k != "recorded_at"}
        return sha256_digest(payload)

    def __repr__(self) -> str:
        return (
            f"CommissioningEvidence(status={self.activation_status}, "
            f"plan={self.plan_digest}, digest={self.digest()})"
        )


def evidence_from_dict(data: object) -> CommissioningEvidence:
    """Strictly validate + re-check an evidence record from its canonical dict (read from disk).

    A tampered record — a flipped seal, an injected status, an int-as-bool, an unknown field, a bad
    digest, a duplicate role, or a smuggled secret — fails closed on load.
    """
    if not isinstance(data, dict):
        reject("evidence_not_object")
    scan_forbidden(data)  # no secret-shaped field/value may enter, even in evidence
    from pydantic import ValidationError

    try:
        return CommissioningEvidence.model_validate(data)
    except ValidationError as exc:
        errors = exc.errors()
        etype = errors[0].get("type") if errors else None
        loc = errors[0].get("loc", ()) if errors else ()
        # For an UNKNOWN field the leaf key is attacker-controlled (a tampered record could name it
        # a
        # topology string), so the reason names only the KNOWN parent path — never the offending
        # key.
        if etype == "extra_forbidden":
            parent = ".".join(str(p) for p in loc[:-1] if isinstance(p, str)) or "evidence"
            raise EvidenceError("evidence_unknown_field:" + _safe(parent)) from None
        field = ".".join(str(p) for p in loc if isinstance(p, str)) or "evidence"
        raise EvidenceError("evidence_invalid:" + _safe(field)) from None


def _safe(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.]", "", text)[:60]
