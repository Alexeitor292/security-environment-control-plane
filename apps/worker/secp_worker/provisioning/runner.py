"""ProvisioningRunner protocol and result types (worker-only, ADR-012).

The protocol is transport/tool-neutral: a future real ``OpenTofuRunner`` (pinned
binary + pinned provider versions, worker-only secret resolution) implements the
same surface. Result types are secret-free.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field


class RunnerError(Exception):
    """A runner failure. Messages must be redacted (never include secrets)."""


class RunnerValidationResult(BaseModel):
    ok: bool
    errors: list[str] = Field(default_factory=list)


class RunnerChangeSet(BaseModel):
    """Deterministic dry-run change set (plan). Secret-free.

    ``change_set_hash`` / ``workspace_hash`` / ``plan_digest`` are populated by the real
    ``OpenTofuRunner`` (SECP-002B-1A) so a change set can be bound to a human approval;
    the ``FakeOpenTofuRunner`` (B0) leaves them empty.
    """

    operation_id: str
    creates: list[dict] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)
    change_set_hash: str = ""
    workspace_hash: str = ""
    plan_digest: str = ""
    kind: str = "apply"


class RunnerApplyResult(BaseModel):
    operation_id: str
    ok: bool
    resources: list[dict] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)
    idempotent_noop: bool = False


class RunnerDestroyResult(BaseModel):
    operation_id: str
    ok: bool
    destroyed: list[str] = Field(default_factory=list)
    idempotent_noop: bool = False


class RunnerStatus(BaseModel):
    operation_id: str
    state: str
    exists: bool = False
    summary: dict = Field(default_factory=dict)


@runtime_checkable
class ProvisioningRunner(Protocol):
    """Worker-only provisioning runner. Never imported by ``apps/api``."""

    name: str

    def validate(self, manifest: dict) -> RunnerValidationResult: ...

    def dry_run(self, manifest: dict, *, operation_id: str) -> RunnerChangeSet: ...

    def apply(self, manifest: dict, *, operation_id: str) -> RunnerApplyResult: ...

    def destroy(self, manifest: dict, *, operation_id: str) -> RunnerDestroyResult: ...

    def status(self, operation_id: str) -> RunnerStatus: ...
