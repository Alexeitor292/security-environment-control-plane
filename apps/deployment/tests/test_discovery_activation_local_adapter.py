"""Hermetic tests for the closed PR5F local Docker/Compose adapter.

Every process, filesystem, clock, and TLS boundary is fake.  These tests never create a
subprocess, socket, Docker client, Compose client, or production-path artifact.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime

import pytest
from secp_discovery_activation import (
    PACKAGE_CONTRACT_VERSION,
)
from secp_discovery_activation import (
    local_adapter as local_adapter_module,
)
from secp_discovery_activation import split_engine as split_engine_module
from secp_discovery_activation.adapters import (
    ActivationAdapterError,
    ContainerRuntimeObservation,
    FixedInputBinding,
    HostObservation,
    MutationReceipt,
)
from secp_discovery_activation.evidence import WorkerGeneration
from secp_discovery_activation.handoff import ControllerOffer, HandoffAttestation, WorkerResult
from secp_discovery_activation.layout import PRODUCTION_LAYOUT
from secp_discovery_activation.local_adapter import (
    CONTROLLER_BASE_COMPOSE_PATH,
    CONTROLLER_ENV_FILE_PATH,
    ArtifactPosture,
    LocalActivationAdapter,
    LocalHostRole,
    MountSourceIdentityClassification,
    RollbackContext,
    StrictTLSHandshakeProbe,
    _BoundFile,
)
from secp_discovery_activation.profile import DeploymentProfile, parse_deployment_profile
from secp_discovery_activation.render import (
    ActivationRender,
    RenderedArtifact,
    render_activation,
    render_worker_compose_override,
)
from secp_discovery_activation.state import (
    InMemoryWorkerStateFilesystem,
    PreparedStateReceipt,
)
from secp_discovery_activation.tls import (
    ValidatedAdmissionCA,
    ValidatedTLSMaterial,
    generate_tls_material,
    import_admission_ca,
)
from secp_operator_deployment.host_process import CommandResult
from secp_operator_deployment.pinned_exec import ExecutablePin

_CID_BEFORE = "a" * 64
_CID_AFTER = "b" * 64
_IMAGE = "sha256:" + "1" * 64
_STARTED_BEFORE = "2026-07-19T12:00:00Z"
_STARTED_AFTER = "2026-07-19T12:01:00Z"
_NODE_ID = "22222222-2222-4222-8222-222222222222"
_API_ID = "d" * 64
_API_BASELINE_ID = "e" * 64
_API_RESTORED_ID = "f" * 64
_API_NAME = "secp-controller-api-1"
_PROXY_ID = "c" * 64
_BASE_COMPOSE = FixedInputBinding("sha256:" + "e" * 64, 0, 0, 0o640)
_CONTROLLER_ENV = FixedInputBinding("sha256:" + "d" * 64, 0, 0, 0o600)


def _identity_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class FakeMountSourceIdentityResolver:
    """Hermetic identity classifier; aliases model bind/hardlink-equivalent endpoints."""

    def __init__(self) -> None:
        self.aliases: dict[str, set[str]] = {}
        self.drift = False
        self.calls: list[tuple[tuple[str, ...], tuple[str, ...]]] = []

    def classify(
        self,
        *,
        source_paths: tuple[str, ...],
        protected_paths: tuple[str, ...],
    ) -> tuple[MountSourceIdentityClassification, ...]:
        self.calls.append((source_paths, protected_paths))
        epoch = len(self.calls) if self.drift else 0
        protected_bindings = tuple(
            _identity_digest(f"protected:{path}:{epoch}") for path in protected_paths
        )
        return tuple(
            MountSourceIdentityClassification(
                source_binding=_identity_digest(f"source:{source}:{epoch}"),
                protected_bindings=protected_bindings,
                overlaps=tuple(
                    any(
                        local_adapter_module._lexical_path_overlap(candidate, protected)
                        for candidate in {source, *self.aliases.get(source, set())}
                    )
                    for protected in protected_paths
                ),
            )
            for source in source_paths
        )


def _runtime_projection(
    *,
    service: str,
    user: str,
    extra_hosts: list[str] | None = None,
    command_marker: str = "service",
    read_only: bool = True,
    environment: list[str] | None = None,
    tmpfs: dict[str, str] | None = None,
    project: str,
) -> str:
    values = (
        {
            "Cmd": ["python", "-m", command_marker],
            "Entrypoint": None,
            "Env": environment or ["SECP_RUNTIME_MODE=reviewed"],
            "Healthcheck": {"Test": ["CMD", "health"]},
            "Labels": {
                "com.docker.compose.project": project,
                "com.docker.compose.service": service,
            },
            "User": user,
            "WorkingDir": "/app",
        },
        {
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "Devices": None,
            "Dns": None,
            "ExtraHosts": extra_hosts,
            "NetworkMode": "secp_default",
            "PidsLimit": 128 if service != "api" else None,
            "PortBindings": None,
            "Privileged": False,
            "ReadonlyRootfs": read_only,
            "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": tmpfs,
        },
    )
    return "\n".join(json.dumps(value, separators=(",", ":")) for value in values) + "\n"


def _workload_identity_projection(
    *,
    container_id: str,
    executable: str,
    arguments: list[str] | None = None,
    image: str = "registry.internal.test/secp/runtime:reviewed",
    entrypoint: list[str] | None = None,
    command: list[str] | None = None,
    environment: list[str] | None = None,
    service: str,
) -> str:
    values = (
        container_id,
        executable,
        arguments or [],
        {
            "Image": image,
            "Entrypoint": entrypoint,
            "Cmd": command,
            "Env": environment or [],
            "Labels": {
                "com.docker.compose.project": "secp-test",
                "com.docker.compose.service": service,
            },
        },
    )
    return "\n".join(json.dumps(value, separators=(",", ":")) for value in values) + "\n"


def _profile(**overrides: object) -> DeploymentProfile:
    raw: dict[str, object] = {
        "contract_version": PACKAGE_CONTRACT_VERSION,
        "activation_enabled": True,
        "ordinary_worker_image_digest": _IMAGE,
        "worker_runtime_overlay_digest": "sha256:" + "5" * 64,
        "ordinary_runtime_uid": 1001,
        "ordinary_runtime_gid": 1001,
        "worker_node_organization": "11111111-1111-4111-8111-111111111111",
        "worker_node_label": "site-worker-01",
        "admission_endpoint": "https://admission.internal.test:8443",
        "admission_listener_bind": "10.20.30.40:8443",
        "controller_api_upstream": "http://api:8080",
        "controller_compose_project": "secp-controller",
        "worker_compose_project": "secp-worker",
        "admission_certificate_dns_name": "admission.internal.test",
        "admission_proxy_image": ("registry.internal.test/secp/admission-proxy@sha256:" + "2" * 64),
        "admission_proxy_runtime_image_digest": "sha256:" + "8" * 64,
        "controller_api_baseline_image_digest": "sha256:" + "7" * 64,
        "controller_api_runtime_image_digest": "sha256:" + "9" * 64,
        "controller_api_image": "registry.internal.test/secp/api@sha256:" + "6" * 64,
        "admission_proxy_runtime_uid": 1002,
        "admission_proxy_runtime_gid": 1002,
        "container_runtime_executable": "/usr/bin/docker",
        "container_runtime_executable_digest": "sha256:" + "3" * 64,
        "compose_executable": "/usr/libexec/docker/cli-plugins/docker-compose",
        "compose_executable_digest": "sha256:" + "4" * 64,
    }
    raw.update(overrides)
    return parse_deployment_profile(raw)


@pytest.fixture()
def tls_material() -> ValidatedTLSMaterial:
    return generate_tls_material(
        dns_identity="admission.internal.test",
        validity_days=30,
        now=datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
    )


def _worker_ca(material: ValidatedTLSMaterial) -> ValidatedAdmissionCA:
    return import_admission_ca(
        ca_certificate_pem=material.ca_certificate_pem(),
        now=datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
    )


def _probe(*, published: bool = True, enabled: bool = True) -> str:
    node = (
        {
            "id": _NODE_ID,
            "revision": 3,
            "ssh_public_key_fingerprint": "SHA256:" + "A" * 43,
            "admission_anchor_fingerprint": "sha256:" + "5" * 64,
            "public_material_only": True,
        }
        if published
        else None
    )
    return json.dumps(
        {
            "contract_version": "secp.worker.activation-probe/v1",
            "ok": published and enabled,
            "reason_code": "ok" if published and enabled else "activation_disabled",
            "ordinary_task_queue": "secp-orchestration",
            "configuration": {
                "controlled_integration_enabled": enabled,
                "worker_managed_bundle": enabled,
                "fixed_paths_valid": enabled,
                "admission_configured": enabled,
                "runtime_overlay_loaded": enabled,
            },
            "fixed_paths": {
                "worker_state": "/var/run/secp",
                "worker_keys": "/var/run/secp/worker-keys",
                "discovery_bundle": "/var/run/secp/discovery-bundle",
                "worker_identity_key": "/var/run/secp/worker-keys/admission_key",
                "worker_identity_anchor": "/var/run/secp/worker-keys/admission_anchor",
                "admission_ca": "/etc/secp/admission-ca.pem",
                "runtime_overlay": "/opt/secp/secp-pr5f-runtime-overlay.zip",
                "health_marker": "/tmp/secp-worker.ready",
            },
            "health": {
                "ready": True,
                "ordinary_queue": True,
                "bundle_prep_loop_started": True,
            },
            "safety_seals": {
                "generic_activation_subprocess_sealed": True,
                "generic_executor_subprocess_sealed": True,
                "plan_only_process_sealed": False,
                "real_provisioning_disabled": True,
            },
            "worker_keys": {
                "metadata_safe": True,
                "public_node_matches_local_keys": True,
            },
            "worker_node": node,
            "runtime_overlay_sha256": "sha256:" + "5" * 64 if enabled else None,
            "lifecycle": {
                "bootstrap_status": None,
                "worker_identity_approved": False,
                "worker_identity_current": False,
                "live_read_authorization_approved": False,
                "live_read_authorization_current": False,
                "bundle_available": False,
                "discovery_contacted": False,
                "candidate_executable": None,
            },
            "probe_effects": {
                "operator_registered": False,
                "operator_queue_polled": False,
                "workflow_submitted": False,
                "run_plan_generation_called": False,
                "opentofu_executed": False,
                "proxmox_contacted": False,
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    )


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[ExecutablePin, tuple[str, ...], int, int]] = []
        self.generation = "before"
        self.fail_compose = False
        self.malformed_worker = False
        self.proxy_running = True
        self.proxy_container_id = _PROXY_ID
        self.worker_after_id = _CID_AFTER
        self.worker_healthy = True
        self.tls_ca_fingerprint = "sha256:" + "0" * 64
        self.tls_server_fingerprint = "sha256:" + "6" * 64
        # Docker container ``.Image`` is a config/image ID, deliberately distinct from each
        # digest-qualified reference's OCI manifest digest in the profile.
        self.api_image = "sha256:" + "9" * 64
        self.api_container_id = _API_ID
        self.proxy_image = "sha256:" + "8" * 64
        self.worker_extra_hosts = ["admission.internal.test:10.20.30.40"]
        self.proxy_read_only = True
        self.migration_ready = True
        self.rollback_compatible = True
        self.fence_engaged = True
        self.fence_output_override: str | None = None
        self.fence_observe_replacement_id: str | None = None
        self.fail_fence = False
        self.fail_downgrade = False
        self.worker_runtime_drift = False
        self.worker_environment = ["SECP_RUNTIME_MODE=reviewed"]
        self.worker_runtime_calls = 0
        self.worker_private_runtime_drift = False
        self.proxy_runtime_calls = 0
        self.proxy_private_runtime_drift = False
        self.host_role = LocalHostRole.worker
        self.extra_workload_identities: dict[str, str] = {}
        self.extra_mounts: dict[str, str] = {}

    def run(
        self,
        pin: ExecutablePin,
        argv_tail: tuple[str, ...],
        *,
        timeout_seconds: int,
        max_output_bytes: int,
    ) -> CommandResult:
        argv = tuple(argv_tail)
        self.calls.append((pin, argv, timeout_seconds, max_output_bytes))
        if argv[:3] == ("inspect", "--format", "{{.Id}}|{{.Image}}|{{.State.Running}}|"):
            raise AssertionError("format prefix must be one fixed argument")
        if argv[:3] == (
            "inspect",
            "--format",
            local_adapter_module._WORKLOAD_IDENTITY_FORMAT,
        ):
            name = argv[-1]
            if name in self.extra_workload_identities:
                return CommandResult(0, self.extra_workload_identities[name])
            if name == "secp-ordinary-worker":
                return CommandResult(
                    0,
                    _workload_identity_projection(
                        container_id=(
                            _CID_BEFORE if self.generation == "before" else self.worker_after_id
                        ),
                        executable="python",
                        arguments=["-m", "secp_worker.main"],
                        command=["python", "-m", "secp_worker.main"],
                        environment=["SECP_TEMPORAL_TASK_QUEUE=secp-orchestration"],
                        service="worker",
                    ),
                )
            if name == _API_NAME:
                return CommandResult(
                    0,
                    _workload_identity_projection(
                        container_id=self.api_container_id,
                        executable="python",
                        arguments=["-m", "secp_api.main"],
                        command=["python", "-m", "secp_api.main"],
                        environment=[
                            "SECP_TEMPORAL_TASK_QUEUE=secp-orchestration",
                            "SECP_TEMPORAL_OPERATOR_TASK_QUEUE=secp-controlled-live-v1",
                        ],
                        service="api",
                    ),
                )
            if name == "secp-discovery-admission-proxy":
                return CommandResult(
                    0,
                    _workload_identity_projection(
                        container_id=self.proxy_container_id,
                        executable="caddy",
                        arguments=["run", "--config", "/etc/caddy/Caddyfile"],
                        command=["caddy", "run"],
                        service="discovery-admission-proxy",
                    ),
                )
            raise AssertionError(f"unexpected workload identity target: {name!r}")
        if argv[:2] == ("inspect", "--format") and ".Mounts" in argv[2]:
            if argv[-1] in self.extra_mounts:
                return CommandResult(0, self.extra_mounts[argv[-1]])
            if argv[-1] in {
                "secp-ordinary-worker",
                _CID_BEFORE,
                _CID_AFTER,
                self.worker_after_id,
            }:
                return CommandResult(
                    0,
                    "bind|/var/lib/secp/discovery-worker|/var/run/secp|true|rprivate\n"
                    "bind|/etc/secp/discovery-activation/tls/admission-ca.pem|"
                    "/etc/secp/admission-ca.pem|false|rprivate\n"
                    "bind|/var/lib/secp/discovery-activation/runtime/"
                    "secp-pr5f-runtime-overlay.zip|/opt/secp/"
                    "secp-pr5f-runtime-overlay.zip|false|rprivate\n",
                )
            if argv[-1] in {
                "secp-discovery-admission-proxy",
                _PROXY_ID,
                self.proxy_container_id,
            }:
                return CommandResult(
                    0,
                    "bind|/etc/secp/discovery-activation/admission-proxy.json|"
                    "/etc/secp/admission-proxy.json|false|rprivate\n"
                    "bind|/etc/secp/discovery-activation/tls/admission-ca.pem|"
                    "/run/secp/tls/admission-ca.pem|false|rprivate\n"
                    "bind|/etc/secp/discovery-activation/tls/admission-server.pem|"
                    "/run/secp/tls/admission-server.pem|false|rprivate\n"
                    "bind|/etc/secp/discovery-activation/tls/admission-server.key|"
                    "/run/secp/tls/admission-server.key|false|rprivate\n"
                    "bind|/etc/secp/discovery-activation/secrets/"
                    "admission-proxy-gate.secret|/run/secp/"
                    "admission-proxy-gate.secret|false|rprivate\n"
                    "tmpfs||/tmp|true|\n",
                )
            if argv[-1] in {
                _API_ID,
                _API_BASELINE_ID,
                _API_RESTORED_ID,
                _API_NAME,
                self.api_container_id,
            }:
                return CommandResult(
                    0,
                    "bind|/etc/secp/discovery-activation/secrets/"
                    "admission-proxy-gate.secret|/run/secp/"
                    "admission-proxy-gate.secret|false|rprivate\n",
                )
            return CommandResult(0, "")
        if argv[:2] == ("inspect", "--format") and ".Config" in argv[2]:
            if argv[-1] in {
                "secp-ordinary-worker",
                _CID_BEFORE,
                _CID_AFTER,
                self.worker_after_id,
            }:
                self.worker_runtime_calls += 1
                return CommandResult(
                    0,
                    _runtime_projection(
                        service="worker",
                        user="1001:1001",
                        extra_hosts=self.worker_extra_hosts,
                        command_marker=(
                            "changed-service"
                            if self.worker_runtime_drift and self.worker_runtime_calls > 1
                            else "service"
                        ),
                        environment=(
                            ["SECP_RUNTIME_MODE=private-drift"]
                            if self.worker_private_runtime_drift and self.worker_runtime_calls > 1
                            else self.worker_environment
                        ),
                        project="secp-worker",
                    ),
                )
            if argv[-1] in {
                "secp-discovery-admission-proxy",
                _PROXY_ID,
                self.proxy_container_id,
            }:
                self.proxy_runtime_calls += 1
                return CommandResult(
                    0,
                    _runtime_projection(
                        service="discovery-admission-proxy",
                        user="1002:1002",
                        read_only=self.proxy_read_only,
                        environment=(
                            ["SECP_RUNTIME_MODE=private-drift"]
                            if self.proxy_private_runtime_drift and self.proxy_runtime_calls > 1
                            else ["SECP_RUNTIME_MODE=reviewed"]
                        ),
                        tmpfs={"/tmp": "rw,nosuid,nodev,noexec,size=16m,mode=1777"},
                        project="secp-controller",
                    ),
                )
            if argv[-1] in {
                _API_ID,
                _API_BASELINE_ID,
                _API_RESTORED_ID,
                self.api_container_id,
            }:
                return CommandResult(
                    0,
                    _runtime_projection(service="api", user="1000:1000", project="secp-controller"),
                )
        if argv[:3] == ("inspect", "--format", "{{.Name}}"):
            return CommandResult(0, "/" + _API_NAME + "\n")
        if argv[:2] == ("inspect", "--format") and ".NetworkSettings.Networks" in argv[2]:
            return CommandResult(0, "secp_default\n")
        if argv[:2] == ("inspect", "--format") and argv[-1] == "secp-ordinary-worker":
            if self.malformed_worker:
                return CommandResult(0, '{"Config":{"Env":["SECRET=x"]}}')
            if self.generation == "before":
                return CommandResult(
                    0,
                    f"{_CID_BEFORE}|{_IMAGE}|true|healthy|0|{_STARTED_BEFORE}\n",
                )
            return CommandResult(
                0,
                f"{self.worker_after_id}|{_IMAGE}|true|"
                f"{'healthy' if self.worker_healthy else 'unhealthy'}|0|{_STARTED_AFTER}\n",
            )
        if argv[:2] == ("inspect", "--format") and argv[-1] == ("secp-discovery-admission-proxy"):
            if not self.proxy_running:
                return CommandResult(1, "")
            return CommandResult(
                0,
                f"{self.proxy_container_id}|{self.proxy_image}|true|healthy|0|{_STARTED_BEFORE}\n",
            )
        if argv[:2] == ("inspect", "--format") and argv[-1] in {
            _API_ID,
            _API_BASELINE_ID,
            _API_RESTORED_ID,
            self.api_container_id,
        }:
            return CommandResult(
                0,
                f"{self.api_container_id}|{self.api_image}|true|healthy|0|{_STARTED_BEFORE}\n",
            )
        if argv == ("ps", "--all", "--format", "{{.Names}}"):
            if self.host_role is LocalHostRole.controller:
                names = [_API_NAME]
                if self.proxy_running:
                    names.append("secp-discovery-admission-proxy")
                names.extend(self.extra_workload_identities)
                return CommandResult(0, "\n".join(names) + "\n")
            names = ["secp-ordinary-worker", *self.extra_workload_identities]
            return CommandResult(0, "\n".join(names) + "\n")
        if argv[:2] == ("ps", "--all"):
            return CommandResult(0, "")
        if (
            len(argv) == 6
            and argv[0] == "exec"
            and argv[2:5] == ("python", "-m", "secp_api.discovery_activation_rollback_fence")
            and argv[5] in {"engage", "observe", "release"}
        ):
            if self.fail_fence:
                return CommandResult(2, "")
            action = argv[5]
            if action == "engage":
                self.fence_engaged = True
            elif action == "release":
                self.fence_engaged = False
            if self.fence_output_override is not None:
                return CommandResult(0, self.fence_output_override)
            if action == "observe" and self.fence_observe_replacement_id is not None:
                self.api_container_id = self.fence_observe_replacement_id
            return CommandResult(
                0,
                json.dumps(
                    {
                        "action": action,
                        "observation_complete": True,
                        "rollback_fence_state": ("engaged" if self.fence_engaged else "released"),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
            )
        if argv[:2] in {
            ("exec", "secp-ordinary-worker"),
            ("exec", _CID_BEFORE),
            ("exec", _CID_AFTER),
            ("exec", self.worker_after_id),
        }:
            if argv[-1] == "check":
                return CommandResult(0, "")
            if argv[-1] == "secp_api.discovery_activation_rollback_probe":
                return CommandResult(
                    0,
                    json.dumps(
                        {
                            "observation_complete": True,
                            "rollback_compatible": self.rollback_compatible,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n",
                )
            if argv[-1] == "secp_worker.admission_tls_probe":
                return CommandResult(
                    0,
                    json.dumps(
                        {
                            "contract_version": "secp.worker.admission-tls-probe/v1",
                            "ok": True,
                            "ca_certificate_fingerprint": self.tls_ca_fingerprint,
                            "server_certificate_fingerprint": self.tls_server_fingerprint,
                            "server_dns_identity": "admission.internal.test",
                            "tls_version": "TLSv1.3",
                            "probe_effects": {
                                "http_requested": False,
                                "redirect_followed": False,
                                "proxy_used": False,
                            },
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                )
            return CommandResult(0, _probe())
        if (
            len(argv) == 5
            and argv[0] == "exec"
            and len(argv[1]) == 64
            and set(argv[1]) <= set("0123456789abcdef")
            and argv[-1] == "secp_api.discovery_activation_rollback_probe"
        ):
            return CommandResult(
                0,
                json.dumps(
                    {
                        "observation_complete": True,
                        "rollback_compatible": self.rollback_compatible,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
            )
        if argv[:3] == ("exec", "--workdir", "/app/apps/api"):
            assert argv[3] == self.api_container_id
            if argv[-1] == "current":
                return CommandResult(
                    0,
                    "d8f1a2b3c4e5 (head)\n" if self.migration_ready else "c4e2f9a1b7d3\n",
                )
            if argv[-2:] == ("downgrade", "c4e2f9a1b7d3"):
                if self.fail_downgrade:
                    return CommandResult(1, "")
                self.migration_ready = False
                return CommandResult(0, "")
        if argv[:2] == ("exec", self.api_container_id):
            return CommandResult(
                0,
                "d8f1a2b3c4e5 (head)\n" if self.migration_ready else "c4e2f9a1b7d3\n",
            )
        if "ps" in argv and "--quiet" in argv and argv[-1] == "api":
            return CommandResult(0, self.api_container_id + "\n")
        if "ps" in argv and "--services" in argv and argv[-1] == "api":
            return CommandResult(0, "api\n")
        if argv == ("port", "secp-discovery-admission-proxy", "8443/tcp"):
            return CommandResult(0, "10.20.30.40:8443\n")
        if "up" in argv:
            if self.fail_compose:
                return CommandResult(1, "")
            if argv[-1] == "worker":
                self.generation = "after"
            elif argv[-1] == "discovery-admission-proxy":
                self.api_image = "sha256:" + "9" * 64
                self.api_container_id = _API_ID
                self.migration_ready = True
                self.proxy_running = True
            elif argv[-1] == "api":
                self.api_image = "sha256:" + "7" * 64
                self.api_container_id = _API_RESTORED_ID
                self.migration_ready = False
            return CommandResult(0, "")
        if argv[:2] == ("rm", "--force"):
            self.proxy_running = False
            return CommandResult(0, "")
        raise AssertionError(f"unexpected closed command shape: {argv!r}")


def _set_controller_baseline(runner: FakeRunner, store: FakeStore | None = None) -> None:
    runner.api_image = "sha256:" + "7" * 64
    runner.api_container_id = _API_BASELINE_ID
    runner.migration_ready = False
    runner.proxy_running = False
    if store is not None:
        store.controller_prepared = False


class FakeTLSProbe:
    def __init__(self, result: bool = True) -> None:
        self.result = result
        self.route_result = result
        self.calls = 0
        self.route_calls = 0
        self.expected_ca = b"ca"
        self.expected_fingerprint = "sha256:" + "6" * 64

    def verify(self, profile, *, ca_certificate_pem, expected_server_fingerprint):  # noqa: ANN001, ANN201
        self.calls += 1
        assert profile.admission_certificate_dns_name == "admission.internal.test"
        assert ca_certificate_pem == self.expected_ca
        assert expected_server_fingerprint == self.expected_fingerprint
        return self.result

    def verify_route(self, profile, *, ca_certificate_pem, expected_server_fingerprint):  # noqa: ANN001, ANN201
        self.route_calls += 1
        assert profile.admission_certificate_dns_name == "admission.internal.test"
        assert ca_certificate_pem == self.expected_ca
        assert expected_server_fingerprint == self.expected_fingerprint
        return self.route_result


class FakeStore:
    def __init__(self, profile: DeploymentProfile) -> None:
        self.profile = profile
        self.operations: list[str] = []
        self._receipt: MutationReceipt | None = None
        self.evidence: tuple[bytes, bytes] | None = None
        self.raise_restore = False
        self.tls_ca = b"ca"
        self.tls_fingerprint = "sha256:" + "6" * 64
        self._worker_tls_proof: tuple[str, str, str] | None = None
        self._runtime_after: tuple[ContainerRuntimeObservation, ...] | None = None
        self.base_compose_binding = _BASE_COMPOSE
        self.base_compose_drift = False
        self.controller_env_binding = _CONTROLLER_ENV
        self.controller_env_drift = False
        self.controller_prepared = True
        self.controller_override_preexisting = False
        self.worker_override_preexisting = False
        self.recovery_required = False

    def posture(self, host_role: LocalHostRole) -> ArtifactPosture:
        self.operations.append("posture:" + host_role.value)
        digests = (("activation_profile", "sha256:" + "7" * 64),)
        if host_role is LocalHostRole.worker:
            assert self.profile.worker_runtime_overlay_digest is not None
            digests += (("worker_runtime_overlay", self.profile.worker_runtime_overlay_digest),)
        return ArtifactPosture(
            artifacts_prepared=(
                self.controller_prepared if host_role is LocalHostRole.controller else True
            ),
            worker_config_installed=True,
            configuration_artifact_digests=digests,
            base_compose_binding=self.base_compose_binding,
            recovery_required=self.recovery_required,
        )

    def transaction_base_compose_binding(self) -> FixedInputBinding:
        self.operations.append("transaction_base_compose_binding")
        return self.base_compose_binding

    def transaction_profile(self) -> DeploymentProfile:
        self.operations.append("transaction_profile")
        return self.profile

    def transaction_runtime_after(self) -> tuple[ContainerRuntimeObservation, ...] | None:
        self.operations.append("transaction_runtime_after")
        return self._runtime_after

    def assert_base_compose_unchanged(
        self, host_role: LocalHostRole, expected: FixedInputBinding
    ) -> None:
        self.operations.append("assert_base_compose_unchanged:" + host_role.value)
        assert expected == self.base_compose_binding
        if self.base_compose_drift:
            raise ActivationAdapterError("base_compose_drift")

    def transaction_controller_env_binding(self) -> FixedInputBinding:
        self.operations.append("transaction_controller_env_binding")
        return self.controller_env_binding

    def assert_controller_env_unchanged(self, expected: FixedInputBinding) -> None:
        self.operations.append("assert_controller_env_unchanged")
        assert expected == self.controller_env_binding
        if self.controller_env_drift:
            raise ActivationAdapterError("controller_env_drift")

    def validated_runtime_overlay(self, expected_digest: str) -> _BoundFile:
        self.operations.append("validated_runtime_overlay")
        assert expected_digest == self.profile.worker_runtime_overlay_digest
        return _BoundFile(b"validated-overlay", expected_digest, 0, 0, 0o644)

    def operator_service_present(self) -> bool:
        self.operations.append("operator_service_present")
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
        self.operations.append("stage")
        assert profile is self.profile
        assert host_role is LocalHostRole.worker
        assert worker_override.name == "worker_compose_override"
        assert before.coherent
        assert state_receipt["classification"] == "adopted"
        self._runtime_after = None
        self._receipt = MutationReceipt(transaction_id, True, False, False, False, False, False, 0)
        return self._receipt

    def stage_controller(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        before,
        *,
        transaction_id: str,
    ) -> MutationReceipt:  # noqa: ANN001
        self.operations.append("stage_controller")
        assert profile is self.profile
        assert rendered.artifacts and before.coherent and before.inspected
        self._runtime_after = None
        self._receipt = MutationReceipt(transaction_id, True, False, False, False, False, False, 0)
        return self._receipt

    def _effect(self, name: str, field: str) -> None:
        self.operations.append(name)
        assert self._receipt is not None
        values = self._receipt.__dict__ | {
            "effects_started": True,
            field: True,
            "operation_count": self._receipt.operation_count + 1,
        }
        self._receipt = MutationReceipt(**values)

    def install_controller(
        self, rendered: ActivationRender, tls_material: ValidatedTLSMaterial
    ) -> None:
        assert rendered.artifacts and tls_material.server_private_key_pem()
        self.controller_prepared = True
        self._effect("install_controller", "controller_changed")

    def install_worker(
        self,
        worker_override: RenderedArtifact,
        ca_certificate: ValidatedAdmissionCA,
        runtime_overlay: _BoundFile,
    ) -> None:
        assert worker_override.name == "worker_compose_override"
        assert ca_certificate.ca_certificate_pem()
        assert runtime_overlay.digest == self.profile.worker_runtime_overlay_digest
        self.tls_ca = ca_certificate.ca_certificate_pem()
        self._effect("install_worker", "worker_config_changed")

    def record_worker_tls_proof(
        self,
        *,
        ca_certificate_fingerprint: str,
        expected_server_certificate_fingerprint: str,
        expected_server_dns_identity: str,
    ) -> None:
        assert ca_certificate_fingerprint.startswith("sha256:")
        self.operations.append("record_worker_tls_proof")
        self._worker_tls_proof = (
            ca_certificate_fingerprint,
            expected_server_certificate_fingerprint,
            expected_server_dns_identity,
        )

    def worker_tls_proof(self) -> tuple[str, str, str] | None:
        return self._worker_tls_proof

    def note_worker_recreation(self) -> None:
        self._effect("note_worker_recreation", "worker_recreated")

    def note_controller_runtime_change(self) -> None:
        self._effect("note_controller_runtime_change", "controller_runtime_changed")

    def record_controller_runtime_after(
        self,
        api_runtime: ContainerRuntimeObservation,
        proxy_runtime: ContainerRuntimeObservation,
    ) -> None:
        self.operations.append("record_controller_runtime_after")
        self._runtime_after = (api_runtime, proxy_runtime)

    def record_worker_runtime_after(self, runtime: ContainerRuntimeObservation) -> None:
        self.operations.append("record_worker_runtime_after")
        self._runtime_after = (runtime,)

    def receipt(self) -> MutationReceipt:
        assert self._receipt is not None
        return self._receipt

    def tls_probe_material(self) -> tuple[bytes, str] | None:
        return self.tls_ca, self.tls_fingerprint

    def commit_evidence(self, evidence: bytes, attestation: bytes) -> None:
        self._effect("commit_evidence", "evidence_committed")
        self.evidence = evidence, attestation

    def load_evidence(self) -> tuple[bytes, bytes] | None:
        return self.evidence

    def commit_controller_offer(self, offer: bytes, attestation: bytes) -> None:
        self._effect("commit_controller_offer", "controller_changed")
        self.evidence = offer, attestation

    def load_controller_offer(self) -> tuple[bytes, bytes] | None:
        return self.evidence

    def commit_worker_result(self, result: bytes, attestation: bytes) -> None:
        self._effect("commit_worker_result", "worker_config_changed")
        self.evidence = result, attestation

    def load_worker_result(self) -> tuple[bytes, bytes] | None:
        return self.evidence

    def load_worker_controller_offer_inbox(self) -> tuple[bytes, bytes] | None:
        return None

    def load_controller_worker_result_inbox(self) -> tuple[bytes, bytes] | None:
        return None

    def object_classifications(self) -> tuple[tuple[str, str], ...]:
        return (("fake", "adopted"),)

    def restore_artifacts(self, receipt: MutationReceipt) -> RollbackContext:
        self.operations.append("restore_artifacts")
        if self.raise_restore:
            raise ActivationAdapterError("rollback_content_or_metadata_drift")
        assert receipt == self._receipt
        return RollbackContext(
            transaction_id=receipt.transaction_id,
            container_runtime=ExecutablePin(
                self.profile.container_runtime_executable,
                self.profile.container_runtime_executable_digest,
            ),
            compose_runtime=ExecutablePin(
                self.profile.compose_executable, self.profile.compose_executable_digest
            ),
            before_worker_present=True,
            before_worker_image_digest=_IMAGE,
            before_worker_running=True,
            before_worker_healthy=True,
            controller_override_preexisting=self.controller_override_preexisting,
            worker_override_preexisting=self.worker_override_preexisting,
            controller_changed=receipt.controller_changed,
            controller_runtime_changed=receipt.controller_runtime_changed,
            worker_config_changed=receipt.worker_config_changed,
            worker_recreated=receipt.worker_recreated,
            base_compose_binding=self.base_compose_binding,
            controller_env_binding=self.controller_env_binding,
            profile=self.profile,
        )

    def finish_rollback(self, *, proven: bool) -> None:
        self.operations.append("finish_rollback:" + str(proven).lower())
        self.recovery_required = not proven


def _adapter(
    profile: DeploymentProfile,
    *,
    role: LocalHostRole = LocalHostRole.worker,
    mount_source_identity_resolver: FakeMountSourceIdentityResolver | None = None,
) -> tuple[
    LocalActivationAdapter,
    FakeRunner,
    FakeStore,
    InMemoryWorkerStateFilesystem,
    FakeTLSProbe,
]:
    runner = FakeRunner()
    runner.host_role = role
    store = FakeStore(profile)
    state = InMemoryWorkerStateFilesystem()
    state.present = True
    state.prepared = True
    state.keys_generated = True
    tls_probe = FakeTLSProbe()
    mount_resolver = mount_source_identity_resolver or FakeMountSourceIdentityResolver()

    def runtime_binding(message: bytes) -> str:
        return (
            "hmac-sha256:"
            + hmac.new(b"test-only-runtime-binding-key", message, hashlib.sha256).hexdigest()
        )

    adapter = LocalActivationAdapter(
        host_role=role,
        command_runner=runner,
        artifact_store=store,
        state_backend=state,
        tls_probe=tls_probe,
        mount_source_identity_resolver=mount_resolver,
        runtime_configuration_binder=runtime_binding,
        publication_timeout_seconds=1,
        publication_poll_seconds=0.001,
    )
    return adapter, runner, store, state, tls_probe


def _state_receipt() -> dict[str, object]:
    return {
        "classification": "adopted",
        "root_created": False,
        "keys_created": False,
        "bundle_created": False,
        "root_device": 1,
        "root_inode": 2,
        "keys_inode": 3,
        "bundle_inode": 4,
    }


def _prepared_state_receipt() -> PreparedStateReceipt:
    return PreparedStateReceipt(**_state_receipt())  # type: ignore[arg-type]


def _handoff_attestation() -> HandoffAttestation:
    return HandoffAttestation.model_construct(
        contract_schema="secp.discovery-activation.handoff-attestation/v1",
        algorithm="Ed25519",
        key_id="sha256:" + "9" * 64,
        public_key_hex="8" * 64,
        signature="7" * 128,
    )


def test_construction_is_inert_and_public_surface_has_no_generic_exec_or_path() -> None:
    profile = _profile()
    adapter, runner, store, state, tls_probe = _adapter(profile)
    assert runner.calls == []
    assert store.operations == []
    assert state.operations == []
    assert tls_probe.calls == 0
    assert not any(
        hasattr(adapter, name)
        for name in ("run", "exec", "command", "write_path", "install_path", "shell")
    )


def test_each_local_adapter_is_explicitly_bound_to_one_physical_host_role(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    worker_override = render_worker_compose_override(profile)
    worker_ca = _worker_ca(tls_material)
    worker, worker_runner, worker_store, _state, _tls = _adapter(profile)
    controller, controller_runner, controller_store, _state2, _tls2 = _adapter(
        profile, role=LocalHostRole.controller
    )
    with pytest.raises(ActivationAdapterError) as exc:
        controller.observe(profile)
    assert exc.value.reason_code == "split_host_worker_observation_required"
    with pytest.raises(ActivationAdapterError) as exc:
        worker.install_controller(profile, rendered, tls_material)
    assert exc.value.reason_code == "controller_host_role_required"
    with pytest.raises(ActivationAdapterError) as exc:
        controller.install_worker(profile, worker_override, worker_ca)
    assert exc.value.reason_code == "worker_host_role_required"
    assert worker_runner.calls == controller_runner.calls == []
    assert worker_store.operations == controller_store.operations == []


def test_observe_uses_safe_fixed_projections_and_returns_coherent_public_facts() -> None:
    profile = _profile()
    adapter, runner, _store, _state, tls_probe = _adapter(profile)
    observed = adapter.observe(profile)
    assert observed.inspected and observed.coherent
    assert observed.worker_image_digest == _IMAGE
    assert observed.base_compose_binding == _BASE_COMPOSE
    assert observed.worker_runtime is not None
    assert observed.worker_runtime.verified()
    assert observed.worker_runtime.endpoint_binding_verified
    assert observed.worker_runtime.compose_service == "worker"
    assert observed.worker_generation == WorkerGeneration(
        container_id=_CID_BEFORE,
        restart_count=0,
        started_at=_STARTED_BEFORE,
    )
    assert observed.worker_running and observed.worker_healthy
    assert observed.ordinary_queues == ("secp-orchestration",)
    assert observed.operator_absent()
    assert observed.safety_seals_valid()
    assert not observed.tls_ready and tls_probe.calls == 0
    assert observed.worker_public is not None
    assert observed.worker_public.node_id == _NODE_ID
    assert observed.worker_public.public_material_only
    flattened = "\n".join(" ".join(call[1]) for call in runner.calls)
    assert "Config.Env" not in flattened
    assert "SECRET" not in flattened
    assert "inspect --format" in flattened
    assert not any(argv[0] in {"pull", "build"} for _pin, argv, _timeout, _cap in runner.calls)


def test_public_runtime_digest_redacts_environment_values_and_private_binding_never_exports() -> (
    None
):
    profile = _profile()
    adapter, runner, _store, _state, _tls = _adapter(profile)
    first = adapter.observe(profile).worker_runtime
    assert first is not None
    first_binding = first.private_configuration_binding
    assert isinstance(first_binding, str) and first_binding.startswith("hmac-sha256:")

    # Changing only one credential-like value must not change the public guessing surface, while
    # the root-local journal binding still detects the exact Docker configuration substitution.
    runner.worker_environment = ["SECP_RUNTIME_MODE=credential-value-changed"]
    second = adapter.observe(profile).worker_runtime
    assert second is not None
    assert second.configuration_digest == first.configuration_digest
    assert second.private_configuration_binding != first_binding
    assert second == first  # The private MAC is deliberately excluded from dataclass equality.
    assert first_binding not in repr(first)

    safe_status = json.dumps(split_engine_module._safe_runtime(first), sort_keys=True)
    safe_evidence = split_engine_module._runtime_evidence(
        "ordinary_worker",
        first,
        expected_image_digest=_IMAGE,
        reason="runtime_invalid",
    ).model_dump_json()
    for public_value in (safe_status, safe_evidence):
        assert first_binding not in public_value
        assert "private_configuration_binding" not in public_value


@pytest.mark.parametrize(
    "identity",
    [
        _workload_identity_projection(
            container_id="1" * 64,
            executable="python",
            arguments=["-m", "secp_worker.operator_bootstrap"],
            command=["python", "-m", "secp_worker.operator_bootstrap"],
            environment=["SECP_RUNTIME_MODE=reviewed"],
            service="telemetry",
        ),
        _workload_identity_projection(
            container_id="2" * 64,
            executable="/opt/reviewed/runtime",
            arguments=["serve"],
            image="registry.internal.test/reviewed/runtime:latest",
            command=["/opt/reviewed/runtime", "serve"],
            environment=["SECP_TEMPORAL_TASK_QUEUE=secp-orchestration"],
            service="metrics",
        ),
    ],
    ids=("renamed-operator", "opaque-extra-poller"),
)
def test_renamed_operator_and_extra_poller_metadata_cannot_evade_worker_observation(
    identity: str,
) -> None:
    profile = _profile()
    adapter, runner, _store, _state, _tls = _adapter(profile)
    runner.extra_workload_identities["unrelated-looking-sidecar"] = identity

    observed = adapter.observe(profile)

    assert observed.operator_container_present
    assert observed.operator_registration_present
    assert observed.operator_queue_polled
    assert not observed.operator_absent()


def test_unrelated_sidecar_without_worker_or_queue_markers_remains_allowed() -> None:
    profile = _profile()
    adapter, runner, _store, _state, _tls = _adapter(profile)
    runner.extra_workload_identities["metrics-sidecar"] = _workload_identity_projection(
        container_id="3" * 64,
        executable="/usr/bin/node_exporter",
        arguments=["--web.listen-address=:9100"],
        image="registry.internal.test/metrics/node-exporter:reviewed",
        command=["/usr/bin/node_exporter"],
        service="metrics",
    )

    observed = adapter.observe(profile)

    assert observed.operator_absent()


def test_worker_mount_source_identity_alias_in_unrelated_sidecar_fails_isolation() -> None:
    profile = _profile()
    resolver = FakeMountSourceIdentityResolver()
    source_alias = "/mnt/worker-state-alias"
    resolver.aliases[source_alias] = {PRODUCTION_LAYOUT.worker_state_host_path}
    adapter, runner, _store, _state, _tls = _adapter(
        profile, mount_source_identity_resolver=resolver
    )
    runner.extra_workload_identities["metrics-sidecar"] = _workload_identity_projection(
        container_id="3" * 64,
        executable="/usr/bin/node_exporter",
        arguments=["--web.listen-address=:9100"],
        image="registry.internal.test/metrics/node-exporter:reviewed",
        command=["/usr/bin/node_exporter"],
        service="metrics",
    )
    runner.extra_mounts["metrics-sidecar"] = (
        f"bind|{source_alias}|/var/lib/metrics-cache|false|rprivate\n"
    )

    observed = adapter.observe(profile)

    assert observed.coherent
    assert not observed.discovery_mount_absent_from_other_containers
    assert not observed.state_mount_read_write_only_worker
    assert observed.worker_runtime is not None
    assert not observed.worker_runtime.mounts_verified


def test_mount_source_identity_drift_between_inventory_samples_is_incoherent() -> None:
    profile = _profile()
    resolver = FakeMountSourceIdentityResolver()
    resolver.drift = True
    adapter, _runner, _store, _state, _tls = _adapter(
        profile, mount_source_identity_resolver=resolver
    )

    observed = adapter.observe(profile)

    assert len(resolver.calls) == 2
    assert not observed.coherent
    assert observed.worker_generation is None


def test_controller_mount_source_identity_alias_blocks_all_readiness() -> None:
    profile = _profile()
    resolver = FakeMountSourceIdentityResolver()
    source_alias = "/mnt/controller-key-alias"
    resolver.aliases[source_alias] = {PRODUCTION_LAYOUT.server_private_key_path}
    adapter, runner, _store, _state, tls_probe = _adapter(
        profile,
        role=LocalHostRole.controller,
        mount_source_identity_resolver=resolver,
    )
    runner.extra_workload_identities["metrics-sidecar"] = _workload_identity_projection(
        container_id="4" * 64,
        executable="/usr/bin/node_exporter",
        arguments=["--web.listen-address=:9100"],
        image="registry.internal.test/metrics/node-exporter:reviewed",
        command=["/usr/bin/node_exporter"],
        service="metrics",
    )
    runner.extra_mounts["metrics-sidecar"] = (
        f"bind|{source_alias}|/var/lib/metrics-cache|false|rprivate\n"
    )

    observed = adapter.observe_controller(profile)

    assert not observed.coherent
    assert not observed.tls_ready
    assert not observed.activation_route_enabled
    assert not observed.proxy_healthy
    assert tls_probe.calls == tls_probe.route_calls == 0


def test_controller_observation_binds_api_proxy_runtime_and_migration_head() -> None:
    profile = _profile()
    adapter, runner, _store, _state, tls_probe = _adapter(profile, role=LocalHostRole.controller)

    observed = adapter.observe_controller(profile)

    assert observed.inspected and observed.coherent
    assert observed.base_compose_binding == _BASE_COMPOSE
    assert observed.api_runtime is not None and observed.api_runtime.verified()
    assert observed.api_runtime.image_digest == "sha256:" + "9" * 64
    assert observed.api_runtime.compose_service == "api"
    assert observed.proxy_runtime is not None and observed.proxy_runtime.verified()
    assert observed.proxy_runtime.image_digest == "sha256:" + "8" * 64
    assert observed.proxy_runtime.compose_service == "discovery-admission-proxy"
    assert observed.migration_head == "d8f1a2b3c4e5"
    assert observed.migration_head_ready
    assert observed.tls_ready and observed.activation_route_enabled and observed.proxy_healthy
    assert tls_probe.calls == tls_probe.route_calls == 1
    assert any(
        argv
        == (
            "exec",
            "--workdir",
            "/app/apps/api",
            _API_ID,
            "python",
            "-m",
            "alembic",
            "--config",
            "/app/apps/api/alembic.ini",
            "current",
        )
        for _pin, argv, _timeout, _cap in runner.calls
    )


def test_controller_rollback_gate_probes_then_engages_through_exact_api_generation(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    adapter, runner, store, _state, _tls = _adapter(profile, role=LocalHostRole.controller)
    _set_controller_baseline(runner, store)
    rendered = render_activation(profile, tls_material.metadata)
    adapter.stage_controller_rollback(profile, rendered, adapter.observe_controller(profile))
    adapter.install_controller(profile, rendered, tls_material)
    runner.calls.clear()

    assert adapter.controller_api_rollback_compatible(profile) is True
    runner.rollback_compatible = False
    assert adapter.controller_api_rollback_compatible(profile) is False
    probe_calls = [
        argv
        for _pin, argv, _timeout, _cap in runner.calls
        if "secp_api.discovery_activation_rollback_probe" in argv
    ]
    assert (
        probe_calls
        == [
            (
                "exec",
                _API_ID,
                "python",
                "-m",
                "secp_api.discovery_activation_rollback_probe",
            )
        ]
        * 2
    )
    fence_calls = [
        argv
        for _pin, argv, _timeout, _cap in runner.calls
        if "secp_api.discovery_activation_rollback_fence" in argv
    ]
    assert fence_calls == [
        (
            "exec",
            _API_ID,
            "python",
            "-m",
            "secp_api.discovery_activation_rollback_fence",
            "engage",
        )
    ]
    assert runner.calls.index(next(call for call in runner.calls if call[1] == probe_calls[0])) < (
        runner.calls.index(next(call for call in runner.calls if call[1] == fence_calls[0]))
    )
    assert runner.fence_engaged


def test_worker_rollback_gate_probes_then_engages_through_exact_overlay_generation(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    adapter, runner, _store, _state, _tls = _adapter(profile)
    rendered = render_activation(profile, tls_material.metadata)
    adapter.stage_rollback(
        profile, rendered, adapter.observe(profile), state_receipt=_state_receipt()
    )
    adapter.install_worker(
        profile, render_worker_compose_override(profile), _worker_ca(tls_material)
    )
    adapter.recreate_worker(profile)
    runner.calls.clear()

    assert adapter.worker_api_rollback_compatible(profile) is True
    runner.rollback_compatible = False
    assert adapter.worker_api_rollback_compatible(profile) is False
    probe_calls = [
        argv
        for _pin, argv, _timeout, _cap in runner.calls
        if "secp_api.discovery_activation_rollback_probe" in argv
    ]
    assert (
        probe_calls
        == [
            (
                "exec",
                _CID_AFTER,
                "python",
                "-m",
                "secp_api.discovery_activation_rollback_probe",
            )
        ]
        * 2
    )
    fence_calls = [
        argv
        for _pin, argv, _timeout, _cap in runner.calls
        if "secp_api.discovery_activation_rollback_fence" in argv
    ]
    assert fence_calls == [
        (
            "exec",
            _CID_AFTER,
            "python",
            "-m",
            "secp_api.discovery_activation_rollback_fence",
            "engage",
        )
    ]
    assert runner.fence_engaged


def test_controller_releases_fence_only_through_rebound_d8_api_generation(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile, role=LocalHostRole.controller)
    _set_controller_baseline(runner, store)
    adapter.stage_controller_rollback(profile, rendered, adapter.observe_controller(profile))
    adapter.install_controller(profile, rendered, tls_material)
    adapter.commit_activation_evidence(b"evidence", b"attestation")
    runner.calls.clear()

    adapter.release_api_rollback_fence(profile)

    fence_calls = [
        argv
        for _pin, argv, _timeout, _cap in runner.calls
        if "secp_api.discovery_activation_rollback_fence" in argv
    ]
    assert fence_calls == [
        (
            "exec",
            _API_ID,
            "python",
            "-m",
            "secp_api.discovery_activation_rollback_fence",
            "release",
        )
    ]
    assert not runner.fence_engaged
    assert any(argv[-1] == "current" for _pin, argv, _timeout, _cap in runner.calls)


def test_controller_refuses_fence_release_without_committed_evidence(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile, role=LocalHostRole.controller)
    _set_controller_baseline(runner, store)
    adapter.stage_controller_rollback(profile, rendered, adapter.observe_controller(profile))
    adapter.install_controller(profile, rendered, tls_material)
    runner.calls.clear()

    with pytest.raises(ActivationAdapterError) as caught:
        adapter.release_api_rollback_fence(profile)

    assert caught.value.reason_code == "activation_evidence_unavailable_for_fence_release"
    assert not any(
        "secp_api.discovery_activation_rollback_fence" in argv
        for _pin, argv, _timeout, _cap in runner.calls
    )
    assert runner.fence_engaged


def test_controller_observes_exact_live_fence_with_bounded_output(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile, role=LocalHostRole.controller)
    _set_controller_baseline(runner, store)
    adapter.stage_controller_rollback(profile, rendered, adapter.observe_controller(profile))
    adapter.install_controller(profile, rendered, tls_material)
    runner.calls.clear()

    engaged = adapter.observe_api_rollback_fence(profile)
    runner.fence_engaged = False
    released = adapter.observe_api_rollback_fence(profile)

    assert engaged.observation_complete is True
    assert engaged.state == "engaged"
    assert engaged.api_container_id == _API_ID
    assert engaged.migration_head == "d8f1a2b3c4e5"
    assert released.observation_complete is True
    assert released.state == "released"
    fence_calls = [
        call for call in runner.calls if "secp_api.discovery_activation_rollback_fence" in call[1]
    ]
    assert [call[1] for call in fence_calls] == [
        (
            "exec",
            _API_ID,
            "python",
            "-m",
            "secp_api.discovery_activation_rollback_fence",
            "observe",
        )
    ] * 2
    assert all(call[3] == 256 for call in fence_calls)


@pytest.mark.parametrize(
    "output",
    [
        "",
        '{"action":"observe","observation_complete":true,"rollback_fence_state":"released"}',
        '{"action":"observe","observation_complete":false,"rollback_fence_state":"unverified"}\n',
        '{"action":"observe","observation_complete":true,"rollback_fence_state":"unknown"}\n',
    ],
)
def test_controller_fence_observation_malformed_output_is_unverified(
    tls_material: ValidatedTLSMaterial, output: str
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile, role=LocalHostRole.controller)
    _set_controller_baseline(runner, store)
    adapter.stage_controller_rollback(profile, rendered, adapter.observe_controller(profile))
    adapter.install_controller(profile, rendered, tls_material)
    runner.fence_output_override = output

    observation = adapter.observe_api_rollback_fence(profile)

    assert observation.observation_complete is False
    assert observation.state == "unverified"
    assert observation.api_container_id == _API_ID
    assert observation.migration_head == "d8f1a2b3c4e5"


def test_controller_fence_observation_rejects_generation_drift(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile, role=LocalHostRole.controller)
    _set_controller_baseline(runner, store)
    adapter.stage_controller_rollback(profile, rendered, adapter.observe_controller(profile))
    adapter.install_controller(profile, rendered, tls_material)
    runner.fence_observe_replacement_id = "1" * 64

    with pytest.raises(ActivationAdapterError) as caught:
        adapter.observe_api_rollback_fence(profile)

    assert caught.value.reason_code == "api_rollback_fence_unverified"


def test_fence_release_rejects_runtime_substitution_before_running_helper(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile, role=LocalHostRole.controller)
    _set_controller_baseline(runner, store)
    adapter.stage_controller_rollback(profile, rendered, adapter.observe_controller(profile))
    adapter.install_controller(profile, rendered, tls_material)
    adapter.commit_activation_evidence(b"evidence", b"attestation")
    runner.api_container_id = "1" * 64
    runner.calls.clear()

    with pytest.raises(ActivationAdapterError):
        adapter.release_api_rollback_fence(profile)

    assert not any(
        "secp_api.discovery_activation_rollback_fence" in argv
        for _pin, argv, _timeout, _cap in runner.calls
    )
    assert runner.fence_engaged


@pytest.mark.parametrize(
    "output",
    [
        '{"action":"release","observation_complete":true,"rollback_fence_state":"released"}',
        '{"action":"release","observation_complete":true,"rollback_fence_state":"released"}\n\n',
        '{"action":"release","observation_complete":false,"rollback_fence_state":"unverified"}\n',
    ],
)
def test_fence_release_requires_exact_closed_success_output(
    tls_material: ValidatedTLSMaterial, output: str
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile, role=LocalHostRole.controller)
    _set_controller_baseline(runner, store)
    adapter.stage_controller_rollback(profile, rendered, adapter.observe_controller(profile))
    adapter.install_controller(profile, rendered, tls_material)
    adapter.commit_activation_evidence(b"evidence", b"attestation")
    runner.fence_output_override = output

    with pytest.raises(ActivationAdapterError) as caught:
        adapter.release_api_rollback_fence(profile)

    assert caught.value.reason_code == "api_rollback_fence_unverified"


def test_fence_engage_requires_exact_closed_success_output(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile)
    adapter.stage_rollback(
        profile, rendered, adapter.observe(profile), state_receipt=_state_receipt()
    )
    adapter.install_worker(
        profile, render_worker_compose_override(profile), _worker_ca(tls_material)
    )
    adapter.recreate_worker(profile)
    runner.fence_output_override = (
        '{"action":"engage","observation_complete":true,"rollback_fence_state":"engaged"}'
    )

    with pytest.raises(ActivationAdapterError) as caught:
        adapter.worker_api_rollback_compatible(profile)

    assert caught.value.reason_code == "api_rollback_fence_unverified"
    assert "restore_artifacts" not in store.operations


@pytest.mark.parametrize("failure", ["api_image", "proxy_hardening", "migration_head"])
def test_controller_runtime_integrity_blocks_all_tls_readiness(failure: str) -> None:
    profile = _profile()
    adapter, runner, _store, _state, tls_probe = _adapter(profile, role=LocalHostRole.controller)
    if failure == "api_image":
        runner.api_image = "sha256:" + "f" * 64
    elif failure == "proxy_hardening":
        runner.proxy_read_only = False
    else:
        runner.migration_ready = False

    observed = adapter.observe_controller(profile)

    assert observed.coherent
    assert not observed.tls_ready
    assert not observed.activation_route_enabled
    assert not observed.proxy_healthy
    assert tls_probe.calls == tls_probe.route_calls == 0


def test_worker_extra_hosts_binding_and_runtime_coherence_fail_closed() -> None:
    profile = _profile()
    adapter, runner, _store, _state, _tls = _adapter(profile)
    runner.worker_extra_hosts = ["admission.internal.test:10.20.30.41"]

    wrong_binding = adapter.observe(profile)

    assert wrong_binding.coherent
    assert wrong_binding.worker_runtime is not None
    assert not wrong_binding.worker_runtime.endpoint_binding_verified
    assert not wrong_binding.worker_running and not wrong_binding.worker_healthy

    runner.worker_extra_hosts = ["admission.internal.test:10.20.30.40"]
    runner.worker_runtime_calls = 0
    runner.worker_runtime_drift = True
    drifting = adapter.observe(profile)
    assert not drifting.coherent
    assert drifting.worker_generation is None
    assert not drifting.worker_running and not drifting.worker_healthy


def test_private_runtime_mac_drift_alone_breaks_worker_and_controller_coherence() -> None:
    profile = _profile()
    worker, worker_runner, _store, _state, _tls = _adapter(profile)
    worker_runner.worker_private_runtime_drift = True

    worker_observed = worker.observe(profile)

    assert not worker_observed.coherent
    assert worker_observed.worker_generation is None

    controller, controller_runner, _store2, _state2, tls_probe = _adapter(
        profile, role=LocalHostRole.controller
    )
    controller_runner.proxy_private_runtime_drift = True

    controller_observed = controller.observe_controller(profile)

    assert not controller_observed.coherent
    assert not controller_observed.tls_ready
    assert not controller_observed.proxy_healthy
    assert tls_probe.calls == tls_probe.route_calls == 1


def test_malformed_or_full_inspect_payload_is_refused_without_leaking_it() -> None:
    profile = _profile()
    adapter, runner, _store, _state, _tls = _adapter(profile)
    runner.malformed_worker = True
    with pytest.raises(ActivationAdapterError) as exc:
        adapter.observe(profile)
    assert exc.value.reason_code == "worker_inspect_malformed"
    assert "SECRET" not in repr(exc.value)


def test_install_journals_before_fixed_compose_and_never_pulls_or_builds(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    worker_override = render_worker_compose_override(profile)
    worker_ca = _worker_ca(tls_material)
    worker, worker_runner, worker_store, _state, _worker_tls = _adapter(profile)
    before = worker.observe(profile)
    controller, controller_runner, store, _controller_state, tls_probe = _adapter(
        profile, role=LocalHostRole.controller
    )
    _set_controller_baseline(controller_runner, store)
    controller_before = controller.observe_controller(profile)
    receipt = controller.stage_controller_rollback(profile, rendered, controller_before)
    assert receipt.journal_present and not receipt.effects_started
    controller.install_controller(profile, rendered, tls_material)
    assert store.operations.index("install_controller") < len(store.operations)
    store.tls_ca = tls_material.ca_certificate_pem()
    store.tls_fingerprint = tls_material.metadata.server_certificate_fingerprint
    tls_probe.expected_ca = store.tls_ca
    tls_probe.expected_fingerprint = store.tls_fingerprint
    assert controller.verify_internal_tls(profile, tls_material)
    assert tls_probe.calls == 2
    worker.stage_rollback(profile, rendered, before, state_receipt=_state_receipt())
    worker.install_worker(profile, worker_override, worker_ca)
    worker.recreate_worker(profile)
    assert worker_runner.generation == "after"
    calls = controller_runner.calls + worker_runner.calls
    compose_calls = [argv for _pin, argv, _timeout, _cap in calls if "up" in argv]
    assert len(compose_calls) == 2
    for argv in compose_calls:
        assert "--no-deps" in argv
        assert "--no-build" in argv
        assert argv[argv.index("--pull") + 1] == "never"
        assert "build" not in argv and "pull" not in argv
    assert compose_calls[0][-2:] == ("api", "discovery-admission-proxy")
    assert compose_calls[1][-1] == "worker"
    assert worker_store.operations.index("note_worker_recreation") < len(worker_store.operations)
    worker_install_operations = worker_store.operations
    assert worker_install_operations.index("transaction_base_compose_binding") < (
        worker_install_operations.index("validated_runtime_overlay")
    )
    assert worker_install_operations.index("validated_runtime_overlay") < (
        worker_install_operations.index("install_worker")
    )


def test_base_compose_drift_refuses_before_artifact_or_compose_mutation(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    worker_override = render_worker_compose_override(profile)
    worker_ca = _worker_ca(tls_material)

    controller, controller_runner, controller_store, _state, _tls = _adapter(
        profile, role=LocalHostRole.controller
    )
    _set_controller_baseline(controller_runner, controller_store)
    controller.stage_controller_rollback(profile, rendered, controller.observe_controller(profile))
    controller_store.base_compose_drift = True
    with pytest.raises(ActivationAdapterError) as controller_exc:
        controller.install_controller(profile, rendered, tls_material)
    assert controller_exc.value.reason_code == "base_compose_drift"
    assert "install_controller" not in controller_store.operations
    assert not any("up" in argv for _pin, argv, _timeout, _cap in controller_runner.calls)

    worker, worker_runner, worker_store, _state2, _tls2 = _adapter(profile)
    before = worker.observe(profile)
    worker.stage_rollback(profile, rendered, before, state_receipt=_state_receipt())
    worker_store.base_compose_drift = True
    with pytest.raises(ActivationAdapterError) as worker_exc:
        worker.install_worker(profile, worker_override, worker_ca)
    assert worker_exc.value.reason_code == "base_compose_drift"
    assert "validated_runtime_overlay" not in worker_store.operations
    assert "install_worker" not in worker_store.operations
    assert not any("up" in argv for _pin, argv, _timeout, _cap in worker_runner.calls)


def test_compensation_restores_fixed_base_deployments_and_removes_only_proxy(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    worker_override = render_worker_compose_override(profile)
    worker_ca = _worker_ca(tls_material)
    adapter, runner, store, _state, _tls = _adapter(profile)
    before = adapter.observe(profile)
    adapter.stage_rollback(profile, rendered, before, state_receipt=_state_receipt())
    adapter.install_worker(profile, worker_override, worker_ca)
    adapter.recreate_worker(profile)
    receipt = adapter.receipt()
    assert adapter.worker_api_rollback_compatible(profile)
    call_count = len(runner.calls)
    outcome = adapter.compensate(receipt)
    assert outcome.proven
    assert outcome.previous_worker_restored and outcome.previous_artifacts_restored
    assert "restore_artifacts" in store.operations
    assert store.operations[-1] == "finish_rollback:true"
    rollback_calls = [argv for _pin, argv, _timeout, _cap in runner.calls if "up" in argv][-2:]
    assert all("--no-build" in argv and "never" in argv for argv in rollback_calls)
    assert not any("discovery-admission-proxy" in argv for _, argv, _, _ in runner.calls)
    rollback_tail = [argv for _pin, argv, _timeout, _cap in runner.calls[call_count:]]
    fence_index = next(
        index
        for index, argv in enumerate(rollback_tail)
        if "secp_api.discovery_activation_rollback_fence" in argv
    )
    compose_index = next(index for index, argv in enumerate(rollback_tail) if "up" in argv)
    assert rollback_tail[fence_index][-1] == "engage"
    assert compose_index == fence_index + 1
    assert (
        sum(
            "secp_api.discovery_activation_rollback_fence" in argv
            for _pin, argv, _timeout, _cap in runner.calls
        )
        == 2
    )


def test_base_compose_drift_during_rollback_requires_manual_recovery(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    worker_override = render_worker_compose_override(profile)
    worker_ca = _worker_ca(tls_material)
    adapter, runner, store, _state, _tls = _adapter(profile)
    before = adapter.observe(profile)
    adapter.stage_rollback(profile, rendered, before, state_receipt=_state_receipt())
    adapter.install_worker(profile, worker_override, worker_ca)
    adapter.recreate_worker(profile)
    compose_count = sum("up" in argv for _pin, argv, _timeout, _cap in runner.calls)
    store.base_compose_drift = True

    outcome = adapter.compensate(adapter.receipt())

    assert not outcome.proven
    assert outcome.reason_code == "rollback_runtime_unproven"
    assert store.operations[-1] == "finish_rollback:false"
    assert sum("up" in argv for _pin, argv, _timeout, _cap in runner.calls) == compose_count


def test_controller_compensation_never_observes_or_mutates_worker(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    controller, runner, _store, _state2, _tls2 = _adapter(profile, role=LocalHostRole.controller)
    _set_controller_baseline(runner, _store)
    controller.stage_controller_rollback(profile, rendered, controller.observe_controller(profile))
    controller.install_controller(profile, rendered, tls_material)
    assert controller.controller_api_rollback_compatible(profile)
    call_count = len(runner.calls)
    outcome = controller.compensate(controller.receipt())
    assert outcome.proven
    rollback_tail = [argv for _pin, argv, _timeout, _cap in runner.calls]
    assert ("rm", "--force", _PROXY_ID) in rollback_tail
    assert not any("secp-ordinary-worker" in argv for argv in rollback_tail)
    compensation_calls = [argv for _pin, argv, _timeout, _cap in runner.calls[call_count:]]
    fence_index = next(
        index
        for index, argv in enumerate(compensation_calls)
        if "secp_api.discovery_activation_rollback_fence" in argv
    )
    downgrade_index = next(
        index
        for index, argv in enumerate(compensation_calls)
        if argv[-2:] == ("downgrade", "c4e2f9a1b7d3")
    )
    assert compensation_calls[fence_index][-1] == "engage"
    assert downgrade_index == fence_index + 1
    assert (
        sum(
            "secp_api.discovery_activation_rollback_fence" in argv
            for _pin, argv, _timeout, _cap in runner.calls
        )
        == 2
    )


@pytest.mark.parametrize("substituted", ["api", "proxy"])
def test_controller_runtime_substitution_refuses_before_any_rollback_mutation(
    tls_material: ValidatedTLSMaterial, substituted: str
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile, role=LocalHostRole.controller)
    _set_controller_baseline(runner, store)
    adapter.stage_controller_rollback(profile, rendered, adapter.observe_controller(profile))
    adapter.install_controller(profile, rendered, tls_material)
    if substituted == "api":
        runner.api_container_id = "1" * 64
    else:
        runner.proxy_container_id = "2" * 64
    call_count = len(runner.calls)

    outcome = adapter.compensate(adapter.receipt())

    assert not outcome.proven
    assert "restore_artifacts" not in store.operations
    rollback_calls = [argv for _pin, argv, _timeout, _cap in runner.calls[call_count:]]
    assert not any("up" in argv or argv[:2] == ("rm", "--force") for argv in rollback_calls)
    assert not any(
        "secp_api.discovery_activation_rollback_probe" in argv for argv in rollback_calls
    )


def test_worker_runtime_substitution_and_environment_drift_refuse_before_restore(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile)
    adapter.stage_rollback(
        profile, rendered, adapter.observe(profile), state_receipt=_state_receipt()
    )
    adapter.install_worker(
        profile, render_worker_compose_override(profile), _worker_ca(tls_material)
    )
    adapter.recreate_worker(profile)
    runner.worker_after_id = "3" * 64
    runner.worker_environment = ["SECP_RUNTIME_MODE=substituted"]
    call_count = len(runner.calls)

    outcome = adapter.compensate(adapter.receipt())

    assert not outcome.proven
    assert "restore_artifacts" not in store.operations
    rollback_calls = [argv for _pin, argv, _timeout, _cap in runner.calls[call_count:]]
    assert not any("up" in argv for argv in rollback_calls)
    assert not any(
        "secp_api.discovery_activation_rollback_probe" in argv for argv in rollback_calls
    )


def test_worker_runtime_environment_value_drift_with_same_generation_refuses_before_restore(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile)
    adapter.stage_rollback(
        profile, rendered, adapter.observe(profile), state_receipt=_state_receipt()
    )
    adapter.install_worker(
        profile, render_worker_compose_override(profile), _worker_ca(tls_material)
    )
    adapter.recreate_worker(profile)
    runner.worker_environment = ["SECP_RUNTIME_MODE=credential-value-changed"]
    call_count = len(runner.calls)

    outcome = adapter.compensate(adapter.receipt())

    assert not outcome.proven
    assert "restore_artifacts" not in store.operations
    rollback_calls = [argv for _pin, argv, _timeout, _cap in runner.calls[call_count:]]
    assert not any("up" in argv for argv in rollback_calls)
    assert not any(
        "secp_api.discovery_activation_rollback_probe" in argv for argv in rollback_calls
    )


def test_missing_runtime_after_image_refuses_without_probe_restore_or_compose(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile)
    adapter.stage_rollback(
        profile, rendered, adapter.observe(profile), state_receipt=_state_receipt()
    )
    adapter.install_worker(
        profile, render_worker_compose_override(profile), _worker_ca(tls_material)
    )
    adapter.recreate_worker(profile)
    store._runtime_after = None  # noqa: SLF001 - simulate crash before durable after-image
    call_count = len(runner.calls)

    outcome = adapter.compensate(adapter.receipt())

    assert not outcome.proven
    assert "restore_artifacts" not in store.operations
    rollback_calls = [argv for _pin, argv, _timeout, _cap in runner.calls[call_count:]]
    assert not any("up" in argv for argv in rollback_calls)
    assert not any(
        "secp_api.discovery_activation_rollback_probe" in argv for argv in rollback_calls
    )


def test_config_only_failure_restores_artifacts_without_recreating_worker(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile)
    adapter.stage_rollback(
        profile, rendered, adapter.observe(profile), state_receipt=_state_receipt()
    )
    adapter.install_worker(
        profile, render_worker_compose_override(profile), _worker_ca(tls_material)
    )
    call_count = len(runner.calls)

    outcome = adapter.compensate(adapter.receipt())

    assert outcome.proven
    assert "restore_artifacts" in store.operations
    assert not any("up" in argv for _pin, argv, _timeout, _cap in runner.calls[call_count:])


def test_dormant_preexisting_overrides_are_not_activated_during_rollback(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    worker, worker_runner, worker_store, _state, _tls = _adapter(profile)
    worker_store.worker_override_preexisting = True
    worker.stage_rollback(
        profile, rendered, worker.observe(profile), state_receipt=_state_receipt()
    )
    worker.install_worker(
        profile, render_worker_compose_override(profile), _worker_ca(tls_material)
    )
    worker.recreate_worker(profile)
    assert worker.compensate(worker.receipt()).proven
    worker_rollback = [argv for _pin, argv, _timeout, _cap in worker_runner.calls if "up" in argv][
        -1
    ]
    assert PRODUCTION_LAYOUT.worker_compose_override_path not in worker_rollback

    controller, runner, store, _state2, _tls2 = _adapter(profile, role=LocalHostRole.controller)
    store.controller_override_preexisting = True
    _set_controller_baseline(runner, store)
    controller.stage_controller_rollback(profile, rendered, controller.observe_controller(profile))
    controller.install_controller(profile, rendered, tls_material)
    assert controller.compensate(controller.receipt()).proven
    controller_rollback = [argv for _pin, argv, _timeout, _cap in runner.calls if "up" in argv][-1]
    assert PRODUCTION_LAYOUT.controller_compose_override_path not in controller_rollback
    assert ("rm", "--force", _PROXY_ID) in [argv for _pin, argv, _timeout, _cap in runner.calls]


def _controller_compose_up_calls(runner: FakeRunner) -> list[tuple[str, ...]]:
    return [
        argv
        for _pin, argv, _timeout, _cap in runner.calls
        if "up" in argv and CONTROLLER_BASE_COMPOSE_PATH in argv
    ]


def test_controller_activation_and_rollback_bind_the_fixed_env_file(
    tls_material: ValidatedTLSMaterial,
) -> None:
    # PR5F.1: both the activation Compose 'up' and the baseline rollback 'up' carry the code-owned
    # fixed --env-file, and the binding is proven (assert_controller_env_unchanged) each time.
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile, role=LocalHostRole.controller)
    _set_controller_baseline(runner, store)
    adapter.stage_controller_rollback(profile, rendered, adapter.observe_controller(profile))
    store.operations.clear()
    runner.calls.clear()
    adapter.install_controller(profile, rendered, tls_material)
    install_up = _controller_compose_up_calls(runner)
    assert install_up
    for argv in install_up:
        assert argv[:2] == ("--env-file", CONTROLLER_ENV_FILE_PATH)
    assert "assert_controller_env_unchanged" in store.operations

    store.operations.clear()
    runner.calls.clear()
    assert adapter.compensate(adapter.receipt()).proven
    rollback_up = _controller_compose_up_calls(runner)
    assert rollback_up
    for argv in rollback_up:
        assert argv[:2] == ("--env-file", CONTROLLER_ENV_FILE_PATH)
    assert "assert_controller_env_unchanged" in store.operations


def test_controller_install_refuses_on_env_binding_drift_before_any_compose(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile, role=LocalHostRole.controller)
    _set_controller_baseline(runner, store)
    adapter.stage_controller_rollback(profile, rendered, adapter.observe_controller(profile))
    store.controller_env_drift = True
    runner.calls.clear()
    with pytest.raises(ActivationAdapterError) as caught:
        adapter.install_controller(profile, rendered, tls_material)
    assert caught.value.reason_code == "controller_env_drift"
    assert _controller_compose_up_calls(runner) == []  # refused before the mutation


def test_worker_recreation_never_binds_or_asserts_the_controller_env_file(
    tls_material: ValidatedTLSMaterial,
) -> None:
    # PR5F.1: the worker uses its own service-level env_file; it never receives the controller
    # environment file and never runs the controller env-binding assertion.
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile)
    adapter.stage_rollback(
        profile, rendered, adapter.observe(profile), state_receipt=_state_receipt()
    )
    runner.calls.clear()
    store.operations.clear()
    adapter.install_worker(
        profile, render_worker_compose_override(profile), _worker_ca(tls_material)
    )
    adapter.recreate_worker(profile)
    assert "assert_controller_env_unchanged" not in store.operations
    for _pin, argv, _timeout, _cap in runner.calls:
        assert "--env-file" not in argv
        assert CONTROLLER_ENV_FILE_PATH not in argv


def test_controller_downgrade_failure_reports_recovery_before_runtime_switch(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile, role=LocalHostRole.controller)
    _set_controller_baseline(runner, store)
    adapter.stage_controller_rollback(profile, rendered, adapter.observe_controller(profile))
    adapter.install_controller(profile, rendered, tls_material)
    runner.fail_downgrade = True
    call_count = len(runner.calls)

    outcome = adapter.compensate(adapter.receipt())

    assert not outcome.proven
    assert "restore_artifacts" in store.operations
    assert adapter.observe_controller(profile).recovery_required is True
    rollback_calls = [argv for _pin, argv, _timeout, _cap in runner.calls[call_count:]]
    assert any(argv[-2:] == ("downgrade", "c4e2f9a1b7d3") for argv in rollback_calls)
    assert not any("up" in argv or argv[:2] == ("rm", "--force") for argv in rollback_calls)


def test_successful_compose_unhealthy_worker_has_a_rollbackable_after_image(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _state, _tls = _adapter(profile)
    adapter.stage_rollback(
        profile, rendered, adapter.observe(profile), state_receipt=_state_receipt()
    )
    adapter.install_worker(
        profile, render_worker_compose_override(profile), _worker_ca(tls_material)
    )
    runner.worker_healthy = False
    with pytest.raises(ActivationAdapterError) as exc:
        adapter.recreate_worker(profile)
    assert exc.value.reason_code == "worker_runtime_after_unverified"
    assert store.transaction_runtime_after() is not None
    runner.worker_healthy = True
    assert adapter.compensate(adapter.receipt()).proven


def test_command_result_repr_redacts_environment_values() -> None:
    secret = "SECP_DATABASE_URL=postgresql://private-value"
    result = CommandResult(0, secret)
    assert secret not in repr(result)
    assert "stdout_bytes=" in repr(result)


def test_typed_controller_offer_is_transaction_bound_and_stored_only_on_controller(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    controller, runner, store, _state, _tls = _adapter(profile, role=LocalHostRole.controller)
    _set_controller_baseline(runner, store)
    controller.stage_controller_rollback(profile, rendered, controller.observe_controller(profile))
    controller.install_controller(profile, rendered, tls_material)
    offer = ControllerOffer.model_construct(
        contract_schema="secp.discovery-activation.controller-offer/v1",
        transaction_id=controller.receipt().transaction_id,
    )
    attestation = _handoff_attestation()
    first = controller.emit_controller_offer(offer, attestation)
    second = controller.emit_controller_offer(offer, attestation)
    assert first == second
    assert first[0].endswith(b"\n") and first[1].endswith(b"\n")
    assert b"PRIVATE KEY" not in first[0]
    controller.store_controller_offer(offer, attestation)
    assert controller.load_controller_offer() == first
    assert store.operations[-1] == "commit_controller_offer"
    assert not any("secp-ordinary-worker" in argv for _pin, argv, _timeout, _cap in runner.calls)


def test_worker_result_is_local_and_controller_offer_methods_refuse(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    worker, runner, store, _state, _tls = _adapter(profile)
    rendered = render_activation(profile, tls_material.metadata)
    worker.stage_rollback(
        profile,
        rendered,
        worker.observe(profile),
        state_receipt=_state_receipt(),
    )
    result = WorkerResult.model_construct(
        contract_schema="secp.discovery-activation.worker-result/v1",
        worker_transaction_id=worker.receipt().transaction_id,
    )
    attestation = _handoff_attestation()
    worker.store_worker_result(result, attestation)
    loaded = worker.load_worker_result()
    assert loaded is not None and loaded[0].endswith(b"\n") and loaded[1].endswith(b"\n")
    command_count = len(runner.calls)
    operation_count = len(store.operations)
    with pytest.raises(ActivationAdapterError) as exc:
        worker.store_controller_offer(  # type: ignore[arg-type]
            b"{}\n", b"{}\n"
        )
    assert exc.value.reason_code == "controller_host_role_required"
    assert len(runner.calls) == command_count
    assert len(store.operations) == operation_count


def test_compose_failure_is_an_effect_and_drifted_rollback_requires_recovery(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, runner, store, _controller_state, _controller_tls = _adapter(
        profile, role=LocalHostRole.controller
    )
    _set_controller_baseline(runner, store)
    adapter.stage_controller_rollback(profile, rendered, adapter.observe_controller(profile))
    runner.fail_compose = True
    with pytest.raises(ActivationAdapterError):
        adapter.install_controller(profile, rendered, tls_material)
    receipt = adapter.receipt()
    assert receipt.effects_started and receipt.controller_changed
    store.raise_restore = True
    outcome = adapter.compensate(receipt)
    assert not outcome.proven
    assert outcome.reason_code == "rollback_recovery_required"
    assert store.operations[-1] == "finish_rollback:false"


def test_tls_probe_failure_never_becomes_tls_ready() -> None:
    profile = _profile()
    adapter, _runner, _store, _state, tls_probe = _adapter(profile, role=LocalHostRole.controller)
    tls_probe.result = False
    material = generate_tls_material(
        dns_identity="admission.internal.test",
        validity_days=30,
        now=datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
    )
    _store.tls_ca = material.ca_certificate_pem()
    _store.tls_fingerprint = material.metadata.server_certificate_fingerprint
    tls_probe.expected_ca = _store.tls_ca
    tls_probe.expected_fingerprint = _store.tls_fingerprint
    assert adapter.verify_internal_tls(profile, material) is False


def test_strict_tls_handshake_connects_to_listener_ip_with_dns_sni(monkeypatch) -> None:  # noqa: ANN001
    peer = b"reviewed-server-certificate"
    connections: list[tuple[tuple[str, int], float]] = []
    server_names: list[str] = []

    class RawSocket:
        def __enter__(self):  # noqa: ANN204
            return self

        def __exit__(self, *_args):  # noqa: ANN002, ANN204
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def close(self) -> None:
            return None

    class SecuredSocket:
        def __enter__(self):  # noqa: ANN204
            return self

        def __exit__(self, *_args):  # noqa: ANN002, ANN204
            return None

        def getpeercert(self, *, binary_form: bool):  # noqa: ANN201
            assert binary_form
            return peer

        def version(self) -> str:
            return "TLSv1.3"

    class Context:
        verify_mode = None
        check_hostname = False
        minimum_version = None

        def load_verify_locations(self, *, cadata: str) -> None:
            assert cadata == "reviewed-ca"

        def wrap_socket(self, _raw: RawSocket, *, server_hostname: str) -> SecuredSocket:
            server_names.append(server_hostname)
            return SecuredSocket()

    def create_connection(address: tuple[str, int], *, timeout: float) -> RawSocket:
        connections.append((address, timeout))
        return RawSocket()

    monkeypatch.setattr(local_adapter_module.ssl, "SSLContext", lambda _protocol: Context())
    monkeypatch.setattr(local_adapter_module.socket, "create_connection", create_connection)

    verified = StrictTLSHandshakeProbe().verify(
        _profile(),
        ca_certificate_pem=b"reviewed-ca",
        expected_server_fingerprint="sha256:" + hashlib.sha256(peer).hexdigest(),
    )

    assert verified
    assert connections == [(("10.20.30.40", 8443), 5)]
    assert server_names == ["admission.internal.test"]


def test_controller_route_probe_is_required_for_route_and_health_readiness() -> None:
    profile = _profile()
    adapter, _runner, store, _state, tls_probe = _adapter(profile, role=LocalHostRole.controller)
    tls_probe.route_result = False

    observed = adapter.observe_controller(profile)

    assert observed.tls_ready
    assert not observed.activation_route_enabled
    assert not observed.proxy_healthy
    assert tls_probe.calls == 1
    assert tls_probe.route_calls == 1


def test_probe_with_effect_claim_or_private_extra_field_is_refused() -> None:
    payload = json.loads(_probe())
    payload["probe_effects"]["opentofu_executed"] = True
    payload["private_key"] = "must-not-be-accepted"
    profile = _profile()
    adapter, runner, _store, _state, _tls = _adapter(profile)

    original = runner.run

    def poisoned(pin, argv_tail, *, timeout_seconds, max_output_bytes):  # noqa: ANN001, ANN202
        if (
            tuple(argv_tail)[:2]
            in {
                ("exec", _CID_BEFORE),
                ("exec", _CID_AFTER),
            }
            and tuple(argv_tail)[-1] != "check"
        ):
            return CommandResult(0, json.dumps(payload))
        return original(
            pin,
            tuple(argv_tail),
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    runner.run = poisoned  # type: ignore[method-assign]
    with pytest.raises(ActivationAdapterError) as exc:
        adapter.observe(profile)
    assert exc.value.reason_code == "activation_probe_output_malformed"
    assert "must-not-be-accepted" not in repr(exc.value)


def test_generation_must_change_before_publication_is_accepted(monkeypatch) -> None:  # noqa: ANN001
    profile = _profile()
    adapter, runner, _store, _state, _tls = _adapter(profile)
    previous = WorkerGeneration(
        container_id=_CID_BEFORE,
        restart_count=0,
        started_at=_STARTED_BEFORE,
    )
    ticks = iter((0.0, 0.0, 2.0, 2.0))
    adapter._monotonic = lambda: next(ticks, 2.0)  # type: ignore[method-assign]
    monkeypatch.setattr("threading.Event.wait", lambda self, timeout: True)
    unchanged = adapter.await_worker_publication(profile, previous_generation=previous)
    assert unchanged.worker_generation == previous
    runner.generation = "after"
    ticks = iter((0.0, 0.0, 2.0))
    adapter._monotonic = lambda: next(ticks, 2.0)  # type: ignore[method-assign]
    changed = adapter.await_worker_publication(profile, previous_generation=previous)
    assert changed.worker_generation != previous


def test_evidence_is_committed_through_store_only_after_other_effects(
    tls_material: ValidatedTLSMaterial,
) -> None:
    profile = _profile()
    rendered = render_activation(profile, tls_material.metadata)
    adapter, _controller_runner, store, _controller_state, _controller_tls = _adapter(
        profile, role=LocalHostRole.controller
    )
    _set_controller_baseline(_controller_runner, store)
    adapter.stage_controller_rollback(profile, rendered, adapter.observe_controller(profile))
    adapter.install_controller(profile, rendered, tls_material)
    adapter.commit_evidence(b'{"safe":true}\n', b'{"signature":"00"}\n')
    receipt = adapter.receipt()
    assert receipt.evidence_committed
    assert store.operations[-1] == "commit_evidence"
    assert adapter.load_evidence() == (b'{"safe":true}\n', b'{"signature":"00"}\n')


def test_receipt_must_never_be_inferred_from_missing_observation() -> None:
    profile = _profile()
    adapter, _runner, _store, _state, _tls = _adapter(profile)
    with pytest.raises(ActivationAdapterError) as exc:
        adapter.stage_rollback(
            profile,
            object(),  # type: ignore[arg-type]
            HostObservation(),
            state_receipt=_state_receipt(),
        )
    assert exc.value.reason_code in {
        "activation_input_type_invalid",
        "rollback_observation_incomplete",
    }
