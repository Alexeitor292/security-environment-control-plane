"""Shared test support for the deployment package (SECP-PR5D, round 2).

Documentation-only fixtures (RFC-reserved / never-real values); a valid secret-free deployment
profile whose package manifest digest matches the ACTUAL package manifest; an independent
``ExpectedDeploymentIdentities`` that agrees with the profile; a typed test runtime-provisioning
seam
that yields a VALID controlled-live plan-execution seam set (the concrete OpenBao chain, from
documentation values, contacts nothing); and a scripted command runner keyed by (executable-path,
argv-tail). Nothing here contacts the network, Temporal, a database, or any external infrastructure.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

FIXED_PROFILE_PATH = "/etc/secp/operator-deployment/profile.json"

# Documentation-only constants (RFC 5737 / RFC 2606 style). NEVER a real value.
SOURCE_SHA = "a" * 40
SOURCE_TREE_SHA = "b" * 40
DIGEST_CP = "sha256:" + "1" * 64
DIGEST_OW = "sha256:" + "2" * 64
DIGEST_OP = "sha256:" + "3" * 64
CONTAINER_EXE = "/usr/bin/docker"
CONTAINER_EXE_DIGEST = "sha256:" + "4" * 64
INSPECTOR_EXE = "/usr/bin/systemctl"
INSPECTOR_EXE_DIGEST = "sha256:" + "5" * 64
ORDINARY_QUEUE = "secp-orchestration"
OPERATOR_QUEUE = "secp-controlled-live-v1"
OPERATOR_SERVICE = "secp-operator-worker.service"
ORDINARY_CONTAINER = "secp-ordinary-worker"
HEALTH_ARGV = ("/usr/bin/python3", "-m", "secp_worker.health", "check")


def _reviewed_pins() -> dict:
    from secp_operator_deployment.compositions import reviewed_composition_pins

    return reviewed_composition_pins()


def _manifest_digest() -> str:
    from secp_operator_deployment import package_implementation_digest

    return package_implementation_digest()


def valid_profile_raw(**overrides: object) -> dict:
    from secp_operator_deployment import (
        PACKAGE_CONTRACT_VERSION,
        PACKAGE_IMPLEMENTATION_ID,
        PACKAGE_VERSION,
    )
    from secp_operator_deployment.identities import (
        ELIGIBILITY_PROVIDER_IDENTITY,
        PLAN_PROVIDER_IDENTITY,
        READINESS_PROVIDER_IDENTITY,
    )

    pins = _reviewed_pins()
    raw: dict = {
        "contract_version": PACKAGE_CONTRACT_VERSION,
        "package_version": PACKAGE_VERSION,
        "package_implementation_id": PACKAGE_IMPLEMENTATION_ID,
        "package_implementation_digest": _manifest_digest(),
        "release_source_sha": SOURCE_SHA,
        "source_tree_sha": SOURCE_TREE_SHA,
        "parent_sha": None,
        "control_plane_image_digest": DIGEST_CP,
        "ordinary_worker_image_digest": DIGEST_OW,
        "operator_image_digest": DIGEST_OP,
        "ordinary_runtime_uid": 10001,
        "ordinary_runtime_gid": 10001,
        "operator_runtime_uid": 10001,
        "operator_runtime_gid": 10001,
        "ordinary_task_queue": ORDINARY_QUEUE,
        "operator_task_queue": OPERATOR_QUEUE,
        "ordinary_health_command": list(HEALTH_ARGV),
        "operator_service_name": OPERATOR_SERVICE,
        "ordinary_container_name": ORDINARY_CONTAINER,
        "container_runtime_executable": CONTAINER_EXE,
        "container_runtime_executable_digest": CONTAINER_EXE_DIGEST,
        "service_inspector_executable": INSPECTOR_EXE,
        "service_inspector_executable_digest": INSPECTOR_EXE_DIGEST,
        "controlled_live_renderer_registration": pins["renderer_registration"],
        "controlled_live_renderer_digest": pins["renderer_digest"],
        "controlled_live_process_registration": pins["process_registration"],
        "controlled_live_process_digest": pins["process_digest"],
        "controlled_live_provider_source": pins["provider_source"],
        "plan_provider_identity": PLAN_PROVIDER_IDENTITY,
        "readiness_provider_identity": READINESS_PROVIDER_IDENTITY,
        "eligibility_provider_identity": ELIGIBILITY_PROVIDER_IDENTITY,
    }
    raw.update(overrides)
    return raw


def valid_profile(**overrides: object):  # noqa: ANN201
    from secp_operator_deployment.profile import parse_deployment_profile

    return parse_deployment_profile(valid_profile_raw(**overrides))


def valid_expected(**overrides: object):  # noqa: ANN201
    """An independent trusted-pins object that AGREES with :func:`valid_profile_raw`."""
    from secp_operator_deployment import (
        PACKAGE_CONTRACT_VERSION,
        PACKAGE_VERSION,
    )
    from secp_operator_deployment.identities import ExpectedDeploymentIdentities

    pins = _reviewed_pins()
    base = dict(
        package_contract_version=PACKAGE_CONTRACT_VERSION,
        package_version=PACKAGE_VERSION,
        package_implementation_digest=_manifest_digest(),
        release_source_sha=SOURCE_SHA,
        source_tree_sha=SOURCE_TREE_SHA,
        parent_sha=None,
        control_plane_image_digest=DIGEST_CP,
        ordinary_worker_image_digest=DIGEST_OW,
        operator_image_digest=DIGEST_OP,
        ordinary_runtime_uid=10001,
        ordinary_runtime_gid=10001,
        operator_runtime_uid=10001,
        operator_runtime_gid=10001,
        ordinary_task_queue=ORDINARY_QUEUE,
        operator_task_queue=OPERATOR_QUEUE,
        ordinary_health_command=HEALTH_ARGV,
        operator_service_name=OPERATOR_SERVICE,
        ordinary_container_name=ORDINARY_CONTAINER,
        container_runtime_executable=CONTAINER_EXE,
        container_runtime_executable_digest=CONTAINER_EXE_DIGEST,
        service_inspector_executable=INSPECTOR_EXE,
        service_inspector_executable_digest=INSPECTOR_EXE_DIGEST,
        controlled_live_renderer_registration=pins["renderer_registration"],
        controlled_live_renderer_digest=pins["renderer_digest"],
        controlled_live_process_registration=pins["process_registration"],
        controlled_live_process_digest=pins["process_digest"],
        controlled_live_provider_source=pins["provider_source"],
    )
    base.update(overrides)
    return ExpectedDeploymentIdentities(**base)


def expected_identities_raw(**overrides: object) -> dict:
    """The JSON-serializable independent trusted-pins file body that AGREES with the profile."""
    from secp_operator_deployment import PACKAGE_CONTRACT_VERSION, PACKAGE_VERSION
    from secp_operator_deployment.identities import (
        ELIGIBILITY_PROVIDER_IDENTITY,
        PLAN_PROVIDER_IDENTITY,
        READINESS_PROVIDER_IDENTITY,
    )

    pins = _reviewed_pins()
    raw: dict = {
        "package_contract_version": PACKAGE_CONTRACT_VERSION,
        "package_version": PACKAGE_VERSION,
        "package_implementation_digest": _manifest_digest(),
        "release_source_sha": SOURCE_SHA,
        "source_tree_sha": SOURCE_TREE_SHA,
        "parent_sha": None,
        "control_plane_image_digest": DIGEST_CP,
        "ordinary_worker_image_digest": DIGEST_OW,
        "operator_image_digest": DIGEST_OP,
        "ordinary_runtime_uid": 10001,
        "ordinary_runtime_gid": 10001,
        "operator_runtime_uid": 10001,
        "operator_runtime_gid": 10001,
        "ordinary_task_queue": ORDINARY_QUEUE,
        "operator_task_queue": OPERATOR_QUEUE,
        "ordinary_health_command": list(HEALTH_ARGV),
        "operator_service_name": OPERATOR_SERVICE,
        "ordinary_container_name": ORDINARY_CONTAINER,
        "container_runtime_executable": CONTAINER_EXE,
        "container_runtime_executable_digest": CONTAINER_EXE_DIGEST,
        "service_inspector_executable": INSPECTOR_EXE,
        "service_inspector_executable_digest": INSPECTOR_EXE_DIGEST,
        "controlled_live_renderer_registration": pins["renderer_registration"],
        "controlled_live_renderer_digest": pins["renderer_digest"],
        "controlled_live_process_registration": pins["process_registration"],
        "controlled_live_process_digest": pins["process_digest"],
        "controlled_live_provider_source": pins["provider_source"],
        "plan_provider_identity": PLAN_PROVIDER_IDENTITY,
        "readiness_provider_identity": READINESS_PROVIDER_IDENTITY,
        "eligibility_provider_identity": ELIGIBILITY_PROVIDER_IDENTITY,
    }
    raw.update(overrides)
    return raw


# --------------------------------------------------------------------------- controlled-live
# runtime


class _FakeAuthMaterialProvider:
    """A non-serializable, test-only worker-auth provider (yields an inert non-secret header)."""

    def __getstate__(self):  # noqa: ANN204
        raise TypeError("cannot serialize")

    def auth_headers(self, *, now):  # noqa: ANN001, ANN201
        return {"X-Vault-Token": "TEST-TOKEN-NEVER-REAL"}


def _concrete_openbao_resolver():  # noqa: ANN202
    """A controlled-live-bindable resolver over the concrete OpenBao HTTPS transport, built from
    documentation values. Construction validates the origin and contacts nothing."""
    from secp_worker.openbao_plan_http_transport import OpenBaoHttpTransport
    from secp_worker.plan_gen.openbao_plan_resolver import (
        ConcreteOpenBaoPlanSecretClient,
        OpenBaoPlanSecretResolver,
    )

    transport = OpenBaoHttpTransport(
        origin="https://vault.example",
        ca_path="/etc/ssl/certs/reviewed-ca.pem",
        auth_provider=_FakeAuthMaterialProvider(),
    )
    return OpenBaoPlanSecretResolver(client=ConcreteOpenBaoPlanSecretClient(transport=transport))


def plan_execution_seams(**over):  # noqa: ANN001, ANN201
    from secp_operator_deployment.runtime_seams import PlanExecutionRuntimeSeams
    from secp_worker.plan_gen.composition import ProviderRuntimeInputSource, StateRuntimeInputSource
    from secp_worker.provisioning.toolchain_verify import ToolchainFilesystemLayout

    base = dict(
        toolchain_layout=ToolchainFilesystemLayout(
            trusted_root="/opt/secp/operator-deployment/toolchain",
            executable="bin/tofu",
            version_metadata="meta/version.json",
            module_bundle="bundle",
            provider_lockfile="meta/provider.lock",
            provider_mirror="mirror",
            cli_config="meta/cli.tofurc",
        ),
        trusted_workspace_root="/opt/secp/operator-deployment/workspace",
        provider_version="0.80.0",
        provider_runtime_input_source=ProviderRuntimeInputSource(
            endpoint="https://pve.example:8006"
        ),
        state_runtime_input_source=StateRuntimeInputSource(
            address="https://state.example/lab",
            lock_address="https://state.example/lab?lock",
            unlock_address="https://state.example/lab?unlock",
            username="u",
        ),
        provider_resolver=_concrete_openbao_resolver(),
        state_resolver=_concrete_openbao_resolver(),
        provider_resolver_activation=object(),
        state_resolver_activation=object(),
        process_timeout_seconds=60,
        max_output_bytes=1024,
        deployment_activation_dossier_hash="sha256:" + "a" * 64,
        worker_identity_registration_id=str(uuid.UUID(int=1)),
    )
    base.update(over)
    return PlanExecutionRuntimeSeams(**base)


@dataclass
class StubControlledLiveRuntime:
    """A provisioned test runtime seam yielding a VALID controlled-live plan-execution seam set. It
    is
    provisioned for COMPOSITION building, but its attestation is UNPROVISIONED (PR5D installs no
    reviewed runtime provider), so ``provisioning_attestation`` fails closed like the sealed
    default."""

    seams: object = None

    def provisioned(self) -> bool:
        return True

    def plan_execution_seams(self):  # noqa: ANN201
        return self.seams if self.seams is not None else plan_execution_seams()

    def provisioning_attestation(self, *, deployment_profile_digest, expected_identities_digest):  # noqa: ANN001, ANN201
        from secp_operator_deployment import DeploymentPackageError

        raise DeploymentPackageError("controlled_live_runtime_not_provisioned")


def runtime_attestation(runtime: object | None = None):  # noqa: ANN201
    """Produce a bound :class:`RuntimeProvisioningAttestation` from a runtime (default: a sealed
    stub,
    so the attestation is UNPROVISIONED — PR5D installs no reviewed runtime provider). It never
    calls ``plan_execution_seams()`` / a resolver."""
    from secp_operator_deployment.runtime_seams import attest_runtime

    return attest_runtime(
        runtime if runtime is not None else StubControlledLiveRuntime(),
        profile=valid_profile(),
        expected=valid_expected(),
    )


def built_controlled_live_compositions(**over):  # noqa: ANN003, ANN201
    """Build the reviewed controlled-live composition aggregate from the valid profile + a
    provisioned
    stub runtime + the agreeing expected pins. This is the CALLER's construction step — read-only
    ``verify`` never builds the aggregate itself (blocker #7); it only consumes an already-built
    one."""
    from secp_operator_deployment.compositions import build_controlled_live_compositions

    kwargs = dict(
        profile=valid_profile(), runtime=StubControlledLiveRuntime(), expected=valid_expected()
    )
    kwargs.update(over)
    return build_controlled_live_compositions(**kwargs)


# --------------------------------------------------------------------------- host observation


def host_evidence(  # noqa: ANN201
    *, inspected=True, coherent=True, present=True, enabled=False, running=False, ordinary=True
):
    """A deployment-owned :class:`HostObservationEvidence` for verify tests (default: prepared +
    ready
    — operator present/disabled/stopped, ordinary running + healthy)."""
    from secp_operator_deployment.host_adapters import HostObservationEvidence

    return HostObservationEvidence(
        inspected=inspected,
        coherent=coherent,
        operator_present=present,
        operator_enabled=enabled,
        operator_running=running,
        ordinary_running=ordinary,
    )


def prepared_host_runner():  # noqa: ANN201
    """A scripted command runner whose systemctl/docker outputs model a PREPARED host: operator
    loaded/inactive/disabled, ordinary container running, exact health passing."""
    from secp_operator_deployment.host_adapters import _CONTAINER_FORMAT, _OPERATOR_PROPERTIES

    show_tail = ("show", "--property", ",".join(_OPERATOR_PROPERTIES), OPERATOR_SERVICE)
    inspect_tail = ("inspect", "--format", _CONTAINER_FORMAT, ORDINARY_CONTAINER)
    health_tail = ("exec", ORDINARY_CONTAINER, *HEALTH_ARGV)
    cid = "3f2a" + "0" * 60
    show_out = (
        "LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n"
        "InvocationID=\nStateChangeTimestampMonotonic=123\n"
    )
    inspect_out = f"{cid} true 0 2026-01-02T03:04:05.000000000Z 0001-01-01T00:00:00Z 4242\n"
    return FakeCommandRunner(
        {
            (INSPECTOR_EXE, show_tail): (0, show_out),
            (CONTAINER_EXE, inspect_tail): (0, inspect_out),
            (CONTAINER_EXE, health_tail): (0, ""),
        }
    )


# --------------------------------------------------------------------------- host-adapter fakes


@dataclass
class FakeCommandRunner:
    """A scripted command runner keyed by (executable-path, argv-tail) → (exit_code, stdout)."""

    responses: dict

    def run(self, pin, argv_tail, *, timeout_seconds, max_output_bytes):  # noqa: ANN001, ANN201
        from secp_operator_deployment.host_process import CommandResult

        key = (pin.path, tuple(argv_tail))
        if key not in self.responses:
            raise AssertionError(f"unscripted command: {key}")
        code, out = self.responses[key]
        return CommandResult(exit_code=code, stdout=out)


def seeded_profile_fs(raw_bytes: bytes | None = None):  # noqa: ANN201
    """An in-memory filesystem seeded with the profile JSON at the fixed path (root-owned, 0640)
    plus
    its trusted parent directory. Pass ``raw_bytes`` to seed exact bytes (e.g. duplicate keys)."""
    import json

    from secp_commissioning.runtime import InMemoryFilesystem

    fs = InMemoryFilesystem()
    fs.seed_dir("/etc/secp/operator-deployment", uid=0, gid=0, mode=0o755)
    payload = (
        raw_bytes if raw_bytes is not None else json.dumps(valid_profile_raw()).encode("utf-8")
    )
    fs.seed_file(FIXED_PROFILE_PATH, payload, uid=0, gid=0, mode=0o640)
    return fs


def seeded_production_fs(
    *,
    profile_bytes: bytes | None = None,
    expected_bytes: bytes | None = None,
    seed_profile: bool = True,
    seed_expected: bool = True,
):  # noqa: ANN201
    """An in-memory filesystem seeded with BOTH root-controlled files — the profile and the SEPARATE
    independent expected-identities file — at their fixed paths (root-owned, 0640). Toggle
    ``seed_profile`` / ``seed_expected`` to model partial bindings (e.g. only the profile
    present)."""
    import json

    from secp_commissioning.runtime import InMemoryFilesystem
    from secp_operator_deployment.identities import FIXED_EXPECTED_IDENTITIES_PATH

    fs = InMemoryFilesystem()
    fs.seed_dir("/etc/secp/operator-deployment", uid=0, gid=0, mode=0o755)
    if seed_profile:
        fs.seed_file(
            FIXED_PROFILE_PATH,
            profile_bytes
            if profile_bytes is not None
            else json.dumps(valid_profile_raw()).encode("utf-8"),
            uid=0,
            gid=0,
            mode=0o640,
        )
    if seed_expected:
        fs.seed_file(
            FIXED_EXPECTED_IDENTITIES_PATH,
            expected_bytes
            if expected_bytes is not None
            else json.dumps(expected_identities_raw()).encode("utf-8"),
            uid=0,
            gid=0,
            mode=0o640,
        )
    return fs
