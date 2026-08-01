"""PR5H-A architecture guards: provider neutrality, plane boundaries, and inertness.

These are **guards, not behaviour**. They exist so a future refactor cannot silently give the
durable-enrollment foundation a provider dependency, let it cross a reviewed plane boundary, or
activate the customer path before PR5H-B.

Deliberate methodology: provider neutrality is judged from **imports, schema, closed
vocabularies and non-docstring string constants** — never a blind substring scan, which would
false-positive on explanatory prose (the modules legitimately *discuss* being provider-neutral).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_PKG = REPO / "apps" / "api" / "secp_api"

#: The PR5H-A production surface. Every one of these must stay provider-neutral and pure.
PR5H_PRODUCTION_MODULES = (
    API_PKG / "worker_enrollment_contract.py",
    API_PKG / "worker_enrollment_models.py",
    API_PKG / "worker_enrollment_repository.py",
    API_PKG / "worker_enrollment_schema.py",
    API_PKG / "services" / "worker_enrollment.py",
    API_PKG / "services" / "worker_enrollment_recovery.py",
    REPO
    / "apps"
    / "api"
    / "migrations"
    / "versions"
    / "b6e2f4a9c1d7_worker_enrollment_foundation.py",
)

#: Provider / IaC / orchestrator tokens. Matched by IDENTIFIER SEGMENT (so ``aws_region`` and
#: ``proxmox-node`` are both caught) rather than by naive substring, and only against imports,
#: schema names, closed vocabularies and non-docstring literals.
PROVIDER_TOKENS = frozenset(
    {
        "proxmox",
        "proxmoxer",
        "vmware",
        "vsphere",
        "esxi",
        "pyvmomi",
        "hyperv",
        "hyper",
        "aws",
        "boto",
        "boto3",
        "botocore",
        "ec2",
        "azure",
        "gcp",
        "googlecloud",
        "gce",
        "kubernetes",
        "k8s",
        "kubectl",
        "openshift",
        "opentofu",
        "tofu",
        "terraform",
        "ansible",
        "libvirt",
        "openstack",
        "nutanix",
        "secp_plugin_proxmox",
        "secp_plugin_simulator",
    }
)


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _segments(value: str) -> set[str]:
    """Split an identifier-ish value into lowercase segments on non-alphanumeric boundaries."""
    out: list[str] = []
    current: list[str] = []
    for char in value:
        if char.isalnum():
            current.append(char.lower())
        elif current:
            out.append("".join(current))
            current = []
    if current:
        out.append("".join(current))
    return set(out)


def _provider_hits(value: str) -> set[str]:
    return _segments(value) & PROVIDER_TOKENS


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
        elif isinstance(node, ast.Call):
            target = node.func
            dynamic = isinstance(target, ast.Name) and target.id == "__import__"
            dynamic = dynamic or (
                isinstance(target, ast.Attribute) and target.attr == "import_module"
            )
            if dynamic and node.args and isinstance(node.args[0], ast.Constant):
                if isinstance(node.args[0].value, str):
                    names.add(node.args[0].value)
    return names


def _docstring_nodes(tree: ast.Module) -> set[int]:
    """Ids of the Constant nodes that are docstrings (module/class/function), so prose that merely
    *describes* provider neutrality is not mistaken for provider behaviour."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                ids.add(id(body[0].value))
    return ids


def _behavioural_strings(path: Path) -> list[str]:
    """Every string literal that is NOT a docstring — i.e. one that can influence behaviour."""
    tree = _tree(path)
    skip = _docstring_nodes(tree)
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip
    ]


# --- family 1: provider neutrality ---------------------------------------------------------------


@pytest.mark.parametrize("path", PR5H_PRODUCTION_MODULES, ids=lambda p: p.name)
def test_pr5h_module_imports_no_provider(path: Path) -> None:
    offending = {mod for mod in _imports(path) if _provider_hits(mod)}
    assert not offending, f"{path.name} imports provider module(s) {sorted(offending)}"


@pytest.mark.parametrize("path", PR5H_PRODUCTION_MODULES, ids=lambda p: p.name)
def test_pr5h_module_encodes_no_provider_behaviour(path: Path) -> None:
    """No provider name may appear in a behaviour-bearing literal: a column/table name, a state, a
    reason code, an adapter key, a branch discriminator or a credential/config key."""
    offending = {value for value in _behavioural_strings(path) if _provider_hits(value)}
    assert not offending, f"{path.name} encodes provider-specific literal(s) {sorted(offending)}"


def test_enrollment_schema_has_no_provider_or_extra_endpoint_columns() -> None:
    from secp_api.models import Base
    from sqlalchemy import create_engine, inspect

    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    inspector = inspect(engine)
    tables = (
        "worker_enrollment_invitation",
        "worker_enrollment_state",
        "worker_enrollment_revision",
        "worker_enrollment_step_receipt",
    )
    endpointish = {"endpoint", "url", "uri", "host", "hostname", "addr", "address", "ip", "fqdn"}
    for table in tables:
        assert not _provider_hits(table), table
        for column in inspector.get_columns(table):
            name = column["name"]
            assert not _provider_hits(name), f"{table}.{name} is provider-specific"
            # the ONLY endpoint-shaped field permitted is the already-validated controller origin
            if _segments(name) & endpointish:
                assert name == "controller_origin", (
                    f"{table}.{name} is an unexpected endpoint field"
                )
    engine.dispose()


def test_closed_vocabularies_are_provider_neutral() -> None:
    from secp_api.enums import WorkerEnrollmentErrorCode
    from secp_api.services.worker_enrollment_recovery import SWEEP_REASON
    from secp_api.worker_enrollment_contract import ALL_STATES
    from secp_api.worker_enrollment_models import (
        WORKER_ENROLLMENT_STATES,
        WORKER_ENROLLMENT_STEPS,
    )

    for value in (
        *ALL_STATES,
        *WORKER_ENROLLMENT_STATES,
        *WORKER_ENROLLMENT_STEPS,
        *(code.value for code in WorkerEnrollmentErrorCode),
        SWEEP_REASON,
    ):
        assert not _provider_hits(value), f"provider-specific vocabulary entry: {value}"


def test_deployment_site_label_grammar_carries_no_provider_semantics() -> None:
    """The site label is an OPAQUE grouping string.  Organization is the only authorization
    boundary; the label is never *interpreted* as an endpoint, provider, region or tenant.  It is
    not claimed to be lexically un-provider-like — a string that merely LOOKS like a provider,
    region or hostname is permitted but confers no meaning.  What is deterministically rejected is
    every IP-address literal, so no address can ride a grouping label into persisted output, plus
    anything URL/path/scheme/whitespace shaped (the grammar forbids '/', ':', '@' and space)."""
    from secp_api.worker_enrollment_contract import is_deployment_site_label

    # opaque labels are accepted, INCLUDING provider/region/hostname-SHAPED strings (uninterpreted)
    for good in ("rack-01.eu_a", "site-01.rack_2", "aws-us-east-1", "proxmox", "example.com"):
        assert is_deployment_site_label(good), good
    # URL/host/path/scheme/whitespace shapes are rejected by the grammar
    for bad in (
        "https://proxmox.example.com",
        "10.0.0.5/24",
        "aws:us-east-1",
        "/var/lib/thing",
        "user@host",
        "a b",
    ):
        assert not is_deployment_site_label(bad), bad
    # and every IP-address literal is rejected by deterministic parsing (not a substring heuristic)
    for ip in (
        "10.0.0.5",  # private IPv4
        "127.0.0.1",  # loopback
        "0.0.0.0",  # unspecified
        "169.254.0.1",  # link-local
        "198.51.100.7",  # public-format IPv4 (RFC 5737 TEST-NET-2 documentation range)
        "203.0.113.5",  # public-format IPv4 (RFC 5737 TEST-NET-3 documentation range)
        "192.168.1.1",  # private IPv4
        "255.255.255.255",  # broadcast / reserved
    ):
        assert not is_deployment_site_label(ip), ip
    # IPv6 literals in every representable form are rejected too (the grammar forbids ':')
    for ip6 in ("::1", "::", "fe80::1", "2001:db8::1", "::ffff:10.0.0.5"):
        assert not is_deployment_site_label(ip6), ip6


# --- family 2: plane boundaries -------------------------------------------------------------------


def test_api_enrollment_modules_do_not_import_the_management_plane() -> None:
    for path in PR5H_PRODUCTION_MODULES:
        offending = {m for m in _imports(path) if m.split(".")[0] == "secp_management"}
        assert not offending, f"{path.name} imports {sorted(offending)}"


def test_management_plane_does_not_import_api_persistence_or_services() -> None:
    mgmt = REPO / "apps" / "management" / "secp_management"
    for path in sorted(mgmt.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        offending = {m for m in _imports(path) if m == "secp_api" or m.startswith("secp_api.")}
        assert not offending, f"{path.relative_to(REPO)} imports {sorted(offending)}"


def test_deployment_plane_does_not_import_the_api_enrollment_repository_or_service() -> None:
    forbidden = {
        "secp_api.worker_enrollment_repository",
        "secp_api.services.worker_enrollment",
        "secp_api.services.worker_enrollment_recovery",
    }
    for root in (
        REPO / "apps" / "deployment" / "secp_discovery_activation",
        REPO / "apps" / "deployment" / "secp_operator_deployment",
    ):
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            assert not (_imports(path) & forbidden), path.relative_to(REPO)


def test_existing_boundary_test_covers_every_new_pr5h_production_module() -> None:
    """The reviewed management-plane boundary test must actually govern the new modules — otherwise
    a new file could quietly sit outside the guard. That test is NOT modified or weakened here."""
    import sys

    sys.path.insert(0, str(REPO / "tests"))
    import test_management_plane_boundary as boundary

    covered = set(boundary._py_files(API_PKG))
    for path in PR5H_PRODUCTION_MODULES:
        if path.parts[-2] == "versions":  # the migration lives outside the package tree
            continue
        assert path in covered, f"{path.relative_to(REPO)} is outside the boundary scan"
        boundary.test_lower_plane_cannot_import_bootstrap_write_adapters(path)


def test_no_enrollment_allowlist_exception_exists() -> None:
    """No allowlist may permit apps/api to import secp_management.enrollment."""
    import sys

    sys.path.insert(0, str(REPO / "tests"))
    import test_management_plane_boundary as boundary

    source = Path(boundary.__file__).read_text(encoding="utf-8")
    assert "secp_management.enrollment" not in source
    # the guard takes a path and nothing else — there is no allowlist parameter
    code = boundary.test_lower_plane_cannot_import_bootstrap_write_adapters.__code__
    assert code.co_varnames[: code.co_argcount] == ("path",)


def test_only_the_test_layer_imports_both_enrollment_contract_copies() -> None:
    both: list[str] = []
    for root in (REPO / "apps", REPO / "plugins"):
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts or "tests" in path.parts:
                continue
            names = set(_imports(path))
            for node in ast.walk(_tree(path)):
                if isinstance(node, ast.ImportFrom) and node.module:
                    names.update(f"{node.module}.{a.name}" for a in node.names)
            if any(m.startswith("secp_management.enrollment") for m in names) and any(
                "worker_enrollment_contract" in m for m in names
            ):
                both.append(str(path.relative_to(REPO)))
    assert not both, both


def test_api_enrollment_surface_gains_no_privileged_capability() -> None:
    """No host-adapter, filesystem, systemd, Docker/Compose, subprocess or bootstrap capability."""
    privileged = {
        "subprocess",
        "shutil",
        "os",
        "pathlib",
        "tempfile",
        "docker",
        "systemd",
        "paramiko",
        "asyncssh",
        "fabric",
        "pexpect",
        "ctypes",
        "socket",
        "http",
        "requests",
        "httpx",
        "aiohttp",
        "secp_management",
    }
    for path in PR5H_PRODUCTION_MODULES:
        offending = {m for m in _imports(path) if m.split(".")[0] in privileged}
        assert not offending, f"{path.name} gained privileged capability {sorted(offending)}"


# --- family 3: PR5H-B1 activation boundary --------------------------------------------------------
#
# PR5H-B1 activates the SUPPORTED controller enrollment path over the durable PR5H-A foundation. The
# controller API route is now wired and authenticated, but the activation stays narrow: the outbound
# transport stays sealed, the restart/recovery sweep stays unwired, no supported mutating production
# CLI exists yet, and no operator / provider / controlled-live capability is reachable. These guards
# fail the moment the activation widens past the controller API slice.

# the single production entry point permitted to import the enrollment service (PR5H-B1 slice 1)
_ALLOWED_ENROLLMENT_SERVICE_REACHERS = {"apps/api/secp_api/routers/enrollment.py"}

#: WS-B R3: the expiry sweep is no longer unwired — it now has exactly ONE production caller, the
#: scheduled all-organizations driver. Before R3 it had none, and ``recovery_required`` was
#: unreachable in a running deployment. The guard therefore changed from "nothing may reach it" to
#: "exactly this one module may", which is a tighter statement than the original once a caller has
#: to exist at all: any SECOND caller — a router, a CLI, an operator module — still fails closed.
_ALLOWED_RECOVERY_SWEEP_REACHERS = {
    "apps/api/secp_api/services/worker_enrollment_recovery_schedule.py"
}

#: ...and the scheduled driver itself is reachable from exactly one place: the ordinary-queue
#: Temporal activity. This is what keeps the sweep on the ordinary queue by construction — a module
#: that could reach the driver could schedule it anywhere, so the reachability set IS the routing
#: guarantee. A controlled-live/operator module appearing here would be the failure to catch.
_ALLOWED_RECOVERY_SCHEDULE_REACHERS = {"apps/worker/secp_worker/temporal_app.py"}


#: C1: the two SUPPORTED evidence-driven exchange routes authenticate by the worker's SIGNED
#: EVIDENCE (verified against the authoritative persisted invitation), NOT a control-plane OIDC
#: principal — a real worker transport sends no human bearer token — so they take NO
#: ``current_principal``. Every OTHER enrollment route (operator create/status/revoke + the sealed
#: claim-only routes) stays principal-authenticated.
_EVIDENCE_AUTHENTICATED_ROUTES = {"bind_worker_exchange", "record_worker_result_exchange"}


def test_enrollment_api_router_is_registered_and_authenticated() -> None:
    """PR5H-B1 registers the controller enrollment router. Every operator/claim-only route must
    require an authenticated principal (organization is the authorization boundary); the two
    supported evidence-driven exchange routes instead authenticate by the worker's signed evidence
    and must take NO principal (C1). The router must reach no operator, provider, controlled-live or
    transport-activation capability."""
    main_py = API_PKG / "main.py"
    registered = [
        ast.unparse(node)
        for node in ast.walk(_tree(main_py))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "include_router"
    ]
    assert any("enrollment" in call.lower() for call in registered), (
        "the PR5H-B1 controller enrollment router must be registered"
    )
    router = API_PKG / "routers" / "enrollment.py"
    assert router.is_file(), "the enrollment router module must exist"

    tree = _tree(router)
    route_funcs = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and any(
            isinstance(dec, ast.Call)
            and isinstance(dec.func, ast.Attribute)
            and dec.func.attr in {"get", "post", "put", "delete", "patch"}
            for dec in node.decorator_list
        )
    ]
    assert route_funcs, "the enrollment router must define at least one route"
    for func in route_funcs:
        args = ast.unparse(func.args)
        if func.name in _EVIDENCE_AUTHENTICATED_ROUTES:
            assert "current_principal" not in args, (
                f"the evidence-driven exchange route {func.name} must NOT depend on "
                "current_principal (it authenticates by the worker's signed evidence, C1)"
            )
        else:
            assert "current_principal" in args, (
                f"enrollment route {func.name} must require an authenticated principal"
            )
    forbidden = ("operator", "opentofu", "proxmox", "controlled_live", "temporalio")
    router_imports = {m.lower() for m in _imports(router)}
    offending = {m for m in router_imports if any(f in m for f in forbidden)}
    assert not offending, f"the enrollment router reaches forbidden capability: {sorted(offending)}"


def test_only_the_enrollment_router_reaches_the_service_and_the_sweep_has_one_caller() -> None:
    """The enrollment SERVICE is reachable from exactly one production entry point (the controller
    API router); nothing else — no operator, worker, provider, CLI or bootstrap module — may import
    it.

    The restart/recovery SWEEP is reachable from exactly one module (the scheduled driver), and that
    driver from exactly one module (the ordinary-queue Temporal activity). Reachability IS the
    routing guarantee here: anything able to reach the driver could schedule the sweep onto any
    queue, so a second reacher — especially an operator/controlled-live module — must fail closed.
    """
    service_reachers: list[str] = []
    recovery_reachers: list[str] = []
    schedule_reachers: list[str] = []
    for root in (REPO / "apps", REPO / "plugins", REPO / "contracts"):
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts or "tests" in path.parts:
                continue
            if path.name in {
                "worker_enrollment.py",
                "worker_enrollment_recovery.py",
                "worker_enrollment_recovery_schedule.py",
            }:
                continue  # the modules themselves
            names = set(_imports(path))
            for node in ast.walk(_tree(path)):
                if isinstance(node, ast.ImportFrom) and node.module:
                    names.update(f"{node.module}.{a.name}" for a in node.names)
            rel = str(path.relative_to(REPO)).replace("\\", "/")
            if (
                "secp_api.services.worker_enrollment" in names
                and rel not in _ALLOWED_ENROLLMENT_SERVICE_REACHERS
            ):
                service_reachers.append(rel)
            if (
                "secp_api.services.worker_enrollment_recovery" in names
                and rel not in _ALLOWED_RECOVERY_SWEEP_REACHERS
            ):
                recovery_reachers.append(rel)
            if (
                "secp_api.services.worker_enrollment_recovery_schedule" in names
                and rel not in _ALLOWED_RECOVERY_SCHEDULE_REACHERS
            ):
                schedule_reachers.append(rel)
    assert not service_reachers, (
        f"the enrollment service is wired into unexpected modules: {service_reachers}"
    )
    assert not recovery_reachers, (
        f"the recovery sweep may only be reached by its scheduled driver: {recovery_reachers}"
    )
    assert not schedule_reachers, (
        "the scheduled sweep driver may only be reached by the ordinary-queue Temporal activity: "
        f"{schedule_reachers}"
    )


def test_the_scheduled_sweep_driver_really_is_reached_by_its_one_caller() -> None:
    """Anti-vacuity for the guard above: an allowlist naming a module that reaches nothing would
    let the real invariant rot silently. The single permitted reacher must ACTUALLY reach it."""
    driver = (
        REPO / "apps" / "api" / "secp_api" / "services" / "worker_enrollment_recovery_schedule.py"
    )
    assert driver.exists(), "the scheduled sweep driver must exist for the guard to mean anything"
    activity = REPO / "apps" / "worker" / "secp_worker" / "temporal_app.py"
    assert "worker_enrollment_recovery_schedule" in activity.read_text(encoding="utf-8")


def test_enrollment_transport_remains_sealed() -> None:
    import sys

    sys.path.insert(0, str(REPO / "apps" / "management"))
    from secp_management import enrollment as mgmt_enrollment

    assert hasattr(mgmt_enrollment, "SealedEnrollmentTransport")
    transport = mgmt_enrollment.SealedEnrollmentTransport()
    for call in (
        lambda: transport.deliver_controller_offer(enrollment_id="x", payload=b""),
        lambda: transport.retrieve_worker_result(enrollment_id="x"),
    ):
        with pytest.raises(Exception):  # noqa: B017 - a sealed transport must refuse, closed
            call()


def test_no_supported_mutating_enrollment_cli_command_is_registered() -> None:
    """No production CLI exposes a mutating enrollment command."""
    for cli in (
        REPO / "apps" / "commissioning" / "secp_commissioning" / "cli.py",
        REPO / "apps" / "deployment" / "secp_discovery_activation" / "cli.py",
    ):
        if not cli.is_file():
            continue
        literals = {s.lower() for s in _behavioural_strings(cli)}
        offending = {s for s in literals if "enroll" in s}
        assert not offending, (
            f"{cli.name} registers enrollment command literal(s) {sorted(offending)}"
        )


def test_seals_and_queues_are_preserved_exactly() -> None:
    import sys

    for extra in ("apps/worker", "apps/deployment", "apps/management"):
        sys.path.insert(0, str(REPO / extra))
    from secp_management.topology import OPERATOR_TASK_QUEUE, ORDINARY_TASK_QUEUE
    from secp_worker.plan_gen import process_boundary
    from secp_worker.provisioning import activation, process_executor

    assert activation._B1A_SUBPROCESS_SEALED is True
    assert process_executor._B1A_SUBPROCESS_SEALED is True
    assert process_boundary._PLAN_ONLY_PROCESS_SEALED is False
    assert ORDINARY_TASK_QUEUE == "secp-orchestration"
    assert OPERATOR_TASK_QUEUE == "secp-controlled-live-v1"

    runner = REPO / "apps" / "deployment" / "secp_operator_deployment" / "runner.py"
    sealed = [
        node
        for node in ast.walk(_tree(runner))
        if isinstance(node, ast.Assign)
        and any(
            isinstance(t, ast.Name) and t.id == "_OPERATOR_ACTIVATION_SEALED" for t in node.targets
        )
    ]
    assert len(sealed) == 1
    assert isinstance(sealed[0].value, ast.Constant) and sealed[0].value.value is True


def test_pr5h_modules_perform_no_workflow_provider_or_iac_execution() -> None:
    """No Temporal/workflow submission, provider call, or OpenTofu/Terraform execution."""
    forbidden_calls = {
        "start_workflow",
        "execute_workflow",
        "submit",
        "run_plan_generation",
        "apply",
        "destroy",
        "plan",
        "provision",
    }
    forbidden_modules = {"temporalio", "opentofu", "terraform", "python_tofu"}
    for path in PR5H_PRODUCTION_MODULES:
        assert not (_imports(path) & forbidden_modules), path.name
        called = {
            node.func.attr
            for node in ast.walk(_tree(path))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert not (called & forbidden_calls), (
            f"{path.name} calls {sorted(called & forbidden_calls)}"
        )
