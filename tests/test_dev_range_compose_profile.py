"""The range-capable development Compose profile (infra/dev/docker-compose.range.yml).

`docker compose up worker` builds a worker that connects to Temporal, accepts a range operation and
then refuses at the seal: the base `worker` service passes no `SECP_RANGE_LOCAL_DOCKER` and mounts
no Docker socket. The overlay is what makes the SHIPPED Compose path range-capable, so acceptance
runs stop depending on a worker started by hand on the host.

These are structural checks; they start no containers. The one property worth more than all the
others is that the Docker socket reaches the worker AND NOTHING ELSE, and it is asserted in the
inverted form — *every* service in the merged composition that mounts a socket must be the approved
one — so adding a socket to a new or existing service fails here rather than passing a name check.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DEV_DIR = REPO_ROOT / "infra" / "dev"
BASE = DEV_DIR / "docker-compose.yml"
RANGE_OVERLAY = DEV_DIR / "docker-compose.range.yml"
RANGE_DOCKERFILE = DEV_DIR / "Dockerfile.range-worker"
SHARED_DOCKERFILE = DEV_DIR / "Dockerfile.python"
ENV_EXAMPLE = REPO_ROOT / ".env.example"

DOCKER_SOCKET = "/var/run/docker.sock"

#: The ONLY service permitted to receive the host Docker socket. Driving that socket is
#: root-equivalent on the host, so this is a one-name list on purpose.
SOCKET_ALLOWED_SERVICES = frozenset({"worker"})


class _TolerantLoader(yaml.SafeLoader):
    """Compose merge tags (`!override`, `!reset`) are not YAML types PyYAML knows.

    Without this the overlay raises ConstructorError and every assertion below would be reported as
    a collection error rather than as the check it is.
    """


def _passthrough(loader, node):
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)


for _tag in ("!override", "!reset"):
    _TolerantLoader.add_constructor(_tag, _passthrough)


def _load(path: Path) -> dict:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=_TolerantLoader)


def _services(path: Path) -> dict:
    return _load(path).get("services") or {}


def _merged() -> dict:
    """Base services overlaid by the range file, mirroring `-f base -f range`.

    Only the keys these tests read are merged, and each is merged the way Compose merges it:
    `environment` mappings update, `volumes` lists CONCATENATE (which is exactly why the overlay
    needs `!override` for `ports`, and why a socket added to the base would survive into the merge).
    """
    merged = {name: dict(cfg or {}) for name, cfg in _services(BASE).items()}
    for name, cfg in _services(RANGE_OVERLAY).items():
        target = merged.setdefault(name, {})
        for key, value in (cfg or {}).items():
            if key == "environment" and isinstance(value, dict):
                base_env = target.get("environment") or {}
                target["environment"] = {**base_env, **value}
            elif key == "volumes" and isinstance(value, list):
                target["volumes"] = list(target.get("volumes") or []) + list(value)
            else:
                target[key] = value
    return merged


def _mount_sources(service: dict) -> list[str]:
    sources = []
    for entry in service.get("volumes") or []:
        if isinstance(entry, str):
            sources.append(entry.split(":", 1)[0])
        elif isinstance(entry, dict):
            sources.append(str(entry.get("source", "")))
    return sources


def _env(service: dict) -> dict:
    env = service.get("environment") or {}
    if isinstance(env, list):  # `- KEY=value` form
        out = {}
        for item in env:
            key, _, value = str(item).partition("=")
            out[key] = value
        return out
    return {str(k): v for k, v in env.items()}


# --- the defect the overlay exists to fix stays described ----------------------------------------


def test_base_worker_is_range_sealed_and_socketless():
    """The base stack must NOT become range-capable by accident.

    If someone "helpfully" adds the socket or the seal to the base worker, the overlay stops being
    an opt-in and every plain `docker compose up` hands out a root-equivalent socket.
    """
    worker = _services(BASE)["worker"]
    assert DOCKER_SOCKET not in _mount_sources(worker), (
        "the BASE dev worker mounts the Docker socket; range capability must stay opt-in via "
        "docker-compose.range.yml"
    )
    assert "SECP_RANGE_LOCAL_DOCKER" not in _env(worker), (
        "the BASE dev worker sets SECP_RANGE_LOCAL_DOCKER; the seal must be opened only by the "
        "explicit range overlay"
    )


# --- the socket reaches the worker and nothing else -----------------------------------------------


def test_only_the_worker_receives_the_docker_socket():
    """Inverted, so it cannot be satisfied by checking a name.

    Every service in the merged composition is examined; any that mounts the socket must be in the
    approved set. A future `range-runner`, a debug sidecar, or a socket quietly added to `api` all
    fail here.
    """
    offenders = sorted(
        name
        for name, service in _merged().items()
        if DOCKER_SOCKET in _mount_sources(service) and name not in SOCKET_ALLOWED_SERVICES
    )
    assert not offenders, (
        f"services {offenders} mount the host Docker socket. That is root-equivalent on the host "
        f"and is permitted only for {sorted(SOCKET_ALLOWED_SERVICES)}"
    )


def test_the_api_stays_socketless_under_the_range_overlay():
    """Stated separately from the sweep above because it is the specific boundary at stake.

    The API holds the range CONTRACT types and dispatches; it never constructs a provider and never
    runs one (Charter Invariants 6/7, ADR-005). The architecture-boundary guard forbids `subprocess`
    under `secp_api`, but a socket mount is privilege that guard cannot see.
    """
    api = _merged()["api"]
    assert DOCKER_SOCKET not in _mount_sources(api)


def test_the_api_image_does_not_even_carry_the_docker_cli():
    """The shared image must stay free of the docker binary.

    `secp_worker.range.docker_cli` resolves the tool with `shutil.which("docker")`, so a docker
    binary in the SHARED api/worker image would arm the API image with the tool as well. The range
    worker layers the binary on separately (Dockerfile.range-worker) precisely to avoid that.
    """
    shared = SHARED_DOCKERFILE.read_text(encoding="utf-8").lower()
    assert "docker:" not in shared and "docker-ce-cli" not in shared, (
        "infra/dev/Dockerfile.python appears to install the docker CLI. That image is the API "
        "image too; add the binary in Dockerfile.range-worker instead"
    )


# --- the overlay actually opens the seal ----------------------------------------------------------


def test_overlay_worker_is_range_capable():
    worker = _merged()["worker"]
    env = _env(worker)
    assert str(env.get("SECP_RANGE_LOCAL_DOCKER")).lower() == "true", (
        "the overlay does not set SECP_RANGE_LOCAL_DOCKER; the provider refuses to be constructed "
        "at all, socket or no socket"
    )
    assert DOCKER_SOCKET in _mount_sources(worker), "the overlay worker has no Docker socket"
    assert env.get("SECP_WORKFLOW_DISPATCH_MODE") == "temporal", (
        "range operations require the durable path; InlineDispatcher refuses them outright"
    )


def test_overlay_worker_builds_the_image_that_carries_the_docker_cli():
    """The seal and the socket are worthless without the tool.

    `secp_worker.range.docker_cli` resolves the binary with `shutil.which("docker")`, and the shared
    `Dockerfile.python` deliberately does not ship one. Repointing this build at the shared file
    yields a worker that is socket-mounted, seal-open, and still unable to execute a single range
    step -- and every other assertion in this module keeps passing. So the build input is pinned.
    """
    build = _services(RANGE_OVERLAY)["worker"].get("build") or {}
    assert build.get("dockerfile", "").endswith(RANGE_DOCKERFILE.name), (
        f"the range worker does not build from {RANGE_DOCKERFILE.name}; without the docker CLI "
        f"the provider fails at shutil.which('docker') no matter how it is configured"
    )
    assert "base" in (build.get("additional_contexts") or {}), (
        "the range image no longer layers on the built worker image; it would drift from the "
        "ordinary worker"
    )


def test_overlay_api_dispatches_to_the_durable_path():
    """A range deploy dispatched inline fails before the worker is ever consulted."""
    assert _env(_merged()["api"]).get("SECP_WORKFLOW_DISPATCH_MODE") == "temporal"


def test_overlay_worker_waits_for_temporal():
    """In temporal mode the worker is fail-closed: it exits non-zero rather than degrading.

    Starting it before Temporal serves is a real crash loop, not a retry, so the dependency is load-
    bearing and not cosmetic. The base file only waits on postgres because its worker runs inline.
    """
    depends = _services(RANGE_OVERLAY)["worker"].get("depends_on") or {}
    assert "temporal" in depends, "the range worker does not wait for Temporal"
    assert depends["temporal"].get("condition") == "service_healthy"


def test_overlay_worker_reaches_the_socket_without_running_as_root():
    """uid 10001 gets EACCES on a root:root 0660 socket without a matching supplementary group.

    This is hygiene for everything OTHER than the socket -- it is not a limit on socket power -- but
    silently switching to `user: root` would drop that hygiene without anyone noticing.
    """
    worker = _services(RANGE_OVERLAY)["worker"]
    assert worker.get("group_add"), "no group_add; the worker cannot open the mounted socket"
    assert str(worker.get("user", "")) not in {"root", "0", "0:0"}, (
        "the range worker runs as root; use group_add so the container identity stays unprivileged"
    )


# --- production is untouched ----------------------------------------------------------------------


def _all_compose_files() -> list[Path]:
    return sorted(REPO_ROOT.rglob("*compose*.y*ml"))


#: Anchors so a glob that silently stops matching is a failure, not a vacuous pass. An earlier
#: version of this sweep was scoped to infra/production and infra/acceptance -- neither of which
#: contains a compose file -- so it collected an EMPTY parameter set and reported `skipped` while
#: checking nothing at all.
_EXPECTED_COMPOSE_FILES = frozenset(
    {
        "docker-compose.yml",
        "docker-compose.range.yml",
        "docker-compose.verify.yml",
        "docker-compose.discovery-live.yml",
    }
)


def test_the_compose_sweep_below_actually_finds_the_compose_files():
    found = {p.name for p in _all_compose_files()}
    missing = _EXPECTED_COMPOSE_FILES - found
    assert not missing, (
        f"the compose glob no longer finds {sorted(missing)}; the socket sweep would pass while "
        f"covering less than it claims"
    )


@pytest.mark.parametrize("compose_file", _all_compose_files(), ids=lambda p: p.name)
def test_only_the_range_overlay_mounts_a_docker_socket_anywhere_in_the_repo(compose_file: Path):
    """EVERY compose file in the repository, discovered by globbing rather than listed.

    The range overlay is the single permitted exception, and only for `worker`. Any other
    composition -- a sibling dev overlay, an acceptance stack, a production one added later --
    fails on arrival rather than after someone remembers to extend a list.
    """
    offenders = sorted(
        name
        for name, svc in _services(compose_file).items()
        if DOCKER_SOCKET in _mount_sources(svc)
    )
    if compose_file.name == RANGE_OVERLAY.name:
        assert set(offenders) <= SOCKET_ALLOWED_SERVICES, (
            f"{compose_file.name} mounts the Docker socket into {offenders}; only "
            f"{sorted(SOCKET_ALLOWED_SERVICES)} may receive it"
        )
    else:
        assert not offenders, (
            f"{compose_file} mounts the host Docker socket into {offenders}. That is "
            f"root-equivalent on the host and is confined to {RANGE_OVERLAY.name}"
        )


def test_no_production_material_references_the_range_overlay():
    scanned = 0
    for path in (REPO_ROOT / "infra" / "production").rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1
        assert RANGE_OVERLAY.name not in text, (
            f"{path} references {RANGE_OVERLAY.name}; the range overlay is development-only and "
            f"hands out a root-equivalent Docker socket"
        )
    assert scanned, "scanned no production files; this check proved nothing"


# --- the file tells the truth about what it does ------------------------------------------------


def test_overlay_warns_that_socket_access_is_root_equivalent():
    """An operator must not be able to read this file and miss what the mount grants."""
    text = RANGE_OVERLAY.read_text(encoding="utf-8").lower()
    assert "root-equivalent" in text
    assert "docker socket" in text


def test_overlay_documents_the_env_file_requirement():
    """`docker compose` resolves a relative `.env` against infra/dev, never the repo root.

    Omitting `--env-file ../../.env` leaves every variable blank and Temporal then fails against
    PostgreSQL as user `temporal` -- a failure that does not name its cause. The documented command
    has to carry the flag.
    """
    text = RANGE_OVERLAY.read_text(encoding="utf-8")
    assert "--env-file ../../.env" in text
    assert "docker-compose.range.yml" in text


def test_range_dockerfile_adds_only_the_cli_and_stays_non_root():
    text = RANGE_DOCKERFILE.read_text(encoding="utf-8")
    assert "FROM base" in text, (
        "the range image must layer on the built worker image, not restate it"
    )
    lowered = text.lower()
    assert lowered.rstrip().endswith("user secp"), (
        "Dockerfile.range-worker must end back on the unprivileged runtime user"
    )


def test_env_example_documents_the_range_profile_without_arming_it():
    """The example must explain the profile but must NOT set the seal.

    A `SECP_RANGE_LOCAL_DOCKER=true` in `.env.example` would arm every plain `docker compose up`
    for anyone who copied the file, which is the opposite of an opt-in.
    """
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert "docker-compose.range.yml" in text, ".env.example does not mention the range profile"
    assert "root-equivalent" in text.lower()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert not stripped.startswith("SECP_RANGE_LOCAL_DOCKER="), (
            ".env.example sets SECP_RANGE_LOCAL_DOCKER; the seal must be opened only by the "
            "explicit overlay, never by a copied example file"
        )
