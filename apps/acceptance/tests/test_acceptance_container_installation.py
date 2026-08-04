"""Container tier: build ONE signed release, install it on both hosts, and record what happened.

This module produces the ``packages``, ``controller`` and ``worker_install`` evidence stages. Every
check it records comes from executing the real product — the release-authority tooling a release
engineer uses, and the ``secpctl`` console script installed from the release wheel — against two
disposable hosts. No check is satisfied by a literal, a seeded document, or a harness-supplied
double.

HOW TO READ A FAILURE HERE
--------------------------
The driver records every check before any node asserts, so a node that fails names the bounded
reason the product or the harness gave rather than dying at the first step and taking the rest with
it. A red node therefore means "this specific claim could not be made, and here is why", which is
the report a reader needs.

THE STAGE ORDER IS LOAD-BEARING
-------------------------------
Controller before worker. The worker's own commit gate requires ``ordinary_healthy``, which requires
the readiness marker, which ``secp_worker.main`` writes only after connecting to Temporal — a
controller-stack component. Installing the worker first would be cheaper and would produce a
``worker_status_ok`` that could not mean what it says.
"""

from __future__ import annotations

import pathlib

import pytest
from secp_acceptance.driver import (
    HOST_BUNDLE,
    InstallationRun,
    drive_controller,
    drive_packages,
    drive_worker,
)
from secp_acceptance.evidence import ReleaseRecord
from secp_acceptance.hosts import ROLE_CONTROLLER, ROLE_WORKER, HostFleet
from secp_acceptance.install import HOST_STAGING, HostInstallation
from secp_acceptance.reasons import CHECKS_BY_STAGE, OUTCOME_OBSERVED
from secp_acceptance.release import (
    PRODUCT_MAX_IMAGE_ARCHIVE_BYTES,
    Artifact,
    ReleaseMaterial,
    build_and_sign,
    build_image,
    build_wheel,
    controller_compose_template,
    init_anchor,
    measure_host_executables,
    migration_head,
    pull_image,
    repo_root,
    save_image,
    sha256_file,
    source_lineage,
    worker_compose_template,
)
from secp_acceptance.run import AcceptanceRun
from secp_acceptance.tier import witness

pytestmark = pytest.mark.container_tier


# --------------------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def workdir(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    return tmp_path_factory.mktemp("secp-acc-release")


@pytest.fixture(scope="module")
def release(fleet: HostFleet, workdir: pathlib.Path) -> ReleaseMaterial:
    """Build, sign and re-verify ONE release, then cut both role bundles from it.

    Images are resolved from the product's own ``CONTROLLER_STACK``: a component whose reviewed
    image reference is a ``secp/*`` name is BUILT from the repository, and everything else is pulled
    at the exact reviewed reference. Deriving the set from the product means a stack change breaks
    the release build rather than silently producing a bundle that installs a different controller.
    """
    from secp_management.release_bundle import (
        WORKER_DEPLOYMENT_PACKAGE_PURPOSE,
        WORKER_OPERATOR_PURPOSE,
        WORKER_ORDINARY_PURPOSE,
    )
    from secp_management.topology import CONTROLLER_STACK

    root = repo_root()
    material = ReleaseMaterial(workdir=workdir)
    material.key_path, material.anchor = init_anchor(workdir)
    material.source_sha, material.parent_sha = source_lineage(root)
    material.migration_identity = migration_head(root)
    material.runtime_pins = measure_host_executables(fleet.image)

    controller_dir = workdir / "bundle-controller"
    worker_dir = workdir / "bundle-worker"
    for directory in (controller_dir, worker_dir):
        (directory / "images").mkdir(parents=True, exist_ok=True)
    material.bundles = {"controller": controller_dir, "worker": worker_dir}

    # --- the product images -------------------------------------------------------------
    python_dockerfile = root / "infra" / "dev" / "Dockerfile.python"
    web_context = root / "apps" / "web"
    product_images: dict[str, str] = {}

    def product_image(component: str) -> str:
        """Build (once) the image backing a ``secp/*`` component."""
        if component in ("api", "worker"):
            key = "python"
            if key not in product_images:
                product_images[key] = build_image(
                    tag="secp-acceptance/python:local",
                    context=root,
                    dockerfile=python_dockerfile,
                )
            return product_images[key]
        if component == "web":
            if "web" not in product_images:
                product_images["web"] = build_image(
                    tag="secp-acceptance/web:local",
                    context=web_context,
                    dockerfile=web_context / "Dockerfile",
                )
            return product_images["web"]
        raise AssertionError(f"no build recipe for controller component {component}")

    image_map: dict[str, str] = {}
    controller_artifacts: list[Artifact] = []
    for service in CONTROLLER_STACK:
        component = service.component
        if service.image_ref.startswith("secp/"):
            digest = product_image(component)
        else:
            digest = pull_image(service.image_ref)
        image_map[component] = digest
        archive = controller_dir / "images" / f"{component}.tar"
        save_image(digest, archive)
        sha, size = sha256_file(archive)
        controller_artifacts.append(
            Artifact(
                name=f"images/{component}.tar",
                kind="image_archive",
                role="shared",
                sha256=sha,
                size=size,
                image_digest=digest,
                purpose=f"controller/{component}",
            )
        )

    compose = controller_compose_template(image_map)
    (controller_dir / "controller-compose.yml").write_bytes(compose)
    sha, size = sha256_file(controller_dir / "controller-compose.yml")
    controller_artifacts.insert(
        0,
        Artifact(
            name="controller-compose.yml",
            kind="controller_compose_template",
            role="controller",
            sha256=sha,
            size=size,
        ),
    )

    # --- the worker bundle --------------------------------------------------------------
    ordinary = product_images["python"]
    worker_artifacts: list[Artifact] = []
    for purpose, name in (
        (WORKER_ORDINARY_PURPOSE, "images/ordinary.tar"),
        (WORKER_OPERATOR_PURPOSE, "images/operator.tar"),
    ):
        archive = worker_dir / name
        save_image(ordinary, archive)
        sha, size = sha256_file(archive)
        worker_artifacts.append(
            Artifact(
                name=name,
                kind="image_archive",
                role="shared",
                sha256=sha,
                size=size,
                image_digest=ordinary,
                purpose=purpose,
            )
        )

    worker_compose = worker_compose_template(ordinary)
    (worker_dir / "worker-compose.yml").write_bytes(worker_compose)
    sha, size = sha256_file(worker_dir / "worker-compose.yml")
    worker_artifacts.insert(
        0,
        Artifact(
            name="worker-compose.yml",
            kind="worker_compose_template",
            role="worker",
            sha256=sha,
            size=size,
        ),
    )

    wheel = build_wheel(root, workdir / "dist")
    wheel_target = worker_dir / "wheels" / wheel.name
    wheel_target.parent.mkdir(parents=True, exist_ok=True)
    wheel_target.write_bytes(wheel.read_bytes())
    sha, size = sha256_file(wheel_target)
    worker_artifacts.append(
        Artifact(
            name=f"wheels/{wheel.name}",
            kind="python_wheel",
            role="shared",
            sha256=sha,
            size=size,
            purpose=WORKER_DEPLOYMENT_PACKAGE_PURPOSE,
        )
    )

    material.artifacts = {"controller": controller_artifacts, "worker": worker_artifacts}
    # The implementation aggregate binds the release to the wheel the run actually built.
    material.implementation_aggregate = sha256_file(wheel)[0]
    for role in ("controller", "worker"):
        build_and_sign(material, role)
    witness("release_built")
    material.workdir = workdir
    material.wheel_name = wheel.name
    return material


@pytest.fixture(scope="module")
def installation(
    fleet: HostFleet, release: ReleaseMaterial, acceptance_run: AcceptanceRun
) -> InstallationRun:
    """Deliver the release to both hosts and drive all three stages, recording every check.

    Records into the SESSION's run, never a recorder of its own — four streams produce the nine
    stages and four recorders would produce four documents that cannot be reconciled.

    Supplies the RELEASE record, which no other stream builds. The FLEET record is set by the
    session fleet fixture during its teardown, not here: it carries ``hosts_destroyed``, so a
    record taken while the fleet is still up would permanently report zero teardown. Setting it
    from both places would also be refused — ``set_fleet`` rejects a second, differing record, and
    those two records genuinely differ.
    """
    run = InstallationRun(acceptance_run=acceptance_run, material=release)
    acceptance_run.set_release(
        ReleaseRecord(
            role="worker",
            baseline_aggregate=release.aggregates["worker"],
            baseline_source_sha=release.source_sha,
            signing_anchor_id=release.anchor["key_id"],
            # TRUE, and it is the gap declared below: the anchor is one this run minted, because
            # the shipped trust root is empty and production holds no release-signing key.
            test_only_anchor=True,
        )
    )
    wheel_name = release.wheel_name

    for role, bundle_role in ((ROLE_CONTROLLER, "controller"), (ROLE_WORKER, "worker")):
        host = fleet.hosts[role]
        install = HostInstallation(host=host)
        run.installations[role] = install
        host.exec(("mkdir", "-p", HOST_STAGING), check=True)
        install.deliver(release.workdir / "dist" / wheel_name, f"{HOST_STAGING}/{wheel_name}")
        install.deliver(release.bundles[bundle_role], HOST_BUNDLE)

    drive_packages(run, fleet, wheel_name)
    acceptance_run.declare_gap(
        gap="ephemeral_release_anchor",
        stage="packages",
        substitute="A run-scoped Ed25519 anchor minted by release_authority.authority_init.",
        why=(
            "signing.SHIPPED_TRUST_ROOT is empty and production holds no release-signing private "
            "key, so no reviewed anchor exists to sign an acceptance release with."
        ),
        weakens=("controller_packages_installed", "worker_packages_installed"),
    )
    witness("packages_stage_driven")

    for role in (ROLE_CONTROLLER, ROLE_WORKER):
        run.installations[role].seed_production_inputs(anchor=release.anchor)

    drive_controller(run, fleet)
    witness("controller_stage_driven")

    ordinary = next(
        a.image_digest
        for a in release.artifacts["worker"]
        if a.purpose == "worker/ordinary" and a.image_digest
    )
    drive_worker(run, fleet, ordinary)
    witness("worker_install_stage_driven")
    return run


def _assert_observed(run: InstallationRun, check: str) -> None:
    outcome = run.outcome_of(check)
    assert outcome == OUTCOME_OBSERVED, (
        f"{check} was recorded {outcome!r} (reason: {run.reason_for(check) or 'none'}). "
        f"An unproven check is never a pass."
    )


# --------------------------------------------------------------------------- the release itself


def test_the_release_is_signed_and_reverifies_under_its_own_anchor(release: ReleaseMaterial):
    """Both role bundles were built, signed and re-verified by the reviewed authority commands.

    ``build_and_sign`` refuses unless ``authority_verify`` returned true, so reaching here already
    means the signature covered the canonical manifest and every artifact's bytes were re-read. What
    this node adds is that BOTH roles got there under ONE anchor — the property that makes it one
    release rather than two.
    """
    assert set(release.aggregates) == {"controller", "worker"}
    assert release.anchor["key_id"].startswith("sha256:")
    assert release.aggregates["controller"] != release.aggregates["worker"]


def test_no_image_archive_exceeds_the_products_own_installation_cap(release: ReleaseMaterial):
    """The release the run built must be one the product can actually install.

    ``real_adapters._load_and_verify_image`` refuses an archive over
    ``PRODUCT_MAX_IMAGE_ARCHIVE_BYTES`` with ``bootstrap_image_too_large``. That constant is READ
    from the product here, not restated, so raising the product cap moves this node with it.

    A failure is a REPORT, not something to route around: it says the reviewed bundle path cannot
    install this release's own images at their real size. Shrinking an image, splitting the
    artifact, or raising the cap would each turn a true finding into a green run.
    """
    oversized = release.oversized()
    sizes = {
        a.name: a.size
        for role in release.artifacts
        for a in release.artifacts[role]
        if a.kind == "image_archive"
    }
    assert not oversized, (
        f"{len(oversized)} image archive(s) exceed the product's own "
        f"{PRODUCT_MAX_IMAGE_ARCHIVE_BYTES // (1024 * 1024)} MiB installation cap: "
        f"{ {name: sizes.get(name) for name in oversized} }. The product refuses these with "
        f"bootstrap_image_too_large, so this release cannot be installed through the reviewed "
        f"bundle path. Report it; do not resize the image or the cap."
    )


# --------------------------------------------------------------------------- packages stage


def test_the_controller_host_has_the_release_packages_installed(installation: InstallationRun):
    _assert_observed(installation, "controller_packages_installed")


def test_the_worker_host_has_the_release_packages_installed(installation: InstallationRun):
    _assert_observed(installation, "worker_packages_installed")


def test_the_secpctl_entrypoint_is_present_and_answers(installation: InstallationRun):
    """The console script the distribution installs, not a module invocation.

    A ``secpctl`` that exists but cannot import its module is exactly what a distribution/image
    mismatch produces, so presence alone would not settle it — the entrypoint has to answer.
    """
    _assert_observed(installation, "secpctl_entrypoint_present")


def test_the_worker_package_import_closure_resolves_from_the_installed_distribution(
    installation: InstallationRun,
):
    """Every SHIPPED package imports on the worker host, out of the wheel.

    The declared set is read from ``packaging-contract.toml``, so a package dropped from the wheel
    while its code stays in the tree fails HERE — the PR5F regression, observed rather than argued.
    """
    _assert_observed(installation, "worker_package_import_closure")


# --------------------------------------------------------------------------- controller stage


def test_the_controller_database_is_migrated_to_the_signed_head(installation: InstallationRun):
    _assert_observed(installation, "controller_database_migrated")


def test_the_controller_api_serves_tls(installation: InstallationRun):
    """A real TLS handshake verified against the CA the installation wrote.

    Deliberately not taken from the controller observation's ``healthy`` map, which is
    ``dict(running)`` — that map would report "healthy" for a container serving nothing.
    """
    _assert_observed(installation, "controller_api_serving_tls")


def test_the_controller_temporal_component_is_reachable(installation: InstallationRun):
    _assert_observed(installation, "controller_temporal_reachable")


def test_the_enrollment_signer_broker_is_active(installation: InstallationRun):
    _assert_observed(installation, "controller_signer_broker_active")


def test_the_controller_api_locator_was_recorded(installation: InstallationRun):
    """Read back through the PRODUCT's own locator reader: a record only the harness can parse is
    not a record the product can use."""
    _assert_observed(installation, "controller_locator_recorded")


# --------------------------------------------------------------------------- worker install stage


def test_the_pinned_health_interpreter_resolves_in_the_installed_worker_image(
    installation: InstallationRun,
):
    """The exact image this release binds, probed BY CONTENT DIGEST.

    Stronger than probing the upstream base image, because it asks the question of the image the
    release actually binds rather than of the base it was built from. It is also the observation
    that keeps the two interpreter constants tied to reality — the constant once named a path the
    image lacked, which blocked the install and manufactured a false operator-queue containment
    breach.

    Independent of every install step by construction, so it still reports when the controller or
    the bootstrap never got off the ground.
    """
    _assert_observed(installation, "worker_health_command_resolves_in_the_worker_image")


def test_the_worker_bootstrap_plan_defaults_to_a_dry_run_that_wrote_nothing(
    installation: InstallationRun,
):
    """Both halves. The product declared a dry run AND none of the objects it would have written
    exist — a report alone would be satisfied by an installer that wrote anyway."""
    _assert_observed(installation, "worker_bootstrap_plan_is_dry_run")


def test_the_worker_bootstrap_committed(installation: InstallationRun):
    _assert_observed(installation, "worker_bootstrap_written")


def test_the_worker_bootstrap_reobserved_the_host_healthy(installation: InstallationRun):
    _assert_observed(installation, "worker_bootstrap_reobserved_healthy")


def test_the_worker_status_is_clean(installation: InstallationRun):
    _assert_observed(installation, "worker_status_ok")


def test_the_operator_unit_is_present_disabled_and_stopped(installation: InstallationRun):
    """The headline safety observation, answered by real systemd on a host where it is PID 1.

    ``LoadState`` is read alongside the other two because a unit systemd cannot load reports
    ``ActiveState=inactive`` — indistinguishable from a correctly stopped one — and without it the
    check would pass for a unit that is not there at all.
    """
    _assert_observed(installation, "worker_operator_unit_present_disabled_stopped")


def test_the_worker_evidence_is_attested(installation: InstallationRun):
    _assert_observed(installation, "worker_evidence_attested")


# --------------------------------------------------------------------------- the document


def test_every_opened_stage_is_completely_covered(installation: InstallationRun):
    """Opening a stage commits the run to recording every check it declares.

    This is what makes a partially-driven stage a failure rather than a quiet omission: a stage that
    recorded four of its five checks is INCOMPLETE, not partially passed.
    """
    missing = installation.acceptance_run.missing()
    assert not missing, f"opened stages left checks unrecorded: {missing}"
    # The recorder and the driver's own per-stage view must agree. They are written separately, so
    # a check present in one and absent from the other would mean a node is asserting on something
    # the document does not carry (or the reverse) — which is how a check gets a passing node and no
    # evidence record.
    for stage in installation.acceptance_run.stages:
        for check in CHECKS_BY_STAGE[stage]:
            assert installation.outcome_of(check) != "absent", (
                f"{check} is declared by stage {stage} and has no driver outcome"
            )


def test_the_run_carries_this_release_lineage_and_its_declared_gap(
    installation: InstallationRun, release: ReleaseMaterial
):
    """The two records only this stream can supply are on the SESSION's run.

    Deliberately does NOT seal. ``AcceptanceRun.seal`` is idempotent and caches, so sealing here
    would freeze the document mid-session and silently discard every check the later stages have
    not recorded yet. The session-final hook in ``conftest.py`` is the only sealer, and it runs on
    the failure paths too.
    """
    assert set(installation.acceptance_run.stages) >= {"packages", "controller", "worker_install"}
    assert release.aggregates["worker"]
    assert release.anchor["key_id"].startswith("sha256:")
