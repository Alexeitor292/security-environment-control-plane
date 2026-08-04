"""Build ONE exact signed release for an acceptance run, through the REVIEWED authority path.

This module authors no manifest. Every release it produces is assembled, signed and re-verified by
:mod:`secp_management.release_authority` — the offline release-authority tooling a release engineer
uses — driven here with run-scoped inputs. That is deliberate and it is the whole point: a harness
that hand-rolled a manifest would be proving that ITS idea of a release installs, not that the
product's does. Any drift in the release contract therefore breaks this builder, which is the
correct direction for the failure to travel.

WHAT "ONE EXACT RELEASE" MEANS
------------------------------
One signing anchor, one source lineage, one migration identity, one set of measured artifacts —
from which TWO role bundles are cut (``controller`` and ``worker``). The two bundles are different
inventories of the same release, exactly as the release contract models them, and they are signed
by the same anchor. A run that signed the worker bundle under one anchor and the controller bundle
under another would be two releases wearing one name.

WHAT IS MEASURED RATHER THAN DECLARED
-------------------------------------
Every value that could be wrong is read from the thing it describes:

* image digests come from ``docker image inspect --format {{.Id}}`` on the image that was actually
  built or pulled, never from a tag;
* archive digests and sizes come from the bytes on disk after ``docker save``;
* the migration identity is derived from the real migration graph in the repository, so a manifest
  can never claim a head the API does not have (the controller end-state gate compares them, and a
  restated constant would agree with itself while disagreeing with the database);
* the host-runtime executable pins are hashed out of the real disposable host image;
* the source lineage comes from git.

THE SIGNING ANCHOR IS EPHEMERAL AND THAT IS MANDATORY
-----------------------------------------------------
``secp_management.signing.SHIPPED_TRUST_ROOT`` is empty: no reviewed release-signing public key is
committed, and production holds no private key. The harness therefore mints a fresh anchor per run
through ``authority_init`` and destroys it with the run. This is the sealed posture working as
designed, not a shortcut around it — but it does mean the signature path is proven against a
harness-minted anchor rather than the reviewed one, which the caller declares as an explicit gap.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
from dataclasses import dataclass, field

from secp_management.real_adapters import _MAX_ARTIFACT_BYTES

from secp_acceptance import AcceptanceError
from secp_acceptance.shell import docker, run

#: The product's OWN cap on a loadable image archive, READ rather than restated.
#:
#: ``real_adapters._load_and_verify_image`` refuses an archive above this with
#: ``bootstrap_image_too_large``. The harness needs the number to classify an over-cap archive
#: honestly BEFORE it drives an install, and a copy of the literal here would be a constant agreeing
#: with itself: raise the product's cap and a hardcoded harness copy would keep reporting the old
#: refusal, which is precisely the class of defect this harness exists to find. Binding the private
#: name is the price of reading the real one.
PRODUCT_MAX_IMAGE_ARCHIVE_BYTES = _MAX_ARTIFACT_BYTES

_SAVE_TIMEOUT = 1800
_BUILD_TIMEOUT = 3600
_PULL_TIMEOUT = 1800
_INSPECT_TIMEOUT = 120

#: A 12-hex alembic revision, the shape ``RealManagementHostObserver._migration_identity`` recovers
#: from ``alembic current`` and the controller end-state gate compares against.
_REVISION = re.compile(r"[0-9a-f]{12}")

_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")


def repo_root() -> pathlib.Path:
    """The repository root, located by its own marker files rather than by a relative hop count."""
    here = pathlib.Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file() and (parent / "infra").is_dir():
            return parent
    raise AcceptanceError("acceptance_release_build_failed")


# --------------------------------------------------------------------------- measured lineage


def migration_head(root: pathlib.Path) -> str:
    """The REAL single head of the API's migration graph.

    Derived from the migration files themselves — the head is the revision no other revision names
    as its ``down_revision`` — because the controller end-state gate compares the signed
    ``migration_identity`` against what ``alembic current`` reports from the running API. A constant
    restated here would agree with the manifest and disagree with the database, and the resulting
    ``controller_migration_mismatch`` would look like a product defect rather than a harness one.

    A graph with zero or several heads refuses: signing one of several heads would make the
    comparison a coin flip.
    """
    versions = root / "apps" / "api" / "migrations" / "versions"
    if not versions.is_dir():
        raise AcceptanceError("acceptance_release_build_failed")
    revisions: set[str] = set()
    parents: set[str] = set()
    for path in sorted(versions.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        own = re.search(r"^revision(?::\s*str)?\s*=\s*[\"']([0-9a-zA-Z_]+)[\"']", text, re.M)
        if own:
            revisions.add(own.group(1))
        for down in re.findall(
            r"^down_revision(?::[^=]*)?\s*=\s*[\"']([0-9a-zA-Z_]+)[\"']", text, re.M
        ):
            parents.add(down)
    heads = sorted(revisions - parents)
    if len(heads) != 1 or not _REVISION.fullmatch(heads[0]):
        raise AcceptanceError("acceptance_release_build_failed")
    return heads[0]


def source_lineage(root: pathlib.Path) -> tuple[str, str]:
    """``(source_sha, parent_sha)`` from real git history.

    The release contract carries a lineage so an upgrade can be proven a linear successor. Reading
    it from git rather than inventing it keeps a later upgrade scenario able to make that proof
    against the same repository a reviewer is looking at.
    """
    head = run(("git", "-C", str(root), "rev-parse", "HEAD"), timeout=120)
    parent = run(("git", "-C", str(root), "rev-parse", "HEAD^"), timeout=120)
    if not head.ok:
        raise AcceptanceError("acceptance_release_build_failed")
    source = head.stdout.strip()
    if len(source) != 40:
        raise AcceptanceError("acceptance_release_build_failed")
    prior = parent.stdout.strip() if parent.ok else ""
    return source, (prior if len(prior) == 40 else "")


# --------------------------------------------------------------------------- measured artifacts


def sha256_file(path: pathlib.Path) -> tuple[str, int]:
    """``(sha256:<hex>, size)`` of a real file, streamed so a multi-hundred-megabyte image archive
    is never materialised in memory just to be measured."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            block = handle.read(1 << 20)
            if not block:
                break
            digest.update(block)
            size += len(block)
    if size == 0:
        raise AcceptanceError("acceptance_release_build_failed")
    return "sha256:" + digest.hexdigest(), size


def image_id(reference: str) -> str:
    """The exact content id of a local image. Never a tag — a tag is a moving name, and the release
    contract identifies an image only by the digest the loader will re-inspect."""
    probe = docker("image", "inspect", "--format", "{{.Id}}", reference, timeout=_INSPECT_TIMEOUT)
    value = probe.stdout.strip()
    if not probe.ok or not _IMAGE_ID.fullmatch(value):
        raise AcceptanceError("acceptance_release_build_failed")
    return value


def pull_image(reference: str) -> str:
    if not docker("pull", reference, timeout=_PULL_TIMEOUT).ok:
        raise AcceptanceError("acceptance_release_build_failed")
    return image_id(reference)


def build_image(*, tag: str, context: pathlib.Path, dockerfile: pathlib.Path) -> str:
    if not docker(
        "build", "-t", tag, "-f", str(dockerfile), str(context), timeout=_BUILD_TIMEOUT
    ).ok:
        raise AcceptanceError("acceptance_release_build_failed")
    return image_id(tag)


def save_image(reference: str, destination: pathlib.Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not docker("save", "-o", str(destination), reference, timeout=_SAVE_TIMEOUT).ok:
        raise AcceptanceError("acceptance_release_build_failed")


def build_wheel(root: pathlib.Path, out_dir: pathlib.Path) -> pathlib.Path:
    """Build the REAL distribution wheel — the artifact the packaging contract governs.

    The worker deployment package is this wheel, not a copy of the source tree. That distinction is
    what gives ``worker_package_import_closure`` something to prove: a package dropped from
    ``[tool.hatch.build.targets.wheel].packages`` is absent HERE, and the import closure fails
    on the host exactly as it did in the PR5F image regression.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    built = run(
        ("uv", "build", "--wheel", "--out-dir", str(out_dir), str(root)), timeout=_BUILD_TIMEOUT
    )
    if not built.ok:
        raise AcceptanceError("acceptance_release_build_failed")
    wheels = sorted(out_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise AcceptanceError("acceptance_release_build_failed")
    return wheels[0]


# --------------------------------------------------------------------------- host runtime pins


#: The three host-runtime capabilities the signed profile must pin, and where the disposable host
#: image puts each. ``compose`` names the standalone binary the management adapters invoke with
#: global flags BEFORE the subcommand; the invocation prefix is empty because it is a standalone
#: executable rather than the ``docker compose`` plugin form.
HOST_EXECUTABLES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("container_runtime", "/usr/bin/docker", ()),
    ("compose", "/usr/local/bin/docker-compose", ()),
    ("service_manager", "/usr/bin/systemctl", ()),
)

#: The exact allowed-subcommand sets the release contract requires per capability. Imported from the
#: product at call time rather than copied, for the same reason as the archive cap above.


def _allowed_subcommands(capability: str) -> tuple[str, ...]:
    from secp_management.release_bundle import _RUNTIME_ALLOWED_SUBCOMMANDS

    return tuple(sorted(_RUNTIME_ALLOWED_SUBCOMMANDS[capability]))


def measure_host_executables(host_image: str) -> list[dict[str, object]]:
    """Hash the three pinned executables OUT OF the real disposable host image.

    Measured in a throwaway container from the same image the fleet boots, so the digests are facts
    about the filesystem the installer will actually open. ``sha256sum`` is run once over all three
    paths; a missing path makes the command fail rather than yielding a short answer that a caller
    might read as success.

    The pins land in the SIGNED manifest and in the host's ``production-executables.json``, and
    ``open_pinned_executable`` re-verifies the object at every call — so a digest invented here
    would refuse at the first real adapter invocation rather than passing quietly.
    """
    paths = [path for _, path, _ in HOST_EXECUTABLES]
    probe = docker(
        "run",
        "--rm",
        "--network",
        "none",
        "--entrypoint",
        "/usr/bin/sha256sum",
        host_image,
        *paths,
        timeout=300,
    )
    if not probe.ok:
        raise AcceptanceError("acceptance_release_build_failed")
    measured: dict[str, str] = {}
    for line in probe.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            measured[parts[1]] = "sha256:" + parts[0]
    pins: list[dict[str, object]] = []
    for capability, path, invocation in HOST_EXECUTABLES:
        digest = measured.get(path)
        if digest is None:
            raise AcceptanceError("acceptance_release_build_failed")
        pins.append(
            {
                "capability": capability,
                "path": path,
                "sha256": digest,
                "invocation": list(invocation),
                "allowed_subcommands": list(_allowed_subcommands(capability)),
            }
        )
    return pins


# --------------------------------------------------------------------------- compose templates


def controller_compose_template(image_map: dict[str, str]) -> bytes:
    """The controller Compose artifact this release signs.

    Built ON the reviewed reference rather than instead of it: the reference states what the
    installation contract REQUIRES of ``services.api`` (the two read-only binds, in the same path
    constants the validator imports), and a release is explicitly free to carry a richer template.
    So the reference's api block is emitted verbatim and the deployable facts a real bring-up needs
    — the digest-pinned image and the container name the host observer inspects — are added around
    it.

    Every image is pinned by CONTENT DIGEST from the signed map. No floating tag reaches a template
    this release signs, which is the same rule the loader enforces when it re-inspects the loaded
    image. Container names come from the product's own helper, so a rename in the observer breaks
    the template rather than silently producing a stack the observer cannot see.
    """
    from secp_commissioning.enrollment_signer_binding_digest import (
        ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH,
        ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH,
    )
    from secp_commissioning.enrollment_signer_marker import ENROLLMENT_SIGNER_MARKER_PATH
    from secp_management.controller_compose_validation import CONTROLLER_API_SERVICE
    from secp_management.real_adapters import _controller_container
    from secp_management.topology import EXPECTED_CONTROLLER_COMPONENTS

    missing = [c for c in EXPECTED_CONTROLLER_COMPONENTS if c not in image_map]
    if missing:
        raise AcceptanceError("acceptance_release_build_failed")

    ordered = (CONTROLLER_API_SERVICE,) + tuple(
        c for c in EXPECTED_CONTROLLER_COMPONENTS if c != CONTROLLER_API_SERVICE
    )
    lines = ["services:"]
    for component in ordered:
        lines.append(f"  {component}:")
        lines.append(f"    image: {image_map[component]}")
        lines.append(f"    container_name: {_controller_container(component)}")
        lines.append("    restart: unless-stopped")
        if component == CONTROLLER_API_SERVICE:
            # The two reviewed read-only binds, emitted in the long form the contract requires.
            lines.append("    volumes:")
            for source, target in (
                (ENROLLMENT_SIGNER_MARKER_PATH, ENROLLMENT_SIGNER_MARKER_PATH),
                (
                    ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH,
                    ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH,
                ),
            ):
                lines.append("      - type: bind")
                lines.append(f"        source: {source}")
                lines.append(f"        target: {target}")
                lines.append("        read_only: true")
                lines.append("        bind:")
                lines.append("          create_host_path: false")
    return ("\n".join(lines) + "\n").encode("utf-8")


def worker_compose_template(ordinary_image: str) -> bytes:
    """The worker Compose artifact this release signs.

    One service: the ordinary worker, pinned by content digest and named exactly what the host
    observer inspects (``topology.ORDINARY_CONTAINER_NAME``). It carries no Compose ``healthcheck``
    — deliberately, and not as an omission. The management observer establishes ordinary readiness
    by running ``topology.ORDINARY_HEALTH_COMMAND`` itself, as ``<runtime> exec <container>
    <argv>``, so a Compose healthcheck here would be a second, unrelated notion of health that no
    gate reads and that a reader could easily mistake for the one that counts.
    """
    from secp_management.topology import ORDINARY_CONTAINER_NAME

    lines = [
        "services:",
        "  ordinary:",
        f"    image: {ordinary_image}",
        f"    container_name: {ORDINARY_CONTAINER_NAME}",
        "    restart: unless-stopped",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


# --------------------------------------------------------------------------- the release


@dataclass(frozen=True)
class Artifact:
    """One measured release artifact, ready to be declared in a manifest."""

    name: str
    kind: str
    role: str
    sha256: str
    size: int
    image_digest: str | None = None
    purpose: str | None = None

    def declaration(self) -> dict[str, object]:
        out: dict[str, object] = {
            "name": self.name,
            "kind": self.kind,
            "role": self.role,
            "sha256": self.sha256,
            "size": self.size,
        }
        if self.image_digest is not None:
            out["image_digest"] = self.image_digest
        if self.purpose is not None:
            out["purpose"] = self.purpose
        return out

    @property
    def over_product_cap(self) -> bool:
        """True when the product's own loader would refuse this archive for size.

        Recorded rather than worked around. An archive above the cap is a real statement about the
        release the product cannot install, and the acceptance must report it as such — shrinking
        the image, splitting the artifact, or raising the cap would manufacture the pass this
        harness exists to remove.
        """
        return self.kind == "image_archive" and self.size > PRODUCT_MAX_IMAGE_ARCHIVE_BYTES


@dataclass
class ReleaseMaterial:
    """The run-scoped signed release: one anchor, one lineage, two role bundles."""

    workdir: pathlib.Path
    anchor: dict[str, str] = field(default_factory=dict)
    key_path: str = ""
    source_sha: str = ""
    parent_sha: str = ""
    migration_identity: str = ""
    implementation_aggregate: str = ""
    runtime_pins: list[dict[str, object]] = field(default_factory=list)
    artifacts: dict[str, list[Artifact]] = field(default_factory=dict)
    bundles: dict[str, pathlib.Path] = field(default_factory=dict)
    aggregates: dict[str, str] = field(default_factory=dict)
    #: The file name of the distribution wheel this release built, so the installer can name it
    #: inside a host without the harness re-globbing a directory it already measured.
    wheel_name: str = ""

    def oversized(self) -> tuple[str, ...]:
        """Every declared image archive the product's own cap would refuse."""
        names: list[str] = []
        for role_artifacts in self.artifacts.values():
            names.extend(a.name for a in role_artifacts if a.over_product_cap)
        return tuple(sorted(set(names)))

    def observation(self) -> dict[str, object]:
        """The bounded, secret-free projection of this release for the evidence document."""
        return {
            "anchor": self.anchor.get("key_id", ""),
            "source_sha": self.source_sha,
            "migration_identity": self.migration_identity,
            "roles": sorted(self.bundles),
            "aggregates": {role: self.aggregates[role] for role in sorted(self.aggregates)},
            "artifact_counts": {role: len(self.artifacts[role]) for role in sorted(self.artifacts)},
            "oversized_archives": len(self.oversized()),
        }


def init_anchor(workdir: pathlib.Path) -> tuple[str, dict[str, str]]:
    """Mint the run-scoped release anchor through the reviewed authority ``init``.

    The private key is written to a 0700 directory OUTSIDE the repository, which is what
    ``authority_init`` requires and re-checks; it never enters an evidence document, a log line, or
    a container. It dies with the run's working directory.
    """
    from secp_management.release_authority import authority_init

    keydir = workdir / "authority"
    keydir.mkdir(parents=True, exist_ok=True)
    os.chmod(keydir, 0o700)
    key_path = str((keydir / "release-signing.key").resolve())
    try:
        _, payload = authority_init(key_path=key_path, repo_root=str(repo_root()))
    except Exception:  # noqa: BLE001 - bounded; the authority's own reason never leaves the harness
        raise AcceptanceError("acceptance_release_not_signed") from None
    anchor = payload["anchor"]
    if not isinstance(anchor, dict) or set(anchor) != {"key_id", "public_key_hex"}:
        raise AcceptanceError("acceptance_release_not_signed")
    return key_path, {
        "key_id": str(anchor["key_id"]),
        "public_key_hex": str(anchor["public_key_hex"]),
    }


def release_spec(material: ReleaseMaterial, role: str) -> dict[str, object]:
    """The v1alpha2 manifest spec for one role bundle of this release.

    Every field is either measured (lineage, migration head, artifact digests, runtime pins) or a
    closed contract constant. Nothing here is a deployment value: no origin, no credential, no
    registry reference, no host name.
    """
    from secp_management import BOOTSTRAP_CONTRACT_VERSION_V1ALPHA2, PLANE_MANAGEMENT
    from secp_management.release_bundle import TLS_MODE_GENERATED_LOCAL_CA

    spec: dict[str, object] = {
        "bootstrap_contract_version": BOOTSTRAP_CONTRACT_VERSION_V1ALPHA2,
        "plane": PLANE_MANAGEMENT,
        "role": role,
        "release_version": "0.0.0-acceptance",
        "source_sha": material.source_sha,
        "source_tree_sha": material.source_sha,
        "migration_identity": material.migration_identity,
        "implementation_aggregate": material.implementation_aggregate,
        "bootstrap_package_identity": "secp-acceptance/management-bootstrap/v1",
        "signing_anchor_id": material.anchor["key_id"],
        "artifacts": [a.declaration() for a in material.artifacts[role]],
        "platform_profile": {
            "os": "linux",
            "arch": _canonical_arch(),
            "installation_profile_version": "secp-acceptance-profile-v1",
        },
        "runtime_profile": {"pins": material.runtime_pins},
        # The generated-local-CA mode is the one a disposable fleet can honestly satisfy: the
        # imported-enterprise mode would need an enterprise PKI the harness must never contact, and
        # declaring a mode the run cannot exercise would put an unexercised policy in a signed
        # artifact.
        "controller_tls_policy": {
            "allowed_modes": [TLS_MODE_GENERATED_LOCAL_CA],
            "key_algorithm": "ecdsa-p256",
            "signature_algorithm": "ecdsa-with-sha256",
            "max_validity_days": 90,
            "require_san": True,
            "server_auth_eku_required": True,
            "ca_pathlen_zero": True,
            "min_tls_version": "1.2",
            "allow_ip_origin": False,
            "allow_generated_local_ca": True,
        },
    }
    if material.parent_sha:
        spec["parent_sha"] = material.parent_sha
    return spec


def build_variant_bundle(
    material: ReleaseMaterial,
    role: str,
    label: str,
    *,
    source_sha: str | None = None,
    parent_sha: str | None = None,
    image_overrides: dict[str, tuple[pathlib.Path, str]] | None = None,
) -> dict[str, object]:
    """Cut a SIBLING bundle from this release, differing in exactly the fields named.

    PUBLISHED SIGNATURE — three positionals, then keyword-only overrides::

        build_variant_bundle(material, role, label, *, source_sha=None, parent_sha=None,
                             image_overrides=None) -> dict

    ``material`` is the run's :class:`ReleaseMaterial` (it carries the anchor and key, which is what
    makes the sibling a sibling); ``role`` is ``"controller"`` or ``"worker"``; ``label`` names the
    variant and becomes part of its directory name, so two variants of one role cannot collide.
    The signature is written out because an omitted required positional in a published summary is
    the same class of defect as a stale comment — a caller writing against the summary gets it
    wrong and finds out at run time.

    Returns ``{"bundle_dir": Path, "source_sha": str, "parent_sha": str, "aggregate_digest": str}``.

    Published for the lifecycle stage, which needs three siblings signed by the SAME anchor: a
    linear successor, a non-successor differing in ``parent_sha`` ALONE, and an unhealthy successor
    differing in the ordinary worker image ALONE.

    SINGLE-FIELD ATTRIBUTION IS THE POINT. A "non-linear upgrade refused" proof means nothing if the
    refused bundle also differed in its images, its lineage and its digests — the product could have
    refused it for any of those, and the check would pass without ever exercising linearity. So this
    copies the base bundle verbatim and changes only what the caller named; everything else,
    including the signing anchor, is shared with the release the run installed.

    Returns ``{bundle_dir, source_sha, parent_sha, aggregate_digest}``. ``bundle_dir`` is a real
    directory the caller can hand to ``secpctl --bundle``; the three scalars are what an upgrade
    assertion needs to state which sibling it drove.

    There is deliberately no second signer here. A stream that minted its own anchor would be
    proving that ITS releases upgrade, not that this run's release does.
    """
    import shutil

    if role not in material.bundles:
        raise AcceptanceError("acceptance_release_build_failed")
    variant_dir = material.workdir / f"bundle-{role}-{label}"
    if variant_dir.exists():
        shutil.rmtree(variant_dir)
    shutil.copytree(material.bundles[role], variant_dir)

    # Artifacts are frozen, so sharing the unreplaced ones is safe and keeps every untouched
    # declaration byte-identical to the base release.
    artifacts = list(material.artifacts[role])
    if image_overrides:
        replaced: list[Artifact] = []
        for artifact in artifacts:
            override = image_overrides.get(artifact.purpose or "")
            if override is None or artifact.kind != "image_archive":
                replaced.append(artifact)
                continue
            archive, digest = override
            target = variant_dir / artifact.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(archive, target)
            sha, size = sha256_file(target)
            replaced.append(
                Artifact(
                    name=artifact.name,
                    kind=artifact.kind,
                    role=artifact.role,
                    sha256=sha,
                    size=size,
                    image_digest=digest,
                    purpose=artifact.purpose,
                )
            )
        artifacts = replaced

    # A scratch material sharing this run's anchor and key, differing only where asked.
    variant = ReleaseMaterial(
        workdir=material.workdir,
        anchor=dict(material.anchor),
        key_path=material.key_path,
        source_sha=source_sha or material.source_sha,
        parent_sha=material.parent_sha if parent_sha is None else parent_sha,
        migration_identity=material.migration_identity,
        implementation_aggregate=material.implementation_aggregate,
        runtime_pins=list(material.runtime_pins),
        artifacts={role: artifacts},
        bundles={role: variant_dir},
    )
    build_and_sign(variant, role)
    return {
        "bundle_dir": variant_dir,
        "source_sha": variant.source_sha,
        "parent_sha": variant.parent_sha,
        "aggregate_digest": variant.aggregates[role],
    }


def _canonical_arch() -> str:
    """The canonical architecture name, through the product's ONE normalization boundary.

    ``normalize_arch`` is the only place an alias like ``amd64`` becomes ``x86_64``; going around it
    would be how an implicit alias mismatch reaches a signed profile.
    """
    import platform

    from secp_management.release_bundle import normalize_arch

    try:
        return normalize_arch(platform.machine())
    except Exception:  # noqa: BLE001 - an unsupported build host refuses, bounded
        raise AcceptanceError("acceptance_release_build_failed") from None


def build_and_sign(material: ReleaseMaterial, role: str) -> pathlib.Path:
    """Assemble, sign and re-verify one role bundle through the reviewed authority commands.

    Order is the authority's, not ours: ``build`` canonicalises and refuses a malformed profile,
    ``sign`` re-verifies EVERY artifact's bytes before it will produce a signature, and ``verify``
    then re-checks the detached envelope under the run's public anchor alone. The harness asserts
    nothing about the release that these three did not already establish.
    """
    import json as _json

    from secp_management.release_authority import authority_build, authority_sign, authority_verify

    bundle = material.bundles[role]
    spec_bytes = _json.dumps(release_spec(material, role)).encode("utf-8")
    try:
        _, built = authority_build(spec_bytes=spec_bytes, artifacts_dir=str(bundle))
    except Exception:  # noqa: BLE001
        raise AcceptanceError("acceptance_release_build_failed") from None
    manifest_bytes = str(built["manifest_bytes"]).encode("utf-8")
    manifest_path = bundle / str(built["manifest_name"])
    manifest_path.write_bytes(manifest_bytes)

    try:
        _, signed = authority_sign(
            manifest_bytes=manifest_bytes, key_path=material.key_path, artifacts_dir=str(bundle)
        )
    except Exception:  # noqa: BLE001
        raise AcceptanceError("acceptance_release_not_signed") from None
    signature_bytes = str(signed["signature_bytes"]).encode("utf-8")
    signature_path = bundle / str(signed["signature_name"])
    signature_path.write_bytes(signature_bytes)

    try:
        _, verified = authority_verify(
            manifest_bytes=manifest_bytes,
            signature_bytes=signature_bytes,
            anchor=dict(material.anchor),
            artifacts_dir=str(bundle),
        )
    except Exception:  # noqa: BLE001
        raise AcceptanceError("acceptance_release_not_signed") from None
    if verified.get("verified") is not True:
        raise AcceptanceError("acceptance_release_not_signed")
    material.aggregates[role] = str(built["aggregate_digest"])
    return bundle


__all__ = [
    "Artifact",
    "HOST_EXECUTABLES",
    "PRODUCT_MAX_IMAGE_ARCHIVE_BYTES",
    "ReleaseMaterial",
    "build_and_sign",
    "build_variant_bundle",
    "build_image",
    "build_wheel",
    "image_id",
    "init_anchor",
    "measure_host_executables",
    "migration_head",
    "pull_image",
    "release_spec",
    "repo_root",
    "save_image",
    "sha256_file",
    "source_lineage",
]
