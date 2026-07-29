"""Managed controller UPGRADE (generation N+1) + rollback-to-prior-generation (SECP-PR5H-B2).

Hermetic end-to-end proofs for the NEW managed-upgrade write path in ``controller_install``:

* install release A (fresh, generation 0) to create the committed prior B2 state (marker +
  A-evidence with finalization generation 0), then install release B — an authenticated LINEAR
  SUCCESSOR of A (``B.parent_sha == A.source_sha``) with a different compose template and different
  component images — as a MANAGED UPGRADE at generation 1. Under R2 that upgrade is a REAL candidate
  STACK upgrade performed BY the transaction: the signed candidate images are loaded, the candidate
  compose config + the code-owned supervisor unit are installed, the daemon is reloaded, the
  identity-UNCHANGED migration transition is applied, the candidate stack is started, and the EXACT
  signed candidate component/image map is reobserved — and only THEN may finalization begin. An
  externally upgraded stack does NOT qualify;
* the MIGRATION-TRANSITION LIMIT: a candidate whose ``migration_identity`` differs from the
  authenticated prior one refuses ``controller_upgrade_migration_transition_unsupported`` before any
  host effect, because an irreversible schema transition cannot honestly claim prior-stack rollback;
* a post-activation failure drives the engine-owned ``_upgrade_rollback`` (reactivate the prior
  identity's facts as a NEW row at generation N+2, predecessor = the failed candidate) AND
  ``_restore_controller_stack`` (reinstall the prior compose config + supervisor unit, restart, and
  PROVE the prior image map operational again), then refuses with the ORIGINAL reason — or
  ``recovery_required`` when either cannot be proven. The candidate images this transaction
  introduced are NOT deleted, so the reported ``candidate_image_cache_residual`` is truthful;
* every other changed-release state (non-linear successor, prior-not-B2, prior unauthenticated/
  drifted, missing/drifted marker, stale/skipped/downgrade generation) refuses BEFORE any B change.

No source file is edited. The finalization + identity-activation effects are simulated by an
in-memory hardened filesystem plus a closed fake finalization adapter (an extension of the 2b-3c-a
fake) that shares a MODULE-LEVEL append-only identity DB mirroring the real API activation
one-shot's predecessor CAS + per-row generation rules, so the engine's generation threading across
the forward drive and the rollback reactivation is genuinely exercised. The host stack is simulated
by binding the shared fake bootstrap adapter to the in-memory filesystem: ``install_config`` /
``install_unit`` persist the exact reviewed bytes to their fixed paths and ``start_stack`` brings up
exactly the component/image map the INSTALLED compose config selects — so the observed stack can
only advance when the transaction itself installs + starts it. Every controller-adapter op and every
finalization op is recorded on ONE ordered timeline, so operation order (candidate stack first,
finalization strictly after the candidate-stack proof) is asserted directly. Only leaf effects are
faked.
"""

from __future__ import annotations

import copy
import dataclasses
import json

import pytest
from _mgmt_support import (
    CONTROLLER_COMPONENT_IMAGE,
    default_artifacts,
    deps_for,
    ephemeral_trust_root,
    fresh_controller_world,
    manifest_dict,
    seed_signed_bundle,
    seed_write_ancestors,
)
from secp_commissioning.canonical import canonical_json, sha256_bytes
from secp_commissioning.enrollment_signer_marker import render_marker_bytes
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import BOOTSTRAP_CONTRACT_VERSION_V1ALPHA2 as V2
from secp_management import ManagementError
from secp_management import enrollment_signer_runtime_observer as obs_mod
from secp_management.adapters import CompensationResult
from secp_management.cli import run
from secp_management.evidence import (
    CLASSIFY_MANAGED_UPGRADE,
    FINALIZATION_SCHEMA_VERSION,
)
from secp_management.finalization import (
    FINALIZATION_EFFECTS,
    ActivationReceipt,
    EffectDisposition,
    FinalizationEffectReceipt,
)
from secp_management.layout import ManagementLocations
from secp_management.release_bundle import (
    ReleaseManifest,
    manifest_aggregate_digest,
    manifest_signing_message,
)
from secp_management.signing import sign_ed25519
from secp_management.topology import EXPECTED_CONTROLLER_COMPONENTS
from test_controller_install_2b3c import (
    _FakeFinalizationAdapter,
    _FakeInventory,
    _FakeLiveState,
    _install_argv,
    _live_observer_factory,
    _read_evidence,
    _seed_etc_controller,
    _seed_v2_controller_bundle,
    _valid_profile,
)
from test_enrollment_signer_runtime_observer import LiveApiWorld, RecordingExpectations

_MAX = 256 * 1024

# A's lineage: `_seed_v2_controller_bundle` seeds the default fixture, whose source_sha is "a" * 40
# and whose migration_identity is the shared fixture one. B and M are seeded as LINEAR SUCCESSORS of
# A (parent_sha == A.source_sha) with distinct source_shas and DIFFERENT component images, image
# archives and compose templates so the aggregate differs (→ the base classifier returns
# preexisting_changed_release, the ONLY gate into the managed-upgrade path). M additionally changes
# the signed migration_identity — the one transition the managed upgrade refuses to perform.
SA = "a" * 40
SB = "d" * 40
SM = "f" * 40
BD_A = "/var/lib/secp/bootstrap/release/controller"
BD_B = "/var/lib/secp/bootstrap/release/controller-b"
BD_M = "/var/lib/secp/bootstrap/release/controller-m"

A_IMAGES = dict(CONTROLLER_COMPONENT_IMAGE)
B_IMAGES = {
    c: sha256_bytes(f"image:controller-B/{c}".encode()) for c in EXPECTED_CONTROLLER_COMPONENTS
}
B_COMPOSE = b"# compose template (controller release B)\n"
B_CONFIG_IDENTITY = sha256_bytes(B_COMPOSE)
# a DIFFERENT signed schema-migration identity (the unsupported transition)
M_MIGRATION_IDENTITY = "f1e2d3c4b5a6"

_RUNTIME_FAIL_REASON = "finalization_post_marker_runtime_unverified"

# the controller-adapter host ops the R2 candidate stack upgrade drives, in their reviewed order
_STACK_OPS = (
    "load_image",
    "install_config",
    "install_unit",
    "daemon_reload",
    "run_migrations",
    "start_stack",
)
_STACK_TAIL = ["install_config", "install_unit", "daemon_reload", "run_migrations", "start_stack"]
_N_IMAGES = len(EXPECTED_CONTROLLER_COMPONENTS)


def _compose_identity_of(artifacts: list[dict]) -> str:
    """The SIGNED compose-template digest of a controller artifact set — the same value the engine
    derives as the expected installed config identity."""
    for art in artifacts:
        if str(art["kind"]).endswith("compose_template"):
            return str(art["sha256"])
    raise AssertionError("no compose template artifact")


A_CONFIG_IDENTITY = _compose_identity_of(default_artifacts("controller"))


# --------------------------------------------------------------- shared fake identity-activation DB


class _IdentityDb:
    """A MODULE-shared, APPEND-ONLY fake of the API identity-activation one-shot's durable per-row
    state. ``activate`` mirrors the real one-shot's two invariants so the engine's generation
    threading is genuinely exercised: a predecessor CAS (``previous_active_row_id`` must equal the
    currently-active row) and a per-row generation successor rule (``generation`` must equal the
    predecessor's recorded generation + 1, fresh → 0 when the predecessor is None). A successful
    activation MINTS a new distinct row + token, records its generation, and makes it active — it
    NEVER updates or deletes an existing row (the receipts + append-only log prove immutability), so
    the rollback reactivation is a genuine N+2 append, not an in-place rewrite."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.active_row: str | None = None
        self.generation_by_row: dict[str, int] = {}
        self.receipts: dict[str, dict] = {}  # row -> immutable snapshot
        self.log: list[dict] = []  # append-only ledger of every activation
        self._counter = 0

    def activate(self, activation: object) -> tuple[str, str]:
        prev = activation.previous_active_row_id  # type: ignore[attr-defined]
        if prev != self.active_row:  # predecessor CAS (concurrent/foreign predecessor)
            raise ManagementError("finalization_predecessor_conflict")
        expected = 0 if prev is None else self.generation_by_row[prev] + 1
        if activation.generation != expected:  # type: ignore[attr-defined]
            raise ManagementError("activation_generation_out_of_order")
        self._counter += 1
        row = f"{self._counter:08d}-1111-1111-1111-111111111111"
        token = f"{row}|token-{self._counter}"
        gen = activation.generation  # type: ignore[attr-defined]
        # append-only: build NEW dicts so existing rows are never mutated in place
        self.generation_by_row = {**self.generation_by_row, row: gen}
        snap = {"row": row, "generation": gen, "token": token, "previous_active_row_id": prev}
        self.receipts = {**self.receipts, row: dict(snap)}
        self.log.append(dict(snap))
        self.active_row = row
        return row, token


_IDENTITY_DB = _IdentityDb()


# ----------------------------------------------------------------------- the ordered op timeline


class _TimelineOps(list):
    """The finalization adapter's own ``ops`` list, mirrored onto the SHARED transaction timeline so
    stack ops, host reobservations and finalization ops are ordered against one another."""

    def __init__(self, timeline: list[tuple[str, object]]) -> None:
        super().__init__()
        self._timeline = timeline

    def append(self, item: object) -> None:
        super().append(item)
        self._timeline.append(("finalization", item))


def _names(segment: list[tuple[str, object]]) -> list[str]:
    return [op for op, _ in segment]


def _values(segment: list[tuple[str, object]], op_name: str) -> list[object]:
    return [value for op, value in segment if op == op_name]


def _stack_sequence(segment: list[tuple[str, object]]) -> list[str]:
    return [op for op, _ in segment if op in _STACK_OPS]


def _image_map(mapping: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted(mapping.items()))


def _assert_candidate_stack_upgrade(
    segment: list[tuple[str, object]],
    *,
    images: dict[str, str],
    config_identity: str,
    unit_identity: str,
    migration_identity: str,
) -> None:
    """R2 assertions 1/2/3/4/9 in one place: the EXACT reviewed candidate-stack operation ORDER
    (signed images → compose config → supervisor unit → daemon-reload → migration → start_stack),
    the exact candidate config/unit/migration identities, an independent reobservation of the EXACT
    candidate component/image map after the start, and NO finalization op anywhere before that
    proof.

    Everything asserted here is scoped to the segment BEFORE the first finalization op, so the same
    proof holds whether the transaction went on to commit or to restore the prior stack."""
    names = _names(segment)
    assert "finalization" in names, segment
    first_finalization = names.index("finalization")
    candidate = segment[:first_finalization]

    # 1/9. the COMPLETE reviewed candidate-stack sequence runs, and it runs entirely BEFORE the
    # first finalization op — no finalization begins on an unapplied or unproven candidate stack.
    assert _stack_sequence(candidate) == ["load_image"] * len(images) + _STACK_TAIL, segment
    # 3/4. the exact signed candidate config, the code-owned unit, the UNCHANGED migration identity
    assert _values(candidate, "install_config") == [config_identity]
    assert _values(candidate, "install_unit") == [unit_identity]
    assert _values(candidate, "run_migrations") == [migration_identity]
    assert _values(candidate, "start_stack") == [tuple(sorted(images))]
    loaded = {digest for _archive, digest in _values(candidate, "load_image")}  # type: ignore[misc]
    assert loaded == set(images.values())

    last_stack = max(i for i, op in enumerate(_names(candidate)) if op in _STACK_OPS)
    proofs = [
        value for i, (op, value) in enumerate(candidate) if op == "observe" and i > last_stack
    ]
    # 2. the EXACT signed candidate component/image map is reobserved before finalization
    assert proofs, segment
    assert proofs[0] == _image_map(images)


# --------------------------------------------------------------- upgrade-aware finalization adapter


class _UpgradeFakeAdapter(_FakeFinalizationAdapter):
    """The 2b-3c-a closed fake EXTENDED for the managed-upgrade drive. It keeps the 9-op recording,
    CA-bundle write, marker write, receipt, and commit of its base, and overrides exactly the seams
    a generation-threaded upgrade + rollback exercises:

    * ``activate_controller_identity`` routes through the shared identity DB (predecessor CAS +
      generation successor), minting a NEW distinct row/token on success — so the forward drive
      (P→C, gen N+1) and the rollback reactivation (C→P′, gen N+2) both thread real predecessors;
    * ``_effects`` classifies the adopted surface (TLS/locator/credential/role/key/broker) as
      EXACT_ADOPTED and identity+marker as MANAGED_REPLACED on an upgrade (all ABSENT when fresh);
    * ``enable_api_signer`` models the runtime-health ``.ok`` gate (``runtime_fail_generations``
      forces a post-activation failure on a chosen generation), reverting the marker FIRST on fail;
    * ``compensate`` restores the prior marker (marker-first) and returns the expected
      ``identity_activation`` residual the ENGINE's rollback reactivation resolves — leaving the
      adopted objects in place — only when this drive actually activated;
    * every recorded op is mirrored onto the shared transaction timeline, so the R2 ordering proof
      (no finalization before the candidate-stack proof) can be made directly."""

    def __init__(
        self,
        plan: object,
        fs: InMemoryFilesystem,
        loc: object,
        db: _IdentityDb,
        timeline: list[tuple[str, object]],
        *,
        runtime_fail_generations: frozenset[int] = frozenset(),
        runtime_observer: object | None = None,
    ) -> None:
        super().__init__(plan, fs, loc, runtime_observer=runtime_observer)
        self.ops = _TimelineOps(timeline)  # type: ignore[assignment]
        self._db = db
        self._runtime_fail_generations = frozenset(runtime_fail_generations)
        self._activated = False
        self._wrote_marker = False
        self._prior_marker: bytes | None = None

    @property
    def generation(self) -> int:
        return int(self.plan.generation)  # type: ignore[attr-defined]

    def activate_controller_identity(self, activation: object) -> ActivationReceipt:
        self.ops.append("activate_controller_identity")
        row, token = self._db.activate(activation)  # raises on predecessor/generation conflict
        self._activated = True
        return ActivationReceipt(
            operation_id=activation.operation_id,  # type: ignore[attr-defined]
            candidate_digest="sha256:" + "a" * 64,
            resulting_row_id=row,
            activation_token=token,
            previous_active_row_id=activation.previous_active_row_id,  # type: ignore[attr-defined]
            created=True,
            resulting_status="active",
            resulting_public_state_digest="sha256:" + "b" * 64,
        )

    def enable_api_signer(self, marker: object) -> None:  # LAST
        self.ops.append("enable_api_signer")
        try:
            self._prior_marker = self._fs.safe_read(
                self._loc.api_signer_marker_path(),  # type: ignore[attr-defined]
                max_bytes=_MAX,
                expected_uid=0,
            )
        except Exception:  # noqa: BLE001 - no prior marker on a fresh install
            self._prior_marker = None
        self._write_marker(marker)
        self._wrote_marker = True
        # R4: the AUTHORITATIVE post-marker runtime observation, when one is composed. A refusal
        # reverts the marker FIRST (restoring the prior working generation) and only THEN raises.
        if self._runtime_observer is not None:
            observation = self._runtime_observer(marker)
            self.runtime_observation = observation
            self.events.append("runtime_ok" if observation.ok else "runtime_refused")
            if not observation.ok:
                self._revert_marker()
                raise ManagementError(_RUNTIME_FAIL_REASON)
        if self.generation in self._runtime_fail_generations:
            # mirror the real adapter: on a failed post-marker runtime observation, revert the
            # marker FIRST (return the API to the prior generation / sealed) THEN raise.
            self._revert_marker()
            raise ManagementError(_RUNTIME_FAIL_REASON)

    def _revert_marker(self) -> None:
        if not self._wrote_marker:
            return  # this adapter never wrote a marker → never touch a prior generation's marker
        if self._prior_marker is not None:
            self._fs.atomic_install(
                self._loc.api_signer_marker_path(),  # type: ignore[attr-defined]
                self._prior_marker,
                uid=0,
                gid=0,
                mode=0o640,
            )  # RESTORE the prior working generation's marker (upgrade)
            self.events.append("marker_restore")
        else:
            self._reseal_marker()  # remove (fresh install → SEALED)

    def _effects(self) -> tuple[FinalizationEffectReceipt, ...]:
        if self.generation == 0:
            return super()._effects()  # fresh → every effect ABSENT
        replaced = {"identity_activation", "marker"}
        return tuple(
            FinalizationEffectReceipt(
                effect=name,
                transaction_id="tx-fake-0",
                generation=self.generation,
                object_identity=name,
                disposition=(
                    EffectDisposition.MANAGED_REPLACED.value
                    if name in replaced
                    else EffectDisposition.EXACT_ADOPTED.value
                ),
                candidate_digest="sha256:" + "c" * 64,
            )
            for name in FINALIZATION_EFFECTS
        )

    def compensate(self, receipt: object) -> CompensationResult:
        self.compensated = True
        if self._compensate_raises:
            raise ManagementError("fake_finalization_compensate_error")
        if self.generation == 0:  # fresh install → base marker-first reseal semantics
            self._reseal_marker()
            if self._compensate_residual:
                return CompensationResult(proven=False, residual=("marker",))
            return CompensationResult(proven=True)
        # upgrade: restore the prior marker (marker-first) + leave the adopted surface; the ONLY
        # residual is the activated identity — which the ENGINE's rollback reactivation resolves. If
        # this drive never activated, there is nothing durable to compensate (proven).
        self._revert_marker()
        if self._activated:
            return CompensationResult(proven=False, residual=("identity_activation",))
        return CompensationResult(proven=True)


# --------------------------------------------------------------------------- seeding + setup


def _controller_artifacts(
    image_map: dict[str, str], *, compose: bytes, archive_tag: str
) -> tuple[list[dict], dict[str, bytes]]:
    """The default controller artifacts re-bound to a DIFFERENT release: each image_archive gets
    its own archive bytes AND signed image_digest, and the compose template gets its own content.
    Returns the artifact dicts plus the exact bytes to seed for them (so the file, its size and its
    signed digest all agree)."""
    arts: list[dict] = []
    blobs: dict[str, bytes] = {}
    for art in default_artifacts("controller"):
        name = str(art["name"])
        if art["kind"] == "image_archive":
            component = str(art["purpose"]).split("/", 1)[1]
            data = f"fake image archive {archive_tag}/{name}\n".encode()
            art = {
                **art,
                "image_digest": image_map[component],
                "sha256": sha256_bytes(data),
                "size": len(data),
            }
            blobs[name] = data
        elif str(art["kind"]).endswith("compose_template"):
            art = {**art, "sha256": sha256_bytes(compose), "size": len(compose)}
            blobs[name] = compose
        arts.append(art)
    return arts, blobs


def _seed_v2_controller_bundle_custom(
    fs: InMemoryFilesystem,
    bundle_dir: str,
    key_id: str,
    priv: str,
    *,
    source_sha: str,
    parent_sha: str | None,
    image_map: dict[str, str],
    compose: bytes,
    archive_tag: str,
    migration_identity: str | None = None,
) -> str:
    """Seed a v1alpha2 controller bundle with explicit lineage, component images, compose template
    and (optionally) a CHANGED signed migration identity, re-signing the manifest so it verifies
    under the same trust root. Returns the aggregate."""
    arts, blobs = _controller_artifacts(image_map, compose=compose, archive_tag=archive_tag)
    seed_signed_bundle(
        fs,
        bundle_dir,
        "controller",
        key_id,
        priv,
        arts,
        source_sha=source_sha,
        parent_sha=parent_sha,
    )
    for name, data in blobs.items():
        # seed_signed_bundle writes the SHARED fixture bytes; overwrite with this release's own so
        # every file matches the size + digest its manifest signs.
        fs.seed_file(f"{bundle_dir}/{name}", data, mode=0o644)
    d = manifest_dict("controller", arts, source_sha=source_sha, parent_sha=parent_sha)
    d["bootstrap_contract_version"] = V2
    d["signing_anchor_id"] = key_id
    if migration_identity is not None:
        d["migration_identity"] = migration_identity
    d.update(_valid_profile())
    manifest = ReleaseManifest.model_validate(d)
    sig = sign_ed25519(priv, manifest_signing_message(manifest))
    fs.seed_file(f"{bundle_dir}/release-manifest.json", manifest.canonical().encode(), mode=0o644)
    fs.seed_file(
        f"{bundle_dir}/release-manifest.sig.json",
        canonical_json({"algorithm": "ed25519", "key_id": key_id, "signature": sig}).encode(),
        mode=0o644,
    )
    return manifest_aggregate_digest(manifest)


def _seed_stack_dirs(fs: InMemoryFilesystem) -> None:
    """Seed the ancestors of the two fixed controller stack objects. The FILES themselves are never
    seeded: they are written by the install/upgrade/restore ops through the bound adapter, so the
    prior stack a managed upgrade captures is exactly what the prior install actually applied."""
    loc = ManagementLocations()
    for path in (loc.controller_compose_path(), loc.controller_unit_path()):
        current = ""
        for segment in path.split("/")[1:-1]:
            current += "/" + segment
            if fs.lstat(current) is None:
                fs.seed_dir(current, uid=0, gid=0, mode=0o755)


def _advance_world_to(world: object, image_map: dict[str, str]) -> None:
    """Advance the OBSERVED controller stack to ``image_map`` (running + healthy)."""
    world.controller_containers = dict(image_map)  # type: ignore[attr-defined]
    world.controller_running = {c: True for c in image_map}  # type: ignore[attr-defined]
    world.controller_healthy = {c: True for c in image_map}  # type: ignore[attr-defined]


def _bind_host_stack(
    deps: object,
    fs: InMemoryFilesystem,
    world: object,
    timeline: list[tuple[str, object]],
    images_by_config: dict[str, dict[str, str]],
) -> None:
    """Bind the shared fake bootstrap adapter to the in-memory host so the R2 stack transition is a
    genuine consequence of the transaction's own ops, never an out-of-band arrangement:

    * ``install_config`` / ``install_unit`` persist the EXACT reviewed bytes to their fixed paths —
      so ``_plan_controller_stack_upgrade`` captures the real prior stack and
      ``_restore_controller_stack`` can put the real prior stack back;
    * ``start_stack`` brings up exactly the component/image map the INSTALLED compose config
      selects, so the observed stack advances to the candidate ONLY when this transaction installed
      and started the candidate config (and returns to the prior map when the prior config is
      reinstalled and restarted);
    * every controller-adapter op and every controller observation is appended to the shared ordered
      timeline.
    """
    adapter = deps.controller_adapter  # type: ignore[attr-defined]
    observer = deps.observer  # type: ignore[attr-defined]
    loc = deps.locations  # type: ignore[attr-defined]
    o_load = adapter.load_image
    o_config = adapter.install_config
    o_unit = adapter.install_unit
    o_reload = adapter.daemon_reload
    o_migrations = adapter.run_migrations
    o_start = adapter.start_stack
    o_observe = observer.observe_controller

    def load_image(artifact: object) -> None:
        o_load(artifact)
        timeline.append(("load_image", (artifact.digest, artifact.image_digest)))  # type: ignore[attr-defined]

    def install_config(config: object) -> None:
        o_config(config)
        fs.atomic_install(
            loc.controller_compose_path(),
            config.content,  # type: ignore[attr-defined]
            uid=0,
            gid=0,
            mode=0o640,
        )
        timeline.append(("install_config", config.identity))  # type: ignore[attr-defined]

    def install_unit(unit: object) -> None:
        o_unit(unit)
        fs.atomic_install(
            loc.controller_unit_path(),
            unit.content,  # type: ignore[attr-defined]
            uid=0,
            gid=0,
            mode=0o640,
        )
        timeline.append(("install_unit", unit.identity))  # type: ignore[attr-defined]

    def daemon_reload() -> None:
        o_reload()
        timeline.append(("daemon_reload", None))

    def run_migrations(*, migration_identity: str) -> None:
        o_migrations(migration_identity=migration_identity)
        timeline.append(("run_migrations", migration_identity))

    def start_stack(*, expected_components: tuple[str, ...]) -> None:
        o_start(expected_components=expected_components)
        installed = world.controller_config_identity  # type: ignore[attr-defined]
        assert installed in images_by_config, installed  # only a KNOWN release's config can run
        _advance_world_to(world, images_by_config[installed])
        timeline.append(("start_stack", tuple(sorted(expected_components))))

    def observe_controller() -> object:
        obs = o_observe()
        timeline.append(("observe", _image_map(dict(obs.container_image_digests))))  # type: ignore[attr-defined]
        return obs

    adapter.load_image = load_image  # type: ignore[assignment]
    adapter.install_config = install_config  # type: ignore[assignment]
    adapter.install_unit = install_unit  # type: ignore[assignment]
    adapter.daemon_reload = daemon_reload  # type: ignore[assignment]
    adapter.run_migrations = run_migrations  # type: ignore[assignment]
    adapter.start_stack = start_stack  # type: ignore[assignment]
    observer.observe_controller = observe_controller  # type: ignore[assignment]


def _upgrade_setup(
    *,
    b_source_sha: str = SB,
    b_parent_sha: str | None = SA,
    b_images: dict[str, str] | None = None,
    runtime_fail_generations: frozenset[int] = frozenset(),
    runtime_observer_factory: object | None = None,
):  # noqa: ANN201
    """Build a shared world (release A + release B + release M bundles, one fs/world/deps) whose
    finalization factory produces upgrade-aware fakes bound to the module identity DB, and whose
    bootstrap adapter is bound to the in-memory host. Resets the DB per setup so each test threads
    generations from a clean prior state."""
    _IDENTITY_DB.reset()
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    _seed_v2_controller_bundle(fs, BD_A, kid, priv)  # A: default images/compose, source_sha "a"*40
    images = b_images or B_IMAGES
    _seed_v2_controller_bundle_custom(
        fs,
        BD_B,
        kid,
        priv,
        source_sha=b_source_sha,
        parent_sha=b_parent_sha,
        image_map=images,
        compose=B_COMPOSE,
        archive_tag="controller-B",
    )
    # M: an equally authenticated linear successor whose ONLY additional difference is a CHANGED
    # signed migration identity — the transition the managed upgrade refuses to perform.
    _seed_v2_controller_bundle_custom(
        fs,
        BD_M,
        kid,
        priv,
        source_sha=SM,
        parent_sha=SA,
        image_map=images,
        compose=B_COMPOSE,
        archive_tag="controller-B",
        migration_identity=M_MIGRATION_IDENTITY,
    )
    seed_write_ancestors(fs)
    _seed_etc_controller(fs)
    _seed_stack_dirs(fs)
    world = fresh_controller_world()
    deps = deps_for(fs, world, trust)
    loc = deps.locations
    timeline: list[tuple[str, object]] = []
    state: dict = {"calls": 0, "adapters": [], "timeline": timeline}

    def _factory(plan: object) -> _UpgradeFakeAdapter:
        state["calls"] += 1
        adapter = _UpgradeFakeAdapter(
            plan,
            fs,
            loc,
            _IDENTITY_DB,
            timeline,
            runtime_fail_generations=runtime_fail_generations,
            runtime_observer=(
                None if runtime_observer_factory is None else runtime_observer_factory(plan)
            ),
        )
        state["adapters"].append(adapter)
        return adapter

    # R1/R3: the pre-mutation inventory + live-state proofs are composed exactly as the driven
    # install composes them (a genuinely clean/complete host, every live proof holding), so this
    # file's subject stays the UPGRADE transaction rather than those independently-tested seams.
    inventory = _FakeInventory()
    live = _FakeLiveState()
    deps = dataclasses.replace(
        deps,
        finalization_factory=_factory,
        finalization_inventory=lambda: inventory,
        finalization_state_observer=lambda *, expected: live,
    )
    _bind_host_stack(
        deps,
        fs,
        world,
        timeline,
        {A_CONFIG_IDENTITY: A_IMAGES, B_CONFIG_IDENTITY: images},
    )
    return deps, fs, world, state


def _install_a(deps: object) -> dict:
    """Install release A fresh (generation 0) — the committed prior B2 state a managed upgrade
    builds on. Asserts it committed with an authenticated finalization at generation 0 and that the
    observable stack is A's."""
    code, rep = run(_install_argv(BD_A, write=True), deps)
    assert code == 0, rep
    assert rep["mode"] == "written"
    assert rep["classification"] == "fresh"
    assert rep["finalization_generation"] == 0
    return rep


def _bootstrap_a(deps: object) -> dict:
    """Install release A via plain ``bootstrap controller`` — a controller install with NO
    finalization extension and NO enablement marker (a non-B2 prior)."""
    code, rep = run(["bootstrap", "controller", "--bundle", BD_A, "--write", "--confirm"], deps)
    assert code == 0 and rep["mode"] == "written", rep
    return rep


def _prior_stack_facts(state: dict) -> dict:
    """The prior (release A) stack facts, taken from what A's install ACTUALLY applied: its compose
    config identity, the code-owned supervisor unit identity, its migration identity and the archive
    digests it loaded. The upgrade must restore exactly these."""
    timeline = state["timeline"]
    return {
        "config_identity": _values(timeline, "install_config")[-1],
        "unit_identity": _values(timeline, "install_unit")[-1],
        "migration_identity": _values(timeline, "run_migrations")[-1],
        "archives": {archive for archive, _digest in _values(timeline, "load_image")},  # type: ignore[misc]
    }


def _read_marker(fs: InMemoryFilesystem, loc: object) -> dict:
    raw = fs.safe_read(loc.api_signer_marker_path(), max_bytes=_MAX, expected_uid=0)  # type: ignore[attr-defined]
    return json.loads(raw)


def _read_identity(fs: InMemoryFilesystem, loc: object) -> dict:
    raw = fs.safe_read(loc.identity_path("controller"), max_bytes=_MAX, expected_uid=0)  # type: ignore[attr-defined]
    return json.loads(raw)


def _read_stack_objects(fs: InMemoryFilesystem, loc: object) -> tuple[bytes, bytes]:
    """The two fixed controller stack objects exactly as they are on disk."""
    compose = fs.safe_read(loc.controller_compose_path(), max_bytes=_MAX, expected_uid=0)  # type: ignore[attr-defined]
    unit = fs.safe_read(loc.controller_unit_path(), max_bytes=_MAX, expected_uid=0)  # type: ignore[attr-defined]
    return compose, unit


# =========================================================== 1. A→B managed upgrade at generation 1


def test_upgrade_A_to_B_success_generation_1():
    deps, fs, world, state = _upgrade_setup()
    loc = deps.locations
    rep_a = _install_a(deps)
    a_row = _IDENTITY_DB.active_row
    assert _IDENTITY_DB.generation_by_row[a_row] == 0
    prior = _prior_stack_facts(state)
    # A's install really did apply A's stack: A's signed compose config and A's image map
    assert prior["config_identity"] == A_CONFIG_IDENTITY
    assert world.controller_containers == A_IMAGES
    prior_compose, prior_unit = _read_stack_objects(fs, loc)

    mark = len(state["timeline"])
    calls_after_a = state["calls"]  # == 1 (only A's plan-bound adapter)

    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 0, rep
    assert rep["mode"] == "written"
    assert rep["classification"] == CLASSIFY_MANAGED_UPGRADE
    assert rep["planned_generation"] == 1
    assert rep["idempotent_replay"] is False
    assert rep["finalization_generation"] == 1
    assert rep["release_aggregate_digest"] != rep_a["release_aggregate_digest"]

    # R2 (1/2/3/4/9): the managed upgrade performed a REAL candidate stack upgrade INSIDE the
    # transaction, in the exact reviewed order, with the exact signed candidate identities, and NO
    # finalization op ran before the candidate component/image map was independently reobserved.
    segment = state["timeline"][mark:]
    _assert_candidate_stack_upgrade(
        segment,
        images=B_IMAGES,
        config_identity=B_CONFIG_IDENTITY,
        unit_identity=prior["unit_identity"],  # the supervisor unit is code-owned, release-fixed
        migration_identity=prior["migration_identity"],  # 4. UNCHANGED migration identity succeeds
    )
    assert B_CONFIG_IDENTITY != A_CONFIG_IDENTITY  # the candidate config really is a new one
    # 2/3: the durable + observable end state is exactly the candidate's
    assert world.controller_containers == B_IMAGES
    assert world.controller_config_identity == B_CONFIG_IDENTITY
    assert world.controller_unit_identity == prior["unit_identity"]
    compose_after, unit_after = _read_stack_objects(fs, loc)
    assert compose_after == B_COMPOSE and compose_after != prior_compose
    assert unit_after == prior_unit  # the code-owned unit content is reinstalled unchanged
    assert state["calls"] == calls_after_a + 1

    # the surface was ADOPTED and the identity re-activated against A's row at generation 1
    c_row = _IDENTITY_DB.active_row
    assert c_row != a_row
    assert _IDENTITY_DB.generation_by_row[c_row] == 1
    assert _IDENTITY_DB.receipts[c_row]["previous_active_row_id"] == a_row
    # both historical receipts present (A@0, C@1), append-only
    assert set(_IDENTITY_DB.receipts) == {a_row, c_row}

    ev = _read_evidence(fs, loc, "controller")
    assert ev["finalization"]["generation"] == 1
    assert ev["finalization"]["classification"] == CLASSIFY_MANAGED_UPGRADE
    assert ev["finalization"]["schema_version"] == FINALIZATION_SCHEMA_VERSION
    assert ev["finalization"]["active_identity_row_id"] == c_row
    dispositions = {e["effect"]: e["disposition"] for e in ev["finalization"]["effects"]}
    assert dispositions["identity_activation"] == EffectDisposition.MANAGED_REPLACED.value
    assert dispositions["marker"] == EffectDisposition.MANAGED_REPLACED.value
    assert dispositions["tls"] == EffectDisposition.EXACT_ADOPTED.value

    # the live enablement marker binds the NEW active identity C at the new release
    marker = _read_marker(fs, loc)
    assert marker["active_identity_row_id"] == c_row
    assert marker["release_digest"] == rep["release_aggregate_digest"]


# ============================== 1b. an externally-upgraded stack does NOT qualify as an upgrade


def test_upgrade_refuses_when_the_prior_stack_was_changed_out_of_band():
    # R2: the managed upgrade is the ONLY thing allowed to move the controller stack. If the host
    # is pre-advanced to B's images out of band (the old "finalization-only, stack upgraded out of
    # band" shape), the prior stack is no longer observably the authenticated prior one, so the
    # transaction refuses BEFORE any host effect instead of blessing a stack it did not apply.
    deps, fs, world, state = _upgrade_setup()
    loc = deps.locations
    _install_a(deps)
    a_row = _IDENTITY_DB.active_row
    marker_before = _read_marker(fs, loc)
    compose_before, unit_before = _read_stack_objects(fs, loc)
    _advance_world_to(world, B_IMAGES)  # someone upgraded the containers by hand
    mark = len(state["timeline"])

    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 2
    assert rep["reason_code"] == "controller_upgrade_prior_stack_not_operational"

    # nothing was applied: no candidate stack op ran, no finalization adapter was built for B, and
    # the installed stack objects / marker / identity generation are untouched.
    segment = state["timeline"][mark:]
    assert _stack_sequence(segment) == [], segment
    assert "finalization" not in _names(segment), segment
    assert state["calls"] == 1
    assert _read_stack_objects(fs, loc) == (compose_before, unit_before)
    assert _read_marker(fs, loc) == marker_before
    assert _IDENTITY_DB.active_row == a_row and set(_IDENTITY_DB.receipts) == {a_row}


# ================================== 2. post-activation failure → provable rollback to A′


def test_upgrade_fail_after_activation_reactivates_prior_and_proves_healthy():
    # fail the FORWARD (generation 1) runtime-health gate AFTER activation; the rollback
    # reactivation (generation 2) is NOT failed, so the engine fully proves the rolled-back state —
    # identity AND the prior controller stack.
    deps, fs, world, state = _upgrade_setup(runtime_fail_generations=frozenset({1}))
    loc = deps.locations
    rep_a = _install_a(deps)
    a_agg = rep_a["release_aggregate_digest"]
    a_row = _IDENTITY_DB.active_row
    prior = _prior_stack_facts(state)
    prior_compose, prior_unit = _read_stack_objects(fs, loc)
    mark = len(state["timeline"])

    code, rep = run(_install_argv(BD_B, write=True), deps)

    # a fully-proven rollback refuses with the ORIGINAL finalization reason, NOT recovery_required
    assert code == 2
    assert rep["reason_code"] == _RUNTIME_FAIL_REASON

    segment = state["timeline"][mark:]
    # the candidate stack WAS really applied first (order/identities/proof), then finalization ran
    _assert_candidate_stack_upgrade(
        segment,
        images=B_IMAGES,
        config_identity=B_CONFIG_IDENTITY,
        unit_identity=prior["unit_identity"],
        migration_identity=prior["migration_identity"],
    )
    # 6. PRIOR-STACK RESTORATION: after the candidate failed, the prior compose config + supervisor
    # unit were REINSTALLED, the daemon reloaded, the prior migration identity reapplied and the
    # prior stack RESTARTED — a second complete stack pass, in the same reviewed order.
    assert _stack_sequence(segment) == (["load_image"] * _N_IMAGES + _STACK_TAIL + _STACK_TAIL), (
        segment
    )
    assert _values(segment, "install_config") == [B_CONFIG_IDENTITY, prior["config_identity"]]
    assert _values(segment, "install_unit") == [prior["unit_identity"], prior["unit_identity"]]
    assert _values(segment, "run_migrations") == [
        prior["migration_identity"],
        prior["migration_identity"],
    ]
    # the prior stack is byte-restored on disk and the prior image map is observable again
    assert _read_stack_objects(fs, loc) == (prior_compose, prior_unit)
    assert world.controller_config_identity == prior["config_identity"]
    assert world.controller_unit_identity == prior["unit_identity"]
    assert world.controller_containers == A_IMAGES
    assert all(world.controller_running.values()) and all(world.controller_healthy.values())

    # 7. candidate_image_cache_residual TRUTHFULNESS: the candidate images this transaction loaded
    # are NOT deleted (exclusive ownership of a shared image layer is unprovable in-plane), so the
    # bounded residual the restore reports is a true statement about the host — while the prior
    # release's own archives remain loaded, so the restored stack is genuinely runnable.
    candidate_archives = {archive for archive, _digest in _values(segment, "load_image")}  # type: ignore[misc]
    assert candidate_archives.isdisjoint(prior["archives"])  # B ships its own archives
    assert candidate_archives <= world.loaded_images  # the residual really is still there
    assert prior["archives"] <= world.loaded_images

    # the shared DB now has a NEW active row P′ at generation 2 whose predecessor is the failed
    # candidate C — the prior identity's facts reactivated as an append (never an in-place rewrite)
    c_row = _IDENTITY_DB.log[1]["row"]
    p_row = _IDENTITY_DB.active_row
    assert p_row not in (a_row, c_row)
    assert _IDENTITY_DB.generation_by_row[p_row] == 2
    assert _IDENTITY_DB.receipts[p_row]["previous_active_row_id"] == c_row
    # every historical receipt still present (append-only: A@0, C@1, P′@2)
    assert set(_IDENTITY_DB.receipts) == {a_row, c_row, p_row}
    assert _IDENTITY_DB.generation_by_row[a_row] == 0
    assert _IDENTITY_DB.generation_by_row[c_row] == 1

    # the on-disk record is A's (byte-restored); the re-authored evidence binds A's facts + the NEW
    # rolled-back row P′ at generation 2; the live marker binds P′
    ev = _read_evidence(fs, loc, "controller")
    assert ev["release_aggregate_digest"] == a_agg
    assert ev["finalization"]["generation"] == 2
    assert ev["finalization"]["active_identity_row_id"] == p_row
    assert _read_identity(fs, loc)["release_digest"] == a_agg
    assert _read_marker(fs, loc)["active_identity_row_id"] == p_row


# ================================================= 3. unprovable rollback reactivation → recovery


def test_upgrade_rollback_unprovable_is_recovery_required():
    # fail BOTH the forward (gen 1) AND the rollback reactivation (gen 2) runtime gates: the engine
    # cannot prove the rolled-back state healthy → the transaction refuses recovery_required. The
    # controller STACK is still restored + proven (an unprovable identity must not strand a
    # half-upgraded stack as well).
    deps, fs, world, state = _upgrade_setup(runtime_fail_generations=frozenset({1, 2}))
    loc = deps.locations
    _install_a(deps)
    prior = _prior_stack_facts(state)
    prior_compose, prior_unit = _read_stack_objects(fs, loc)
    mark = len(state["timeline"])

    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 2
    assert rep["reason_code"] == "recovery_required"

    segment = state["timeline"][mark:]
    assert _values(segment, "install_config") == [B_CONFIG_IDENTITY, prior["config_identity"]]
    assert _read_stack_objects(fs, loc) == (prior_compose, prior_unit)
    assert world.controller_containers == A_IMAGES


# =============================== 3b. a CHANGED migration identity is an unsupported transition


def test_upgrade_changed_migration_identity_refuses_before_any_host_effect():
    # R2 MIGRATION-TRANSITION LIMIT: release M is an equally authenticated linear successor of A
    # with the same compose/images as B, differing ONLY in its SIGNED migration_identity. Applying
    # it would advance the schema past the point where A's binaries still run, so "restore the prior
    # stack" could no longer be honoured — the transaction refuses rather than run an irreversible
    # transition while claiming rollback.
    deps, fs, world, state = _upgrade_setup()
    loc = deps.locations
    _install_a(deps)
    a_row = _IDENTITY_DB.active_row
    prior = _prior_stack_facts(state)
    assert prior["migration_identity"] != M_MIGRATION_IDENTITY
    marker_before = _read_marker(fs, loc)
    ev_before = _read_evidence(fs, loc, "controller")
    compose_before, unit_before = _read_stack_objects(fs, loc)
    mark = len(state["timeline"])

    # a dry run reports the managed upgrade (classification is unaffected: M IS a linear successor)
    dry_code, dry = run(_install_argv(BD_M, write=False), deps)
    assert dry_code == 0 and dry["classification"] == CLASSIFY_MANAGED_UPGRADE

    code, rep = run(_install_argv(BD_M, write=True), deps)
    assert code == 2
    assert rep["reason_code"] == "controller_upgrade_migration_transition_unsupported"

    # refused BEFORE any host effect: no image loaded, no config/unit installed, no migration run,
    # no stack restarted, no finalization adapter built for M, nothing on disk changed.
    segment = state["timeline"][mark:]
    assert _stack_sequence(segment) == [], segment
    assert "finalization" not in _names(segment), segment
    assert state["calls"] == 1
    assert _read_stack_objects(fs, loc) == (compose_before, unit_before)
    assert world.controller_containers == A_IMAGES
    assert world.controller_config_identity == prior["config_identity"]
    assert _read_marker(fs, loc) == marker_before
    assert _read_evidence(fs, loc, "controller") == ev_before
    assert _IDENTITY_DB.active_row == a_row and set(_IDENTITY_DB.receipts) == {a_row}


# ============================= 4. stale / skipped / downgrade generation → CAS refuses drive


@pytest.mark.parametrize("db_generation", [1, 2, 7])
def test_upgrade_stale_or_skipped_or_downgrade_generation_refuses(db_generation):
    # the engine derives the forward generation (1) from A's authenticated finalization evidence;
    # the durable per-row generation CAS is the independent anti-downgrade/anti-skip backstop: make
    # the DB's recorded generation for A's row disagree so the forward activation refuses.
    deps, fs, world, state = _upgrade_setup()
    loc = deps.locations
    rep_a = _install_a(deps)
    a_agg = rep_a["release_aggregate_digest"]
    a_row = _IDENTITY_DB.active_row
    prior = _prior_stack_facts(state)
    prior_compose, prior_unit = _read_stack_objects(fs, loc)
    _IDENTITY_DB.generation_by_row[a_row] = db_generation  # DB moved ahead of the on-disk evidence
    mark = len(state["timeline"])

    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 2
    assert rep["reason_code"] == "activation_generation_out_of_order"

    # the prior generation stays active; NO candidate row was minted; A's documents are restored
    assert _IDENTITY_DB.active_row == a_row
    assert set(_IDENTITY_DB.receipts) == {a_row}  # no C created
    assert _read_evidence(fs, loc, "controller")["release_aggregate_digest"] == a_agg
    assert _read_marker(fs, loc)["active_identity_row_id"] == a_row

    # 6: the candidate stack this transaction DID apply before the CAS refusal is restored — the
    # candidate pass ran in full, then the prior compose config + supervisor unit were reinstalled,
    # the prior migration identity reapplied and the prior stack restarted.
    segment = state["timeline"][mark:]
    assert _stack_sequence(segment) == ["load_image"] * _N_IMAGES + _STACK_TAIL + _STACK_TAIL
    assert _values(segment, "install_config") == [B_CONFIG_IDENTITY, prior["config_identity"]]
    assert _values(segment, "install_unit") == [prior["unit_identity"], prior["unit_identity"]]
    assert _values(segment, "run_migrations") == [
        prior["migration_identity"],
        prior["migration_identity"],
    ]
    assert _read_stack_objects(fs, loc) == (prior_compose, prior_unit)  # byte-restored on disk


def test_prior_stack_survives_a_pre_activation_upgrade_refusal():
    # REGRESSION (2b-3c-c): a managed upgrade that refuses BEFORE the identity activation must leave
    # the prior stack running. _restore_controller_stack owns that participant, so the bootstrap
    # adapter's fresh-install TEARDOWN compensation (compose down + remove unit/config/images) must
    # NOT also run -- otherwise the just-restored prior stack is stopped and its fixed objects
    # deleted while the transaction reports a bounded refusal. The claim: after a refusal that
    # restored the prior stack, the prior stack must still be
    # the observable, running, prior-image controller stack.
    deps, fs, world, state = _upgrade_setup()
    _install_a(deps)
    prior = _prior_stack_facts(state)
    prior_archives = prior["archives"]
    _IDENTITY_DB.generation_by_row[_IDENTITY_DB.active_row] = 7

    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 2 and rep["reason_code"] == "activation_generation_out_of_order"

    assert world.controller_containers == A_IMAGES
    assert world.controller_config_identity == prior["config_identity"]
    assert all(world.controller_running.values()) and all(world.controller_healthy.values())
    assert prior_archives <= world.loaded_images


# ============================================================= 5. non-linear successor refuses


def test_upgrade_non_linear_successor_refuses():
    # B whose parent_sha does NOT descend from A's source_sha is a changed release but NOT an
    # authenticated linear successor → refuse in classification (dry-run AND write), no mutation.
    deps, fs, world, state = _upgrade_setup(b_parent_sha="e" * 40)
    loc = deps.locations
    _install_a(deps)
    a_row = _IDENTITY_DB.active_row
    marker_before = _read_marker(fs, loc)
    ev_before = _read_evidence(fs, loc, "controller")
    stack_before = _read_stack_objects(fs, loc)
    calls_before = state["calls"]
    mark = len(state["timeline"])

    dry_code, dry = run(_install_argv(BD_B, write=False), deps)
    assert dry_code == 2 and dry["reason_code"] == "controller_upgrade_not_linear_successor"

    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 2 and rep["reason_code"] == "controller_upgrade_not_linear_successor"

    # nothing mutated: stack/marker/docs/DB untouched, no finalization adapter built for B
    assert _stack_sequence(state["timeline"][mark:]) == []
    assert _read_stack_objects(fs, loc) == stack_before
    assert world.controller_containers == A_IMAGES
    assert _read_marker(fs, loc) == marker_before
    assert _read_evidence(fs, loc, "controller") == ev_before
    assert _IDENTITY_DB.active_row == a_row and set(_IDENTITY_DB.receipts) == {a_row}
    assert state["calls"] == calls_before


# ============================================================= 6. prior is not a B2 install


def test_upgrade_prior_not_b2_refuses():
    # A installed via plain `bootstrap controller` (no finalization extension) is not eligible for a
    # B2 managed upgrade → refuse before any B mutation.
    deps, fs, world, state = _upgrade_setup()
    loc = deps.locations
    _bootstrap_a(deps)
    ev = _read_evidence(fs, loc, "controller")
    assert "finalization" not in ev  # bootstrap wrote no finalization extension
    assert fs.lstat(loc.api_signer_marker_path()) is None  # and no enablement marker
    mark = len(state["timeline"])

    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 2 and rep["reason_code"] == "controller_upgrade_prior_not_finalized"
    assert state["calls"] == 0  # bootstrap never touched finalization; B refused before the drive
    assert _stack_sequence(state["timeline"][mark:]) == []  # and before any candidate stack op
    assert world.controller_containers == A_IMAGES


# ==================================== 7. prior unauthenticated / drifted refuses pre-mutation


@pytest.mark.parametrize(
    "tamper,reason",
    [
        ("attestation", "controller_upgrade_prior_unauthenticated"),
        ("identity_mode", "controller_upgrade_prior_drifted"),
    ],
)
def test_upgrade_prior_unauthenticated_or_drifted_refuses(tamper, reason):
    deps, fs, world, state = _upgrade_setup()
    loc = deps.locations
    _install_a(deps)
    a_row = _IDENTITY_DB.active_row
    marker_before = _read_marker(fs, loc)
    stack_before = _read_stack_objects(fs, loc)
    mark = len(state["timeline"])

    if tamper == "attestation":
        # corrupt the detached attestation → its signature no longer parses/verifies (unauth)
        fs.seed_file(
            loc.evidence_attestation_path("controller"), b"not-json", uid=0, gid=0, mode=0o640
        )
    else:
        # re-seed A's identity byte-identical but at a DIFFERENT mode: authentication still passes
        # (content + attestation unchanged), but the installed-document integrity check finds drift
        raw = fs.safe_read(loc.identity_path("controller"), max_bytes=_MAX, expected_uid=0)
        fs.seed_file(loc.identity_path("controller"), raw, uid=0, gid=0, mode=0o600)

    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 2 and rep["reason_code"] == reason
    # refused BEFORE any B mutation: no candidate stack op, no finalization adapter built; prior
    # identity active + bound; the prior stack objects untouched
    assert state["calls"] == 1
    assert _stack_sequence(state["timeline"][mark:]) == []
    assert _read_stack_objects(fs, loc) == stack_before
    assert world.controller_containers == A_IMAGES
    assert _IDENTITY_DB.active_row == a_row and set(_IDENTITY_DB.receipts) == {a_row}
    assert _read_marker(fs, loc) == marker_before


# ========================================================= 8. dry-run reports a managed upgrade


def test_upgrade_dry_run_reports_managed_upgrade():
    deps, fs, world, state = _upgrade_setup()
    loc = deps.locations
    _install_a(deps)
    calls_before = state["calls"]  # == 1 (A's install)
    marker_before = _read_marker(fs, loc)
    ev_before = _read_evidence(fs, loc, "controller")
    stack_before = _read_stack_objects(fs, loc)
    mark = len(state["timeline"])

    code, rep = run(_install_argv(BD_B, write=False), deps)
    assert code == 0
    assert rep["mode"] == "dry_run"
    assert rep["classification"] == CLASSIFY_MANAGED_UPGRADE
    assert rep["planned_generation"] == 1

    # zero NEW factory calls, and no stack/doc/marker mutation on a dry run
    assert state["calls"] == calls_before
    assert _stack_sequence(state["timeline"][mark:]) == []
    assert _read_stack_objects(fs, loc) == stack_before
    assert world.controller_containers == A_IMAGES
    assert _read_marker(fs, loc) == marker_before
    assert _read_evidence(fs, loc, "controller") == ev_before


# ============================================= 9. marker absent / marker binding drift refuses


def test_upgrade_marker_absent_refuses():
    # re-installing the SAME release with the enablement marker removed refuses on the exact-same-
    # release replay path (a clean bootstrap host must also carry the managed finalization marker).
    deps, fs, world, state = _upgrade_setup()
    loc = deps.locations
    _install_a(deps)
    fs.remove_file(loc.api_signer_marker_path())

    code, rep = run(_install_argv(BD_A, write=True), deps)
    assert code == 2 and rep["reason_code"] == "controller_install_marker_absent"


def test_upgrade_marker_binding_drift_refuses():
    # drift a bound field of the prior enablement marker, then attempt the B upgrade: the marker no
    # longer binds the authenticated finalization identity → refuse before any B mutation.
    # (`controller_install_binding_drift` — the sibling EVIDENCE-binding check — is a defensive
    # invariant that cannot be reached by a black-box tamper: any change to the finalization binding
    # also breaks the evidence attestation, which is caught first as `..._prior_unauthenticated`.)
    #
    # R7: the drifted marker is re-rendered through the ONE strict renderer, so the bytes stay
    # canonically CONFORMANT (the strict parser accepts them) and the refusal is genuinely the
    # engine's binding check rather than a parse failure.
    deps, fs, world, state = _upgrade_setup()
    loc = deps.locations
    _install_a(deps)
    a_row = _IDENTITY_DB.active_row
    stack_before = _read_stack_objects(fs, loc)
    marker = _read_marker(fs, loc)
    drifted = {k: v for k, v in marker.items() if k not in ("schema", "recorded_at")}
    drifted["bootstrap_evidence_digest"] = "sha256:" + "0" * 64
    fs.seed_file(
        loc.api_signer_marker_path(),
        render_marker_bytes(recorded_at=str(marker["recorded_at"]), **drifted),
        uid=0,
        gid=0,
        mode=0o640,
    )
    mark = len(state["timeline"])

    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 2 and rep["reason_code"] == "controller_marker_identity_drift"
    assert _IDENTITY_DB.active_row == a_row and set(_IDENTITY_DB.receipts) == {a_row}
    assert state["calls"] == 1  # no B drive
    assert _stack_sequence(state["timeline"][mark:]) == []  # and no candidate stack op
    assert _read_stack_objects(fs, loc) == stack_before
    assert world.controller_containers == A_IMAGES


# ============================================= 10. historical activation receipts are immutable


def test_historical_receipts_immutable_after_upgrade_and_rollback():
    # after a SUCCESSFUL upgrade: A's receipt is byte-identical (no UPDATE/DELETE); C is appended.
    deps, fs, world, state = _upgrade_setup()
    _install_a(deps)
    a_row = _IDENTITY_DB.active_row
    a_receipt = copy.deepcopy(_IDENTITY_DB.receipts[a_row])

    assert run(_install_argv(BD_B, write=True), deps)[0] == 0
    c_row = _IDENTITY_DB.active_row
    assert _IDENTITY_DB.receipts[a_row] == a_receipt  # A untouched
    assert c_row in _IDENTITY_DB.receipts and c_row != a_row
    _assert_receipts_are_append_only(_IDENTITY_DB)

    # after a ROLLBACK: A and C receipts are still byte-identical; P′ is appended (never a rewrite).
    deps, fs, world, state = _upgrade_setup(runtime_fail_generations=frozenset({1}))
    _install_a(deps)
    a_row = _IDENTITY_DB.active_row
    a_receipt = copy.deepcopy(_IDENTITY_DB.receipts[a_row])
    assert run(_install_argv(BD_B, write=True), deps)[0] == 2  # post-activation failure → rollback

    c_row, p_row = _IDENTITY_DB.log[1]["row"], _IDENTITY_DB.log[2]["row"]
    c_receipt = copy.deepcopy(_IDENTITY_DB.receipts[c_row])
    assert _IDENTITY_DB.receipts[a_row] == a_receipt
    assert _IDENTITY_DB.receipts[c_row] == c_receipt == _IDENTITY_DB.log[1]
    assert set(_IDENTITY_DB.receipts) == {a_row, c_row, p_row}
    _assert_receipts_are_append_only(_IDENTITY_DB)


# ================= 11. R4: each generation's observation is bound to ITS OWN signed api image


def test_each_generations_plan_binds_that_releases_signed_api_image():
    # the expectation the observation is bound to comes from the SIGNED controller/api mapping of
    # the release being installed -- A's for generation 0, B's for generation 1 -- never from a
    # Docker observation, and never carried over from the prior generation.
    deps, fs, world, state = _upgrade_setup()
    _install_a(deps)
    assert run(_install_argv(BD_B, write=True), deps)[0] == 0

    plan_a, plan_b = state["adapters"][0].plan, state["adapters"][1].plan
    assert A_IMAGES["api"] != B_IMAGES["api"]
    assert plan_a.expected_api_image_digest == A_IMAGES["api"]
    assert plan_b.expected_api_image_digest == B_IMAGES["api"]
    assert (plan_a.generation, plan_b.generation) == (0, 1)
    # the controller-stack generation is the authenticated generation of the stack this transaction
    # applied AND proved before finalization began
    assert plan_a.controller_stack_generation == 0
    assert plan_b.controller_stack_generation == 1


def test_upgrade_proves_the_successor_image_only_after_the_candidate_stack_switch(monkeypatch):
    # F: with the REAL plan-bound production observer wired in and the live API image taken from the
    # stack the transaction itself switches, A is proven at generation 0 on A's image and B is
    # proven at generation 1 on B's image.
    holder: dict = {}
    live = LiveApiWorld(image=lambda: holder["world"].controller_containers["api"]).install(
        monkeypatch
    )
    deps, fs, world, state = _upgrade_setup(runtime_observer_factory=_live_observer_factory(live))
    holder["world"] = world

    _install_a(deps)
    assert live.current_image() == A_IMAGES["api"]
    assert state["adapters"][0].runtime_observation.ok is True
    assert live.seeded[-1][1] == 0  # observed at the finalization generation the plan carries

    code, rep = run(_install_argv(BD_B, write=True), deps)

    assert code == 0, rep
    assert rep["finalization_generation"] == 1
    candidate = state["adapters"][1]
    assert candidate.plan.expected_api_image_digest == B_IMAGES["api"]
    assert candidate.events[:2] == ["marker_write", "runtime_ok"]
    assert candidate.runtime_observation.ok is True
    assert candidate.runtime_observation.no_mixed_generation is True
    assert live.seeded[-1][1] == 1
    # the observation was taken against the image the transaction's OWN candidate stack switch put
    # in place -- the successor's, never the prior release's.
    assert world.controller_containers["api"] == B_IMAGES["api"]
    assert live.current_image() == B_IMAGES["api"]


def test_upgrade_refuses_when_the_api_is_still_on_the_prior_release_image(monkeypatch):
    # F: the successor's marker + identity are in place but the live API never left A's image. The
    # forward observation refuses (bounded R4 reason, marker reverted FIRST), and the engine's
    # rollback re-drive is bound to the PRIOR release's expectations -- it must never retain B's.
    recorder = RecordingExpectations()
    monkeypatch.setattr(obs_mod, "ApiSignerRuntimeExpectations", recorder)
    live = LiveApiWorld(image=A_IMAGES["api"]).install(monkeypatch)
    deps, fs, world, state = _upgrade_setup(runtime_observer_factory=_live_observer_factory(live))
    loc = deps.locations
    rep_a = _install_a(deps)
    a_row = _IDENTITY_DB.active_row

    code, rep = run(_install_argv(BD_B, write=True), deps)

    assert code == 2
    # the bounded R4 reason, never a blanket recovery_required
    assert rep["reason_code"] == _RUNTIME_FAIL_REASON

    # -- the FORWARD drive: the candidate expected B's signed image and the live API disagreed --
    forward = state["adapters"][1]
    assert forward.plan.expected_api_image_digest == B_IMAGES["api"]
    assert forward.runtime_observation.ok is False
    assert forward.runtime_observation.no_mixed_generation is False
    # only the image/generation agreement broke; the marker + broker halves still held
    assert forward.runtime_observation.binding_equals_marker is True
    assert forward.runtime_observation.effective_signer_is_fixed_uds is True
    assert forward.runtime_observation.broker_reachable is True
    # marker FIRST: the prior working generation's marker is restored before anything else
    assert forward.events[:3] == ["marker_write", "runtime_refused", "marker_restore"]

    # -- the ROLLBACK re-drive: bound to A, never to B --
    rollback = state["adapters"][2]
    assert rollback.plan.expected_api_image_digest == A_IMAGES["api"]
    assert rollback.plan.expected_api_image_digest != B_IMAGES["api"]
    assert rollback.plan.generation == 2
    assert rollback.plan.controller_stack_generation == 2
    assert rollback.runtime_observation.ok is True  # A's image IS what is live -> provable
    # the LAST expectation the observer composition built is the rollback's: A's signed image at
    # generation 2. B's expectations are not retained anywhere.
    last = recorder.built[-1]
    assert last["api_image_digest"] == A_IMAGES["api"]
    assert last["finalization_generation"] == 2
    assert last["controller_stack_generation"] == 2
    assert last["release_digest"] == rep_a["release_aggregate_digest"]

    # -- the rolled-back end state: A's release, a NEW row at generation 2, the prior stack back --
    p_row = _IDENTITY_DB.active_row
    assert p_row not in (a_row, _IDENTITY_DB.log[1]["row"])
    assert _IDENTITY_DB.generation_by_row[p_row] == 2
    ev = _read_evidence(fs, loc, "controller")
    assert ev["release_aggregate_digest"] == rep_a["release_aggregate_digest"]
    assert ev["finalization"]["generation"] == 2
    assert ev["finalization"]["active_identity_row_id"] == p_row
    assert _read_marker(fs, loc)["active_identity_row_id"] == p_row
    assert world.controller_containers == A_IMAGES


def _assert_receipts_are_append_only(db: _IdentityDb) -> None:
    """The receipts map is EXACTLY the append-only log — one entry per activation, keyed by a
    distinct row, and every stored receipt equals its original log entry (no UPDATE, no DELETE)."""
    rows = [entry["row"] for entry in db.log]
    assert len(rows) == len(set(rows))  # every activation minted a distinct row
    assert set(db.receipts) == set(rows)  # nothing deleted
    for entry in db.log:
        assert db.receipts[entry["row"]] == entry  # nothing updated in place


def test_rollback_restores_the_prior_stack_before_it_reactivates_the_prior_generation():
    """REGRESSION (2b-3c-c): the rollback reactivation re-drives finalization for the PRIOR release,
    and its authoritative R4 observation requires the running API to be on the PRIOR release's
    SIGNED image. If the candidate stack were still running at that moment the proof could never
    hold, so every post-activation upgrade failure would escalate to recovery_required instead of
    completing the provable restoration. The prior stack MUST therefore be restored FIRST.

    Proven on the transaction's own ordered timeline: the prior-stack restore pass must complete
    BEFORE the rollback adapter's finalization ops begin.
    """
    deps, fs, world, state = _upgrade_setup(runtime_fail_generations=frozenset({1}))
    _install_a(deps)
    mark = len(state["timeline"])

    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 2 and rep["reason_code"] == _RUNTIME_FAIL_REASON

    names = _names(state["timeline"][mark:])
    # two stack passes: the candidate switch, then the PRIOR-stack restore
    assert names.count("start_stack") >= 2, names
    restore_start = len(names) - 1 - names[::-1].index("start_stack")
    last_finalization = len(names) - 1 - names[::-1].index("finalization")
    # the rollback reactivation's finalization ops run AFTER the prior stack is back, so its R4
    # observation can genuinely see the PRIOR release's signed image.
    assert restore_start < last_finalization, names
    assert "finalization" in names[restore_start:], names

    # and the prior stack is observably back on its own signed images + compose bytes
    assert world.controller_containers == A_IMAGES, world.controller_containers
