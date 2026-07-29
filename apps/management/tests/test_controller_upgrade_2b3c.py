"""Managed controller UPGRADE (generation N+1) + rollback-to-prior-generation (SECP-PR5H-B2).

Hermetic end-to-end proofs for the NEW managed-upgrade write path in ``controller_install``:

* install release A (fresh, generation 0) to create the committed prior B2 state (marker +
  A-evidence with finalization generation 0), then install release B — an authenticated LINEAR
  SUCCESSOR of A (``B.parent_sha == A.source_sha``) with a different aggregate — as a MANAGED
  UPGRADE at generation 1: the surface is adopted, the identity is re-activated against A's row, and
  the host stack ops are NOT re-run (a managed upgrade is finalization-only; stack upgraded oob);
* a post-activation failure drives the engine-owned ``_upgrade_rollback``: reactivate the prior
  identity's facts as a NEW row at generation N+2 (predecessor = the failed candidate), prove the
  rolled-back state healthy, and refuse with the ORIGINAL reason — or ``recovery_required`` when the
  reactivation cannot be proven;
* every other changed-release state (non-linear successor, prior-not-B2, prior unauthenticated/
  drifted, missing/drifted marker, stale/skipped/downgrade generation) refuses BEFORE any B change.

No source file is edited. The finalization + identity-activation effects are simulated by an
in-memory hardened filesystem plus a closed fake finalization adapter (an extension of the 2b-3c-a
fake) that shares a MODULE-LEVEL append-only identity DB mirroring the real API activation
one-shot's predecessor CAS + per-row generation rules, so the engine's generation threading across
the forward drive and the rollback reactivation is genuinely exercised. Only leaf effects are faked.
"""

from __future__ import annotations

import copy
import dataclasses
import json

import pytest
from _mgmt_support import (
    default_artifacts,
    deps_for,
    ephemeral_trust_root,
    fresh_controller_world,
    manifest_dict,
    seed_signed_bundle,
    seed_write_ancestors,
)
from secp_commissioning.canonical import canonical_json, sha256_bytes
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import BOOTSTRAP_CONTRACT_VERSION_V1ALPHA2 as V2
from secp_management import ManagementError
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
    _install_argv,
    _read_evidence,
    _seed_etc_controller,
    _seed_v2_controller_bundle,
    _valid_profile,
)

_MAX = 256 * 1024

# A's lineage: `_seed_v2_controller_bundle` seeds the default fixture, whose source_sha is "a" * 40.
# B is seeded as a LINEAR SUCCESSOR of A (B.parent_sha == A.source_sha) with a distinct source_sha
# and DIFFERENT component images so the aggregate differs (→ base classifier returns
# preexisting_changed_release, the ONLY gate into the managed-upgrade path).
SA = "a" * 40
SB = "d" * 40
BD_A = "/var/lib/secp/bootstrap/release/controller"
BD_B = "/var/lib/secp/bootstrap/release/controller-b"
B_IMAGES = {
    c: sha256_bytes(f"image:controller-B/{c}".encode()) for c in EXPECTED_CONTROLLER_COMPONENTS
}

_RUNTIME_FAIL_REASON = "finalization_post_marker_runtime_unverified"


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
      adopted objects in place — only when this drive actually activated."""

    def __init__(
        self,
        plan: object,
        fs: InMemoryFilesystem,
        loc: object,
        db: _IdentityDb,
        *,
        runtime_fail_generations: frozenset[int] = frozenset(),
    ) -> None:
        super().__init__(plan, fs, loc)
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


def _controller_artifacts_with_images(image_map: dict[str, str]) -> list[dict]:
    """The default controller artifacts with each image_archive's signed image_digest overridden, so
    release B differs from A in its aggregate while keeping the same components + compose/unit."""
    arts: list[dict] = []
    for art in default_artifacts("controller"):
        if art["kind"] == "image_archive":
            component = str(art["purpose"]).split("/", 1)[1]
            art = {**art, "image_digest": image_map[component]}
        arts.append(art)
    return arts


def _seed_v2_controller_bundle_custom(
    fs: InMemoryFilesystem,
    bundle_dir: str,
    key_id: str,
    priv: str,
    *,
    source_sha: str,
    parent_sha: str | None,
    image_map: dict[str, str],
) -> str:
    """Seed a v1alpha2 controller bundle with explicit lineage + component images (for release B),
    re-signing the manifest so it verifies under the same trust root. Returns the aggregate."""
    arts = _controller_artifacts_with_images(image_map)
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
    d = manifest_dict("controller", arts, source_sha=source_sha, parent_sha=parent_sha)
    d["bootstrap_contract_version"] = V2
    d["signing_anchor_id"] = key_id
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


def _upgrade_setup(
    *,
    b_source_sha: str = SB,
    b_parent_sha: str | None = SA,
    b_images: dict[str, str] | None = None,
    runtime_fail_generations: frozenset[int] = frozenset(),
    seed_b: bool = True,
):  # noqa: ANN201
    """Build a shared world (release A + release B bundles, one fs/world/deps) whose finalization
    factory produces upgrade-aware fakes bound to the module identity DB. Resets the DB per setup so
    each test threads generations from a clean prior state."""
    _IDENTITY_DB.reset()
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    _seed_v2_controller_bundle(fs, BD_A, kid, priv)  # A: default images, source_sha "a"*40
    if seed_b:
        _seed_v2_controller_bundle_custom(
            fs,
            BD_B,
            kid,
            priv,
            source_sha=b_source_sha,
            parent_sha=b_parent_sha,
            image_map=b_images or B_IMAGES,
        )
    seed_write_ancestors(fs)
    _seed_etc_controller(fs)
    # R2: the real controller install writes the compose config + supervisor unit to their fixed
    # paths; the shared fake bootstrap adapter records ops without touching the fs, so seed them
    # here — the managed upgrade must be able to CAPTURE the prior stack in order to restore it.
    _loc0 = ManagementLocations()
    for _p, _b in (
        (_loc0.controller_compose_path(), b"# prior controller compose (release A)"),
        (_loc0.controller_unit_path(), b"[Unit] prior controller (release A)"),
    ):
        _cur = ""
        for _seg in _p.split("/")[1:-1]:
            _cur += "/" + _seg
            if fs.lstat(_cur) is None:
                fs.seed_dir(_cur, uid=0, gid=0, mode=0o755)
        fs.seed_file(_p, _b, uid=0, gid=0, mode=0o640)
    world = fresh_controller_world()
    deps = deps_for(fs, world, trust)
    loc = deps.locations
    state: dict = {"calls": 0, "adapters": []}

    def _factory(plan: object) -> _UpgradeFakeAdapter:
        state["calls"] += 1
        adapter = _UpgradeFakeAdapter(
            plan, fs, loc, _IDENTITY_DB, runtime_fail_generations=runtime_fail_generations
        )
        state["adapters"].append(adapter)
        return adapter

    deps = dataclasses.replace(deps, finalization_factory=_factory)
    return deps, fs, world, state


def _advance_world_to(world: object, image_map: dict[str, str]) -> None:
    """Advance the OBSERVED controller stack to ``image_map``. Under R2 the managed upgrade performs
    the stack transition ITSELF, so this is armed as a side effect of the bootstrap adapter's
    ``start_stack`` (see :func:`_arm_stack_transition`) rather than applied out of band."""
    world.controller_containers = dict(image_map)  # type: ignore[attr-defined]
    world.controller_running = {c: True for c in image_map}  # type: ignore[attr-defined]
    world.controller_healthy = {c: True for c in image_map}  # type: ignore[attr-defined]


def _arm_stack_transition(deps: object, world: object, image_map: dict[str, str]) -> None:
    """R2: the candidate stack becomes observable ONLY when the transaction itself starts it. Wrap
    the fake bootstrap adapter's reviewed ``start_stack`` op so the observed component/image map
    advances exactly then — and so a ROLLBACK that reinstalls + restarts the PRIOR config/unit
    likewise returns the observed stack to the prior images."""
    adapter = deps.controller_adapter  # type: ignore[attr-defined]
    original = adapter.start_stack
    prior = dict(world.controller_containers)  # type: ignore[attr-defined]

    def _start_stack(*, expected_components: tuple[str, ...]) -> None:
        original(expected_components=expected_components)
        target = image_map if set(expected_components) == set(image_map) else prior
        _advance_world_to(world, target)

    adapter.start_stack = _start_stack  # type: ignore[assignment]


def _install_a(deps: object) -> dict:
    """Install release A fresh (generation 0) — the committed prior B2 state a managed upgrade
    builds on. Asserts it committed with an authenticated finalization at generation 0."""
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


def _read_marker(fs: InMemoryFilesystem, loc: object) -> dict:
    raw = fs.safe_read(loc.api_signer_marker_path(), max_bytes=_MAX, expected_uid=0)  # type: ignore[attr-defined]
    return json.loads(raw)


def _read_identity(fs: InMemoryFilesystem, loc: object) -> dict:
    raw = fs.safe_read(loc.identity_path("controller"), max_bytes=_MAX, expected_uid=0)  # type: ignore[attr-defined]
    return json.loads(raw)


# =========================================================== 1. A→B managed upgrade at generation 1


def test_upgrade_A_to_B_success_generation_1():
    deps, fs, world, state = _upgrade_setup()
    loc = deps.locations
    rep_a = _install_a(deps)
    a_row = _IDENTITY_DB.active_row
    assert _IDENTITY_DB.generation_by_row[a_row] == 0

    _arm_stack_transition(deps, world, B_IMAGES)
    ops_after_a = list(world.ops)  # the FakeControllerAdapter's recorded host ops (from A install)
    calls_after_a = state["calls"]  # == 1 (only A's plan-bound adapter)

    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 0, rep
    assert rep["mode"] == "written"
    assert rep["classification"] == CLASSIFY_MANAGED_UPGRADE
    assert rep["planned_generation"] == 1
    assert rep["idempotent_replay"] is False
    assert rep["finalization_generation"] == 1
    assert rep["release_aggregate_digest"] != rep_a["release_aggregate_digest"]

    # R2: the managed upgrade performs a REAL candidate stack upgrade INSIDE the transaction — the
    # bootstrap controller adapter's ops MUST advance (candidate images loaded, candidate compose
    # config + supervisor unit installed, daemon-reload, migration transition, candidate stack
    # started). An externally upgraded stack no longer qualifies.
    assert len(world.ops) > len(ops_after_a)
    _new_ops = world.ops[len(ops_after_a) :]
    for _expected in ("install_config", "install_unit", "daemon_reload", "start_stack"):
        assert _expected in _new_ops, (_expected, _new_ops)
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


# ================================== 2. post-activation failure → provable rollback to A′


def test_upgrade_fail_after_activation_reactivates_prior_and_proves_healthy():
    # fail the FORWARD (generation 1) runtime-health gate AFTER activation; the rollback
    # reactivation (generation 2) is NOT failed, so the engine fully proves the rolled-back state.
    deps, fs, world, state = _upgrade_setup(runtime_fail_generations=frozenset({1}))
    loc = deps.locations
    rep_a = _install_a(deps)
    a_agg = rep_a["release_aggregate_digest"]
    a_row = _IDENTITY_DB.active_row

    _arm_stack_transition(deps, world, B_IMAGES)
    code, rep = run(_install_argv(BD_B, write=True), deps)

    # a fully-proven rollback refuses with the ORIGINAL finalization reason, NOT recovery_required
    assert code == 2
    assert rep["reason_code"] == _RUNTIME_FAIL_REASON

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
    # cannot prove the rolled-back state healthy → the transaction refuses recovery_required.
    deps, fs, world, state = _upgrade_setup(runtime_fail_generations=frozenset({1, 2}))
    _install_a(deps)
    _arm_stack_transition(deps, world, B_IMAGES)
    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 2
    assert rep["reason_code"] == "recovery_required"


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
    _IDENTITY_DB.generation_by_row[a_row] = db_generation  # DB moved ahead of the on-disk evidence

    _arm_stack_transition(deps, world, B_IMAGES)
    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 2
    assert rep["reason_code"] == "activation_generation_out_of_order"

    # the prior generation stays active; NO candidate row was minted; A's documents are restored
    assert _IDENTITY_DB.active_row == a_row
    assert set(_IDENTITY_DB.receipts) == {a_row}  # no C created
    assert _read_evidence(fs, loc, "controller")["release_aggregate_digest"] == a_agg
    assert _read_marker(fs, loc)["active_identity_row_id"] == a_row


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
    calls_before = state["calls"]

    dry_code, dry = run(_install_argv(BD_B, write=False), deps)
    assert dry_code == 2 and dry["reason_code"] == "controller_upgrade_not_linear_successor"

    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 2 and rep["reason_code"] == "controller_upgrade_not_linear_successor"

    # nothing mutated: marker/docs/DB untouched, no finalization adapter built for B
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

    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 2 and rep["reason_code"] == "controller_upgrade_prior_not_finalized"
    assert state["calls"] == 0  # bootstrap never touched finalization; B refused before the drive


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
    # refused BEFORE any B mutation: no finalization adapter built; prior identity active + bound
    assert state["calls"] == 1
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

    code, rep = run(_install_argv(BD_B, write=False), deps)
    assert code == 0
    assert rep["mode"] == "dry_run"
    assert rep["classification"] == CLASSIFY_MANAGED_UPGRADE
    assert rep["planned_generation"] == 1

    # zero NEW factory calls, and no doc/marker mutation on a dry run
    assert state["calls"] == calls_before
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
    deps, fs, world, state = _upgrade_setup()
    loc = deps.locations
    _install_a(deps)
    a_row = _IDENTITY_DB.active_row
    marker = _read_marker(fs, loc)
    marker["bootstrap_evidence_digest"] = "sha256:" + "0" * 64
    fs.seed_file(
        loc.api_signer_marker_path(),
        json.dumps(marker, sort_keys=True).encode("ascii"),
        uid=0,
        gid=0,
        mode=0o640,
    )

    code, rep = run(_install_argv(BD_B, write=True), deps)
    assert code == 2 and rep["reason_code"] == "controller_marker_identity_drift"
    assert _IDENTITY_DB.active_row == a_row and set(_IDENTITY_DB.receipts) == {a_row}
    assert state["calls"] == 1  # no B drive


# ============================================= 10. historical activation receipts are immutable


def test_historical_receipts_immutable_after_upgrade_and_rollback():
    # after a SUCCESSFUL upgrade: A's receipt is byte-identical (no UPDATE/DELETE); C is appended.
    deps, fs, world, state = _upgrade_setup()
    _install_a(deps)
    a_row = _IDENTITY_DB.active_row
    a_receipt = copy.deepcopy(_IDENTITY_DB.receipts[a_row])

    _arm_stack_transition(deps, world, B_IMAGES)
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
    _arm_stack_transition(deps, world, B_IMAGES)
    assert run(_install_argv(BD_B, write=True), deps)[0] == 2  # post-activation failure → rollback

    c_row, p_row = _IDENTITY_DB.log[1]["row"], _IDENTITY_DB.log[2]["row"]
    c_receipt = copy.deepcopy(_IDENTITY_DB.receipts[c_row])
    assert _IDENTITY_DB.receipts[a_row] == a_receipt
    assert _IDENTITY_DB.receipts[c_row] == c_receipt == _IDENTITY_DB.log[1]
    assert set(_IDENTITY_DB.receipts) == {a_row, c_row, p_row}
    _assert_receipts_are_append_only(_IDENTITY_DB)


def _assert_receipts_are_append_only(db: _IdentityDb) -> None:
    """The receipts map is EXACTLY the append-only log — one entry per activation, keyed by a
    distinct row, and every stored receipt equals its original log entry (no UPDATE, no DELETE)."""
    rows = [entry["row"] for entry in db.log]
    assert len(rows) == len(set(rows))  # every activation minted a distinct row
    assert set(db.receipts) == set(rows)  # nothing deleted
    for entry in db.log:
        assert db.receipts[entry["row"]] == entry  # nothing updated in place
