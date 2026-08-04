"""Drive the release build, the two installations, and record what each one actually produced.

This is the stage driver for ``packages``, ``controller`` and ``worker_install``. It owns the
ORDER those stages run in and the rule that every check gets a record.

WHY THE ORDER IS CONTROLLER BEFORE WORKER
-----------------------------------------
It is not a cost decision, and the cheaper order is wrong. The ordinary worker's readiness marker is
written only by ``secp_worker.main`` after ``Client.connect`` returns and the Temporal worker is
confirmed polling; the management observer establishes ``ordinary_healthy`` by running that health
command inside the container; and ``engine._worker_end_state_reason`` refuses the whole worker end
state without it. Temporal is a controller-stack component. So a worker installed against no
controller cannot reach the state its own commit gate requires, and a green ``worker_status_ok``
in that ordering would be a false green rather than a saving.

WHY NOTHING HERE RAISES PAST A STAGE
------------------------------------
A stage that dies must still leave a record. Every step is wrapped so that a failure becomes an
``unproven`` check with a bounded reason instead of an exception that removes the check from the
document — a check that quietly disappears reads as a check that passed, which is the exact defect
this program exists to remove. The only failures allowed to escape are the ones that mean the fleet
itself is unusable, because after those there is nothing left to observe.

THE READ-BEFORE-REFUSE HAZARD, INSTRUMENTED
-------------------------------------------
``real_adapters._load_and_verify_image`` reads an entire image archive into memory and only THEN
compares it against the product's 512 MiB cap. An over-cap archive on a host that is already running
an eight-service stack may therefore die as an OOM or a killed process rather than as the clean
``bootstrap_image_too_large`` refusal. Both outcomes are recorded here, and a death with no bounded
reason is recorded as unproven with the death itself as the observation — never as an absence.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

from secp_acceptance import AcceptanceError
from secp_acceptance.hosts import ROLE_CONTROLLER, ROLE_WORKER, Host, HostFleet
from secp_acceptance.install import (
    HOST_STAGING,
    HostInstallation,
    host_untouched,
    observe_health_command_in_worker_image,
    plan_is_dry_run,
    read_operator_unit_properties,
    shipped_packages,
)
from secp_acceptance.queues import record_verdict, resolve_operator_unit_dormant
from secp_acceptance.reasons import (
    STAGE_CONTROLLER,
    STAGE_PACKAGES,
    STAGE_WORKER_INSTALL,
)
from secp_acceptance.release import PRODUCT_MAX_IMAGE_ARCHIVE_BYTES, ReleaseMaterial
from secp_acceptance.run import AcceptanceRun

#: The bundle directory name inside each host. Fixed, so no host-read value becomes a host path.
HOST_BUNDLE = f"{HOST_STAGING}/bundle"


@dataclass
class StageOutcome:
    """What one driven stage produced, for the test nodes to assert on."""

    recorded: dict[str, str] = field(default_factory=dict)  # check -> outcome
    reasons: dict[str, str] = field(default_factory=dict)  # check -> bounded reason
    notes: dict[str, object] = field(default_factory=dict)


@dataclass
class InstallationRun:
    """The complete driven installation: the SHARED run, and the per-stage outcomes.

    Holds the session's :class:`~secp_acceptance.run.AcceptanceRun` rather than a recorder of its
    own. Four streams produce the nine stages; a per-stream recorder would give four partial
    documents that cannot be reconciled and a ``stages_attempted`` that means only "whatever this
    module happened to open".
    """

    acceptance_run: AcceptanceRun
    material: ReleaseMaterial
    packages: StageOutcome = field(default_factory=StageOutcome)
    controller: StageOutcome = field(default_factory=StageOutcome)
    worker: StageOutcome = field(default_factory=StageOutcome)
    installations: dict[str, HostInstallation] = field(default_factory=dict)

    def outcome_of(self, check: str) -> str:
        for stage in (self.packages, self.controller, self.worker):
            if check in stage.recorded:
                return stage.recorded[check]
        return "absent"

    def reason_for(self, check: str) -> str:
        for stage in (self.packages, self.controller, self.worker):
            if check in stage.reasons:
                return stage.reasons[check]
        return ""


class StageRecorder:
    """Records into the shared run AND into a local stage outcome, so the two cannot drift.

    PUBLIC on purpose. The lifecycle stage consumes this rather than forking a second copy, and a
    leading underscore is a promise the owner may change it freely — so a cross-stream consumer of a
    private name is a dependency that breaks silently at integration. It is published instead.

    Every path through :meth:`attempt` produces exactly one record. There is no way to call it and
    get nothing, which is what keeps a stage from being half-covered — and it is what makes the
    per-check assertions in the container tier mean anything, since a path that recorded nothing
    would leave a check ``absent`` rather than failing.
    """

    def __init__(self, run: InstallationRun, stage: str, outcome: StageOutcome) -> None:
        self._run = run
        self._stage = stage
        self._outcome = outcome
        run.acceptance_run.open_stage(stage)

    def observed(self, check: str, observation: object) -> None:
        self._run.acceptance_run.observe(check, self._stage, observation)
        self._outcome.recorded[check] = "observed"

    def unproven(self, check: str, *, reason: str, observation: object) -> None:
        self._run.acceptance_run.unproven(
            check, self._stage, reason_code=reason, observation=observation
        )
        self._outcome.recorded[check] = "unproven"
        self._outcome.reasons[check] = reason

    def violated(self, check: str, *, observation: object) -> None:
        """The harness POSITIVELY OBSERVED the state the check exists to rule out.

        The opposite of ``unproven``, not a worse flavour of it: maximal knowledge rather than
        maximal ignorance. Only reachable where the producer can tell observed-false apart from
        could-not-look, which is why the observation helpers are three-valued.
        """
        self._run.acceptance_run.violated(
            check,
            self._stage,
            reason_code="acceptance_prohibited_state_observed",
            observation=observation,
        )
        self._outcome.recorded[check] = "violated"
        self._outcome.reasons[check] = "acceptance_prohibited_state_observed"

    def record_verdict_for(self, check: str, verdict: object) -> None:
        """File a shared :class:`~secp_acceptance.queues.QueueVerdict` and mirror the outcome.

        Routes through ``queues.record_verdict`` so the three-way verdict encoding lives in exactly
        one place; the local mirror exists only so the container-tier nodes can assert per check.
        """
        from secp_acceptance.queues import encode_verdict

        record_verdict(self._run.acceptance_run, check, verdict, stage=self._stage)  # type: ignore[arg-type]
        outcome, reason = encode_verdict(verdict)  # type: ignore[arg-type]
        self._outcome.recorded[check] = outcome
        if reason:
            self._outcome.reasons[check] = reason

    def attempt(self, check: str, *, reason: str, produce, violation=None) -> object | None:
        """Run ``produce`` and record its result, or record ``unproven`` with ``reason``.

        ``produce`` returns ``(ok, observation)``. A False ``ok`` is a real negative observation —
        the harness looked and the answer was no — and is recorded unproven with the observation
        that says so, NOT dropped. An exception is recorded the same way with the exception's own
        bounded code where it has one.
        """
        try:
            ok, observation = produce()
        except AcceptanceError as exc:
            self.unproven(check, reason=exc.reason_code, observation={"refused": True})
            return None
        except Exception:  # noqa: BLE001 - never a traceback into evidence; bounded reason only
            self.unproven(check, reason=reason, observation={"harness_fault": True})
            return None
        if not ok:
            # A negative result splits two ways. If the producer can say the PROHIBITED state was
            # positively observed, that is a violation and must not be filed as "we could not tell".
            if violation is not None and violation(observation):
                self.violated(check, observation=observation)
            else:
                self.unproven(check, reason=reason, observation=observation)
            return None
        self.observed(check, observation)
        return observation


# --------------------------------------------------------------------------- packages


def drive_packages(run: InstallationRun, fleet: HostFleet, wheel_name: str) -> None:
    """Install the release wheel on both hosts and prove the distribution is really there."""
    stage = StageRecorder(run, STAGE_PACKAGES, run.packages)
    root = _repo_root()
    declared = shipped_packages(root)

    for role, check in (
        (ROLE_CONTROLLER, "controller_packages_installed"),
        (ROLE_WORKER, "worker_packages_installed"),
    ):
        install = run.installations[role]

        def produce(install=install, wheel_name=wheel_name):
            observation = install.install_wheel(wheel_name)
            return bool(
                observation["installed"] and observation["distribution_version"]
            ), observation

        stage.attempt(check, reason="acceptance_package_install_failed", produce=produce)

    def entrypoint():
        observation = run.installations[ROLE_CONTROLLER].observe_entrypoint()
        return (
            bool(observation["entrypoint_executable"] and observation["entrypoint_answers"]),
            observation,
        )

    stage.attempt(
        "secpctl_entrypoint_present", reason="acceptance_entrypoint_absent", produce=entrypoint
    )

    def closure():
        observation = run.installations[ROLE_WORKER].observe_import_closure(declared)
        return observation["importable"] == observation["declared_shipped"], observation

    stage.attempt(
        "worker_package_import_closure", reason="acceptance_import_closure_failed", produce=closure
    )


# --------------------------------------------------------------------------- controller


def drive_controller(run: InstallationRun, fleet: HostFleet) -> None:
    """Bring the controller up from the signed bundle and observe the five controller facts.

    Every check here depends on the stack actually starting. When it does not, all five are recorded
    unproven against the bounded reason the product gave — the run reports a controller that could
    not be brought up, which is a true and reviewable statement, rather than omitting the stage.
    """
    stage = StageRecorder(run, STAGE_CONTROLLER, run.controller)
    install = run.installations[ROLE_CONTROLLER]
    checks = (
        "controller_database_migrated",
        "controller_api_serving_tls",
        "controller_temporal_reachable",
        "controller_signer_broker_active",
        "controller_locator_recorded",
    )

    oversized = run.material.oversized()
    if oversized:
        # The reason code is the PRODUCT's own (`bootstrap_image_too_large`), because the document
        # must be able to tell "the controller stack failed to come up" apart from "the reviewed
        # bundle path cannot install the product's own image at its real size". Those are completely
        # different findings and only the second one points at the product.
        #
        # PREDICTED, NOT OBSERVED — and the observation says so rather than letting the reason code
        # imply the product spoke. The install is deliberately not attempted: the size check in
        # `_load_and_verify_image` happens AFTER the whole archive is read into memory, so driving
        # it on a host already running an eight-service stack risks an OOM that takes the run down
        # and destroys every other stage's evidence with it. Declining to attempt costs one
        # distinction, and the observation records exactly which one.
        for check in checks:
            stage.unproven(
                check,
                reason="bootstrap_image_too_large",
                observation={
                    "oversized_archives": len(oversized),
                    "product_cap_bytes": PRODUCT_MAX_IMAGE_ARCHIVE_BYTES,
                    "refusal_predicted_from_measured_size": True,
                    "refusal_observed_from_product": False,
                },
            )
        run.controller.notes["oversized"] = list(oversized)
        return

    bootstrapped = _bootstrap(install, "controller")
    run.controller.notes["bootstrap"] = bootstrapped

    if not bootstrapped["committed"]:
        for check in checks:
            stage.unproven(
                check,
                reason="acceptance_controller_bringup_failed",
                observation={
                    "bootstrap_exit": bootstrapped["exit_code"],
                    "reason_code": bootstrapped["reason_code"],
                },
            )
        return

    status_code, status = install.secpctl("status", "controller")
    run.controller.notes["status"] = {
        "exit_code": status_code,
        "reason_code": str(status.get("reason_code", ""))[:64],
    }

    def migrated():
        observation = {
            "status_exit": status_code,
            "migration_identity": str(status.get("migration_identity", ""))[:16],
            "expected": run.material.migration_identity,
        }
        return observation["migration_identity"] == run.material.migration_identity, observation

    stage.attempt(
        "controller_database_migrated",
        reason="acceptance_controller_migration_failed",
        produce=migrated,
    )

    def serving_tls():
        return _observe_api_tls(install.host)

    stage.attempt(
        "controller_api_serving_tls",
        reason="acceptance_controller_api_unreachable",
        produce=serving_tls,
    )

    def temporal():
        return _observe_temporal(install.host)

    stage.attempt(
        "controller_temporal_reachable",
        reason="acceptance_controller_temporal_unreachable",
        produce=temporal,
    )

    def broker():
        return _observe_broker(install.host)

    stage.attempt(
        "controller_signer_broker_active",
        reason="acceptance_controller_signer_unavailable",
        produce=broker,
    )

    def locator():
        return _observe_locator(install.host)

    stage.attempt(
        "controller_locator_recorded",
        reason="acceptance_observation_unavailable",
        produce=locator,
    )


# --------------------------------------------------------------------------- worker install


def drive_worker(run: InstallationRun, fleet: HostFleet, ordinary_image: str) -> None:
    """Install the worker from the signed bundle and observe the seven worker-install facts."""
    stage = StageRecorder(run, STAGE_WORKER_INSTALL, run.worker)
    install = run.installations[ROLE_WORKER]
    host = install.host

    # --- the image probe. Independent of every install step, so it is taken first and is the one
    # worker_install fact that survives a controller that never came up.
    def health_command():
        observation = observe_health_command_in_worker_image(ordinary_image)
        return bool(observation["interpreter_resolves"]), observation

    stage.attempt(
        "worker_health_command_resolves_in_the_worker_image",
        reason="acceptance_observation_unavailable",
        produce=health_command,
    )

    # --- the dry run. Also controller-independent: it is a plan, and it must not touch the host.
    from secp_management.layout import ManagementLocations

    locations = ManagementLocations()
    write_targets = (
        locations.worker_compose_path(),
        locations.operator_unit_path(),
        locations.worker_deployment_package_path(),
    )

    def dry_run():
        exit_code, payload = install.secpctl("bootstrap", "worker", "--bundle", HOST_BUNDLE)
        reported = plan_is_dry_run(exit_code, payload)
        untouched = host_untouched(host, write_targets)
        observation = {**reported, **untouched}
        # BOTH halves: the product declared a dry run AND nothing it would have written exists.
        # The report alone would be satisfied by an installer that wrote anyway.
        return (
            bool(reported["declared_dry_run"] and untouched["absent"] == untouched["probed"]),
            observation,
        )

    stage.attempt(
        "worker_bootstrap_plan_is_dry_run",
        reason="acceptance_proof_would_be_vacuous",
        produce=dry_run,
    )

    written = _bootstrap(install, "worker")
    run.worker.notes["bootstrap"] = written

    # The FIRST operator-unit reading, taken as soon as the install has done its writing. The
    # second is taken at the end of the stage, so the pair spans the status and evidence work and
    # the resolver's generation check covers a real interval.
    try:
        operator_before = read_operator_unit_properties(host)
    except AcceptanceError:
        operator_before = {}

    def committed():
        return bool(written["committed"]), {
            "exit_code": written["exit_code"],
            "reason_code": written["reason_code"],
            "mode": written["mode"],
        }

    stage.attempt(
        "worker_bootstrap_written", reason="acceptance_package_install_failed", produce=committed
    )

    def reobserved():
        return bool(written["committed"] and written["reobserved_healthy"]), {
            "reobserved_healthy": written["reobserved_healthy"],
            "reason_code": written["reason_code"],
        }

    stage.attempt(
        "worker_bootstrap_reobserved_healthy",
        reason="acceptance_observation_unavailable",
        produce=reobserved,
    )

    def status_ok():
        exit_code, payload = install.secpctl("status", "worker")
        observation = {
            "exit_code": exit_code,
            "status": str(payload.get("status", ""))[:32],
            "reason_code": str(payload.get("reason_code", ""))[:64],
        }
        return exit_code == 0 and not observation["reason_code"], observation

    stage.attempt(
        "worker_status_ok", reason="acceptance_observation_unavailable", produce=status_ok
    )

    # The operator unit is resolved through the QUEUES stage's dormancy funnel rather than a second
    # implementation of the same predicate. `operator_before` was taken right after the bootstrap
    # committed; this reading closes a real window over the status and evidence work above, so the
    # generation stamp agreeing across the two is a statement about an interval rather than a
    # restatement of one snapshot. Passing the same reading twice would have satisfied the resolver
    # and proven strictly less.
    stage.record_verdict_for(
        "worker_operator_unit_present_disabled_stopped",
        resolve_operator_unit_dormant(operator_before, read_operator_unit_properties(host)),
    )

    def attested():
        exit_code, payload = install.secpctl("evidence", "worker")
        observation = {
            "exit_code": exit_code,
            "trusted": bool(payload.get("trusted", False)),
            "reason_code": str(payload.get("reason_code", ""))[:64],
        }
        return exit_code == 0 and observation["trusted"], observation

    stage.attempt(
        "worker_evidence_attested", reason="acceptance_observation_unavailable", produce=attested
    )


# --------------------------------------------------------------------------- shared helpers


def _bootstrap(install: HostInstallation, role: str) -> dict[str, object]:
    """Drive the real ``secpctl bootstrap <role> --write --confirm`` and reduce the report.

    ``committed`` is taken from the product's own report, never inferred from the exit code alone:
    an installer that exits zero having compensated a failed reobservation has not committed, and
    the difference is the entire point of the reobservation gate.
    """
    exit_code, payload = install.secpctl(
        "bootstrap", role, "--bundle", HOST_BUNDLE, "--write", "--confirm"
    )
    if not payload:
        # No bounded report at all. This is the read-before-refuse hazard's signature — the process
        # died (OOM/kill) rather than refusing. Recorded as a fact, not as an absence.
        return {
            "exit_code": exit_code,
            "mode": "",
            "reason_code": "no_bounded_report",
            "committed": False,
            "reobserved_healthy": False,
            "died_without_report": True,
        }
    return {
        "exit_code": exit_code,
        "mode": str(payload.get("mode", ""))[:32],
        "reason_code": str(payload.get("reason_code", ""))[:64],
        "committed": exit_code == 0 and not payload.get("reason_code"),
        "reobserved_healthy": bool(payload.get("reobserved_healthy", False)),
        "died_without_report": False,
    }


def _observe_api_tls(host: Host) -> tuple[bool, dict[str, object]]:
    """Prove the controller API is serving TLS, independently of the stack observation.

    Deliberately NOT taken from the controller observation's ``healthy`` map: that map is
    ``dict(running)`` — health folded into running — so it says a container exists, not that
    anything is served over TLS. The proof here is an actual TLS handshake against the recorded
    origin from inside the controller host, verified against the CA the installation wrote.
    """
    from secp_management.controller_api_locator import CONTROLLER_API_LOCATOR_PATH

    # The program catches its OWN failures and reports them as data, so the caller can tell a
    # handshake that was attempted and lost from a probe that never ran. Anything it cannot catch
    # (no interpreter, unreachable host) produces no output at all, which the caller refuses as an
    # outage rather than recording as a TLS failure.
    program = (
        "import json,ssl,socket,urllib.parse\n"
        "out={}\n"
        "try:\n"
        f"    loc=json.load(open({CONTROLLER_API_LOCATOR_PATH!r}))\n"
        "    u=urllib.parse.urlparse(loc['canonical_origin'])\n"
        "    ctx=ssl.create_default_context(cafile=loc['ca_bundle_path'])\n"
        "    s=ctx.wrap_socket(socket.create_connection((u.hostname,u.port or 443),timeout=20),"
        "server_hostname=u.hostname)\n"
        "    cert=s.getpeercert()\n"
        "    out={'tls':s.version(),'san':bool(cert.get('subjectAltName'))}\n"
        "except FileNotFoundError:\n"
        "    out={'error':'locator_absent'}\n"
        "except Exception as exc:\n"
        "    out={'error':type(exc).__name__}\n"
        "print(json.dumps(out))\n"
    )
    probe = host.exec(("/usr/bin/python3", "-c", program), timeout=180)
    import json as _json

    # No parsable output means the probe never ran — an outage, not a failed handshake. Returning
    # False on `not probe.ok` conflated the two and would have recorded "the controller API does
    # not serve TLS" for a missing /usr/bin/python3.
    try:
        answer = _json.loads(probe.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise AcceptanceError("acceptance_observation_unavailable") from None
    if not isinstance(answer, dict):
        raise AcceptanceError("acceptance_observation_malformed")
    if answer.get("error"):
        # The program ran and the handshake failed. A real negative about the deployment.
        return False, {"handshake": False, "failed_at": str(answer["error"])[:32]}
    version = str(answer.get("tls", ""))
    return bool(version.startswith("TLSv1.") and answer.get("san")), {
        "tls_version": version[:16],
        "san_present": bool(answer.get("san")),
        "verified_against_installed_ca": True,
    }


def _observe_temporal(host: Host) -> tuple[bool, dict[str, object]]:
    """The controller's Temporal component is present and reachable on the controller host."""
    from secp_management.real_adapters import _controller_container

    container = _controller_container("temporal")
    running = host.exec(
        ("docker", "inspect", "--format", "{{.State.Running}}", container), timeout=120
    )
    # `docker inspect` failing is an OUTAGE, not a stopped component: the inner daemon may be
    # unreachable or the harness unable to exec into the host. Without this the failed inspect
    # yields empty stdout, which compares unequal to "true" and reads as "Temporal is not running"
    # — an accusation against the product for something never observed. The two are separated by
    # asking whether the COMMAND ran, not by what it printed.
    if not running.ok or running.stdout.strip() not in ("true", "false"):
        raise AcceptanceError("acceptance_observation_unavailable")
    if running.stdout.strip() != "true":
        return False, {"component_running": "false", "namespace_query_ok": False}
    reachable = host.exec(
        ("docker", "exec", container, "temporal", "operator", "namespace", "list"), timeout=180
    )
    return reachable.ok, {"component_running": "true", "namespace_query_ok": reachable.ok}


def _observe_broker(host: Host) -> tuple[bool, dict[str, object]]:
    """The root-gated enrollment-signer broker unit is loaded and ACTIVE on the controller host."""
    from secp_management.layout import ManagementLocations

    unit = ManagementLocations().broker_unit_path().rsplit("/", 1)[-1]
    shown = host.exec(
        (
            "systemctl",
            "show",
            unit,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
        ),
        timeout=120,
    )
    if not shown.ok:
        # `systemctl show` answers even for a unit that does not exist (LoadState=not-found), so a
        # non-zero exit here is almost purely "could not ask" — an unreachable host or absent
        # systemd. Reporting it as "the broker is not active" would blame the product for an outage.
        raise AcceptanceError("acceptance_observation_unavailable")
    properties: dict[str, str] = {}
    for line in shown.stdout.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            properties[key.strip()] = value.strip()[:32]
    return (
        properties.get("LoadState") == "loaded" and properties.get("ActiveState") == "active"
    ), {
        "load_state": properties.get("LoadState", ""),
        "active_state": properties.get("ActiveState", ""),
        "sub_state": properties.get("SubState", ""),
    }


def _observe_locator(host: Host) -> tuple[bool, dict[str, object]]:
    """The controller-API locator record exists and parses through the PRODUCT's own reader.

    Read back through ``secp_management.controller_api_locator`` rather than by parsing the JSON
    here: the reader is what every later command uses to find the controller, so a record only this
    harness can read is not a record the product can use.
    """
    from secp_management.controller_api_locator import CONTROLLER_API_LOCATOR_PATH

    program = (
        "import json,sys\n"
        "from secp_commissioning.runtime import RealFilesystem\n"
        "from secp_management.controller_api_locator import ControllerApiLocatorReader\n"
        "r=ControllerApiLocatorReader(RealFilesystem())\n"
        "rec=r.read()\n"
        "print(json.dumps({'present':rec is not None,"
        "'origin_is_https':bool(rec and rec.canonical_origin.startswith('https://')),"
        "'ca_bundle_absolute':bool(rec and rec.ca_bundle_path.startswith('/'))}))\n"
    )
    probe = host.exec(("/usr/bin/python3", "-c", program), timeout=180)
    if not probe.ok:
        exists = host.exec(("test", "-f", CONTROLLER_API_LOCATOR_PATH), timeout=60)
        return False, {"reader_answered": False, "file_present": exists.ok}
    import json as _json

    try:
        answer = _json.loads(probe.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise AcceptanceError("acceptance_observation_malformed") from None
    return bool(
        answer.get("present") and answer.get("origin_is_https") and answer.get("ca_bundle_absolute")
    ), dict(answer)


def _repo_root() -> pathlib.Path:
    from secp_acceptance.release import repo_root

    return repo_root()


__all__ = [
    "HOST_BUNDLE",
    "InstallationRun",
    "StageOutcome",
    "StageRecorder",
    "drive_controller",
    "drive_packages",
    "drive_worker",
]
