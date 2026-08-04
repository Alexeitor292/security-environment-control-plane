"""Install the release on the two hosts and OBSERVE what the installation produced.

This module drives the customer-facing surface — the ``secpctl`` console script installed from the
release wheel — against real hosts, and reduces each result to the bounded, secret-free projection a
check records. It contains no assertion and no verdict: the recorder is where an observation becomes
a check, so there is exactly one place a claim can enter the evidence.

WHY THE PRODUCTION INPUTS ARE SEEDED RATHER THAN INJECTED
---------------------------------------------------------
``secp_management.production`` composes the real adapters ONLY from five fixed root-owned files
under ``/var/lib/secp/bootstrap``. There is no adapter-selection flag, no environment variable, no
caller-supplied import. So the honest way to put the real installer in front of a real host is to
put those five files on the host and let the product's own composer find them — which is what
:meth:`HostInstallation.seed_production_inputs` does. Anything else would be the harness handing the
engine a double and then reporting that the engine worked.

Every value seeded is run-scoped and ephemeral: the release anchor is the one this run minted, the
evidence-signing key is generated per host and never leaves it, and the executable pins are digests
MEASURED from the host's own filesystem rather than declared.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
-----------------------------------------
It never starts the operator worker, never enables the operator unit, and never writes a trust root
outside the run's own fleet. The operator unit is installed by the product as present-disabled-
stopped, and the only thing done to it here is to LOOK at it.
"""

from __future__ import annotations

import json
import pathlib
import re
import secrets
import tomllib
from dataclasses import dataclass, field

from secp_acceptance import AcceptanceError
from secp_acceptance.hosts import Host
from secp_acceptance.shell import Result, docker, run

#: Where the run's material lands inside a host. A fixed, run-independent staging root: the harness
#: never composes a host path from a value it read back off a host.
HOST_STAGING = "/opt/secp/acceptance"


#: The management-plane state directory the production composer reads its five inputs from. Read
#: from the product's own layout rather than restated, so a relocation breaks here loudly.
def _bootstrap_state() -> str:
    from secp_management.layout import ManagementLocations

    return ManagementLocations().bootstrap_state


_PIP_TIMEOUT = 1800
_SECPCTL_TIMEOUT = 1800
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _digest(value: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value).hexdigest()


# --------------------------------------------------------------------------- shipped closure


def shipped_packages(root: pathlib.Path) -> tuple[str, ...]:
    """The packages the packaging contract declares as SHIPPED, read from the contract itself.

    Read rather than restated on purpose. ``worker_package_import_closure`` exists to catch a
    package that was dropped from the wheel while its code stayed in the tree — the exact PR5F
    regression. A hand-maintained list here would be edited in the same breath as the wheel list and
    would keep agreeing with it, which is how that regression stayed green the first time.
    """
    contract = root / "packaging-contract.toml"
    data = tomllib.loads(contract.read_text(encoding="utf-8"))
    packages = data.get("packages", {})
    shipped = tuple(
        sorted(name for name, spec in packages.items() if spec.get("distribution") == "shipped")
    )
    if not shipped:
        raise AcceptanceError("acceptance_import_closure_failed")
    return shipped


# --------------------------------------------------------------------------- one host


@dataclass
class HostInstallation:
    """The product installed on ONE host, and the bounded observations of it."""

    host: Host
    interpreter: str = "/usr/bin/python3"
    entrypoint: str = "/usr/local/bin/secpctl"
    delivered: dict[str, str] = field(default_factory=dict)

    # --- delivery -----------------------------------------------------------------------

    def deliver(self, source: pathlib.Path, destination: str) -> None:
        """Copy run material into the host. ``docker cp`` — never a bind mount, so the host's
        filesystem state is genuinely its own and survives nothing but this host."""
        self.host.exec(("mkdir", "-p", HOST_STAGING), check=True)
        copied = run(
            ("docker", "cp", str(source), f"{self.host.container}:{destination}"), timeout=1800
        )
        if not copied.ok:
            raise AcceptanceError("acceptance_host_command_failed")
        self.delivered[destination] = destination

    # --- packages -----------------------------------------------------------------------

    def install_wheel(self, wheel_name: str) -> dict[str, object]:
        """Install the release wheel into the host's SYSTEM interpreter, and observe the result.

        The system interpreter, not a venv, because the reviewed broker unit's ``ExecStart`` is
        ``topology.BROKER_ENTRYPOINT`` = ``/usr/bin/python3 -m
        secp_management.enrollment_signer_broker_serve``. A venv install would leave that unit
        unable to import the module it names, so the install would write to a place the product
        does not look.

        ``--break-system-packages`` is required on Ubuntu 24.04 (PEP 668). This is a disposable host
        whose entire purpose is to carry one installation, so there is no system Python to protect.

        The ``worker`` extra is included so the import closure below measures the REAL runtime
        closure rather than reporting a missing optional dependency as a packaging defect.
        """
        wheel = f"{HOST_STAGING}/{wheel_name}"
        installed = self.host.exec(
            (
                self.interpreter,
                "-m",
                "pip",
                "install",
                "--break-system-packages",
                "--no-input",
                f"{wheel}[worker]",
            ),
            timeout=_PIP_TIMEOUT,
        )
        if not installed.ok:
            raise AcceptanceError("acceptance_package_install_failed")
        version = self.host.exec(
            (
                self.interpreter,
                "-c",
                "import importlib.metadata as m; print(m.version('secp'))",
            ),
            timeout=120,
        )
        return {
            "role": self.host.role,
            "installed": installed.ok,
            "distribution_version": version.stdout.strip()[:32] if version.ok else "",
            "from_wheel": True,
        }

    def observe_entrypoint(self) -> dict[str, object]:
        """The ``secpctl`` console script exists as a real file AND answers.

        Both halves matter: a console script that exists but cannot import its module is exactly the
        failure a distribution-vs-image mismatch produces, and presence alone would not see it.
        """
        present = self.host.exec(("test", "-x", self.entrypoint), timeout=60)
        answered = self.host.exec((self.entrypoint, "--json", "host", "inspect"), timeout=300)
        payload = _payload(answered)
        return {
            "role": self.host.role,
            "entrypoint_executable": present.ok,
            "entrypoint_answers": answered.exit_code in (0, 2),
            "reported_command": str(payload.get("command", ""))[:32],
        }

    def observe_import_closure(self, packages: tuple[str, ...]) -> dict[str, object]:
        """Import every SHIPPED package from the INSTALLED distribution, on the host.

        Run through the system interpreter from a working directory with no source tree in it, so an
        import can only resolve out of the installed distribution. Each package reports the file it
        resolved to, which is what makes this a statement about the wheel rather than about the
        repository the harness happens to be sitting in.
        """
        program = (
            "import json,sys\n"
            "out={}\n"
            "for name in sys.argv[1:]:\n"
            "    try:\n"
            "        mod=__import__(name)\n"
            "        out[name]=bool(getattr(mod,'__file__',None))\n"
            "    except Exception:\n"
            "        out[name]=False\n"
            "print(json.dumps(out,sort_keys=True))\n"
        )
        probe = self.host.exec(
            ("sh", "-c", f'cd / && exec {self.interpreter} -c "$0" "$@"', program, *packages),
            timeout=600,
        )
        if not probe.ok:
            raise AcceptanceError("acceptance_import_closure_failed")
        try:
            resolved = json.loads(probe.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise AcceptanceError("acceptance_observation_malformed") from None
        return {
            "role": self.host.role,
            "declared_shipped": len(packages),
            "importable": sum(1 for ok in resolved.values() if ok),
            "missing": sorted(name for name, ok in resolved.items() if not ok),
        }

    # --- the five production inputs ------------------------------------------------------

    def measure_executables(self, paths: tuple[str, ...]) -> dict[str, str]:
        """SHA-256 every pinned executable ON THIS HOST.

        Measured here rather than copied from the release, because ``open_pinned_executable``
        re-verifies the object it opens: a digest that came from anywhere but this filesystem would
        refuse at the first adapter call. Measuring it makes the pin true by construction and still
        fails loudly if the host image ever ships a different binary.
        """
        probe = self.host.exec(("sha256sum", *paths), timeout=300)
        if not probe.ok:
            raise AcceptanceError("acceptance_observation_unavailable")
        measured: dict[str, str] = {}
        for line in probe.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2 and _HEX64.fullmatch(parts[0]):
                measured[parts[1]] = "sha256:" + parts[0]
        if set(measured) != set(paths):
            raise AcceptanceError("acceptance_observation_unavailable")
        return measured

    def seed_production_inputs(self, *, anchor: dict[str, str]) -> dict[str, object]:
        """Write the five fixed inputs ``secp_management.production`` composes real adapters from.

        This is the whole seam. Nothing here selects an adapter or relaxes a check — the product
        still verifies every one of these on read: the trust anchor's id must derive from its own
        key, the evidence key must be a root-owned single-link 0600 regular file of exactly 32
        bytes whose public half matches the pinned identity, and each executable pin is re-hashed at
        every invocation.
        """
        state = _bootstrap_state()
        self.host.exec(("mkdir", "-p", state), check=True)
        self.host.exec(("chown", "root:root", state), check=True)
        self.host.exec(("chmod", "0755", state), check=True)

        paths = ("/usr/bin/docker", "/usr/local/bin/docker-compose", "/usr/bin/systemctl")
        measured = self.measure_executables(paths)
        executables = {
            "container_runtime": {"path": paths[0], "digest": measured[paths[0]]},
            "compose_runtime": {"path": paths[1], "digest": measured[paths[1]]},
            "service_manager": {"path": paths[2], "digest": measured[paths[2]]},
        }
        self.host.write_file(
            f"{state}/production-executables.json",
            json.dumps(executables, sort_keys=True).encode("ascii"),
        )
        self.host.write_file(
            f"{state}/production-expected-identities.json",
            json.dumps(
                {"schema": "secp.acceptance.expected-identities/v1", "role": self.host.role},
                sort_keys=True,
            ).encode("ascii"),
        )
        self.host.write_file(
            f"{state}/release-trust-anchor.json",
            json.dumps(dict(anchor), sort_keys=True).encode("ascii"),
        )

        # The evidence-signing key is this HOST's own, generated here and never transported. It is
        # a different root from the release anchor by design: the commit gate verifies the local
        # attestation under the authenticator's own public identity, and pinning the release anchor
        # there would fail every commit closed.
        private = secrets.token_bytes(32)
        public_hex = _ed25519_public(private)
        self.host.write_file(f"{state}/evidence-signing.key", private, mode="0600")
        self.host.write_file(
            f"{state}/evidence-signing.pub.json",
            json.dumps(
                {
                    "key_id": _digest(bytes.fromhex(public_hex)),
                    "public_key_hex": public_hex,
                },
                sort_keys=True,
            ).encode("ascii"),
        )
        return {
            "role": self.host.role,
            "inputs_seeded": 5,
            "executables_measured": len(measured),
            "anchor_id_present": bool(anchor.get("key_id")),
        }

    # --- the product surface -------------------------------------------------------------

    def secpctl(self, *argv: str, timeout: int = _SECPCTL_TIMEOUT) -> tuple[int, dict]:
        """Run the installed ``secpctl`` and return ``(exit_code, payload)``.

        Always ``--json``: the harness parses a bounded report, never scraped human text.
        """
        result = self.host.exec((self.entrypoint, "--json", *argv), timeout=timeout)
        return result.exit_code, _payload(result)


def _payload(result: Result) -> dict:
    """The last JSON object a ``secpctl`` invocation wrote, or an empty report.

    Tolerant of leading output (pip warnings, systemd notices) and never raises on unparsable text:
    a command that produced no report is an absent observation, which the caller records as
    unproven — not an exception that loses which command it came from.
    """
    for line in reversed(result.stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                return parsed
    return {}


def _ed25519_public(private: bytes) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return (
        Ed25519PrivateKey.from_private_bytes(private)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


# --------------------------------------------------------------------------- worker observations


def observe_operator_unit(host: Host) -> dict[str, object]:
    """The headline safety observation: the operator unit is PRESENT, DISABLED and STOPPED.

    Asked of real systemd on a host where systemd is PID 1, so the three answers are systemd's own.
    All three properties are read in ONE ``systemctl show`` call: reading them separately would let
    the unit change between questions and produce a combination that never actually existed.

    ``LoadState`` is read too. Without it, a unit systemd cannot load at all reports
    ``ActiveState=inactive`` — indistinguishable from a correctly stopped one — and the check would
    pass for a unit that is not really there.
    """
    from secp_management.topology import OPERATOR_SERVICE_NAME

    shown = host.exec(
        (
            "systemctl",
            "show",
            OPERATOR_SERVICE_NAME,
            "--property=LoadState",
            "--property=UnitFileState",
            "--property=ActiveState",
            "--property=SubState",
        ),
        timeout=120,
    )
    if not shown.ok:
        raise AcceptanceError("acceptance_observation_unavailable")
    properties: dict[str, str] = {}
    for line in shown.stdout.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            properties[key.strip()] = value.strip()[:32]
    return {
        "unit_loaded": properties.get("LoadState") == "loaded",
        "unit_file_state": properties.get("UnitFileState", ""),
        "active_state": properties.get("ActiveState", ""),
        "sub_state": properties.get("SubState", ""),
        "present_disabled_stopped": (
            properties.get("LoadState") == "loaded"
            and properties.get("UnitFileState") == "disabled"
            and properties.get("ActiveState") == "inactive"
        ),
    }


def observe_health_command_in_worker_image(image_digest: str) -> dict[str, object]:
    """Resolve the pinned worker health interpreter in the EXACT image the release binds.

    Probed BY CONTENT DIGEST on the daemon that built the image, which is precise about what is
    being claimed. The question the check asks — does the absolute ``argv[0]`` the product execs
    exist in the worker image — is a property of image CONTENT, and a digest identifies that content
    wherever it sits. Asking the worker host's own daemon instead would additionally require the
    image to have been LOADED there, which is a different fact (and one the bootstrap establishes
    later); probing here keeps this check independent of every install step, so it still reports
    when the controller or the bootstrap never got off the ground.

    The control probe is what makes the result mean anything: a runner that answered "absent" for
    everything would make the real question unfalsifiable, and one that answered "present" for
    everything would do the same in the other direction.
    """
    from secp_management.topology import ORDINARY_HEALTH_COMMAND, WORKER_CONTAINER_INTERPRETER

    if ORDINARY_HEALTH_COMMAND[0] != WORKER_CONTAINER_INTERPRETER:
        # The probe would be measuring a path the product does not execute.
        raise AcceptanceError("acceptance_proof_would_be_vacuous")

    def executable(path: str) -> bool:
        return docker(
            "run", "--rm", "--network", "none", image_digest, "test", "-x", path, timeout=300
        ).ok

    control_present = executable("/bin/sh")
    control_absent = executable("/definitely-not-a-real-path-9f3a")
    if not control_present or control_absent:
        raise AcceptanceError("acceptance_proof_would_be_vacuous")
    return {
        "interpreter_resolves": executable(WORKER_CONTAINER_INTERPRETER),
        "control_present": control_present,
        "control_absent": control_absent,
    }


def plan_is_dry_run(exit_code: int, payload: dict) -> dict[str, object]:
    """Reduce a ``secpctl bootstrap`` plan invocation to the dry-run facts.

    A plan is a dry run when the product SAYS it is, not when the harness omitted ``--write``. The
    distinction is the point of the check: the default has to be proven, because an installer whose
    dry run mutated would be indistinguishable here from one that did not.
    """
    return {
        "exit_code": exit_code,
        "mode": str(payload.get("mode", ""))[:32],
        "role": str(payload.get("role", ""))[:32],
        "declared_dry_run": payload.get("mode") == "dry_run",
        "reason_code": str(payload.get("reason_code", ""))[:64],
    }


def host_untouched(host: Host, paths: tuple[str, ...]) -> dict[str, object]:
    """Which of the given absolute paths do NOT exist on the host.

    Paired with the dry-run report so the check asserts an EFFECT rather than a claim: a plan that
    reported ``dry_run`` while writing its unit file would satisfy the report and fail here.
    """
    absent: list[str] = []
    for path in paths:
        if not host.exec(("test", "-e", path), timeout=60).ok:
            absent.append(path.rsplit("/", 1)[-1])
    return {"probed": len(paths), "absent": len(absent), "absent_names": sorted(absent)}


__all__ = [
    "HOST_STAGING",
    "HostInstallation",
    "host_untouched",
    "observe_health_command_in_worker_image",
    "observe_operator_unit",
    "plan_is_dry_run",
    "shipped_packages",
]
