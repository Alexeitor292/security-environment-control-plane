"""In-image production smoke check (SECP-PR5F.2).

Fed to the built production image over stdin (``python - < infra/dev/image_smoke.py``) and run in a
network-disabled, read-only, capability-dropped container.  It proves the installed image has the
full pyproject package closure, the real console-script executable files, the reviewed 10001:10001
runtime user, the sole Alembic head, and a deterministic self-validating runtime overlay built from
the image's own copied source.  A JUnit document is written to stdout and the process exits non-zero
on any failure, so the CI gate can prove every check actually executed (no skips, no failures).
"""

from __future__ import annotations

import importlib
import os
import shutil
import sys
import xml.sax.saxutils as saxutils

_PACKAGES = (
    "secp_api",
    "secp_worker",
    "secp_commissioning",
    "secp_operator_deployment",
    "secp_discovery_activation",
    "secp_management",
    "secp_scenario_schema",
    "secp_plugin_api",
    "secp_plugin_simulator",
    "secp_plugin_proxmox",
)
# console script name -> the "module:function" it installs; the module must both resolve to an
# executable file AND be importable in the image (a script whose target module is absent is exactly
# the secp-admission-proxy = secp_discovery_activation.proxy:main regression this guards).
_SCRIPTS = {
    "secpctl": "secp_management.cli",
    "secp-admission-proxy": "secp_discovery_activation.proxy",
    "secp-discovery-activation": "secp_discovery_activation.cli",
}
_EXPECTED_UID = 10001
_EXPECTED_GID = 10001
_EXPECTED_ALEMBIC_HEAD = "d8f1a2b3c4e5"
_API_DIR = "/app/apps/api"


def _check_import_production_packages() -> None:
    for name in _PACKAGES:
        importlib.import_module(name)


def _check_resolve_console_scripts() -> None:
    for name, module in _SCRIPTS.items():
        path = shutil.which(name)
        if path is None or not os.path.isfile(path):
            raise AssertionError(
                f"console script {name!r} is not an installed file (resolved {path!r})"
            )
        importlib.import_module(module)  # the script's target module must also import in the image


def _check_runtime_user_10001() -> None:
    uid, gid = os.getuid(), os.getgid()
    if (uid, gid) != (_EXPECTED_UID, _EXPECTED_GID):
        raise AssertionError(
            f"runtime user is {uid}:{gid}, expected {_EXPECTED_UID}:{_EXPECTED_GID}"
        )


def _check_alembic_sole_head() -> None:
    os.chdir(_API_DIR)
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    heads = tuple(ScriptDirectory.from_config(Config("alembic.ini")).get_heads())
    if heads != (_EXPECTED_ALEMBIC_HEAD,):
        raise AssertionError(
            f"alembic heads {heads}, expected sole head ({_EXPECTED_ALEMBIC_HEAD!r},)"
        )


def _check_deterministic_runtime_overlay() -> None:
    from secp_discovery_activation.runtime_overlay import (
        build_runtime_overlay,
        import_runtime_overlay,
        runtime_overlay_sha256,
    )

    first = build_runtime_overlay("/app")
    second = build_runtime_overlay("/app")
    if first != second:
        raise AssertionError("runtime overlay bytes differ across two builds (not deterministic)")
    digest = runtime_overlay_sha256(first)
    validated = import_runtime_overlay(first, digest)
    if validated.sha256 != digest:
        raise AssertionError("runtime overlay did not validate against its computed digest")


_CHECKS = (
    ("import_production_packages", _check_import_production_packages),
    ("resolve_console_scripts", _check_resolve_console_scripts),
    ("runtime_user_10001_10001", _check_runtime_user_10001),
    ("alembic_sole_head", _check_alembic_sole_head),
    ("deterministic_runtime_overlay", _check_deterministic_runtime_overlay),
)


def main() -> int:
    results: list[tuple[str, str | None]] = []
    for name, check in _CHECKS:
        try:
            check()
            results.append((name, None))
        except Exception as exc:  # noqa: BLE001 — every failure becomes a reported testcase
            results.append((name, f"{type(exc).__name__}: {exc}"))
    failures = sum(1 for _name, error in results if error is not None)
    out = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuite name="python-image-smoke" tests="{len(results)}" '
        f'failures="{failures}" skipped="0">',
    ]
    for name, error in results:
        if error is None:
            out.append(f'  <testcase classname="image-smoke" name="{name}"/>')
        else:
            out.append(f'  <testcase classname="image-smoke" name="{name}">')
            out.append(f"    <failure>{saxutils.escape(error)}</failure>")
            out.append("  </testcase>")
    out.append("</testsuite>")
    sys.stdout.write("\n".join(out) + "\n")
    sys.stdout.flush()
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
