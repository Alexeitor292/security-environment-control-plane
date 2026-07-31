"""Fixed, root-controlled PRODUCTION binding + verification context (SECP-PR5D Round 4).

The fixed PR5C operator entrypoint calls ``compositions.build_controlled_live_compositions()`` with
NO arguments, and the administrator command ``python -m secp_operator_deployment verify --json``
runs with no Python-level dependency injection. This module supplies the ONE code-owned,
fail-closed production binding mechanism both use: it resolves the :class:`DeploymentProfile`, the
INDEPENDENT :class:`ExpectedDeploymentIdentities` (from a separate root-controlled file, so the
profile is never the sole authority), the installed-package TRUST result, a bounded read-only host
observation, a bound runtime-provisioning attestation, and the shipped/installed runtime — all from
fixed root-controlled material read through the HARDENED
:class:`~secp_commissioning.runtime.RealFilesystem`.

There is NO arbitrary path CLI argument, NO environment boolean, NO PATH lookup, and NO
caller-supplied factory. The shipped repository has none of the fixed bindings and no reviewed
runtime provider, so every production entry point fails closed. Test injection is a SEPARATE seam:
tests monkeypatch the private ``_production_fs`` / ``_load_installed_runtime`` /
``_command_runner`` hooks (never reachable from the production CLI) to model a complete fixed
binding over an in-memory filesystem.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProductionBindings:
    """The fixed root-controlled bindings the no-argument composition hook consumes."""

    profile: object
    expected: object
    runtime: object


@dataclass(frozen=True)
class VerifyContext:
    """The fixed root-controlled context the administrator ``verify`` command consumes: the profile
    (+ why it is absent/invalid), the independent expected pins, the installed-package trust result
    + reason, a bound runtime attestation, and a strong host observation (all resolved with
    fail-closed
    fallbacks)."""

    profile: object
    profile_load_reason: str | None
    expected: object
    installed_trust_ok: bool
    installed_trust_reason: str | None
    attestation: object
    host_observation: object
    # How many pinned host commands were actually EXECUTED while resolving this context. Counted,
    # not assumed: resolving a context on a provisioned POSIX host runs `systemctl show` and
    # `docker inspect`/`docker exec`, so a report that declares "no external contact" would be
    # false on the only host that matters. Reports derive their contact statement from this.
    host_commands_executed: int = 0


# --------------------------------------------------------------------------- test seams (private;
# never reachable from the production CLI)


def _production_fs():  # noqa: ANN202
    from secp_commissioning.runtime import RealFilesystem

    return RealFilesystem()


def _load_installed_runtime():  # noqa: ANN202
    # PR5D installs NO reviewed controlled-live runtime provider, so the shipped runtime is sealed
    # and every no-argument composition build fails closed until a reviewed provider is installed.
    from secp_operator_deployment.runtime_seams import SealedControlledLiveRuntime

    return SealedControlledLiveRuntime()


def _command_runner():  # noqa: ANN202
    from secp_operator_deployment.host_process import RealCommandRunner

    return RealCommandRunner()


@dataclass
class _CountingCommandRunner:
    """Wraps a command runner and COUNTS every invocation.

    This is the measurement behind a report's contact statement. Every host read in
    :mod:`host_adapters` goes through ``runner.run`` — there is no direct ``subprocess`` use in
    that module — so this count is complete for host command execution.

    The counter increments BEFORE delegating, deliberately: a command that started and then failed
    still made contact, and reporting otherwise would understate exactly the case an operator most
    needs to know about.
    """

    inner: object
    calls: int = 0

    def run(self, pin, argv_tail, *, timeout_seconds, max_output_bytes):  # noqa: ANN001, ANN201
        self.calls += 1
        return self.inner.run(  # type: ignore[attr-defined]
            pin, argv_tail, timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes
        )


# --------------------------------------------------------------------------- production loaders


def load_production_bindings() -> ProductionBindings:
    """Resolve the fixed root-controlled bindings for the no-argument composition hook. Raises a
    bounded error (``profile_not_installed`` / ``expected_identities_not_installed`` / ... ) when
    any
    binding is absent, so the shipped ``build_controlled_live_compositions()`` fails closed."""
    from secp_operator_deployment.identities import read_expected_identities
    from secp_operator_deployment.profile import read_deployment_profile

    fs = _production_fs()
    profile = read_deployment_profile(fs=fs)  # fixed root-controlled path; raises if absent
    expected = read_expected_identities(fs=fs)  # SEPARATE fixed file; raises if absent
    runtime = _load_installed_runtime()  # sealed in PR5D
    return ProductionBindings(profile=profile, expected=expected, runtime=runtime)


def _installed_package_dir() -> str:
    # The package dir of the INSTALLED module; the trusted dir-fd walk (not Path.resolve) is the
    # trust decision, so this only names the directory to walk.
    import os

    import secp_operator_deployment

    return os.path.dirname(os.path.abspath(secp_operator_deployment.__file__))


def load_verify_context() -> VerifyContext:
    """Resolve the fixed root-controlled context for the administrator ``verify`` command, with
    fail-closed fallbacks for every dimension. Absent/invalid material yields a context that verify
    reports honestly and that can never reach prepared success. Contacts nothing beyond the reviewed
    read-only adapters + the hardened filesystem."""
    from secp_operator_deployment.identities import read_expected_identities
    from secp_operator_deployment.manifest import verify_installed_package_trust
    from secp_operator_deployment.profile import read_deployment_profile
    from secp_operator_deployment.runtime_seams import attest_runtime

    # The hardened filesystem itself can refuse to CONSTRUCT (it is POSIX + root only), and that
    # refusal used to escape every per-dimension handler below and leave the CLI with an unbounded
    # traceback. It is a dimension like any other: resolve it fail-closed and carry the bounded
    # reason into the profile dimension, so a non-POSIX host yields a report rather than a stack.
    fs = None
    fs_reason: str | None = None
    try:
        fs = _production_fs()
    except Exception as exc:
        fs_reason = getattr(exc, "reason_code", "production_filesystem_unavailable")

    profile = None
    profile_load_reason: str | None = fs_reason
    if fs is not None:
        try:
            profile = read_deployment_profile(fs=fs)
        except Exception as exc:
            profile = None
            profile_load_reason = getattr(exc, "reason_code", "profile_unreadable")

    expected = None
    if fs is not None:
        try:
            expected = read_expected_identities(fs=fs)
        except Exception:
            expected = None

    # Installed-package trust: the trusted dir-fd walk over the INSTALLED module dir, compared to
    # the independent expected aggregate when available.
    installed_trust_ok = False
    installed_trust_reason: str | None = "install_trust_not_evaluated"
    try:
        expected_aggregate = (
            expected.package_implementation_digest if expected is not None else None
        )
        verify_installed_package_trust(
            _installed_package_dir(), expected_aggregate=expected_aggregate
        )
        installed_trust_ok = True
        installed_trust_reason = None
    except Exception as exc:
        installed_trust_reason = getattr(exc, "reason_code", "install_untrusted")

    # A bound (UNPROVISIONED in PR5D) runtime attestation, when the deployment identities resolved.
    attestation: object = None
    if profile is not None and expected is not None:
        try:
            attestation = attest_runtime(
                _load_installed_runtime(), profile=profile, expected=expected
            )
        except Exception:
            attestation = None

    # A strong, generation-checked host observation through the reviewed read-only adapters. This
    # is where real host commands are executed, so it is also where they are COUNTED — the count is
    # what a report's contact statement is derived from, instead of being declared.
    host_observation: object = None
    host_commands_executed = 0
    if profile is not None and expected is not None:
        counting: _CountingCommandRunner | None = None
        try:
            counting = _CountingCommandRunner(_command_runner())
        except Exception:
            counting = None
        if counting is not None:
            try:
                from secp_operator_deployment.host_adapters import build_real_host_adapters

                _container, service = build_real_host_adapters(
                    profile, expected, command_runner=counting
                )
                host_observation = service.observe()
            except Exception:
                host_observation = None
            # Read the count OUTSIDE the try: commands executed before a later failure still ran,
            # and a failed observation is exactly when an operator needs the contact count.
            host_commands_executed = counting.calls

    return VerifyContext(
        host_commands_executed=host_commands_executed,
        profile=profile,
        profile_load_reason=profile_load_reason,
        expected=expected,
        installed_trust_ok=installed_trust_ok,
        installed_trust_reason=installed_trust_reason,
        attestation=attestation,
        host_observation=host_observation,
    )
