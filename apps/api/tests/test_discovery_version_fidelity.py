"""Version fidelity, and the SSH probe that is deliberately gone.

Two things this file holds.

**An observed 9.1.1 must not be recorded as 9.1.** The original parser's regex had two capture
groups and no third, so the patch component was discarded at the regex and the loss was final
before anything downstream could notice. Provider compatibility is decided at the patch level.

**The `pveversion` SSH probe is removed, and must stay removed.** It was allowlisted and accepted by
the host forced-command wrapper for a probe nothing ever emitted. Every fact it would have supplied
— exact patch version, build id, running kernel — is available over the HTTPS API, and `/version`
needs no privilege at all. Keeping a granted-but-unreached execution capability because a parser for
it is useful is exactly the kind of latent surface that is hard to notice and easy to re-reach.
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest
from secp_worker.target_discovery.probes import (
    ProbeError,
    ProbeVersion,
    ReadOnlyHostProbe,
    api_and_package_version_agree,
    assert_read_only,
    parse_api_version,
    parse_host_package_version,
    parse_version_major_minor,
    render_probe_argv,
)

PROBES_PATH = (
    pathlib.Path(__file__).resolve().parents[3]
    / "apps"
    / "worker"
    / "secp_worker"
    / "target_discovery"
    / "probes.py"
)


def _api(version: str) -> bytes:
    return json.dumps({"version": version, "release": "9.1", "repoid": "abc123"}).encode()


# --- the patch component --------------------------------------------------------------------------


def test_an_observed_patch_version_survives():
    assert parse_api_version(_api("9.1.1")) == (9, 1, 1)


@pytest.mark.parametrize(
    "version,expected",
    [("9.1.1", (9, 1, 1)), ("8.2.4", (8, 2, 4)), ("9.1.11", (9, 1, 11)), ("10.0.0", (10, 0, 0))],
)
def test_full_versions_parse_completely(version, expected):
    assert parse_api_version(_api(version)) == expected


def test_a_genuinely_two_part_version_reports_none_not_zero():
    """``None`` means the target reported two parts. ``0`` would be a third part it never sent."""
    assert parse_api_version(_api("9.1")) == (9, 1, None)


def test_the_coarse_helper_is_derived_from_the_full_parser():
    assert parse_version_major_minor(_api("9.1.1")) == (9, 1)
    major, minor, _ = parse_api_version(_api("9.1.1"))
    assert parse_version_major_minor(_api("9.1.1")) == (major, minor)


@pytest.mark.parametrize("bad", [b"{}", b"not json", json.dumps({"version": 91}).encode()])
def test_malformed_api_version_is_refused_not_guessed(bad):
    with pytest.raises(ProbeError, match="malformed_probe_output"):
        parse_api_version(bad)


# --- the SSH probe is gone, and stays gone --------------------------------------------------------


def test_the_host_package_probe_no_longer_exists():
    """Removed from the module entirely, not merely unreferenced."""
    import secp_worker.target_discovery.probes as probes_module

    assert not hasattr(probes_module, "ProbeHostPackageVersion")


def test_the_probe_union_does_not_admit_it():
    names = {t.__name__ for t in ReadOnlyHostProbe.__args__}
    assert "ProbeHostPackageVersion" not in names
    assert "ProbeVersion" in names


def test_pveversion_is_not_in_the_read_only_executable_allowlist():
    """The capability is withdrawn, not just unused.

    An executable that stays allowlisted while nothing emits it is a granted-but-unreached
    execution surface — the exact shape that gets quietly re-reached later.
    """
    from secp_worker.target_discovery.probes import _READ_ONLY_EXECUTABLES

    assert _READ_ONLY_EXECUTABLES == frozenset({"pvesh", "cat"})
    assert "pveversion" not in _READ_ONLY_EXECUTABLES


def test_a_bare_pveversion_argv_is_now_refused():
    """Mutation-proof for the removal: the argv that used to be admitted is refused."""
    with pytest.raises(ProbeError, match="executable_not_read_only"):
        assert_read_only(("pveversion",))
    with pytest.raises(ProbeError, match="executable_not_read_only"):
        assert_read_only(("pveversion", "-verbose"))


def test_no_probe_renders_pveversion():
    """Exhaustive over the union rather than spot-checked: a future probe that reintroduced the
    executable would be caught here even if it were named something else."""
    from secp_worker.deployment.locators import BridgeLocator
    from secp_worker.target_discovery.probes import (
        ProbeClusterStatus,
        ProbeNestedVirtualization,
        ProbeNodeCapacity,
        ProbeNodeIdentity,
        ProbeStorage,
        ProbeVmidAvailability,
        candidate_presence_probe,
    )

    samples = [
        ProbeVersion(),
        ProbeClusterStatus(),
        ProbeNodeIdentity(),
        ProbeNodeCapacity("pve-node-1"),
        ProbeStorage("pve-node-1"),
        ProbeVmidAvailability(),
        ProbeNestedVirtualization("kvm_intel"),
        candidate_presence_probe(BridgeLocator("pve-node-1", "secpabcd1234br")),
    ]
    assert {type(p) for p in samples} == set(ReadOnlyHostProbe.__args__)
    for probe in samples:
        assert "pveversion" not in render_probe_argv(probe)


def test_the_probe_module_names_no_sudo_or_root_escalation():
    """Checked over the AST's string constants rather than the raw source, so the module docstring
    — which explains why `pveversion` is absent — does not trip its own guard."""
    tree = ast.parse(PROBES_PATH.read_text(encoding="utf-8"))
    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    # Docstrings are Constant nodes too, so exclude anything long enough to be prose.
    tokens = {s for s in literals if len(s) < 40}
    for banned in ("sudo", "su", "root@pam", "pveversion"):
        assert banned not in tokens, banned


# --- the parsers stay, retargeted at the API source -----------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        (
            b"pve-manager/9.1.1/abcdef1234567890 (running kernel: 6.14.11-1-pve)",
            ("9.1.1", "abcdef1234567890", "6.14.11-1-pve"),
        ),
        (b"pve-manager/9.1.1/abcdef1234567890", ("9.1.1", "abcdef1234567890", "")),
        (b"pve-manager/8.2.4", ("8.2.4", "", "")),
    ],
)
def test_the_package_version_string_still_parses(raw, expected):
    """Same shape, different source: `GET /nodes/{node}/apt/versions` reports it in the
    ``pve-manager`` row rather than on a CLI's stdout."""
    assert parse_host_package_version(raw) == expected


@pytest.mark.parametrize("bad", [b"", b"   ", b"something-else/9.1.1", b"pve-manager/x.y.z"])
def test_malformed_package_version_is_refused(bad):
    with pytest.raises(ProbeError, match="malformed_probe_output"):
        parse_host_package_version(bad)


def test_disagreement_between_two_api_sources_is_reported_rather_than_resolved():
    """`/version` and `/nodes/{node}/apt/versions` are independent API observations and can
    disagree — a node upgraded but not restarted. Neither is preferred; silently taking whichever
    looks newer would hide exactly that."""
    assert api_and_package_version_agree((9, 1, 1), "9.1.1") is True
    assert api_and_package_version_agree((9, 0, 3), "9.1.1") is False
    assert api_and_package_version_agree((9, 1, 1), "9.1.2") is False


def test_a_two_part_api_version_does_not_manufacture_a_disagreement():
    assert api_and_package_version_agree((9, 1, None), "9.1.1") is True
    assert api_and_package_version_agree((9, 1, None), "9.2.0") is False


def test_an_unparseable_package_version_never_reads_as_agreement():
    assert api_and_package_version_agree((9, 1, 1), "not-a-version") is False
    assert api_and_package_version_agree((9, 1, 1), "") is False
