"""An observed 9.1.1 must not be recorded as 9.1.

The original parser's regex had two capture groups and no third, so the patch component was
discarded at the regex and the loss was final before anything downstream could notice. Provider
compatibility is decided at the patch level, so a snapshot saying "9.1" when the host said "9.1.1"
is a quiet lie about which release was observed.

The second half of this file covers the probe that was authorised but never issued: ``pveversion``
has been in the read-only executable allowlist and in the host forced-command wrapper all along,
and no probe emitted it.
"""

from __future__ import annotations

import json

import pytest
from secp_worker.target_discovery.probes import (
    ProbeError,
    ProbeHostPackageVersion,
    ProbeVersion,
    ReadOnlyHostProbe,
    api_and_package_version_agree,
    assert_read_only,
    parse_api_version,
    parse_host_package_version,
    parse_version_major_minor,
    render_probe_argv,
)


def _api(version: str) -> bytes:
    return json.dumps({"version": version, "release": "9.1", "repoid": "abc123"}).encode()


# --- the patch component --------------------------------------------------------------------------


def test_an_observed_patch_version_survives():
    """The defect, stated as the value it lost."""
    assert parse_api_version(_api("9.1.1")) == (9, 1, 1)


@pytest.mark.parametrize(
    "version,expected",
    [
        ("9.1.1", (9, 1, 1)),
        ("8.2.4", (8, 2, 4)),
        ("9.1.11", (9, 1, 11)),
        ("10.0.0", (10, 0, 0)),
    ],
)
def test_full_versions_parse_completely(version, expected):
    assert parse_api_version(_api(version)) == expected


def test_a_genuinely_two_part_version_reports_none_not_zero():
    """``None`` means the target reported two parts. ``0`` would be a third part it never sent.

    The difference matters when the value is compared against a provider's supported range: an
    invented ``.0`` is a claim about the host that nobody observed.
    """
    assert parse_api_version(_api("9.1")) == (9, 1, None)


def test_the_coarse_helper_still_works_and_agrees_with_the_full_parser():
    """Kept for callers needing only the pair.

    Derived from the full parse, so the two can never disagree about the same input.
    """
    assert parse_version_major_minor(_api("9.1.1")) == (9, 1)
    major, minor, _ = parse_api_version(_api("9.1.1"))
    assert parse_version_major_minor(_api("9.1.1")) == (major, minor)


@pytest.mark.parametrize("bad", [b"{}", b"not json", json.dumps({"version": 91}).encode()])
def test_malformed_api_version_is_refused_not_guessed(bad):
    with pytest.raises(ProbeError, match="malformed_probe_output"):
        parse_api_version(bad)


# --- the probe that was authorised but never issued ---------------------------------------------


def test_the_host_package_probe_renders_a_bare_pveversion():
    argv = render_probe_argv(ProbeHostPackageVersion())
    assert argv == ("pveversion",)
    # And it passes the same read-only assertion every other probe does.
    assert_read_only(argv)


def test_the_host_package_probe_admits_no_flags():
    """``pveversion -verbose`` exists. It is not admitted: a caller-selectable flag is a
    caller-controlled argv, and the argv must be a property of the probe TYPE."""
    argv = render_probe_argv(ProbeHostPackageVersion())
    assert len(argv) == 1
    with pytest.raises(ProbeError):
        assert_read_only(("pveversion", "-verbose"))


def test_the_probe_union_admits_the_new_probe():
    assert ProbeHostPackageVersion in ReadOnlyHostProbe.__args__
    assert ProbeVersion in ReadOnlyHostProbe.__args__


@pytest.mark.parametrize(
    "raw,expected",
    [
        (
            b"pve-manager/9.1.1/abcdef1234567890 (running kernel: 6.14.11-1-pve)",
            ("9.1.1", "abcdef1234567890", "6.14.11-1-pve"),
        ),
        (b"pve-manager/9.1.1/abcdef1234567890", ("9.1.1", "abcdef1234567890", "")),
        (b"pve-manager/8.2.4", ("8.2.4", "", "")),
        (
            b"pve-manager/9.1 (running kernel: 6.14.11-1-pve)",
            ("9.1", "", "6.14.11-1-pve"),
        ),
    ],
)
def test_host_package_output_is_parsed_into_its_three_parts(raw, expected):
    assert parse_host_package_version(raw) == expected


def test_the_kernel_version_is_recovered_here():
    """Kernel version was one of the eight facts fetched and discarded — via /nodes/{n}/status,
    whose parser bound only cpuinfo and memory. ``pveversion`` carries it too, and this is the
    cheapest place to recover it."""
    _v, _b, kernel = parse_host_package_version(
        b"pve-manager/9.1.1/abcdef1234567890 (running kernel: 6.14.11-1-pve)"
    )
    assert kernel == "6.14.11-1-pve"


@pytest.mark.parametrize("bad", [b"", b"   ", b"something-else/9.1.1", b"pve-manager/x.y.z"])
def test_malformed_host_package_output_is_refused(bad):
    with pytest.raises(ProbeError, match="malformed_probe_output"):
        parse_host_package_version(bad)


# --- the two sources are kept apart ---------------------------------------------------------------


def test_the_two_version_sources_are_distinct_probes():
    """Not merged, deliberately: they answer different questions and can disagree."""
    assert ProbeVersion.probe_code != ProbeHostPackageVersion.probe_code
    assert render_probe_argv(ProbeVersion()) != render_probe_argv(ProbeHostPackageVersion())


def test_agreement_is_reported_when_both_sources_match():
    assert api_and_package_version_agree((9, 1, 1), "9.1.1") is True


def test_disagreement_is_reported_rather_than_resolved():
    """A node whose packages were upgraded but whose services have not restarted.

    Neither value is "wrong" and neither is preferred — silently taking whichever looks newer would
    hide exactly the half-upgraded node an operator needs told about.
    """
    assert api_and_package_version_agree((9, 0, 3), "9.1.1") is False
    assert api_and_package_version_agree((9, 1, 1), "9.1.2") is False
    assert api_and_package_version_agree((8, 2, 4), "9.1.1") is False


def test_a_two_part_api_version_does_not_manufacture_a_disagreement():
    """When the API reported no patch, comparison is on what it DID report. Demanding a patch it
    never sent would report a mismatch that does not exist."""
    assert api_and_package_version_agree((9, 1, None), "9.1.1") is True
    assert api_and_package_version_agree((9, 1, None), "9.2.0") is False


def test_an_unparseable_package_version_never_reads_as_agreement():
    assert api_and_package_version_agree((9, 1, 1), "not-a-version") is False
    assert api_and_package_version_agree((9, 1, 1), "") is False
