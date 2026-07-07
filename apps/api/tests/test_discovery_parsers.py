"""SECP-B6 §4/§6 — hostile / malformed probe-output parsers fail closed (no host contact).

Direct tests that the bounded parsers reject invalid JSON, oversized output, malformed numeric
values,
unsafe identifiers, malformed storage records, invalid version output, duplicate/conflicting facts,
and
unexpected response shapes — and that a hostile response through the executor fails closed with a
closed reason and no persistence of raw output.
"""

from __future__ import annotations

import json

import pytest
from secp_worker.target_discovery.probes import (
    ProbeError,
    parse_is_clustered,
    parse_node_capacity,
    parse_node_identity,
    parse_owner_marker,
    parse_storages,
    parse_used_vmids,
    parse_version_major_minor,
)

_BIG = b"[" + b'{"vmid":1},' * 200_000 + b"{}]"


@pytest.mark.parametrize(
    "fn,payload",
    [
        (parse_version_major_minor, b"{not json"),
        (parse_version_major_minor, b'{"version": 8}'),  # non-string
        (parse_version_major_minor, b'{"version": "garbage"}'),  # no numeric prefix
        (parse_version_major_minor, b"[]"),  # unexpected shape
        (parse_is_clustered, b"{}"),  # not a list
        (parse_node_identity, b"[]"),  # empty
        (parse_node_identity, b'[{"node": "bad host!"}]'),  # unsafe identifier
        (parse_node_identity, b'[{"nonode": 1}]'),  # unexpected shape
        (parse_node_capacity, b"[]"),  # not a dict
        (parse_node_capacity, b'{"cpuinfo": {"cpus": "sixteen"}}'),  # malformed numeric
        (parse_storages, b"{}"),  # not a list
        (parse_used_vmids, b"{}"),  # not a list
    ],
)
def test_parser_fails_closed_on_hostile_input(fn, payload):
    with pytest.raises(ProbeError):
        fn(payload)


def test_oversized_output_refused():
    with pytest.raises(ProbeError) as exc:
        parse_used_vmids(_BIG)
    assert exc.value.args[0] in ("probe_output_too_large",)


@pytest.mark.parametrize(
    "body",
    [
        b'{"cpuinfo": {"cpus": 1e400}, "memory": {"total": 1, "free": 1}}',  # 1e400 -> inf
        b'{"cpuinfo": {"cpus": Infinity}, "memory": {"total": 1, "free": 1}}',  # json literal
        b'{"cpuinfo": {"cpus": 8}, "memory": {"total": NaN, "free": 1}}',  # NaN literal
    ],
)
def test_non_finite_numbers_fail_closed(body):
    # SECP-B6 F4: a hostile host returning inf/NaN must raise a CLOSED ProbeError, never an
    # OverflowError/ValueError leaking through int().
    with pytest.raises(ProbeError):
        parse_node_capacity(body)


def test_non_finite_storage_avail_fails_closed():
    with pytest.raises(ProbeError):
        parse_storages(b'[{"storage": "local", "avail": 1e400, "active": 1}]')


def test_deeply_nested_json_fails_closed():
    # SECP-B6 F5: a deeply nested payload UNDER the size cap raises RecursionError inside
    # json.loads; it must collapse to a closed ProbeError, not escape as a RuntimeError.
    depth = 60_000
    payload = (b"[" * depth) + (b"]" * depth)
    assert len(payload) < 512 * 1024
    with pytest.raises(ProbeError):
        parse_used_vmids(payload)


def test_malformed_storage_records_skipped_or_safe():
    # A record without a string storage id is skipped; a valid one is bounded + tokenized.
    out = parse_storages(
        json.dumps(
            [
                {"nostorage": 1},
                {"storage": 123},
                {
                    "storage": "local-lvm",
                    "avail": 10 * 1024 * 1024,
                    "active": 1,
                    "content": "images",
                },
            ]
        ).encode()
    )
    assert out == (("local-lvm", 10, True),)


def test_unsafe_storage_id_refused():
    with pytest.raises(ProbeError):
        parse_storages(json.dumps([{"storage": "bad;rm -rf"}]).encode())


def test_owner_marker_extracts_only_marker_or_none():
    assert parse_owner_marker(b'{"description": "hello world"}') is None
    marker = "secp-owned:" + "a" * 16 + "#secp" + "b" * 8 + "-isolated_bridge-0"
    body = json.dumps({"comments": f"lab {marker} extra"}).encode()
    assert parse_owner_marker(body) == marker


def test_executor_fails_closed_on_hostile_remote_output(session, principal):
    # A runner that returns invalid JSON => the executor collapses to a closed reason, no raw leak.
    from secp_worker.ssh_channel import CommandResult
    from secp_worker.target_discovery.probe_executor import ReadOnlyProbeExecutor
    from secp_worker.target_discovery.seams import ProbeSourceUnavailable

    class _Src:
        def acquire(self):
            from secp_worker.ssh_channel import SshBootstrapBundle

            return SshBootstrapBundle("h", 22, "u", "/k", "/kh", "SHA256:x")

        def dispose(self):
            self.disposed = True

    class _Verifier:
        def verify(self, bundle):
            return True

    class _HostileRunner:
        def run(self, argv, *, timeout):
            return CommandResult(0, b"{ this is not json ]")

    src = _Src()
    ex = ReadOnlyProbeExecutor(
        bundle_source=src, runner=_HostileRunner(), host_key_verifier=_Verifier()
    )
    with pytest.raises(ProbeSourceUnavailable) as exc:
        ex.read_inventory()
    # A closed reason code only — no raw output.
    reason = exc.value.reason_code.lower()
    assert "json" not in reason or reason == "malformed_probe_output"
    assert getattr(src, "disposed", False) is True  # disposed even on parse failure
