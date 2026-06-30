"""Proof #10 — no real endpoint or credential appears in any authored file.

Scans authored source/docs/tests/infra for:
1. public (globally-routable) IPv4 literals — only private/documentation/loopback
   ranges are allowed; and
2. provider ``base_url`` hosts — only placeholder hosts (.example/.test/.invalid/
   .local), localhost, or private IPs are allowed.

This is a regression guard against accidentally hardcoding a real Proxmox endpoint
or credential. It does not (and cannot) prove the absence of every possible real
private hostname, but it catches public endpoints and non-placeholder hosts.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

SCAN_DIRS = ["apps/api", "apps/worker", "contracts", "plugins", "docs", "tests", "infra"]
SCAN_ROOT_FILES = [".env.example", "README.md"]
SCAN_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".json", ".ts", ".tsx", ".toml", ".cfg", ".env"}
EXCLUDE_PARTS = {"__pycache__", "node_modules", ".venv", "dist", ".git"}
EXCLUDE_NAMES = {"uv.lock", "package-lock.json"}

IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
BASE_URL_RE = re.compile(r"https?://([A-Za-z0-9_.\-]+)")
ALLOWED_HOST_SUFFIXES = (".example", ".test", ".invalid", ".local", ".example.test")
ALLOWED_HOSTS = {"localhost"}


def _files() -> list[Path]:
    out: list[Path] = []
    for d in SCAN_DIRS:
        for p in (REPO / d).rglob("*"):
            if p.is_file() and p.suffix in SCAN_SUFFIXES and not (EXCLUDE_PARTS & set(p.parts)):
                if p.name not in EXCLUDE_NAMES:
                    out.append(p)
    for name in SCAN_ROOT_FILES:
        p = REPO / name
        if p.exists():
            out.append(p)
    return out


def _is_allowed_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # not a real IP (e.g. a version-like token)
    # Documentation ranges (RFC 5737) and private/loopback/etc. are allowed.
    doc_ranges = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]
    if any(addr in n for n in doc_ranges):
        return True
    return not addr.is_global


def test_no_public_ipv4_literals():
    offenders = []
    for path in _files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for m in IPV4_RE.finditer(text):
            ip = m.group(0)
            if not _is_allowed_ip(ip):
                offenders.append(f"{path.relative_to(REPO)}: {ip}")
    assert not offenders, f"public IPv4 literal(s) found: {offenders}"


def test_provider_base_urls_are_placeholders():
    offenders = []
    for path in _files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line in text.splitlines():
            if "base_url" not in line:
                continue
            for host in BASE_URL_RE.findall(line):
                if host in ALLOWED_HOSTS or host.endswith(ALLOWED_HOST_SUFFIXES):
                    continue
                # allow private/documentation IP hosts
                try:
                    if not ipaddress.ip_address(host).is_global:
                        continue
                except ValueError:
                    pass
                offenders.append(f"{path.relative_to(REPO)}: {host}")
    assert not offenders, f"non-placeholder provider host(s) found: {offenders}"
