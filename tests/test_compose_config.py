"""Cross-cutting checks for the dev stack and secret hygiene (Slice 1).

These do not start Docker; they validate the compose file structurally and assert
no real secrets are committed.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE = REPO_ROOT / "infra" / "dev" / "docker-compose.yml"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
GITIGNORE = REPO_ROOT / ".gitignore"

# Only development-safe services are permitted in the dev stack.
ALLOWED_SERVICES = {
    "postgres",
    "minio",
    "keycloak",
    "temporal",
    "temporal-ui",
    "api",
    "worker",
    "web",
}

# Real infrastructure / security tools must never appear in the dev stack.
FORBIDDEN_TOKENS = {
    "proxmox",
    "vmware",
    "vsphere",
    "hyper-v",
    "wazuh-manager",
    "security-onion",
    "opentofu",
    "terraform",
}


def test_compose_parses_and_only_dev_safe_services():
    data = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = set(data.get("services", {}))
    assert services, "no services defined"
    extra = services - ALLOWED_SERVICES
    assert not extra, f"unexpected services in dev stack: {extra}"


def test_compose_has_required_services():
    data = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = set(data.get("services", {}))
    for required in ("postgres", "minio", "keycloak", "temporal", "api", "worker", "web"):
        assert required in services, f"missing required service {required}"


def test_compose_declares_healthchecks_for_core_services():
    data = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = data["services"]
    for svc in ("postgres", "api"):
        assert "healthcheck" in services[svc], f"{svc} missing healthcheck"


def test_no_real_infrastructure_in_compose():
    # Inspect resolved service images/commands (not comments, which legitimately
    # mention what the stack deliberately avoids).
    data = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    haystack = []
    for svc in data["services"].values():
        haystack.append(str(svc.get("image", "")).lower())
        haystack.append(str(svc.get("command", "")).lower())
    blob = " ".join(haystack)
    for token in FORBIDDEN_TOKENS:
        assert token not in blob, f"forbidden infra token '{token}' in a service image"


def test_env_example_exists_and_is_placeholder_only():
    assert ENV_EXAMPLE.exists(), ".env.example must exist"
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    # Every secret-ish value must be an obvious placeholder.
    for line in text.splitlines():
        if "PASSWORD" in line and "=" in line and not line.strip().startswith("#"):
            value = line.split("=", 1)[1].strip()
            assert value == "" or "change-me" in value or "dev-only" in value, (
                f"non-placeholder secret in .env.example: {line}"
            )


def test_env_is_gitignored():
    text = GITIGNORE.read_text(encoding="utf-8")
    assert ".env" in text, ".env must be git-ignored"
    assert "!.env.example" in text, ".env.example must be allowed through gitignore"
