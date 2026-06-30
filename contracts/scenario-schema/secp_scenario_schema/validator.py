"""Validation, canonicalization, and content hashing for environment definitions.

``validate_definition`` dispatches on ``apiVersion`` and runs both the JSON Schema
(structural) and the Pydantic models (cross-field semantics). ``canonicalize`` +
``content_hash`` produce the stable hash used to make environment versions
immutable and approvals verifiable (ADR-002, ADR-004).
"""

from __future__ import annotations

import hashlib
import json
from importlib import resources
from typing import Any

import jsonschema

from secp_scenario_schema.v1alpha1.models import API_VERSION, EnvironmentDefinition

SUPPORTED_API_VERSIONS = (API_VERSION,)


class SchemaValidationError(ValueError):
    """Raised when an environment definition fails validation."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


def _load_schema(api_version: str) -> dict[str, Any]:
    if api_version != API_VERSION:
        raise SchemaValidationError(
            [f"unsupported apiVersion '{api_version}'. supported: {list(SUPPORTED_API_VERSIONS)}"]
        )
    text = (
        resources.files("secp_scenario_schema.v1alpha1")
        .joinpath("schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(text)


def validate_definition(raw: dict[str, Any]) -> EnvironmentDefinition:
    """Validate a raw definition dict. Returns the typed model or raises.

    Runs the JSON Schema first (clear structural errors), then the Pydantic model
    (semantic checks such as roles referencing declared networks).
    """
    if not isinstance(raw, dict):
        raise SchemaValidationError(["definition must be a mapping/object"])

    api_version = raw.get("apiVersion")
    if not isinstance(api_version, str):
        raise SchemaValidationError(["missing or non-string 'apiVersion'"])

    schema = _load_schema(api_version)
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(raw), key=lambda e: list(e.path))
    if errors:
        messages = [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]
        raise SchemaValidationError(messages)

    try:
        return EnvironmentDefinition.model_validate(raw)
    except Exception as exc:  # pydantic ValidationError or ValueError
        raise SchemaValidationError([str(exc)]) from exc


def canonicalize(spec: dict[str, Any]) -> str:
    """Deterministic JSON serialization used for content hashing.

    Sorted keys, no insignificant whitespace, UTF-8. This is the *only* allowed
    serializer for hashing so the hash is stable across processes (ADR-002).
    """
    return json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_hash(spec: dict[str, Any]) -> str:
    """SHA-256 of the canonicalized spec, prefixed with the algorithm."""
    digest = hashlib.sha256(canonicalize(spec).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
