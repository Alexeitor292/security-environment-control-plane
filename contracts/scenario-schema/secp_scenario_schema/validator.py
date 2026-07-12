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
from typing import Any, TypeAlias, cast

import jsonschema
from pydantic import BaseModel

from secp_scenario_schema.v1alpha1.models import API_VERSION as API_VERSION_V1ALPHA1
from secp_scenario_schema.v1alpha1.models import (
    EnvironmentDefinition as EnvironmentDefinitionV1alpha1,
)
from secp_scenario_schema.v1alpha2.models import API_VERSION as API_VERSION_V1ALPHA2
from secp_scenario_schema.v1alpha2.models import (
    EnvironmentDefinition as EnvironmentDefinitionV1alpha2,
)

# The shared typed interface returned for a valid definition (per apiVersion).
# Both members expose the common EnvironmentDefinition surface (apiVersion, kind,
# metadata, spec.teams/roles/networks); v1alpha2 additionally exposes the optional
# spec.topology / spec.publicationProvenance blocks (narrow with isinstance).
EnvironmentDefinition: TypeAlias = EnvironmentDefinitionV1alpha1 | EnvironmentDefinitionV1alpha2

# Dispatch tables keyed by apiVersion. v1alpha1 keeps its exact schema + model;
# v1alpha2 (ADR-016) adds optional topology + publicationProvenance. Adding a
# version here is additive and never changes v1alpha1 semantics (ADR-002).
_SCHEMA_PACKAGE: dict[str, str] = {
    API_VERSION_V1ALPHA1: "secp_scenario_schema.v1alpha1",
    API_VERSION_V1ALPHA2: "secp_scenario_schema.v1alpha2",
}
_MODEL: dict[str, type[BaseModel]] = {
    API_VERSION_V1ALPHA1: EnvironmentDefinitionV1alpha1,
    API_VERSION_V1ALPHA2: EnvironmentDefinitionV1alpha2,
}
SUPPORTED_API_VERSIONS = tuple(_SCHEMA_PACKAGE)


class SchemaValidationError(ValueError):
    """Raised when an environment definition fails validation."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


def _load_schema(api_version: str) -> dict[str, Any]:
    package = _SCHEMA_PACKAGE.get(api_version)
    if package is None:
        raise SchemaValidationError(
            [f"unsupported apiVersion '{api_version}'. supported: {list(SUPPORTED_API_VERSIONS)}"]
        )
    text = resources.files(package).joinpath("schema.json").read_text(encoding="utf-8")
    return json.loads(text)


def validate_definition(raw: dict[str, Any]) -> EnvironmentDefinition:
    """Validate a raw definition dict. Returns the typed model or raises.

    Dispatches on ``apiVersion``: v1alpha1 and v1alpha2 each load their own JSON
    Schema and Pydantic model; unsupported versions fail closed. Runs the JSON
    Schema first (clear structural errors), then the Pydantic model (semantic
    checks such as roles referencing declared networks).
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

    model_cls = _MODEL[api_version]
    try:
        model = model_cls.model_validate(raw)
    except Exception as exc:  # pydantic ValidationError or ValueError
        raise SchemaValidationError([str(exc)]) from exc
    # The dispatch table is keyed by apiVersion, so the constructed model is the
    # exact version's typed EnvironmentDefinition; narrow from BaseModel here.
    return cast(EnvironmentDefinition, model)


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
