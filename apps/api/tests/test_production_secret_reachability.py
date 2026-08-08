"""Production must never source a provider credential from the environment.

`EnvSecretResolver` reads ``os.environ`` and was constructed by the SHIPPED Temporal discovery
activity, which meant a production Proxmox credential could come from an environment variable. That
is the reachability these tests forbid.

The resolver is not deleted — deleting it would push local development onto some other ad-hoc path,
and an undocumented one is worse than a named one. What matters is that no production composition
can REACH it, which is a structural property and is asserted as one here rather than in a docstring.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
import secp_worker
from secp_worker.secrets import (
    EnvSecretResolver,
    SealedProviderSecretResolver,
    SecretResolutionError,
)

_WORKER_ROOT = pathlib.Path(secp_worker.__file__).parent

#: The modules a deployment actually runs. `secrets.py` is excluded because it DEFINES the resolver;
#: the property under test is that nothing else constructs one.
_PRODUCTION_ENTRY_POINTS = (
    "temporal_app.py",
    "temporal_workflows.py",
    "temporal_runtime.py",
    "orchestration.py",
    "main.py",
    "discovery.py",
    "proxmox_discovery_runtime.py",
)


def _names_used(path: pathlib.Path) -> set[str]:
    """Every name the module IMPORTS or CALLS, via the AST.

    Not a substring scan: a comment or docstring explaining that the env resolver is forbidden
    would match one, which is how a guard ends up failing on the prose describing the rule.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.Call):
            fn = node.func
            names.add(fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", ""))
    return names


@pytest.mark.parametrize("module", _PRODUCTION_ENTRY_POINTS)
def test_no_production_entry_point_imports_or_constructs_the_env_resolver(module):
    path = _WORKER_ROOT / module
    if not path.exists():  # pragma: no cover - the set is a superset of what ships
        pytest.skip(f"{module} is not present")
    assert "EnvSecretResolver" not in _names_used(path), module


def test_the_whole_shipped_worker_package_is_free_of_the_env_resolver():
    """Wider than the entry-point list, because the list is a judgement and this is not.

    A new module that constructs the env resolver would pass the parametrised test above simply by
    not being named in it.
    """
    offenders = []
    for path in _WORKER_ROOT.rglob("*.py"):
        if path.name == "secrets.py":
            continue  # the definition site
        if "EnvSecretResolver" in _names_used(path):
            offenders.append(str(path.relative_to(_WORKER_ROOT)))
    assert offenders == [], offenders


def test_the_shipped_discovery_activity_composes_the_sealed_resolver():
    """Positive reachability: the fix is only real if production actually wires the replacement.

    Asserted on the activity's own source, so replacing the sealed resolver with anything else — or
    dropping the argument so a default applies — fails here.
    """
    import inspect

    from secp_worker import temporal_app

    source = inspect.getsource(temporal_app.discover_activity)
    tree = ast.parse(source.lstrip())
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
    called = {
        (n.func.id if isinstance(n.func, ast.Name) else getattr(n.func, "attr", ""))
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
    }
    assert "SealedProviderSecretResolver" in imported
    assert "SealedProviderSecretResolver" in called
    # AST, not a substring: the activity's own comment EXPLAINS what it no longer constructs, and a
    # text scan reads that explanation as the violation it is describing.
    assert "EnvSecretResolver" not in imported
    assert "EnvSecretResolver" not in called


def test_the_sealed_resolver_refuses_rather_than_reading_anything(monkeypatch):
    """A stale environment variable is inert.

    Set the exact variable the env resolver would have read, then prove the shipped resolver still
    refuses — the honest failure for a deployment with no trusted backend composed.
    """
    monkeypatch.setenv("SECP_PROVIDER_SECRET__LAB", "a-real-looking-token")
    with pytest.raises(SecretResolutionError) as ei:
        SealedProviderSecretResolver().resolve("env:SECP_PROVIDER_SECRET__LAB")
    # the refusal names the missing BACKEND, not a missing variable — different operator actions
    assert "backend" in str(ei.value).lower()
    assert "a-real-looking-token" not in str(ei.value)


def test_the_sealed_resolver_still_enforces_the_reference_grammar():
    """It refuses, but not before rejecting a malformed reference — so a caller cannot learn that a
    bad reference and an absent backend are the same thing."""
    with pytest.raises(Exception):  # noqa: B017 - grammar violations raise before the refusal
        SealedProviderSecretResolver().resolve("not-a-valid-ref")


def test_the_env_resolver_still_works_where_it_is_allowed(monkeypatch):
    """Kept deliberately, for development and tests only.

    Asserting it still functions is the point: this is not a stealth deletion, it is a
    reachability change, and the two are different claims.
    """
    monkeypatch.setenv("SECP_PROVIDER_SECRET__LAB", "dev-token")
    cred = EnvSecretResolver().resolve("env:SECP_PROVIDER_SECRET__LAB")
    assert cred.reveal_secret() == "dev-token"


def test_the_sealed_resolver_reads_no_environment_at_all():
    """Structural: it cannot read `os.environ`, rather than happening not to."""
    import inspect

    source = inspect.getsource(SealedProviderSecretResolver)
    tree = ast.parse(source.lstrip())
    referenced = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
    }
    for banned in ("environ", "getenv", "open", "Path", "read_text"):
        assert banned not in referenced, banned
