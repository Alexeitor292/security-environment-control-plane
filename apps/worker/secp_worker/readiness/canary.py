"""The INERT readiness canary (B1B-PR4 / ADR-021 §H).

The ONE place B1B-PR4 constructs :class:`~secp_worker.preflight.secret_resolution.SecretMaterial`,
and it does so from a **locally generated random token** — never from a secret backend, a database
row, a configuration value, an environment variable, a file, or any caller input.

**Why it exists.** The ``jit_injection_contract`` facet must prove that opaque secret material
projects into ONLY the allowlisted child-process environment. Proving that requires typed material.
Resolving the operator's REAL provisioning credential to prove it would defeat the whole point
of the readiness contract — so readiness proves it with an inert canary instead.

**What it is not.** It is not a credential of any kind. It authenticates to nothing, is never sent
anywhere, is never persisted, logged, audited, hashed, or returned, and it exists only inside the
calling function's frame before every reference is dropped.

The SECP-B2-2 static design lock permits exactly two production files to construct
``SecretMaterial``: the reviewed OpenBao adapter (behind its fail-closed client boundary) and this
module — and it additionally asserts that this module's only source of material is
``secrets.token_hex``, and that it imports nothing capable of reading a backend, a database, a file,
or the environment.
"""

from __future__ import annotations

import secrets

from secp_worker.preflight.secret_resolution import SecretMaterial

# A stable, obviously-inert prefix so the canary is instantly recognisable in any (hypothetical)
# leak scan — the leak tests assert this token appears in NO database row, audit row, log, workflow
# argument, exception, repr, model dump, API response, rendered file, or the git diff.
INERT_CANARY_PREFIX = "secp-inert-readiness-canary-"


def inert_canary_material() -> SecretMaterial:
    """Return INERT, locally generated, typed opaque material for the JIT-projection contract.

    The value is ``secrets.token_hex`` randomness. It never comes from — and can never come from — a
    secret manager, a database, a configuration file, or ``os.environ``: this module imports nothing
    that could read any of them.
    """
    return SecretMaterial(INERT_CANARY_PREFIX + secrets.token_hex(16))
