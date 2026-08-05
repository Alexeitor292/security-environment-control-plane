"""Export the live FastAPI application's OpenAPI document to a committed artifact.

THE GENERATED DOCUMENT IS THE CONTRACT. ``contracts/openapi/openapi.json`` is what this script
writes and what every client generator reads; a hand-written client transcription that disagrees
with it is wrong, not the other way round.

Two properties make the committed artifact worth trusting, and both are enforced here rather than
assumed:

* **It is byte-reproducible.** The same application must always produce the same bytes, or the
  staleness guard degrades into a coin flip that reviewers learn to re-run until it passes. Keys
  are sorted at every level, so re-ordering ``include_router`` calls in
  :mod:`secp_api.main` moves nothing in the diff; only a real contract change does.

* **It does not depend on the machine that exported it.** ``Settings`` reads ``SECP_*`` from the
  environment AND from a ``.env`` file in the working directory, and ``info.title`` is
  ``settings.app_name``. A developer with a local ``.env`` would otherwise commit a document
  carrying their own app name. The export pins the settings that reach the document to fixed
  values before ``secp_api`` is imported, and :func:`export_document` is additionally proved
  environment-independent by ``tests/test_openapi_artifact.py``.

Usage::

    python scripts/export_openapi.py            # write the artifact
    python scripts/export_openapi.py --check     # fail if the artifact is stale

``--check`` is the CI gate. It never writes: a guard that repairs what it is meant to detect
reports success on a tree that was broken when it arrived.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
ARTIFACT = REPO_ROOT / "contracts" / "openapi" / "openapi.json"

#: Settings that reach the OpenAPI document, pinned so the artifact is a function of the CODE and
#: nothing else. ``SECP_APP_NAME`` becomes ``info.title``; ``SECP_APP_ENV`` selects the non-
#: production validation path (``production`` refuses to construct without real OIDC configuration,
#: and an artifact that can only be exported from a production-shaped environment is an artifact
#: nobody regenerates). These are set in ``os.environ``, which pydantic-settings ranks ABOVE any
#: ``.env`` file, so a developer's local file cannot leak into the committed contract.
PINNED_ENV: dict[str, str] = {
    "SECP_APP_ENV": "test",
    "SECP_APP_NAME": "Security Environment Control Platform",
}


def build_document() -> dict[str, Any]:
    """Construct the application and return its OpenAPI document.

    ``create_app()`` registers routers and error handlers only; the ``startup`` handler that seeds
    the development database does not run, so exporting touches no database and no filesystem.

    THE ARTIFACT IS A FUNCTION OF THE CODE, and this is where that is made true rather than hoped
    for. Two ambient influences are removed before ``Settings`` is constructed, and each was a real
    failure, not a hypothetical:

    * **Every ``SECP_*`` variable in the environment**, not just the two that reach the document.
      Pinning only the two was the original mistake. No setting moves the document — that is
      verified across all of them in ``tests/test_openapi_artifact.py`` — but five of them
      (``cors_allow_origins``, ``workflow_dispatch_mode``, ``provisioning_application_mode``,
      ``oidc_max_token_bytes``, ``oidc_max_document_bytes``) can make ``Settings`` REFUSE to
      construct. A developer with one of those set got a crash where CI, whose environment is
      clean, got a document. The guard was therefore green on the only machine anyone checked.

    * **A ``.env`` in the working directory.** ``Settings`` declares ``env_file=".env"``, resolved
      against the CWD, and ``.env.example`` tells developers to copy it there for the compose
      stack. The construction below happens from a directory that has no ``.env``, so the file
      cannot reach the artifact whatever it contains.
    """
    for key in [key for key in os.environ if key.startswith("SECP_")]:
        del os.environ[key]
    os.environ.update(PINNED_ENV)

    # ``env_file`` is resolved against the CWD when ``Settings`` is CONSTRUCTED, and the import
    # below is what constructs it: ``secp_api.main`` ends with a module-level ``app =
    # create_app()``, so settings are read the instant the module is imported. Wrapping only the
    # explicit ``create_app()`` call left the .env reaching the artifact through the import — which
    # is exactly what ``test_a_developer_dotenv_cannot_reach_the_artifact`` caught. The import has
    # to happen inside the sealed directory too.
    previous = os.getcwd()
    with tempfile.TemporaryDirectory(prefix="secp-openapi-export-") as sealed:
        os.chdir(sealed)
        try:
            from secp_api.main import create_app

            app = create_app()
        finally:
            os.chdir(previous)
    return app.openapi()


def serialize(document: dict[str, Any]) -> str:
    """Render the document as the exact text of the artifact.

    ``sort_keys`` is what makes the guard usable. Without it the order of ``paths`` follows router
    registration order and the order of ``components.schemas`` follows first reference, so an
    unrelated edit produces a thousand-line diff and the real change hides inside it.
    """
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def export_document() -> str:
    """The artifact text for the application as it exists in this tree."""
    return serialize(build_document())


def _read_artifact() -> str | None:
    if not ARTIFACT.exists():
        return None
    return ARTIFACT.read_text(encoding="utf-8")


def _write_artifact(text: str) -> None:
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    # ``newline=""`` writes the "\n" already in the text verbatim: Python's default translation
    # would emit CRLF on Windows and the artifact would differ from the one CI regenerates.
    with ARTIFACT.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def _diff(committed: str, regenerated: str) -> str:
    lines = difflib.unified_diff(
        committed.splitlines(keepends=True),
        regenerated.splitlines(keepends=True),
        fromfile="contracts/openapi/openapi.json (committed)",
        tofile="contracts/openapi/openapi.json (regenerated from the app)",
        n=2,
    )
    return "".join(lines)


def _write_stderr(message: str) -> None:
    """Report to stderr without dying on the console's encoding.

    The document carries characters a Windows console codepage cannot encode — em dashes and an
    arrow, out of the model docstrings. Printing a diff hunk containing one raises
    UnicodeEncodeError, so the ONE path with something useful to say (a stale artifact) would exit
    on a traceback about encoding instead of naming the field that moved. Written as bytes with a
    replacing codec: a mangled character in a diagnostic beats losing the diagnostic.
    """
    buffer = getattr(sys.stderr, "buffer", None)
    if buffer is None:  # pragma: no cover - a stderr with no byte buffer (pytest capture)
        sys.stderr.write(message + "\n")
        return
    buffer.write((message + "\n").encode(sys.stderr.encoding or "utf-8", "replace"))
    buffer.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when the committed artifact differs from the live application (writes nothing)",
    )
    args = parser.parse_args(argv)

    regenerated = export_document()
    committed = _read_artifact()

    if not args.check:
        _write_artifact(regenerated)
        print(f"wrote {ARTIFACT.relative_to(REPO_ROOT).as_posix()}")
        return 0

    if committed is None:
        _write_stderr(
            "OpenAPI artifact is MISSING: contracts/openapi/openapi.json does not exist.\n"
            "Run: python scripts/export_openapi.py"
        )
        return 1

    if committed != regenerated:
        diff = _diff(committed, regenerated)
        # Bounded: a full 200-path diff buries the cause in the log it is supposed to explain.
        excerpt = "".join(diff.splitlines(keepends=True)[:120])
        _write_stderr(
            "OpenAPI artifact is STALE. The committed contract no longer matches the application "
            "that serves it.\n"
            "Run: python scripts/export_openapi.py "
            "&& (cd apps/web && npm run generate:api)\n"
            "and commit both the document and the regenerated TypeScript.\n\n"
            f"{excerpt}"
        )
        return 1

    print("OpenAPI artifact is in step with the application.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
