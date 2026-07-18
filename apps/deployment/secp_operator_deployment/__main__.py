"""``python -m secp_operator_deployment`` entrypoint (SECP-PR5D). Read-only verification only."""

from __future__ import annotations

from secp_operator_deployment.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
