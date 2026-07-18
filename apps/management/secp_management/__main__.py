"""``python -m secp_management`` entry point (equivalent to the ``secpctl`` console command)."""

from __future__ import annotations

from secp_management.cli import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
