"""Module entry point for the fixed-path PR5F activation CLI."""

from secp_discovery_activation.cli import main

if __name__ == "__main__":  # import remains inert; only ``python -m`` executes
    raise SystemExit(main())
