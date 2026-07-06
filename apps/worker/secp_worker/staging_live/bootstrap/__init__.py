"""Worker-only host-bootstrap authority model for live staging-lab provisioning (SECP-B3).

Deliberately UNWIRED: normal API/UI/worker runtime never constructs a live bootstrap executor, and
nothing here contacts an SSH endpoint, host, network, or CA. It defines the typed, finite bootstrap
authority: a generated SECP ownership namespace, a closed set of typed host operations (never
arbitrary shell / caller strings), and a deployment-local bootstrap-credential seam whose shipped
default refuses. The one-time SSH credential is supplied ONLY through deployment-local injection and
is disposed from memory after use; it never enters the API, database, audit, plan, logs, or Git.
"""
