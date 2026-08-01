"""Live-socket API gates (SECP-PR5H socket gate).

Deliberately OUTSIDE the canonical sharded corpus (`.ci/pytest-suite.json` `roots`); see the
`exclusions` entry for `test_api_read_after_write_over_socket.py` for the full justification. A
package (not a bare directory) so `live_api_server` imports as `socket_gate_tests.live_api_server`
via the `apps/api` entry already present in `[tool.pytest.ini_options] pythonpath`, rather than
depending on pytest's rootdir insertion.
"""
