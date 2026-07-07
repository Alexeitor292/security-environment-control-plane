"""HTTPS transport for the worker discovery-admission client (SECP-B6 MB-1 item-1).

The shipped production realization of the ``AdmissionTransport`` seam
(`secp_worker.target_discovery.admission_client.AdmissionTransport`): CA-validated HTTPS to the
internal control-plane admission endpoint. It lives OUTSIDE ``secp_worker/target_discovery`` on
purpose — the read-only discovery package must stay transport-free (its only permitted transport is
the reviewed SSH channel; the SECP-B5 architecture guard forbids ``httpx`` there). The composition
wiring constructs this transport and injects it into the discovery client. ``httpx`` is imported
lazily inside ``post`` so importing this module has no network dependency.
"""

from __future__ import annotations


class HttpxAdmissionTransport:
    """CA-validated HTTPS transport to the internal admission endpoint.

    The base URL + CA bundle are deployment-local worker settings. TLS server-certificate validation
    uses the configured CA when provided, else the system trust store — it is NEVER disabled
    (``verify`` is provably never ``False``). Worker authentication is the Ed25519 signed-nonce
    proof carried in the request bodies, NOT an X.509 client certificate (this is not mTLS)."""

    def __init__(self, *, base_url: str, ca_path: str = "", timeout: float = 10.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._ca_path = ca_path
        self._timeout = timeout

    def __repr__(self) -> str:
        return f"HttpxAdmissionTransport(base_url={self._base_url!r})"

    @property
    def base_url(self) -> str:
        return self._base_url

    def post(self, path: str, payload: dict) -> tuple[int, dict]:
        import httpx

        verify: str | bool = self._ca_path if self._ca_path else True
        with httpx.Client(verify=verify, timeout=self._timeout) as client:
            resp = client.post(self._base_url + path, json=payload)
        try:
            body = resp.json()
        except ValueError:
            body = {}
        # Unwrap FastAPI's error envelope so callers see the closed reason code directly.
        if isinstance(body, dict) and isinstance(body.get("detail"), dict):
            body = body["detail"]
        if not isinstance(body, dict):
            body = {}
        return resp.status_code, body
