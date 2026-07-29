"""Internal controller-enrollment signer READINESS route (SECP-PR5H-B2, 2b-3c-c, review R4).

One fixed, code-owned GET on :data:`~secp_api.signer_readiness.SIGNER_READINESS_PATH`. It is NOT
mounted on the public ``/api/v1`` surface; in a deployed controller it is reached only over the
controller's CA-validated HTTPS origin by the root installer's management-plane observer, which may
not import ``secp_api`` and therefore cannot otherwise learn the API's ACTUAL effective signer or
reach the root-owned broker socket as the API's peer.

The route takes no path parameter, no query parameter and no body, performs no mutation, requests no
signature, and exposes no root operation — every fact it reports is read from the running process's
own state (see :mod:`secp_api.signer_readiness`). The response is the strict, versioned, canonical,
bounded, secret-free readiness payload; a payload that fails its own schema is refused with a
bounded closed code rather than served.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from secp_api.deps import db_session, get_enrollment_offer_signer
from secp_api.enrollment_signer_client import EnrollmentOfferSignerClient
from secp_api.signer_readiness import (
    SIGNER_READINESS_PREFIX,
    observe_signer_readiness,
    render_signer_readiness,
)

router = APIRouter(
    prefix=SIGNER_READINESS_PREFIX, tags=["internal-controller"], redirect_slashes=False
)


@router.get("/readiness")
def signer_readiness(
    session: Session = Depends(db_session),
    # the app's REAL signer dependency — the effective object is classified by exact type identity,
    # so this route reports what the enrollment service would actually use, not what a file claims.
    signer: EnrollmentOfferSignerClient = Depends(get_enrollment_offer_signer),
) -> Response:
    try:
        payload = observe_signer_readiness(session, signer)
        raw = render_signer_readiness(payload)
    except ValueError as exc:  # a payload that fails its OWN schema/bound is never served
        return JSONResponse(status_code=503, content={"error": {"code": str(exc)}})
    except Exception:  # noqa: BLE001 - any unexpected fault is a bounded closed refusal
        return JSONResponse(
            status_code=503, content={"error": {"code": "signer_readiness_unavailable"}}
        )
    return Response(content=raw, media_type="application/json")
