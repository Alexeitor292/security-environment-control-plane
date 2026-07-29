"""Internal controller-enrollment signer READINESS route (SECP-PR5H-B2, 2b-3c-c, review R4).

One fixed, code-owned GET on :data:`~secp_api.signer_readiness.SIGNER_READINESS_PATH`. It is NOT
mounted on the public ``/api/v1`` surface; in a deployed controller it is reached only over the
controller's CA-validated HTTPS origin by the root installer's management-plane observer, which may
not import ``secp_api`` and therefore cannot otherwise learn the API's ACTUAL effective signer or
reach the root-owned broker socket as the API's peer.

It is a PRIVATE surface (2b-3c-c Defect-3 B). The fixed readiness ORIGIN GATE is attached as a
ROUTER-level dependency, so it runs BEFORE the route body: an unauthorized caller never reaches the
observation, never opens or connects the broker socket, and never performs the no-sign exchange. A
missing, duplicated, malformed or wrong gate value — and an unconfigured controller with no gate
file at all — are ALL the same bare ``404 {"code": "not_found"}``, disclosing no distinction. A
PRESENT gate that cannot be proven safe is a bounded 503 instead, so a configured control that fails
to load never degrades into an open surface. There is no feature flag: the gate file IS the
configuration.

Starlette resolves the METHOD before it runs dependencies, so a bare ``@router.get`` would answer an
unauthorized ``POST`` on this path with ``405 Method Not Allowed`` — which discloses that the path
exists. Every other verb is therefore bound to one explicit refusal handler, so an unauthorized
caller sees the same ``404`` for every method and can learn nothing from the difference. An
AUTHORIZED caller still gets the honest ``405``: the gate dependency has already run by then, so the
distinction is only ever visible to a party that already holds the secret.

The route takes no path parameter, no query parameter and no body, performs no mutation, requests no
signature, and exposes no root operation — every fact it reports is read from the running process's
own state (see :mod:`secp_api.signer_readiness`). The response is the strict, versioned, canonical,
bounded, MINIMIZED readiness payload: closed status vocabularies plus domain-separated binding
digests, never a raw installation identifier. A payload that fails its own schema is refused with a
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
from secp_api.signer_readiness_origin import require_enrollment_signer_readiness_origin

router = APIRouter(
    prefix=SIGNER_READINESS_PREFIX,
    tags=["internal-controller"],
    # ROUTER-level, so the origin gate is proven before ANY route body on this prefix runs.
    dependencies=[Depends(require_enrollment_signer_readiness_origin)],
    redirect_slashes=False,
)


#: every method other than the one supported GET, bound so the gate always runs first.
_NON_READ_METHODS = ("POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


@router.api_route("/readiness", methods=list(_NON_READ_METHODS), include_in_schema=False)
def signer_readiness_method_not_supported() -> Response:
    """Reached ONLY by a caller that already proved the gate (the router dependency runs first).

    This surface is read-only: it never mutates, so the honest refusal for an authorized caller
    is 405. Its real purpose is to keep the UNAUTHORIZED response identical across every verb --
    without it, Starlette would reject the method before the gate ran and answer 405, telling an
    anonymous prober that the path exists."""
    return JSONResponse(
        status_code=405, content={"error": {"code": "signer_readiness_method_not_supported"}}
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
