"""System routes: health, current principal, plugin health."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from secp_api.auth import Principal
from secp_api.deps import current_principal
from secp_api.registry import get_registry
from secp_api.schemas import PluginOut, PrincipalOut

router = APIRouter(tags=["system"])


@router.get("/health")
def health() -> dict:
    """Liveness probe used by Docker Compose and load balancers."""
    return {"status": "ok"}


@router.get("/api/v1/me", response_model=PrincipalOut)
def me(principal: Principal = Depends(current_principal)) -> PrincipalOut:
    return PrincipalOut(
        user_id=principal.user_id,
        organization_id=principal.organization_id,
        email=principal.email,
        permissions=sorted(p.value for p in principal.permissions),
        is_dev_fallback=principal.is_dev_fallback,
    )


@router.get("/api/v1/plugins", response_model=list[PluginOut])
def plugins(_: Principal = Depends(current_principal)) -> list[PluginOut]:
    reports = get_registry().health_all()
    return [
        PluginOut(
            name=r.name,
            version=r.version,
            contract_version=r.contract_version,
            healthy=r.healthy,
            simulated=r.simulated,
            capabilities=r.capabilities,
        )
        for r in reports
    ]
