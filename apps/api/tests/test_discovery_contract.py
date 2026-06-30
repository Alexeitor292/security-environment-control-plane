"""Slice 5 — discovery contract extension (optional protocol, typed errors)."""

from __future__ import annotations

import json
import logging
import pickle

import pytest
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, ConfigDict
from secp_plugin_api.v1 import (
    DiscoveredResource,
    DiscoveryProtocol,
    DiscoveryRequest,
    DiscoveryResult,
    ProviderCredential,
    UnsupportedCapabilityError,
)
from secp_plugin_proxmox import ProxmoxPlugin
from secp_plugin_simulator import SimulatorPlugin


def test_discovery_protocol_is_optional():
    # The Proxmox plugin implements discovery; the Simulator does not.
    assert isinstance(ProxmoxPlugin(), DiscoveryProtocol)
    assert not isinstance(SimulatorPlugin(), DiscoveryProtocol)


def test_unsupported_capability_error_carries_context():
    err = UnsupportedCapabilityError("proxmox", "apply")
    assert err.plugin == "proxmox" and err.capability == "apply"
    assert "apply" in str(err)


def test_provider_credential_repr_is_redacted():
    cred = ProviderCredential.from_secret("super-secret-token")
    assert "super-secret-token" not in repr(cred)
    assert "super-secret-token" not in str(cred)
    assert "redacted" in repr(cred)
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="credential=%s",
        args=(cred,),
        exc_info=None,
    )
    assert "super-secret-token" not in logging.Formatter("%(message)s").format(record)
    assert "super-secret-token" not in f"{cred}"
    assert cred.reveal_secret() == "super-secret-token"
    with pytest.raises(AttributeError):
        _ = cred.secret  # type: ignore[attr-defined]


def test_provider_credential_refuses_common_serialization():
    secret = "super-secret-token"
    cred = ProviderCredential.from_secret(secret)

    with pytest.raises(TypeError) as json_exc:
        json.dumps(cred)
    assert secret not in str(json_exc.value)

    with pytest.raises(TypeError) as dict_exc:
        dict(cred)  # type: ignore[call-overload]
    assert secret not in str(dict_exc.value)

    for pickle_call in (pickle.dumps, lambda value: value.__getstate__()):
        with pytest.raises(TypeError) as exc:
            pickle_call(cred)
        assert secret not in str(exc.value)


def test_provider_credential_does_not_leak_through_pydantic_or_fastapi_encoding():
    secret = "super-secret-token"
    cred = ProviderCredential.from_secret(secret)

    class Holder(BaseModel):
        model_config = ConfigDict(arbitrary_types_allowed=True)

        credential: ProviderCredential

    holder = Holder(credential=cred)
    assert secret not in repr(holder.model_dump())
    with pytest.raises(Exception) as pydantic_exc:
        holder.model_dump_json()
    assert secret not in str(pydantic_exc.value)

    with pytest.raises(ValueError) as fastapi_exc:
        jsonable_encoder(cred)
    assert secret not in str(fastapi_exc.value)


def test_discovery_models_construct():
    req = DiscoveryRequest(
        target_id="t", plugin_name="proxmox", config={"base_url": "https://x.example.test"}
    )
    res = DiscoveryResult(
        ok=True,
        resources=[
            DiscoveredResource(resource_type="node", provider_external_id="n1", display_name="n1")
        ],
        summary={"total": 1},
    )
    assert req.scope is None
    assert res.resources[0].resource_type == "node"
