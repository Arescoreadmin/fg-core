"""FA-2: Connector credential pre-flight validation acceptance tests.

Acceptance criteria (all exercised without network calls, no mocks of internal
business logic — only the external OIDC discovery HTTP call is patched):

  FA2-1  Valid UUID + Azure AD 200 → device-code flow proceeds (mocked MSAL).
  FA2-2  Invalid UUID format → 422 CONNECTOR_INVALID_TENANT_FORMAT before any
         network call.
  FA2-3  Valid UUID + Azure AD 400 → 422 CONNECTOR_TENANT_NOT_FOUND.
  FA2-4  Valid UUID + Azure AD 404 → 422 CONNECTOR_TENANT_NOT_FOUND.
  FA2-5  Valid UUID + network timeout → 502 CONNECTOR_PREFLIGHT_TIMEOUT.
  FA2-6  Valid UUID + Azure AD 503 → 502 CONNECTOR_PREFLIGHT_FAILED.
  FA2-7  Unit: validate_msgraph_tenant_preflight raises MsgraphTenantFormatError
         on malformed input without any HTTP call.
  FA2-8  Unit: validate_msgraph_tenant_preflight raises MsgraphTenantNotFoundError
         on 400 from OIDC endpoint.
"""

from __future__ import annotations

import os
import uuid
from typing import Any
from unittest.mock import MagicMock, patch

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_MSAL_CLIENT_ID", "test-client-id-for-fa2")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import sys

import pytest
from fastapi.testclient import TestClient

from services.connectors.msgraph.preflight import (
    MsgraphTenantFormatError,
    MsgraphTenantNotFoundError,
    validate_msgraph_tenant_preflight,
)

_TENANT_ID = "tenant-fa2-preflight"
_VALID_AZURE_TENANT = str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(build_app: object) -> TestClient:
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    return TestClient(app, headers={"X-API-Key": key})


def _create_engagement(client: TestClient) -> str:
    resp = client.post(
        "/field-assessment/engagements",
        json={
            "client_name": "FA2 Test Corp",
            "assessor_id": "assessor-fa2",
            "assessment_type": "ai_governance",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _oidc_ok_response() -> MagicMock:
    r = MagicMock()
    r.status_code = 200
    return r


def _oidc_response(status: int) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    return r


def _mock_msal_flow() -> dict[str, Any]:
    return {
        "user_code": "TESTCODE",
        "verification_uri": "https://microsoft.com/devicelogin",
        "expires_in": 900,
        "message": "Go to https://microsoft.com/devicelogin and enter TESTCODE",
    }


# ---------------------------------------------------------------------------
# FA2-1: Valid tenant → device-code flow initiated
# ---------------------------------------------------------------------------


class TestFA21ValidTenant:
    def test_fa2_1_valid_tenant_proceeds_to_device_flow(
        self, client: TestClient
    ) -> None:
        """Valid UUID + Azure AD 200 → 200 response with user_code."""
        eid = _create_engagement(client)

        mock_msal = MagicMock()
        mock_app = MagicMock()
        mock_app.initiate_device_flow.return_value = _mock_msal_flow()
        mock_msal.PublicClientApplication.return_value = mock_app

        with (
            patch("services.connectors.msgraph.preflight.httpx") as mock_httpx,
            patch.dict(sys.modules, {"msal": mock_msal}),
        ):
            mock_httpx.get.return_value = _oidc_ok_response()
            mock_httpx.TimeoutException = Exception

            resp = client.post(
                f"/field-assessment/engagements/{eid}/connector-runs/msgraph/initiate",
                json={
                    "azure_tenant_id": _VALID_AZURE_TENANT,
                    "operator_name": "testop",
                    "operator_org": "FrostGate",
                },
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["user_code"] == "TESTCODE"
        assert "verification_uri" in body
        assert "run_id" in body

        # Confirm preflight was actually called with the correct tenant
        mock_httpx.get.assert_called_once()
        call_url = mock_httpx.get.call_args[0][0]
        assert (
            _VALID_AZURE_TENANT in call_url
            or str(uuid.UUID(_VALID_AZURE_TENANT)) in call_url
        )


# ---------------------------------------------------------------------------
# FA2-2: Invalid UUID format → 422 before network call
# ---------------------------------------------------------------------------


class TestFA22InvalidFormat:
    @pytest.mark.parametrize(
        "bad_tenant",
        [
            "not-a-uuid",
            "12345",
            "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "",
            "00000000-0000-0000-0000-00000000000Z",
        ],
    )
    def test_fa2_2_invalid_uuid_returns_422(
        self, client: TestClient, bad_tenant: str
    ) -> None:
        """Non-UUID azure_tenant_id → 422 with CONNECTOR_INVALID_TENANT_FORMAT."""
        eid = _create_engagement(client)

        with patch("services.connectors.msgraph.preflight.httpx") as mock_httpx:
            resp = client.post(
                f"/field-assessment/engagements/{eid}/connector-runs/msgraph/initiate",
                json={
                    "azure_tenant_id": bad_tenant,
                    "operator_name": "testop",
                    "operator_org": "FrostGate",
                },
            )
            # No network call should have been made
            mock_httpx.get.assert_not_called()

        assert resp.status_code == 422, resp.text
        assert resp.json()["detail"]["code"] == "CONNECTOR_INVALID_TENANT_FORMAT"


# ---------------------------------------------------------------------------
# FA2-3 & FA2-4: Azure AD 400 / 404 → 422 CONNECTOR_TENANT_NOT_FOUND
# ---------------------------------------------------------------------------


class TestFA23TenantNotFound:
    @pytest.mark.parametrize("azure_status", [400, 404])
    def test_fa2_3_nonexistent_tenant_returns_422(
        self, client: TestClient, azure_status: int
    ) -> None:
        """Azure AD {400,404} → 422 CONNECTOR_TENANT_NOT_FOUND."""
        eid = _create_engagement(client)

        with patch("services.connectors.msgraph.preflight.httpx") as mock_httpx:
            mock_httpx.get.return_value = _oidc_response(azure_status)
            mock_httpx.TimeoutException = Exception

            resp = client.post(
                f"/field-assessment/engagements/{eid}/connector-runs/msgraph/initiate",
                json={
                    "azure_tenant_id": _VALID_AZURE_TENANT,
                    "operator_name": "testop",
                    "operator_org": "FrostGate",
                },
            )

        assert resp.status_code == 422, resp.text
        assert resp.json()["detail"]["code"] == "CONNECTOR_TENANT_NOT_FOUND"


# ---------------------------------------------------------------------------
# FA2-5: Network timeout → 502 CONNECTOR_PREFLIGHT_TIMEOUT
# ---------------------------------------------------------------------------


class TestFA25NetworkTimeout:
    def test_fa2_5_timeout_returns_502(self, client: TestClient) -> None:
        """Network timeout during pre-flight → 502 CONNECTOR_PREFLIGHT_TIMEOUT."""
        eid = _create_engagement(client)

        with patch("services.connectors.msgraph.preflight.httpx") as mock_httpx:
            # Make TimeoutException the exception class and have get() raise it
            class _Timeout(Exception):
                pass

            mock_httpx.TimeoutException = _Timeout
            mock_httpx.get.side_effect = _Timeout("timed out")

            resp = client.post(
                f"/field-assessment/engagements/{eid}/connector-runs/msgraph/initiate",
                json={
                    "azure_tenant_id": _VALID_AZURE_TENANT,
                    "operator_name": "testop",
                    "operator_org": "FrostGate",
                },
            )

        assert resp.status_code == 502, resp.text
        assert resp.json()["detail"]["code"] == "CONNECTOR_PREFLIGHT_TIMEOUT"


# ---------------------------------------------------------------------------
# FA2-6: Azure AD 503 → 502 CONNECTOR_PREFLIGHT_FAILED
# ---------------------------------------------------------------------------


class TestFA26AzureUnavailable:
    def test_fa2_6_azure_503_returns_502(self, client: TestClient) -> None:
        """Unexpected Azure AD status (503) → 502 CONNECTOR_PREFLIGHT_FAILED."""
        eid = _create_engagement(client)

        with patch("services.connectors.msgraph.preflight.httpx") as mock_httpx:
            mock_httpx.get.return_value = _oidc_response(503)
            mock_httpx.TimeoutException = Exception

            resp = client.post(
                f"/field-assessment/engagements/{eid}/connector-runs/msgraph/initiate",
                json={
                    "azure_tenant_id": _VALID_AZURE_TENANT,
                    "operator_name": "testop",
                    "operator_org": "FrostGate",
                },
            )

        assert resp.status_code == 502, resp.text
        assert resp.json()["detail"]["code"] == "CONNECTOR_PREFLIGHT_FAILED"


# ---------------------------------------------------------------------------
# FA2-7 & FA2-8: Unit tests for validate_msgraph_tenant_preflight
# ---------------------------------------------------------------------------


class TestFA27PrefligthUnit:
    def test_fa2_7_malformed_uuid_raises_format_error(self) -> None:
        """validate_msgraph_tenant_preflight raises MsgraphTenantFormatError without HTTP."""
        with patch("services.connectors.msgraph.preflight.httpx") as mock_httpx:
            with pytest.raises(MsgraphTenantFormatError) as exc_info:
                validate_msgraph_tenant_preflight("not-a-uuid")
            mock_httpx.get.assert_not_called()

        assert exc_info.value.code == "CONNECTOR_INVALID_TENANT_FORMAT"

    def test_fa2_8_azure_400_raises_tenant_not_found(self) -> None:
        """validate_msgraph_tenant_preflight raises MsgraphTenantNotFoundError on 400."""
        with patch("services.connectors.msgraph.preflight.httpx") as mock_httpx:
            mock_httpx.get.return_value = _oidc_response(400)
            mock_httpx.TimeoutException = Exception

            with pytest.raises(MsgraphTenantNotFoundError) as exc_info:
                validate_msgraph_tenant_preflight(str(uuid.uuid4()))

        assert exc_info.value.code == "CONNECTOR_TENANT_NOT_FOUND"
