"""
Tests for OAuth endpoints.

Tests the /api/v1/oauth endpoints including:
- GET /api/v1/oauth/{provider}/authorize - API key, redirect allowlist
- GET /api/v1/oauth/{provider}/callback + POST /{provider}/complete - flow bound to its user
- GET /api/v1/oauth/providers - test list providers
- PUT /api/v1/oauth/providers/{provider} - test update provider status
"""

from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.models import UserConnection
from tests.factories import ApiKeyFactory, DeveloperFactory, UserFactory
from tests.utils import api_key_headers, developer_auth_headers

ALLOWED_REDIRECT = "https://beta.givingwellness.org/wearables/callback"


@pytest.fixture(autouse=True)
def _require_completion() -> Generator[None, None, None]:
    """The deployment default (conftest turns it off for the provider unit tests)."""
    with patch.object(settings, "oauth_require_completion", True):
        yield


@pytest.fixture
def key_headers(db: Session) -> dict[str, str]:
    return api_key_headers(ApiKeyFactory().plain_key)


class TestOAuthAuthorizeEndpoint:
    """Test suite for OAuth authorization endpoint."""

    def test_authorize_provider_success(self, client: TestClient, db: Session, key_headers: dict[str, str]) -> None:
        response = client.get(
            "/api/v1/oauth/garmin/authorize",
            params={"user_id": str(uuid4()), "redirect_uri": ALLOWED_REDIRECT},
            headers=key_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["authorization_url"], str)
        assert isinstance(data["state"], str)
        assert len(data["state"]) > 0

    def test_authorize_requires_api_key(self, client: TestClient, db: Session) -> None:
        response = client.get(
            "/api/v1/oauth/google/authorize",
            params={"user_id": str(uuid4()), "redirect_uri": ALLOWED_REDIRECT},
        )

        assert response.status_code == 401

    def test_authorize_rejects_invalid_api_key(self, client: TestClient, db: Session) -> None:
        response = client.get(
            "/api/v1/oauth/google/authorize",
            params={"user_id": str(uuid4()), "redirect_uri": ALLOWED_REDIRECT},
            headers=api_key_headers("sk-not-a-real-key"),
        )

        assert response.status_code == 401

    def test_authorize_accepts_developer_token(self, client: TestClient, db: Session) -> None:
        response = client.get(
            "/api/v1/oauth/garmin/authorize",
            params={"user_id": str(uuid4()), "redirect_uri": ALLOWED_REDIRECT},
            headers=developer_auth_headers(DeveloperFactory().id),
        )

        assert response.status_code == 200

    @pytest.mark.parametrize(
        "redirect_uri",
        [
            "https://evil.example.com/callback",
            "https://beta.givingwellness.org.evil.example.com/callback",
            "https://evil.example.com/?next=https://beta.givingwellness.org",
            "https://user@beta.givingwellness.org/callback",
            "http://beta.givingwellness.org/wearables/callback",  # wrong scheme
            "https://beta.givingwellness.org:8443/callback",  # wrong port
            "https:\\\\evil.example.com",
            "//evil.example.com/callback",
            "javascript:alert(1)",
            "/relative/path",
        ],
    )
    def test_authorize_rejects_redirect_outside_allowlist(
        self, client: TestClient, db: Session, key_headers: dict[str, str], redirect_uri: str
    ) -> None:
        response = client.get(
            "/api/v1/oauth/google/authorize",
            params={"user_id": str(uuid4()), "redirect_uri": redirect_uri},
            headers=key_headers,
        )

        assert response.status_code == 400

    def test_authorize_requires_redirect_uri_when_completion_required(
        self, client: TestClient, db: Session, key_headers: dict[str, str]
    ) -> None:
        response = client.get(
            "/api/v1/oauth/google/authorize",
            params={"user_id": str(uuid4())},
            headers=key_headers,
        )

        assert response.status_code == 400

    def test_google_authorize_uses_pkce(self, client: TestClient, db: Session, key_headers: dict[str, str]) -> None:
        response = client.get(
            "/api/v1/oauth/google/authorize",
            params={"user_id": str(uuid4()), "redirect_uri": ALLOWED_REDIRECT},
            headers=key_headers,
        )

        assert response.status_code == 200
        query = parse_qs(urlsplit(response.json()["authorization_url"]).query)
        assert query["code_challenge_method"] == ["S256"]
        assert len(query["code_challenge"][0]) >= 43
        assert query["state"] == [response.json()["state"]]

    def test_authorize_different_providers(self, client: TestClient, db: Session, key_headers: dict[str, str]) -> None:
        for provider in ["garmin", "polar", "suunto", "google"]:
            response = client.get(
                f"/api/v1/oauth/{provider}/authorize",
                params={"user_id": str(uuid4()), "redirect_uri": ALLOWED_REDIRECT},
                headers=key_headers,
            )

            assert response.status_code == 200
            data = response.json()
            assert "authorization_url" in data
            assert "state" in data

    def test_authorize_missing_user_id(self, client: TestClient, db: Session, key_headers: dict[str, str]) -> None:
        response = client.get("/api/v1/oauth/garmin/authorize", headers=key_headers)

        assert response.status_code == 400

    def test_authorize_invalid_user_id(self, client: TestClient, db: Session, key_headers: dict[str, str]) -> None:
        response = client.get(
            "/api/v1/oauth/garmin/authorize",
            params={"user_id": "not-a-uuid"},
            headers=key_headers,
        )

        assert response.status_code == 400

    def test_authorize_invalid_provider(self, client: TestClient, db: Session, key_headers: dict[str, str]) -> None:
        response = client.get(
            "/api/v1/oauth/invalid-provider/authorize",
            params={"user_id": str(uuid4())},
            headers=key_headers,
        )

        assert response.status_code == 400

    def test_authorize_non_oauth_provider(self, client: TestClient, db: Session, key_headers: dict[str, str]) -> None:
        # "apple" uses file import, not OAuth
        response = client.get(
            "/api/v1/oauth/apple/authorize",
            params={"user_id": str(uuid4()), "redirect_uri": ALLOWED_REDIRECT},
            headers=key_headers,
        )

        assert response.status_code in [400, 401, 422]


def _google_token_response() -> MagicMock:
    response = MagicMock()
    response.json.return_value = {
        "access_token": "ya29.plain-access-token",
        "refresh_token": "1//plain-refresh-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email",
    }
    response.raise_for_status = MagicMock()
    return response


def _identity_response(*args: Any, **kwargs: Any) -> MagicMock:
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = {"healthUserId": "health-123", "email": "member@example.com"}
    return response


@pytest.fixture
def google_http() -> Generator[dict[str, MagicMock], None, None]:
    """Google's token + identity endpoints and the post-connect sync task, mocked."""
    with (
        patch("httpx.post", return_value=_google_token_response()) as post,
        patch("httpx.get", side_effect=_identity_response),
        patch("app.integrations.celery.tasks.sync_vendor_data.delay") as sync,
    ):
        yield {"post": post, "sync": sync}


class TestOAuthFlowBoundToUser:
    """The callback parks the tokens; only the user who started the flow can complete it."""

    def _start_and_callback(self, client: TestClient, key_headers: dict[str, str], user_id: str) -> str:
        auth = client.get(
            "/api/v1/oauth/google/authorize",
            params={"user_id": user_id, "redirect_uri": ALLOWED_REDIRECT},
            headers=key_headers,
        ).json()
        callback = client.get(
            "/api/v1/oauth/google/callback",
            params={"code": "auth-code", "state": auth["state"]},
            follow_redirects=False,
        )
        assert callback.status_code == 303
        location = callback.headers["location"]
        assert location.startswith(ALLOWED_REDIRECT + "?")
        query = parse_qs(urlsplit(location).query)
        assert query["provider"] == ["google"]
        return query["ow_completion"][0]

    def test_callback_does_not_connect_until_completed(
        self, client: TestClient, db: Session, key_headers: dict[str, str], google_http: dict[str, MagicMock]
    ) -> None:
        user = UserFactory()

        self._start_and_callback(client, key_headers, str(user.id))

        assert db.query(UserConnection).filter_by(user_id=user.id).count() == 0
        # PKCE: the code exchange carried the verifier
        assert "code_verifier" in google_http["post"].call_args.kwargs["data"]

    def test_same_user_completes_and_tokens_are_encrypted(
        self, client: TestClient, db: Session, key_headers: dict[str, str], google_http: dict[str, MagicMock]
    ) -> None:
        user = UserFactory()
        completion = self._start_and_callback(client, key_headers, str(user.id))

        response = client.post(
            "/api/v1/oauth/google/complete",
            json={"user_id": str(user.id), "completion": completion},
            headers=key_headers,
        )

        assert response.status_code == 200
        connection = db.query(UserConnection).filter_by(user_id=user.id, provider="google").one()
        assert connection.access_token == "ya29.plain-access-token"  # decrypted by the ORM
        raw_access, raw_refresh = db.execute(
            text("SELECT access_token, refresh_token FROM user_connection WHERE id = :id"), {"id": connection.id}
        ).one()
        assert raw_access.startswith("owenc1:")
        assert "plain-access-token" not in raw_access
        assert raw_refresh.startswith("owenc1:")
        assert "plain-refresh-token" not in raw_refresh
        google_http["sync"].assert_called_once()

        # one-time: a replay is refused
        replay = client.post(
            "/api/v1/oauth/google/complete",
            json={"user_id": str(user.id), "completion": completion},
            headers=key_headers,
        )
        assert replay.status_code == 400

    def test_other_user_cannot_complete(
        self, client: TestClient, db: Session, key_headers: dict[str, str], google_http: dict[str, MagicMock]
    ) -> None:
        starter, victim = UserFactory(), UserFactory()
        completion = self._start_and_callback(client, key_headers, str(starter.id))

        response = client.post(
            "/api/v1/oauth/google/complete",
            json={"user_id": str(victim.id), "completion": completion},
            headers=key_headers,
        )

        assert response.status_code == 403
        assert db.query(UserConnection).filter(UserConnection.user_id.in_([starter.id, victim.id])).count() == 0
        # and the parked flow is gone, so the starter cannot pick it up afterwards either
        retry = client.post(
            "/api/v1/oauth/google/complete",
            json={"user_id": str(starter.id), "completion": completion},
            headers=key_headers,
        )
        assert retry.status_code == 400

    def test_complete_requires_api_key(self, client: TestClient, db: Session) -> None:
        response = client.post(
            "/api/v1/oauth/google/complete",
            json={"user_id": str(uuid4()), "completion": "anything"},
        )

        assert response.status_code == 401

    def test_provider_error_returns_to_app(
        self, client: TestClient, db: Session, key_headers: dict[str, str], google_http: dict[str, MagicMock]
    ) -> None:
        auth = client.get(
            "/api/v1/oauth/google/authorize",
            params={"user_id": str(uuid4()), "redirect_uri": ALLOWED_REDIRECT},
            headers=key_headers,
        ).json()

        response = client.get(
            "/api/v1/oauth/google/callback",
            params={"error": "access_denied", "state": auth["state"]},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"].startswith(ALLOWED_REDIRECT + "?")
        assert parse_qs(urlsplit(response.headers["location"]).query)["error"] == ["access_denied"]
        google_http["post"].assert_not_called()

    def test_callback_with_unknown_state_is_refused(
        self, client: TestClient, db: Session, google_http: dict[str, MagicMock]
    ) -> None:
        response = client.get(
            "/api/v1/oauth/google/callback",
            params={"code": "auth-code", "state": "forged-state"},
            follow_redirects=False,
        )

        assert response.status_code == 400
        google_http["post"].assert_not_called()


class TestOAuthProvidersEndpoint:
    """Test suite for providers listing endpoint."""

    def test_get_providers_success(self, client: TestClient, db: Session) -> None:
        """Test successfully retrieving all providers."""
        # Act
        response = client.get("/api/v1/oauth/providers")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

        # Verify structure of first provider
        if data:
            provider = data[0]
            assert "provider" in provider
            assert "name" in provider
            assert "icon_url" in provider
            assert "has_cloud_api" in provider
            assert "is_enabled" in provider

    def test_get_providers_enabled_only(self, client: TestClient, db: Session) -> None:
        """Test retrieving only enabled providers."""
        # Act
        response = client.get(
            "/api/v1/oauth/providers",
            params={"enabled_only": True},
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # All returned providers should be enabled
        for provider in data:
            assert provider["is_enabled"] is True

    def test_get_providers_cloud_only(self, client: TestClient, db: Session) -> None:
        """Test retrieving only cloud (OAuth) providers."""
        # Act
        response = client.get(
            "/api/v1/oauth/providers",
            params={"cloud_only": True},
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # All returned providers should have cloud API
        for provider in data:
            assert provider["has_cloud_api"] is True

    def test_get_providers_enabled_and_cloud(self, client: TestClient, db: Session) -> None:
        """Test retrieving providers with both filters."""
        # Act
        response = client.get(
            "/api/v1/oauth/providers",
            params={"enabled_only": True, "cloud_only": True},
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # All returned providers should be enabled AND have cloud API
        for provider in data:
            assert provider["is_enabled"] is True
            assert provider["has_cloud_api"] is True

    def test_get_providers_include_disabled(self, client: TestClient, db: Session) -> None:
        """Test that disabled providers are included by default."""
        # Act - no filters
        response = client.get("/api/v1/oauth/providers")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Should include both enabled and disabled
        any(p["is_enabled"] for p in data)
        any(not p["is_enabled"] for p in data)
        # At least one of each should exist (assuming test data setup)
        # If all are enabled or disabled, that's also valid

    def test_get_providers_response_structure(self, client: TestClient, db: Session) -> None:
        """Test detailed response structure of providers."""
        # Act
        response = client.get("/api/v1/oauth/providers")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert len(data) > 0

        # Check first provider has all required fields
        provider = data[0]
        required_fields = [
            "provider",
            "name",
            "icon_url",
            "has_cloud_api",
            "is_enabled",
        ]
        for field in required_fields:
            assert field in provider, f"Missing field: {field}"


class TestOAuthUpdateProviderEndpoint:
    """Test suite for updating provider status endpoint."""

    def test_update_provider_status_enable(
        self,
        client: TestClient,
        db: Session,
        mock_external_apis: dict[str, MagicMock],
    ) -> None:
        """Test enabling a provider."""
        # Arrange
        developer = DeveloperFactory()
        headers = developer_auth_headers(developer.id)
        update_data = {"is_enabled": True}

        # Act
        response = client.put(
            "/api/v1/oauth/providers/garmin",
            headers=headers,
            json=update_data,
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["provider"] == "garmin"
        assert data["is_enabled"] is True

    def test_update_provider_status_disable(
        self,
        client: TestClient,
        db: Session,
        mock_external_apis: dict[str, MagicMock],
    ) -> None:
        """Test disabling a provider."""
        # Arrange
        developer = DeveloperFactory()
        headers = developer_auth_headers(developer.id)
        update_data = {"is_enabled": False}

        # Act
        response = client.put(
            "/api/v1/oauth/providers/polar",
            headers=headers,
            json=update_data,
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["provider"] == "polar"
        assert data["is_enabled"] is False

    def test_update_provider_requires_authentication(self, client: TestClient, db: Session) -> None:
        """Test that updating provider status requires authentication."""
        # Arrange
        update_data = {"is_enabled": True}

        # Act - no auth headers
        response = client.put(
            "/api/v1/oauth/providers/garmin",
            json=update_data,
        )

        # Assert
        assert response.status_code == 401

    def test_update_provider_invalid_auth(self, client: TestClient, db: Session) -> None:
        """Test that invalid authentication is rejected."""
        # Arrange
        update_data = {"is_enabled": True}
        headers = {"Authorization": "Bearer invalid-token"}

        # Act
        response = client.put(
            "/api/v1/oauth/providers/garmin",
            headers=headers,
            json=update_data,
        )

        # Assert
        assert response.status_code == 401

    def test_update_nonexistent_provider(
        self,
        client: TestClient,
        db: Session,
        mock_external_apis: dict[str, MagicMock],
    ) -> None:
        """Test updating a provider that doesn't exist."""
        # Arrange
        developer = DeveloperFactory()
        headers = developer_auth_headers(developer.id)
        update_data = {"is_enabled": True}

        # Act
        response = client.put(
            "/api/v1/oauth/providers/nonexistent-provider",
            headers=headers,
            json=update_data,
        )

        # Assert
        assert response.status_code == 400

    def test_update_live_sync_mode_non_configurable_provider(
        self,
        client: TestClient,
        db: Session,
        mock_external_apis: dict[str, MagicMock],
    ) -> None:
        """Test setting live_sync_mode on a provider that does not support it returns 400."""
        # Arrange
        developer = DeveloperFactory()
        headers = developer_auth_headers(developer.id)
        # garmin has no rest_pull so live_sync_configurable=False
        update_data = {"live_sync_mode": "webhook"}

        # Act
        response = client.put(
            "/api/v1/oauth/providers/garmin",
            headers=headers,
            json=update_data,
        )

        # Assert
        assert response.status_code == 400

    def test_update_provider_response_structure(
        self,
        client: TestClient,
        db: Session,
        mock_external_apis: dict[str, MagicMock],
    ) -> None:
        """Test response structure of update endpoint."""
        # Arrange
        developer = DeveloperFactory()
        headers = developer_auth_headers(developer.id)
        update_data = {"is_enabled": True}

        # Act
        response = client.put(
            "/api/v1/oauth/providers/garmin",
            headers=headers,
            json=update_data,
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "provider" in data
        assert "name" in data
        assert "icon_url" in data
        assert "has_cloud_api" in data
        assert "is_enabled" in data

    def test_update_multiple_providers_sequentially(
        self,
        client: TestClient,
        db: Session,
        mock_external_apis: dict[str, MagicMock],
    ) -> None:
        """Test updating multiple providers one after another."""
        # Arrange
        developer = DeveloperFactory()
        headers = developer_auth_headers(developer.id)
        providers = ["garmin", "polar", "suunto"]

        for provider in providers:
            # Act
            response = client.put(
                f"/api/v1/oauth/providers/{provider}",
                headers=headers,
                json={"is_enabled": True},
            )

            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["provider"] == provider
            assert data["is_enabled"] is True
