"""Security hardening: log redaction, response headers, API docs, provider tokens at rest."""

from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.middlewares import _log_path
from app.models import UserConnection
from app.utils.redirects import is_allowed_redirect_uri, with_query_params
from app.utils.token_crypto import decrypt_token, encrypt_token
from tests.factories import UserConnectionFactory, UserFactory


def _request(query: str) -> Request:
    scope = {"type": "http", "method": "GET", "path": "/api/v1/oauth/google/callback", "headers": []}
    return Request({**scope, "query_string": query.encode()})


class TestLogRedaction:
    def test_oauth_code_and_state_are_masked(self) -> None:
        logged = _log_path(_request("code=4/0AVG-secret-code&state=abc123&scope=openid"))

        assert "secret-code" not in logged
        assert "abc123" not in logged
        assert "code=REDACTED" in logged
        assert "state=REDACTED" in logged
        assert "scope=openid" in logged


class TestResponseHeaders:
    def test_hsts_and_nosniff_on_every_response(self, client: TestClient) -> None:
        response = client.get("/")

        assert response.headers["Strict-Transport-Security"].startswith("max-age=31536000")
        assert response.headers["X-Content-Type-Options"] == "nosniff"

    def test_api_docs_are_not_served(self, client: TestClient) -> None:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path).status_code == 404, path


class TestRedirectAllowlist:
    def test_exact_origin_only(self) -> None:
        allowed = ["https://app.example.com"]

        assert is_allowed_redirect_uri("https://app.example.com/cb?x=1", allowed)
        assert is_allowed_redirect_uri("https://APP.example.com/cb", allowed)
        assert not is_allowed_redirect_uri("https://app.example.com.evil.com/cb", allowed)
        assert not is_allowed_redirect_uri("https://app.example.com@evil.com/cb", allowed)
        assert not is_allowed_redirect_uri("https://app.example.com:99999/cb", allowed)
        assert not is_allowed_redirect_uri("", allowed)

    def test_query_params_are_appended(self) -> None:
        assert with_query_params("https://a.example/cb?x=1", {"y": "2 3"}) == "https://a.example/cb?x=1&y=2+3"


class TestProviderTokensAtRest:
    def test_round_trip_and_ciphertext_differs(self) -> None:
        first, second = encrypt_token("secret"), encrypt_token("secret")

        assert first != second  # random IV per value
        assert decrypt_token(first) == "secret"
        assert decrypt_token(second) == "secret"
        assert encrypt_token(None) is None
        assert decrypt_token(None) is None

    def test_orm_writes_ciphertext_and_reads_plaintext(self, db: Session) -> None:
        connection = UserConnectionFactory(access_token="access-xyz", refresh_token="refresh-xyz")
        db.flush()

        raw = db.execute(
            text("SELECT access_token, refresh_token FROM user_connection WHERE id = :id"), {"id": connection.id}
        ).one()
        assert raw[0].startswith("owenc1:")
        assert "access-xyz" not in raw[0]
        assert raw[1].startswith("owenc1:")
        assert "refresh-xyz" not in raw[1]

        db.expire_all()
        reloaded = db.get(UserConnection, connection.id)
        assert reloaded is not None
        assert (reloaded.access_token, reloaded.refresh_token) == ("access-xyz", "refresh-xyz")

    def test_legacy_plaintext_rows_still_read(self, db: Session) -> None:
        """Rows written before encryption (until the migration rewrites them) keep working."""
        user = UserFactory()
        connection_id = uuid4()
        db.execute(
            text(
                "INSERT INTO user_connection "
                "(id, user_id, provider, access_token, refresh_token, status, created_at, updated_at) "
                "VALUES (:id, :user_id, 'google', 'legacy-access', 'legacy-refresh', 'active', now(), now())"
            ),
            {"id": connection_id, "user_id": user.id},
        )

        reloaded = db.get(UserConnection, connection_id)
        assert reloaded is not None
        assert reloaded.access_token == "legacy-access"
