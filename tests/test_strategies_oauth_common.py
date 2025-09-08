import pytest
from freezegun import freeze_time
from datetime import datetime, timedelta

from authwrap_client.strategies.oauth.common import TokenResponse


def test_token_response_creation():
    token = TokenResponse(
        access_token="abc123",
        token_type="Bearer",
        expires_in=3600,
        scope="read write",
        refresh_token="refresh456",
        custom_field="extra"
    )

    assert token.access_token == "abc123"
    assert token.token_type == "Bearer"
    assert token.expires_in == 3600
    assert token.refresh_token == "refresh456"
    assert token.scope == "read write"
    assert token.extensions()["custom_field"] == "extra"
    assert isinstance(token.expires_at, datetime)
    assert token.expires_at > datetime.now()


def test_token_response_is_expired_false():
    token = TokenResponse(
        access_token="abc123",
        token_type="Bearer",
        expires_in=5,
        scope="read"
    )
    assert token.is_expired is False
    assert token.is_valid is True


def test_token_response_is_expired_true():
    """Token should report expired if current time > expires_at."""
    with freeze_time("2025-01-01T12:00:00") as frozen:
        token = TokenResponse(
            access_token="abc123",
            token_type="Bearer",
            expires_in=1,
            scope="read"
        )

    # Jump forward in time
    with freeze_time("2025-01-01T12:00:02"):
        assert token.is_expired is True
        assert token.is_valid is False


def test_token_response_is_invalid_if_no_access_token():
    token = TokenResponse(
        access_token="",
        token_type="Bearer",
        expires_in=3600,
        scope="read"
    )
    assert token.is_valid is False


def test_token_response_json_method():
    token = TokenResponse(
        access_token="abc123",
        token_type="Bearer",
        expires_in=3600,
        scope="read",
        refresh_token="refresh456"
    )
    data = token.json()

    assert isinstance(data, dict)
    assert data["access_token"] == "abc123"
    assert data["refresh_token"] == "refresh456"
    assert data["scope"] == "read"


def test_token_response_text_method():
    token = TokenResponse(
        access_token="abc123",
        token_type="Bearer",
        expires_in=3600,
        scope="read"
    )
    assert isinstance(token.text(), str)
    assert "access_token" in token.text()
    assert "abc123" in token.text()


def test_token_response_extensions_includes_expires_at():
    token = TokenResponse(
        access_token="abc123",
        token_type="Bearer",
        expires_in=3600,
        scope="read"
    )
    ext = token.extensions()
    assert "expires_at" in ext
    assert isinstance(ext["expires_at"], datetime)
