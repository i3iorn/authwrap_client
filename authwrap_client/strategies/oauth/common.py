from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TypedDict, Optional, Protocol, Any

from authwrap_client.exceptions import AuthWrapException


class TokenResponse:
    """Represents an OAuth 2.0 token response (RFC 6749 §5.1)."""
    def __init__(self, access_token: str, token_type: str, expires_in: int, scope: str,
                    refresh_token: Optional[str] = None, **kwargs: Any):
        self.access_token = access_token
        self.token_type = token_type
        self.expires_in = expires_in
        self.refresh_token = refresh_token
        self.scope = scope
        self._additional_fields = kwargs
        self._additional_fields["expires_at"] = datetime.now() + timedelta(seconds=expires_in if expires_in else 0)

    @property
    def expires_at(self) -> datetime:
        """
        Returns the expiration time of the access token.
        This is calculated as the current time plus the expires_in value.
        """
        return self._additional_fields["expires_at"]

    @property
    def is_expired(self) -> bool:
        """
        Checks if the access token is expired.
        Returns True if the current time is greater than or equal to the expiration time.
        """
        return datetime.now() >= self.expires_at

    @property
    def is_valid(self) -> bool:
        """
        Checks if the access token is valid.
        Returns True if the token is not expired and has a non-empty access_token.
        """
        return not self.is_expired and bool(self.access_token)

    def json(self) -> dict[str, Any]:
        """
        Returns the token response as a JSON-serializable dictionary.
        """
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "refresh_token": self.refresh_token,
            "scope": self.scope
        }

    def text(self) -> str:
        """
        Returns the token response as a JSON string.
        This is useful for logging or debugging purposes.
        """
        return str(self.json())

    def extensions(self) -> dict[str, Any]:
        """
        Returns any additional fields included in the token response.
        This is useful for implementations that extend the basic token response.
        """
        return self._additional_fields


class DeviceAuthorizationResponse(TypedDict):
    """Represents a Device Authorization response (RFC 8628 §3.1)."""
    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: Optional[int]


class HTTPClientSyncProtocol(Protocol):
    """
    Minimal interface for a synchronous HTTP client that can be used
    to perform OAuth token endpoint requests.
    """

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        ...


class HTTPClientAsyncProtocol(Protocol):
    """
    Minimal interface for an asynchronous HTTP client that can be used
    to perform OAuth token endpoint requests.
    """

    async def request(self, method: str, url: str, **kwargs: Any) -> Any:
        ...


class OAuthError(AuthWrapException):
    """Generic exception for OAuth-related failures."""
