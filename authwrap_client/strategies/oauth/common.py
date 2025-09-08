from typing import TypedDict, Optional, Protocol, Any

from authwrap_client.exceptions import AuthWrapException


class TokenResponse(TypedDict, total=False):
    """Represents an OAuth 2.0 token response (RFC 6749 §5.1)."""
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str
    scope: str
    # Implementations may include additional fields (e.g., id_token, issued_at)


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
