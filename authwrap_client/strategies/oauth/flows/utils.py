from __future__ import annotations
import base64
from typing import Optional, Tuple, Dict

from authwrap_client.strategies.oauth.common import OAuthError, TokenResponse

_sclient: Optional[object] = None
_aclient: Optional[object] = None


def settle_clients(sync_client, async_client) -> Tuple["Session", "AsyncClient"]:
    """Return sync/async HTTP clients, creating and caching defaults if needed.

    Caches created clients so repeated flow construction can reuse them.
    """
    global _sclient, _aclient
    if not sync_client and not _sclient:
        try:
            import requests
        except ImportError as e:
            raise ImportError("requests is required for sync HTTP client support") from e
        sync_client = requests.Session()
    _sclient = sync_client
    if not async_client and not _aclient:
        try:
            import httpx
        except ImportError as e:
            raise ImportError("httpx is required for async HTTP client support") from e
        async_client = httpx.Client
    _aclient = async_client
    return sync_client, async_client


def _basic_auth_header(client_id: Optional[str], client_secret: Optional[str]) -> Dict[str, str]:
    if not client_id or not client_secret:
        raise OAuthError("client_id and client_secret are required for this operation")
    token = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/x-www-form-urlencoded",
    }


def sanitize_token_response(data: dict, fallback_scope: str = "") -> TokenResponse:
    return TokenResponse(
        access_token=data.get("access_token", ""),
        token_type=data.get("token_type", ""),
        expires_in=int(data.get("expires_in", 0) or 0),
        refresh_token=data.get("refresh_token", ""),
        scope=data.get("scope", fallback_scope),
    )

__all__ = [
    "settle_clients",
    "_basic_auth_header",
    "sanitize_token_response",
]

