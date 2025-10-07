from __future__ import annotations

import base64
from typing import Optional, Tuple, Dict

from authwrap_client.strategies.oauth.common import OAuthError, TokenResponse

_sclient: Optional[object] = None
_aclient: Optional[object] = None


def settle_clients(sync_client: Optional[object], async_client: Optional[object]) -> Tuple[object, Optional[object]]:
    """Return sync/async HTTP clients, creating and caching defaults if needed.

    Only the sync client is created by default. The async client is optional and
    left as-is unless explicitly provided, avoiding unnecessary dependencies.
    Returns a tuple of (sync_client_instance, async_client_or_none).
    """
    global _sclient, _aclient

    # Sync client
    if sync_client is None:
        if _sclient is None:
            try:
                import requests
            except ImportError as e:
                raise ImportError("requests is required for sync HTTP client support") from e
            _sclient = requests.Session()
        sync_client = _sclient
    else:
        _sclient = sync_client

    # Async client (optional; do not import httpx unless provided by caller)
    if async_client is None:
        async_client = _aclient  # May be None if never set
    else:
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


# --------- Naming-friendly aliases (backwards compatible) ---------

def get_or_create_http_clients(sync_client: Optional[object], async_client: Optional[object]) -> Tuple[object, Optional[object]]:
    return settle_clients(sync_client, async_client)


def build_basic_authorization_header(client_id: Optional[str], client_secret: Optional[str]) -> Dict[str, str]:
    return _basic_auth_header(client_id, client_secret)


def build_token_response_from_dict(data: dict, fallback_scope: str = "") -> TokenResponse:
    return sanitize_token_response(data, fallback_scope)

__all__ = [
    "settle_clients",
    "_basic_auth_header",
    "sanitize_token_response",
    "get_or_create_http_clients",
    "build_basic_authorization_header",
    "build_token_response_from_dict",
]
