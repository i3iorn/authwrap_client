import base64
from typing import Tuple, Optional, Dict, Type

from authwrap_client.strategies.oauth.flow_protocol import BaseAuthFlowProtocol
from authwrap_client.strategies.oauth.common import OAuthError, TokenResponse
from .client_credentials import ClientCredentialsFlow
from .implicit import ImplicitFlow
from .password_credentials import PasswordCredentialsFlow

__all__ = [
    "settle_clients",
    "_basic_auth_header",
    "get_auth_flow_class",
    "ClientCredentialsFlow",
    "PasswordCredentialsFlow",
    "ImplicitFlow",
]

_sclient: Optional[object] = None
_aclient: Optional[object] = None


def settle_clients(sync_client, async_client) -> Tuple["Session", "AsyncClient"]:
    """Return sync/async HTTP clients, creating and caching defaults if needed."""
    global _sclient, _aclient
    if not sync_client:
        import requests

        sync_client = requests.Session()
    _sclient = sync_client
    if not async_client:
        import httpx

        async_client = httpx.AsyncClient()
    _aclient = async_client
    return sync_client, async_client


def _basic_auth_header(client_id: Optional[str], client_secret: Optional[str]) -> Dict[str, str]:
    """Build a Basic auth header. Raises OAuthError if creds missing."""
    if not client_id or not client_secret:
        raise OAuthError("client_id and client_secret are required for this operation")
    token = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/x-www-form-urlencoded",
    }


def get_auth_flow_class(flow_name: str) -> Type[BaseAuthFlowProtocol]:
    """
    Get the appropriate OAuth2 flow class based on the flow name.

    Args:
        flow_name: The name of the OAuth2 flow (e.g., "client_credentials", "password", "implicit").

    Returns:
        A class implementing the corresponding OAuth2 flow protocol.

    Raises:
        ValueError: If the flow name is not recognized.
    """
    if flow_name == "client_credentials":
        return ClientCredentialsFlow
    elif flow_name == "password":
        return PasswordCredentialsFlow
    elif flow_name == "implicit":
        return ImplicitFlow
    else:
        raise ValueError(f"Unknown OAuth2 flow: {flow_name}")
