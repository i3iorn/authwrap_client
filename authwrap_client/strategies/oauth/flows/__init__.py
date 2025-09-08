from typing import Type

from authwrap_client.strategies.oauth.flow_protocol import BaseAuthFlowProtocol
from .utils import settle_clients, _basic_auth_header, sanitize_token_response
from .client_credentials import ClientCredentialsFlow
from .implicit import ImplicitFlow
from .password_credentials import PasswordCredentialsFlow

__all__ = [
    "settle_clients",
    "_basic_auth_header",
    "sanitize_token_response",
    "get_auth_flow_class",
    "ClientCredentialsFlow",
    "PasswordCredentialsFlow",
    "ImplicitFlow",
]


def get_auth_flow_class(flow_name: str) -> Type:
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
