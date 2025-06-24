from .wrap_client import (
    wrap_client,
    wrap_with_basic_auth,
    wrap_with_oauth,
    wrap_with_bearer_token,
    unwrap_client
)
from .base import AuthStrategy, ClientProtocol
from .validate.service_protocol import ValidationProtocol


__all__ = [
    "ValidationProtocol",
    "ClientProtocol",
    "AuthStrategy",
    "wrap_client",
    "wrap_with_basic_auth",
    "wrap_with_oauth",
    "wrap_with_bearer_token",
    "unwrap_client"
]
