from .wrap_client import *
from .base import AuthStrategy
from .validate.service_protocol import ValidationProtocol


__all__ = [
    "ValidationProtocol",
    "AuthStrategy",
    "wrap_client",
    "wrap_with_basic_auth",
    "wrap_with_oauth",
    "wrap_with_bearer_token"
]
