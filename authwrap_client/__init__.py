from .wrap_client import (
    wrap_client,
    wrap_with_basic_auth,
    wrap_with_bearer_token,
    wrap_with_oauth2,
)
from .base import AuthStrategy
from .validate.service_protocol import ValidationProtocol

# Backwards compatibility: older versions exposed `wrap_with_oauth`
# Provide an alias so existing users won't break when upgrading.
wrap_with_oauth = wrap_with_oauth2

__all__ = [
    "ValidationProtocol",
    "AuthStrategy",
    "wrap_client",
    "wrap_with_basic_auth",
    "wrap_with_oauth2",
    "wrap_with_bearer_token",
]
