from logging import getLogger
from typing import Dict, Any, Callable

logger = getLogger(__name__)


def _standard_string_validation(value: str, name: str) -> None:
    """Helper function to validate standard string inputs."""
    if not value:
        raise ValueError(f"{name} must be provided and cannot be empty.")
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string.")
    if len(value) > 256:
        raise ValueError(f"{name} cannot exceed 256 characters.")
    logger.debug(f"Validated {name}: {value}")


def _validate_client(client: Any) -> None:
    """Helper function to validate the client."""
    if not client:
        raise ValueError("Client must not be None.")
    if not hasattr(client, 'request'):
        raise TypeError("Client must have a 'request' method.")
    if not callable(client.request):
        raise TypeError("Client's 'request' method must be callable.")
    logger.debug(f"Validated client: {client.__class__.__name__}")


def wrap_client(
    client: Any, auth_strategy: str, **kwargs: Any
) -> Any:
    """Wraps a client with the specified authentication strategy."""
    from .proxy import AuthorizedClient

    # Validate input and do sanity checks
    _validate_client(client)

    auth_strategy = auth_strategy.lower()

    if auth_strategy == "basic":
        return wrap_with_basic_auth(client, **kwargs)
    elif auth_strategy == "bearer_token":
        return wrap_with_bearer_token(client, **kwargs)
    elif auth_strategy in ["oauth", "oauth2"]:
        return wrap_with_oauth(client, **kwargs)
    else:
        raise ValueError(f"Unsupported authentication strategy: {auth_strategy}")


def wrap_with_basic_auth(
    client: Any, username: str, password: str, **kwargs: Any
) -> Any:
    """Wraps a client with Basic Auth."""
    from authwrap_client.strategies import BasicAuth
    from .proxy import AuthorizedClient

    # Validate input and do sanity checks
    _standard_string_validation(username, "Username")
    _standard_string_validation(password, "Password")
    _validate_client(client)

    auth = BasicAuth(username, password, **kwargs)
    logger.debug(f"Wrapping client with Basic Auth for user: {username}")
    return AuthorizedClient(client, auth)


def wrap_with_bearer_token(
    client: Any, token: str, **kwargs: Any
) -> Any:
    """Wraps a client with Bearer Token Auth."""
    from authwrap_client.strategies import BearerTokenAuth
    from .proxy import AuthorizedClient

    # Validate input and do sanity checks
    _standard_string_validation(token, "Token")
    _validate_client(client)

    auth = BearerTokenAuth(token, **kwargs)
    logger.debug(f"Wrapping client with Bearer Token Auth")
    return AuthorizedClient(client, auth)


def wrap_with_oauth(
    client: Any, token_url: str, **kwargs: Any
) -> Any:
    """Wraps a client with OAuth 2.0 Auth."""
    from authwrap_client.strategies import OAuth2Auth
    from .proxy import AuthorizedClient

    # Validate input and do sanity checks
    _validate_client(client)

    auth = OAuth2Auth(token_url, **kwargs)
    logger.debug(f"Wrapping client with OAuth 2.0 Auth for token URL: {token_url}")
    return AuthorizedClient(client, auth)
