from logging import getLogger
from typing import Dict, Any, Callable

from .proxy import AuthorizedClient

logger = getLogger(__name__)


# Naming-friendly helpers

def validate_non_empty_string_parameter(value: str, name: str) -> None:
    if not value:
        raise ValueError(f"{name} must be provided and cannot be empty.")
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string.")
    if len(value) > 256:
        raise ValueError(f"{name} cannot exceed 256 characters.")
    logger.debug(f"Validated {name}: {value}")


def validate_http_client_has_request_method(client: Any) -> None:
    if not client:
        raise ValueError("Client must not be None.")
    if not hasattr(client, 'request'):
        raise TypeError("Client must have a 'request' method.")
    if not callable(client.request):
        raise TypeError("Client's 'request' method must be callable.")
    logger.debug(f"Validated client: {client.__class__.__name__}")


# Back-compat wrappers

def _standard_string_validation(value: str, name: str) -> None:
    validate_non_empty_string_parameter(value, name)


def _validate_client(client: Any) -> None:
    validate_http_client_has_request_method(client)


# Public API (existing)

def wrap_client(
    client: Any, auth_strategy: str, **kwargs: Any
) -> Any:
    from .proxy import AuthorizedClient
    validate_http_client_has_request_method(client)
    auth_strategy = auth_strategy.lower()
    if auth_strategy == "basic":
        return wrap_with_basic_auth(client, **kwargs)
    elif auth_strategy == "bearer_token":
        return wrap_with_bearer_token(client, **kwargs)
    elif auth_strategy in ["oauth", "oauth2"]:
        return wrap_with_oauth2(client, **kwargs)
    else:
        raise ValueError(f"Unsupported authentication strategy: {auth_strategy}")


def wrap_with_basic_auth(
    client: Any, username: str, password: str, **kwargs: Any
) -> Any:
    from authwrap_client.strategies import BasicAuth
    validate_non_empty_string_parameter(username, "Username")
    validate_non_empty_string_parameter(password, "Password")
    validate_http_client_has_request_method(client)
    auth = BasicAuth(username, password, **kwargs)
    logger.debug(f"Wrapping client with Basic Auth for user: {username}")
    return AuthorizedClient(client, auth)


def wrap_with_bearer_token(
    client: Any, token: str, **kwargs: Any
) -> Any:
    from authwrap_client.strategies import BearerTokenAuth
    validate_non_empty_string_parameter(token, "Token")
    validate_http_client_has_request_method(client)
        auth = BearerTokenAuth(token, **kwargs)
    logger.debug(f"Wrapping client with Bearer Token Auth")
    return AuthorizedClient(client, auth)


def wrap_with_oauth2(
    client: Any, token_url: str, **kwargs: Any
) -> Any:
    from authwrap_client.strategies import OAuth2Auth
    validate_http_client_has_request_method(client)
    auth = OAuth2Auth(token_url, **kwargs)
    logger.debug(f"Wrapping client with OAuth 2.0 Auth for token URL: {token_url}")
    return AuthorizedClient(client, auth)


def unwrap_client(client: AuthorizedClient) -> Any:
    try:
        if isinstance(client, AuthorizedClient):
            return client.wrapped_client
        inner = getattr(client, "__wrapped__", None)
        return inner if inner is not None else client
    except Exception:
        return client


# Naming-friendly public aliases

def wrap_http_client_with_authentication(client: Any, auth_strategy: str, **kwargs: Any) -> Any:
    return wrap_client(client, auth_strategy, **kwargs)


def wrap_http_client_with_basic_authentication(client: Any, username: str, password: str, **kwargs: Any) -> Any:
    return wrap_with_basic_auth(client, username, password, **kwargs)


def wrap_http_client_with_bearer_token_authentication(client: Any, bearer_token: str, **kwargs: Any) -> Any:
    # Remove 'token' from kwargs if present to avoid multiple values for 'token'
    kwargs.pop('token', None)
    return wrap_with_bearer_token(client, token=bearer_token, **kwargs)


def wrap_http_client_with_oauth2_authentication(client: Any, token_endpoint_url: str, **kwargs: Any) -> Any:
    return wrap_with_oauth2(client, token_endpoint_url, **kwargs)


def unwrap_to_original_client(client: AuthorizedClient) -> Any:
    return unwrap_client(client)
