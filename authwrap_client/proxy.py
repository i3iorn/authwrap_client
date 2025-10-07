import logging
import inspect
import os
import traceback
from collections.abc import Callable
from functools import wraps

import wrapt
from typing import Any, TypeVar, Generic
from .base import AuthStrategy
from .exceptions import AuthWrapConfigurationError, AuthWrapException
from .storage.protocol import StorageProtocol

_invalid_exception_policy_message = "Invalid AUTHWRAP_EXCEPTION_POLICY: {exception_policy}. Must be 'raise', 'log', or 'ignore'."
_auth_injection_failed_message = "Failed to inject auth headers for {name}: {error}"

EXCEPTION_POLICY = os.getenv("AUTHWRAP_EXCEPTION_POLICY", "raise").lower()
if EXCEPTION_POLICY not in {"raise", "log", "ignore"}:
    raise AuthWrapConfigurationError(_invalid_exception_policy_message.format(exception_policy=EXCEPTION_POLICY))

Client = TypeVar('Client')
logger = logging.getLogger(__name__)

class AuthorizedClient(wrapt.ObjectProxy, Generic[Client]):
    """Transparent wrapper that injects auth headers into any HTTP client."""
    def __init__(self, wrapped: Client, auth: AuthStrategy, storage: StorageProtocol = None) -> None:
        """
        Initialize the AuthorizedClient.

        Args:
            wrapped (Any): The HTTP client to wrap.
            auth (AuthStrategy): The authentication strategy to use.
        """
        super().__init__(wrapped)
        self._auth_strategy = auth
        self._storage_backend = storage

    def __getattr__(self, name: str) -> Any:
        """
        Intercept attribute access to inject authentication headers.

        Args:
            name (str): The name of the attribute being accessed.

        Returns:
            Any: The wrapped attribute, potentially modified to inject headers.
        """
        attr = super().__getattr__(name)
        if callable(attr):
            try:
                if inspect.iscoroutinefunction(attr):
                    attr = self._wrap_async_callable_with_authentication(attr)
                else:
                    attr = self._wrap_sync_callable_with_authentication(attr)
            except AuthWrapException as e:
                self._handle_exception(name, e)
        return attr

    @property
    def wrapped_client(self) -> Client:
        """
        Get the wrapped client instance.

        Returns:
            Client: The original HTTP client instance.
        """
        return self.__wrapped__

    def inject_authentication_into_call_kwargs(self, func_name: str, kwargs: dict) -> None:
        """Safely inject auth data into kwargs according to policy."""
        try:
            key = self._auth_strategy.auth_position.value
            kwargs[key] = self._auth_strategy.modify_call(kwargs.get(key))
        except Exception as e:
            self._handle_exception(func_name, e)

    def _wrap_async_callable_with_authentication(self, func: Callable) -> Any:
        """
        Handle the asynchronous call to the wrapped function, injecting authentication headers.

        Args:
            func (Callable): The asynchronous function to call.

        Returns:
            Any: The result of the function call.
        """
        try:
            @wraps(func)
            async def wrapped(*args, **kwargs):
                self.inject_authentication_into_call_kwargs(func.__name__, kwargs)
                return await func(*args, **kwargs)
            return wrapped
        except Exception as e:
            raise AuthWrapException(f"Failed to inject auth headers for {func.__name__}: {e}") from e

    def _wrap_sync_callable_with_authentication(self, func: Callable) -> Any:
        """
        Handle the call to the wrapped function, injecting authentication headers.

        Args:
            func (Callable): The function to call.

        Returns:
            Any: The result of the function call.
        """
        try:
            @wraps(func)
            def wrapped(*args, **kwargs):
                self.inject_authentication_into_call_kwargs(func.__name__, kwargs)
                return func(*args, **kwargs)
            return wrapped
        except Exception as e:
            raise AuthWrapException(f"Failed to inject auth headers for {func.__name__}: {e}") from e

    def _handle_exception(self, name: str, error: Exception):
        """
        Handle exceptions based on the configured exception policy.

        Args:
            name (str): The name of the method where the exception occurred.
            error (Exception): The exception that was raised.
        """
        message = _auth_injection_failed_message.format(name=name, error=str(error))
        if EXCEPTION_POLICY == "raise":
            raise error
        elif EXCEPTION_POLICY == "log":
            logger.warning(message)
            logger.debug(traceback.format_exc())
        elif EXCEPTION_POLICY == "ignore":
            logger.debug(message)
        else:
            raise AuthWrapConfigurationError(_invalid_exception_policy_message.format(exception_policy=EXCEPTION_POLICY))
