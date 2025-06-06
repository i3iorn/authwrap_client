import logging
import inspect
import os
import traceback
from collections.abc import Callable

import wrapt
from typing import Any, TypeVar, Generic
from .base import AuthStrategy
from .exceptions import AuthWrapConfigurationError, AuthWrapException
from .storage.protocol import StorageProtocol

_auth_policy_exception_msg = "Invalid AUTHWRAP_EXCEPTION_POLICY: {exception_policy}. Must be 'raise', 'log', or 'ignore'."
_auth_injection_failed_msg = "Failed to inject auth headers for {name}: {error}"

EXCEPTION_POLICY = os.getenv("AUTHWRAP_EXCEPTION_POLICY", "raise").lower()
if EXCEPTION_POLICY not in {"raise", "log", "ignore"}:
    raise AuthWrapConfigurationError(_auth_policy_exception_msg.format(exception_policy=EXCEPTION_POLICY))

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
        self._self_auth = auth

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
                    attr = self._handle_async_call(attr)
                else:
                    attr = self._handle_call(attr)
            except AuthWrapException as e:
                self._handle_exception(name, e)
        return attr

    def _handle_async_call(self, func: Callable) -> Any:
        """
        Handle the asynchronous call to the wrapped function, injecting authentication headers.

        Args:
            func (Callable): The asynchronous function to call.

        Returns:
            Any: The result of the function call.
        """
        try:
            async def wrapped(*args, **kwargs):
                kwargs[self._self_auth.auth_position.value] = self._self_auth.modify_call(
                    kwargs.get(self._self_auth.auth_position.value))
                return await func(*args, **kwargs)
            return wrapped
        except Exception as e:
            raise AuthWrapException(f"Failed to inject auth headers for {func.__name__}: {e}") from e

    def _handle_call(self, func: Callable) -> Any:
        """
        Handle the call to the wrapped function, injecting authentication headers.

        Args:
            func (Callable): The function to call.

        Returns:
            Any: The result of the function call.
        """
        try:
            def wrapped(*args, **kwargs):
                kwargs[self._self_auth.auth_position.value] = self._self_auth.modify_call(
                    kwargs.get(self._self_auth.auth_position.value))
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
        _msg = _auth_injection_failed_msg.format(name=name, error=str(error))
        if EXCEPTION_POLICY == "raise":
            raise error
        elif EXCEPTION_POLICY == "log":
            logger.warning(_msg)
            logger.debug(traceback.format_exc())
        elif EXCEPTION_POLICY == "ignore":
            logger.debug(_msg)
        else:
            raise AuthWrapConfigurationError(_auth_policy_exception_msg.format(exception_policy=EXCEPTION_POLICY))
