import logging
from enum import Enum
from typing import Dict, Optional, Any

from authwrap_client import AuthStrategy
from authwrap_client.exceptions import InjectionError

logger = logging.getLogger(__name__)


class AuthStrategyPosition(Enum):
    """Defines the position of the auth strategy in the request."""
    HEADER = "headers"
    BODY = "json"
    QUERY_PARAM = "params"


class BaseAuth(AuthStrategy):
    """
    Base class for all authentication strategies.

    This class supports injecting one or more key-value pairs into headers, body, or query params.

    Args:
        data (Dict[str, str]): Key-value pairs to inject into the request.
    """

    def __init__(self, data: Dict[str, str], allow_rewrite: bool = False) -> None:
        if not data:
            raise InjectionError("Auth data must not be empty.")
        self.data = data
        self.rewrite = allow_rewrite

    def modify_call(self, data: Optional[Dict[str, str]]) -> Dict[str, str]:
        """
        Inject authentication data into the given request section.

        Args:
            data (Optional[Dict[str, str]]): Original data (e.g., headers, json, or params).

        Returns:
            Dict[str, str]: Updated data dictionary with injected auth data.

        Raises:
            InjectionError: If the injection process fails.
        """
        try:
            logger.debug(f"Injecting into {self.auth_position.value}: {self.data}")
            updated = data.copy() if data else {}

            if not self.rewrite:
                if data and len(set(self.data.keys()).intersection(data.keys())) > 0:
                    raise InjectionError(
                        f"Cannot inject into {self.auth_position.value} as it would overwrite existing keys. "
                        "Set allow_rewrite=True to allow this."
                    )

            updated.update(self.data)
            return updated
        except Exception as e:
            msg = f"Failed to inject into {self.auth_position.value}: {e}"
            logger.error(msg, exc_info=True)
            raise InjectionError(msg) from e


class HeaderAuth(BaseAuth):
    """Injects authentication data into request headers."""

    @property
    def auth_position(self) -> AuthStrategyPosition:
        return AuthStrategyPosition.HEADER


class BodyAuth(BaseAuth):
    """Injects authentication data into request body (JSON)."""
    @property
    def auth_position(self) -> AuthStrategyPosition:
        return AuthStrategyPosition.BODY


class QueryParamAuth(BaseAuth):
    """Injects authentication data into query parameters."""
    @property
    def auth_position(self) -> AuthStrategyPosition:
        return AuthStrategyPosition.QUERY_PARAM
