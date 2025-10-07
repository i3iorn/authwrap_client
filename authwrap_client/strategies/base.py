from __future__ import annotations

import logging
from typing import Dict, Optional

from authwrap_client.base import AuthStrategy, AuthStrategyPosition
from authwrap_client.exceptions import InjectionError

logger = logging.getLogger(__name__)


class BaseAuth(AuthStrategy):
    """
    Base class for all authentication strategies.

    This class supports injecting one or more key-value pairs into headers, body, or query params.

    Args:
        data (Dict[str, str]): Key-value pairs to inject into the request.
        allow_rewrite (bool): Whether existing keys may be overwritten during injection.
        allow_overwrite (Optional[bool]): Preferred name for allow_rewrite; if provided, overrides allow_rewrite.
    """

    def __init__(self, data: Dict[str, str], allow_rewrite: bool = False, *, allow_overwrite: Optional[bool] = None) -> None:
        if not data:
            raise InjectionError("Auth data must not be empty.")
        self.data = data
        final_overwrite = allow_overwrite if allow_overwrite is not None else allow_rewrite
        self.allow_overwrite = bool(final_overwrite)
        # Backward-compat alias used internally before rename
        self.rewrite = self.allow_overwrite

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
            logger.debug("Injecting into %s: %s", self.auth_position.value, list(self.data.keys()))
            updated = data.copy() if data else {}

            if not self.allow_overwrite and data:
                conflict = set(self.data.keys()).intersection(updated.keys())
                if conflict:
                    raise InjectionError(
                        f"Cannot inject into {self.auth_position.value} as it would overwrite existing keys: {sorted(conflict)}. "
                        "Set allow_overwrite=True (or legacy allow_rewrite=True) to allow this."
                    )

            updated.update(self.data)
            return updated
        except InjectionError:
            raise
        except Exception as e:
            msg = f"Failed to inject into {self.auth_position.value}: {e}"
            logger.error(msg, exc_info=True)
            raise InjectionError(msg) from e

    # Naming-friendly alias for clarity in call sites
    def apply_authentication_to_section(self, existing_section: Optional[Dict[str, str]]) -> Dict[str, str]:
        return self.modify_call(existing_section)


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
