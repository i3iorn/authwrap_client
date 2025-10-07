from typing import Optional, Dict
from datetime import datetime, timedelta
import requests

from authwrap_client.exceptions import InjectionError
from .base import HeaderAuth


class BearerTokenAuth(HeaderAuth):
    """Injects a bearer token into the Authorization header."""

    def __init__(
        self,
        token: Optional[str] = None,
        *,
        bearer_token: Optional[str] = None,
        allow_rewrite: bool = False,
        allow_overwrite: Optional[bool] = None,
        additional_headers: Optional[Dict[str, str]] = None,
        **extra_headers: str,
        ) -> None:
        # If both are provided and different, raise an error to avoid confusion
        if token is not None and bearer_token is not None and token != bearer_token:
            raise InjectionError("Both 'token' and 'bearer_token' were provided with different values. Please provide only one or ensure they are the same.")
        # Prefer the clearer `bearer_token` name if provided
        final_token = bearer_token if bearer_token is not None else token
        if not final_token:
            raise InjectionError("Bearer token must not be empty.")

        # Merge headers under a single clear name
        headers: Dict[str, str] = {"Authorization": f"Bearer {final_token}"}
        if additional_headers:
            if not isinstance(additional_headers, dict):
                raise InjectionError("additional_headers must be a dict of str to str.")
            headers.update(additional_headers)
        if extra_headers:
            headers.update(extra_headers)

        super().__init__(headers, allow_rewrite=allow_rewrite, allow_overwrite=allow_overwrite)
