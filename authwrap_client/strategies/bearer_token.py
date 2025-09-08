from typing import Optional, Dict
from datetime import datetime, timedelta
import requests

from authwrap_client.exceptions import InjectionError
from .base import HeaderAuth


class BearerTokenAuth(HeaderAuth):
    """Injects a bearer token into the Authorization header."""

    def __init__(self, token: str, allow_rewrite: bool = False, **extra_headers: str) -> None:
        if not token:
            raise InjectionError("Bearer token must not be empty.")
        if not isinstance(extra_headers, dict):
            raise InjectionError("Extra headers must be provided as keyword arguments.")
        data = {"Authorization": f"Bearer {token}"}
        data.update(extra_headers)
        super().__init__(data, allow_rewrite=allow_rewrite)
