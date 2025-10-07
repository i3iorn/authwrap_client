from authwrap_client.exceptions import InjectionError
from .base import HeaderAuth
from typing import Optional, Dict


class ApiKeyAuth(HeaderAuth):
    """Injects an API key into a header."""

    def __init__(
        self,
        api_key: str,
        header_name: str = "X-API-Key",
        *,
        api_key_header_name: Optional[str] = None,
        additional_headers: Optional[Dict[str, str]] = None,
        **extra_headers: str,
    ) -> None:
        if not api_key:
            raise InjectionError("API key must not be empty.")
        final_header_name = api_key_header_name or header_name
        data: Dict[str, str] = {final_header_name: api_key}
        if additional_headers:
            if not isinstance(additional_headers, dict):
                raise InjectionError("additional_headers must be a dict of str to str.")
            data.update(additional_headers)
        if extra_headers:
            data.update(extra_headers)
        super().__init__(data)
