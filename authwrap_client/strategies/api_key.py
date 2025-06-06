from authwrap_client.exceptions import InjectionError
from .base import HeaderAuth


class ApiKeyAuth(HeaderAuth):
    """Injects an API key into a header."""

    def __init__(self, api_key: str, header_name: str = "X-API-Key",
                 **extra_headers: str) -> None:
        if not api_key:
            raise InjectionError("API key must not be empty.")
        data = {header_name: api_key}
        data.update(extra_headers)
        super().__init__(data)
