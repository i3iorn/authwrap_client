from authwrap_client.exceptions import InjectionError
from .base import HeaderAuth


class BasicAuth(HeaderAuth):
    """Injects a Basic Auth token into the Authorization header."""

    def __init__(self, username: str, password: str, **extra_headers: str) -> None:
        import base64
        if not username or not password:
            raise InjectionError("Username and password must not be empty.")
        basic_authorization_header_value = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers_to_inject = {"Authorization": f"Basic {basic_authorization_header_value}"}
        headers_to_inject.update(extra_headers)
        super().__init__(headers_to_inject)
