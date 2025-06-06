from authwrap_client.exceptions import InjectionError
from .base import HeaderAuth


class BasicAuth(HeaderAuth):
    """Injects a Basic Auth token into the Authorization header."""

    def __init__(self, username: str, password: str, **extra_headers: str) -> None:
        import base64
        if not username or not password:
            raise InjectionError("Username and password must not be empty.")
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        data = {"Authorization": f"Basic {token}"}
        data.update(extra_headers)
        super().__init__(data)
