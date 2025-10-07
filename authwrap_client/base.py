from __future__ import annotations

from typing import Protocol, Dict, Optional, Any
from enum import Enum


class AuthStrategyPosition(Enum):
    """Defines the position of the auth strategy in the request."""
    HEADER = "headers"
    BODY = "json"
    QUERY_PARAM = "params"


class AuthStrategy(Protocol):
    """Defines a pluggable authorization strategy interface."""
    @property
    def auth_position(self) -> AuthStrategyPosition:
        """Defines the position of the auth strategy in the request."""
        ...

    def modify_call(self, headers: Optional[Dict[str, str]]) -> Dict[str, str]:
        """Return new headers with the authorization information."""
        ...


class ClientProtocol(Protocol):
    """
    Defines a pluggable client protocol interface for making requests.

    This interface is not ment to be used directly, but rather to be used as an
    internal proxy for the actual client implementation. It allows for different
    client implementations to be used interchangeably, as long as they adhere to
    this protocol.
    """
    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Make a request to the specified URL with the given parameters."""
        ...

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Make a GET request to the specified URL."""
        ...

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Make a POST request to the specified URL."""
        ...

    def put(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Make a PUT request to the specified URL."""
        ...

    def delete(self, url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Make a DELETE request to the specified URL."""
        ...

    def patch(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Make a PATCH request to the specified URL."""
        ...

    def head(self, url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Make a HEAD request to the specified URL."""
        ...

    def options(self, url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Make an OPTIONS request to the specified URL."""
        ...


class RequestProtocol(Protocol):
    """
    Describes an HTTP request's components.

    This is intended for per-request data, not global state.
    """
    @property
    def method(self) -> str:
        """Get the HTTP method for the request."""
        ...

    @property
    def url(self) -> str:
        """Get the request URL."""
        ...

    @property
    def headers(self) -> Dict[str, str]:
        """Get the request headers."""
        ...

    @property
    def params(self) -> Dict[str, str]:
        """Get the request query parameters."""
        ...

    @property
    def data(self) -> Optional[Dict[str, str]]:
        """Get the request form data."""
        ...


class ResponseProtocol(Protocol):
    """
    Describes an HTTP response and helpers to access its payload.

    This is intended for per-response data, not global state.
    """
    @property
    def status_code(self) -> int:
        """Get the HTTP status code."""
        ...

    @property
    def headers(self) -> Dict[str, str]:
        """Get the response headers."""
        ...

    @property
    def content(self) -> bytes:
        """Get the raw response bytes."""
        ...

    def json(self) -> Dict[str, Any]:
        """Parse the response content as JSON."""
        ...

    def text(self) -> str:
        """Get the response content as text."""
        ...

    def extensions(self) -> Dict[str, Any]:
        """Get any additional extensions or metadata from the response."""
        ...