from typing import Protocol, Dict, Optional, Any

from authwrap_client.strategies.base import AuthStrategyPosition


class AuthStrategy(Protocol):
    """Defines a pluggable authorization strategy interface."""
    @property
    def auth_position(self) -> AuthStrategyPosition:
        """Defines the position of the auth strategy in the request."""
        ...

    def modify_call(self, headers: Optional[Dict[str, str]]) -> Dict[str, str]:
        """Mutates the request headers with the authorization information."""
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
    Defines a pluggable request protocol interface for making requests.

    This interface is not meant to be used directly, but rather to be used as an
    internal proxy for the actual request implementation. It allows for different
    request implementations to be used interchangeably, as long as they adhere to
    this protocol.
    """
    @property
    def method(self) -> str:
        """Get the method of the last request."""
        ...

    @property
    def url(self) -> str:
        """Get the URL of the last request."""
        ...

    @property
    def headers(self) -> Dict[str, str]:
        """Get the headers of the last request."""
        ...

    @property
    def params(self) -> Dict[str, str]:
        """Get the query parameters of the last request."""
        ...

    @property
    def data(self) -> Optional[Dict[str, str]]:
        """Get the form data of the last request."""
        ...



class ResponseProtocol(Protocol):
    """
    Defines a pluggable response protocol interface for handling responses.

    This interface is not meant to be used directly, but rather to be used as an
    internal proxy for the actual response implementation. It allows for different
    response implementations to be used interchangeably, as long as they adhere to
    this protocol.
    """
    @property
    def status_code(self) -> int:
        """Get the status code of the last request."""
        ...

    @property
    def headers(self) -> Dict[str, str]:
        """Get the headers of the last request."""
        ...

    @property
    def content(self) -> bytes:
        """Get the content of the last request."""
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