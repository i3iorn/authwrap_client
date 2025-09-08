from typing import Protocol, Optional, Union, List, Dict, Any, runtime_checkable

from authwrap_client.strategies.oauth.common import TokenResponse, \
    DeviceAuthorizationResponse


@runtime_checkable
class BaseAuthFlowProtocol(Protocol):
    """
    Base protocol defining common OAuth2 token operations and shared interfaces.

    All methods include both synchronous and asynchronous variants.
    """

    def refresh_access_token(
        self,
        refresh_token: str,
        scope: Optional[Union[str, List[str]]] = None,
        **kwargs: Any
    ) -> TokenResponse:
        """
        Refresh an access token using a refresh token (RFC 6749 §6).

        Args:
            refresh_token: The refresh token issued by the authorization server.
            scope: (Optional) Scopes to request. If omitted, uses original scopes.
            **kwargs: Additional parameters (e.g., headers, extra body fields).

        Returns:
            A TokenResponse dict with at least:
              - access_token
              - token_type
              - expires_in
              - (Sometimes) refresh_token
              - scope
        """
        ...

    async def refresh_access_token_async(
        self,
        refresh_token: str,
        scope: Optional[Union[str, List[str]]] = None,
        **kwargs: Any
    ) -> TokenResponse:
        """
        Asynchronous variant of refresh_access_token.
        """
        ...

    def revoke_token(
        self,
        token: str,
        token_type_hint: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """
        Revoke an access or refresh token (RFC 7009).

        Args:
            token: The token (access or refresh) to be revoked.
            token_type_hint: (Optional) A hint about the type of the token.
            **kwargs: Additional parameters (e.g., headers).

        Raises:
            Implementation-specific exception if revocation fails.
        """
        ...

    async def revoke_token_async(
        self,
        token: str,
        token_type_hint: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """
        Asynchronous variant of revoke_token.
        """
        ...

    def introspect_token(
        self,
        token: str,
        token_type_hint: Optional[str] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Introspect an access or refresh token (RFC 7662).

        Args:
            token: The token to introspect.
            token_type_hint: (Optional) A hint about the type of token.
            **kwargs: Additional parameters (e.g., headers).

        Returns:
            A dictionary containing at least:
              - active: bool
            Plus any other metadata fields the server supports (e.g., scope, exp, client_id).
        """
        ...

    async def introspect_token_async(
        self,
        token: str,
        token_type_hint: Optional[str] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Asynchronous variant of introspect_token.
        """
        ...


@runtime_checkable
class AuthorizationRequestProtocol(Protocol):
    """
    Shared interface for grant types that require building an authorization URL
    or parsing parameters from a redirect response.
    """

    def get_authorization_url(
        self,
        redirect_uri: str,
        scope: Union[str, List[str]],
        state: Optional[str] = None,
        **kwargs: Any
    ) -> str:
        """
        Build the OAuth2 authorization endpoint URL.

        Args:
            redirect_uri: The client redirect URI registered with the authorization server.
            scope: One or more scopes (space-delimited string or list of strings).
            state: (Optional) Opaque value to maintain state between request and callback.
            **kwargs: Additional query parameters (e.g., response_type, audience).

        Returns:
            A fully qualified URL to which the user-agent should be redirected.
        """
        ...


@runtime_checkable
class TokenExchangeProtocol(Protocol):
    """
    Shared interface for grant types that exchange credentials or codes for tokens.

    Methods in this protocol return a TokenResponse.
    """

    def fetch_token(
        self,
        *args: Any,
        **kwargs: Any
    ) -> TokenResponse:
        """
        Exchange grant-specific parameters for an access token.

        The implementing class defines required keyword arguments:
        - For authorization-code flow: code, redirect_uri, client_id, client_secret, etc.
        - For password flow: username, password, scope, client_id, client_secret.
        - For client-credentials flow: scope, client_id, client_secret.
        - For device flow: device_code, etc.

        Returns:
            A TokenResponse dictionary.
        """
        ...

    async def fetch_token_async(
        self,
        *args: Any,
        **kwargs: Any
    ) -> TokenResponse:
        """
        Asynchronous variant of fetch_token.
        """
        ...


@runtime_checkable
class AuthorizationCodeFlowProtocol(
    BaseAuthFlowProtocol,
    AuthorizationRequestProtocol,
    TokenExchangeProtocol,
    Protocol
):
    """
    Protocol for the Authorization Code grant (RFC 6749 §4.1).

    Inherits:
      - get_authorization_url (AuthorizationRequestProtocol)
      - fetch_token / fetch_token_async (TokenExchangeProtocol)
      - refresh_access_token, revoke_token, introspect_token, etc. (BaseAuthFlowProtocol)
    """

    def fetch_token(
        self,
        code: str,
        redirect_uri: str,
        client_id: str,
        client_secret: Optional[str] = None,
        **kwargs: Any
    ) -> TokenResponse:
        """
        Exchange an authorization code for an access token (RFC 6749 §4.1.3).

        Args:
            code: The authorization code returned by the authorization server.
            redirect_uri: The same redirect URI used in get_authorization_url.
            client_id: The client identifier.
            client_secret: (Optional) The client secret, if required.
            **kwargs: Additional parameters (e.g., headers, extra body fields).

        Returns:
            A TokenResponse dict.
        """
        ...

    async def fetch_token_async(
        self,
        code: str,
        redirect_uri: str,
        client_id: str,
        client_secret: Optional[str] = None,
        **kwargs: Any
    ) -> TokenResponse:
        """
        Asynchronous variant of fetch_token.
        """
        ...


@runtime_checkable
class ImplicitFlowProtocol(
    BaseAuthFlowProtocol,
    AuthorizationRequestProtocol,
    Protocol
):
    """
    Protocol for the Implicit grant (RFC 6749 §4.2).

    Inherits:
      - get_authorization_url (AuthorizationRequestProtocol)
      - refresh_access_token, revoke_token, introspect_token, etc. (BaseAuthFlowProtocol)
    """

    def parse_token_from_redirect(
        self,
        redirect_response_url: str
    ) -> TokenResponse:
        """
        Extract the access token (and other fields) from the redirect URI fragment
        after the authorization server redirects the user-agent (RFC 6749 §4.2.2).

        Args:
            redirect_response_url: The full redirect URI including fragment.

        Returns:
            A TokenResponse dict with at least:
              - access_token
              - token_type
              - expires_in (if provided)
              - scope (if provided)
        """
        ...

    async def parse_token_from_redirect_async(
        self,
        redirect_response_url: str
    ) -> TokenResponse:
        """
        Asynchronous variant of parse_token_from_redirect.
        """
        ...


@runtime_checkable
class PasswordCredentialsFlowProtocol(
    BaseAuthFlowProtocol,
    Protocol
):
    """
    Protocol for the Resource Owner Password Credentials grant (RFC 6749 §4.3).

    Inherits:
      - refresh_access_token, revoke_token, introspect_token, etc. (BaseAuthFlowProtocol)
    """

    def fetch_token(
        self,
        username: str,
        password: str,
        scope: Optional[Union[str, List[str]]] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        **kwargs: Any
    ) -> TokenResponse:
        """
        Exchange resource owner credentials for an access token (RFC 6749 §4.3.2).

        Args:
            username: Resource owner’s username.
            password: Resource owner’s password.
            scope: (Optional) Scopes to request.
            client_id: (Optional) Client identifier.
            client_secret: (Optional) Client secret, if required.
            **kwargs: Additional parameters (e.g., headers).

        Returns:
            A TokenResponse dict containing at least:
              - access_token
              - token_type
              - expires_in
              - refresh_token (if issued)
              - scope
        """
        ...

    async def fetch_token_async(
        self,
        username: str,
        password: str,
        scope: Optional[Union[str, List[str]]] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        **kwargs: Any
    ) -> TokenResponse:
        """
        Asynchronous variant of fetch_token_with_password.
        """
        ...


@runtime_checkable
class ClientCredentialsFlowProtocol(
    BaseAuthFlowProtocol,
    Protocol
):
    """
    Protocol for the Client Credentials grant (RFC 6749 §4.4).

    Inherits:
      - refresh_access_token, revoke_token, introspect_token, etc. (BaseAuthFlowProtocol)
    """

    def fetch_token(
        self,
        scope: Optional[Union[str, List[str]]] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        **kwargs: Any
    ) -> TokenResponse:
        """
        Obtain an access token using client credentials (RFC 6749 §4.4.2).

        Args:
            scope: (Optional) Scopes to request.
            client_id: (Optional) Client identifier.
            client_secret: (Optional) Client secret.
            **kwargs: Additional parameters (e.g., headers, token_endpoint).

        Returns:
            A TokenResponse dict containing at least:
              - access_token
              - token_type
              - expires_in
              - scope
        """
        ...

    async def fetch_token_async(
        self,
        scope: Optional[Union[str, List[str]]] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        **kwargs: Any
    ) -> TokenResponse:
        """
        Asynchronous variant of fetch_token_client_credentials.
        """
        ...


@runtime_checkable
class DeviceAuthorizationFlowProtocol(
    BaseAuthFlowProtocol,
    Protocol
):
    """
    Protocol for the Device Authorization grant (RFC 8628).

    Inherits:
      - refresh_access_token, revoke_token, introspect_token, etc. (BaseAuthFlowProtocol)
    """

    def start_device_flow(
        self,
        scope: Optional[Union[str, List[str]]] = None,
        **kwargs: Any
    ) -> DeviceAuthorizationResponse:
        """
        Initiate the Device Authorization Flow and return device and user codes (RFC 8628 §3.1).

        Args:
            scope: (Optional) Scopes to request.
            **kwargs: Additional parameters (e.g., client_id, audience).

        Returns:
            A DeviceAuthorizationResponse dict containing:
              - device_code
              - user_code
              - verification_uri
              - expires_in
              - interval (optional)
        """
        ...

    async def start_device_flow_async(
        self,
        scope: Optional[Union[str, List[str]]] = None,
        **kwargs: Any
    ) -> DeviceAuthorizationResponse:
        """
        Asynchronous variant of start_device_flow.
        """
        ...

    def poll_token(
        self,
        device_code: str,
        interval: Optional[int] = None,
        **kwargs: Any
    ) -> TokenResponse:
        """
        Poll the token endpoint with the device code to obtain an access token (RFC 8628 §3.4).

        Args:
            device_code: The device_code obtained from start_device_flow.
            interval: (Optional) Polling interval in seconds. If omitted, use server-provided default.
            **kwargs: Additional parameters (e.g., client_id, headers).

        Returns:
            A TokenResponse dict.
        """
        ...

    async def poll_token_async(
        self,
        device_code: str,
        interval: Optional[int] = None,
        **kwargs: Any
    ) -> TokenResponse:
        """
        Asynchronous variant of poll_token.
        """
        ...
