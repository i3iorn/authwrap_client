import base64
from typing import Any, Dict, List, Optional, Union, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from authwrap_client.config import FeatureFlag
from authwrap_client.strategies.oauth.common import TokenResponse, OAuthError
from authwrap_client.strategies.oauth.flow_protocol import (
    ClientCredentialsFlowProtocol,
    PasswordCredentialsFlowProtocol,
    ImplicitFlowProtocol, BaseAuthFlowProtocol
)
from authwrap_client.utils import insecure
from requests import Session
from httpx import AsyncClient

_sclient = None
_aclient = None


def settle_clients(sync_client, async_client) -> Tuple["Session", "AsyncClient"]:
    # Default to requests.Session and httpx.AsyncClient if none provided
    if not sync_client:
        import requests
        sync_client = requests.Session()
    _sclient = sync_client

    if not async_client:
        import httpx
        async_client = httpx.AsyncClient()
    _aclient = async_client

    return sync_client, async_client


def get_auth_flow_class(flow_name: str) -> BaseAuthFlowProtocol:
    """
    Get the appropriate OAuth2 flow class based on the flow name.

    Args:
        flow_name: The name of the OAuth2 flow (e.g., "client_credentials", "password", "implicit").

    Returns:
        A class implementing the corresponding OAuth2 flow protocol.

    Raises:
        ValueError: If the flow name is not recognized.
    """
    if flow_name == "client_credentials":
        return ClientCredentialsFlow
    elif flow_name == "password":
        return PasswordCredentialsFlow
    elif flow_name == "implicit":
        return ImplicitFlow
    else:
        raise ValueError(f"Unknown OAuth2 flow: {flow_name}")


def create_basic_auth_header(client_id: str, client_secret: str) -> Dict[str, str]:
    """
    Create the Authorization header for Basic Authentication.

    Args:
        client_id: The OAuth2 client identifier.
        client_secret: The OAuth2 client secret.

    Returns:
        A dictionary containing the Authorization header.
    """
    credentials = f"{client_id}:{client_secret}"
    basic_token = base64.b64encode(credentials.encode()).decode()
    return {
        "Authorization": f"Basic {basic_token}",
        "Content-Type": "application/x-www-form-urlencoded"
    }


def normalize_scope(scope: Optional[Union[str, List[str]]], default_scope: Optional[str] = "") -> str:
    """
    Normalize the scope parameter into a space-delimited string.

    Args:
        scope: A string or list of strings for scope.
        default_scope: The default scope to use if none is provided.

    Returns:
        A space-delimited string representing the scope.
    """
    if isinstance(scope, list):
        return " ".join(scope)
    return scope or default_scope


def fetch_token(
    http_client: Any,
    token_url: str,
    body: Dict[str, Any],
    headers: Dict[str, str],
    **kwargs: Any
) -> TokenResponse:
    """
    Send a POST request to obtain an access token.

    Args:
        http_client: The HTTP client (sync or async).
        token_url: The URL of the OAuth2 token endpoint.
        body: The body data for the token request.
        headers: The headers to include in the request.
        **kwargs: Additional request parameters.

    Returns:
        TokenResponse: The parsed token response.
    """
    response = http_client.request(method="POST", url=token_url, data=body, headers=headers, **kwargs)

    if response.status_code != 200:
        raise OAuthError(f"Token request failed: {response.status_code} {response.text}")

    try:
        return TokenResponse(**response.json(), token_response=response)
    except ValueError as e:
        raise OAuthError(f"Invalid JSON in token response: {e}")


async def fetch_token_async(
    http_client: Any,
    token_url: str,
    body: Dict[str, Any],
    headers: Dict[str, str],
    **kwargs: Any
) -> TokenResponse:
    """
    Async version of fetch_token.

    Args:
        http_client: The async HTTP client.
        token_url: The OAuth2 token endpoint URL.
        body: The body data for the token request.
        headers: The headers to include in the request.
        **kwargs: Additional request parameters.

    Returns:
        TokenResponse: The parsed token response.
    """
    response = await http_client.request(method="POST", url=token_url, data=body, headers=headers, **kwargs)

    if response.status_code != 200:
        raise OAuthError(f"Async token request failed: {response.status_code} {response.text}")

    try:
        return TokenResponse(**response.json(), token_response=response)
    except ValueError as e:
        raise OAuthError(f"Invalid JSON in token response: {e}")


def parse_token_from_redirect(redirect_response_url: str, default_scope: str = "") -> TokenResponse:
    """
    Extract the access token from a redirect URI after authorization.

    Args:
        redirect_response_url: Full redirect URI including the fragment.
        default_scope: Default scope to use if not provided in the URI.

    Returns:
        TokenResponse: The extracted token.
    """
    parsed = urlparse(redirect_response_url)
    fragment = parsed.fragment
    if not fragment:
        raise OAuthError("No fragment found in redirect URL.")

    parsed_qs = parse_qs(fragment)
    access_token_list = parsed_qs.get("access_token")
    token_type_list = parsed_qs.get("token_type")

    if not access_token_list or not token_type_list:
        raise OAuthError("Missing required token fields in redirect fragment.")

    return TokenResponse(
        access_token=access_token_list[0],
        token_type=token_type_list[0],
        expires_in=int(parsed_qs.get("expires_in", ["0"])[0]),
        scope=parsed_qs.get("scope", [default_scope])[0],
    )



# -------------------------------------------------------------------
# Client Credentials Flow Implementation
# -------------------------------------------------------------------

class ClientCredentialsFlow(ClientCredentialsFlowProtocol):
    """
    Implementation of the Client Credentials grant (RFC 6749 §4.4).

    Satisfies:
        - ClientCredentialsFlowProtocol
        - BaseAuthFlowProtocol (via inherited methods from protocol)

    Supports both synchronous and asynchronous token fetch.
    """

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        *,
        scope: Optional[Union[str, List[str]]] = None,
        http_client: Optional[Any] = None,  # Replaced problematic type annotation
        http_client_async: Optional[Any] = None,  # Replaced problematic type annotation
    ) -> None:
        """
        Args:
            token_url: The OAuth2 token endpoint URL.
            client_id: The OAuth2 client identifier.
            client_secret: The OAuth2 client secret.
            scope: (Optional) Space-delimited string or list of scopes.
            http_client: (Optional) Synchronous HTTP client implementing `.request()`.
                         Defaults to `requests.Session()`.
            http_client_async: (Optional) Async HTTP client implementing `.request()`.
                         Defaults to `httpx.AsyncClient()`.
        """
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = normalize_scope(scope)
        self.http_client, self.http_client_async = settle_clients(
            http_client, http_client_async
        )

    def fetch_token_client_credentials(
            self,
            scope: Optional[Union[str, List[str]]] = None,
            client_id: Optional[str] = None,
            client_secret: Optional[str] = None,
            **kwargs: Any
    ) -> TokenResponse:
        """
        Obtain an access token using client credentials (RFC 6749 §4.4.2).

        Args:
            scope: (Optional) Space-delimited string or list of scopes; overrides __init__.
            client_id: (Optional) Overrides the `client_id` provided at init.
            client_secret: (Optional) Overrides the `client_secret` provided at init.
            **kwargs: Additional parameters passed to the HTTP client (e.g., headers).

        Returns:
            TokenResponse with at least:
              - access_token
              - token_type
              - expires_in
              - scope (if provided by server)

        Raises:
            OAuthError: If the token endpoint returns non-200 or invalid JSON.
        """
        token_scope = normalize_scope(scope or self.scope)
        headers = create_basic_auth_header(client_id or self.client_id,
                                           client_secret or self.client_secret)
        body = {"grant_type": "client_credentials", "scope": token_scope}
        return fetch_token(self.http_client, self.token_url, body, headers, **kwargs)

    async def fetch_token_client_credentials_async(
            self,
            scope: Optional[Union[str, List[str]]] = None,
            client_id: Optional[str] = None,
            client_secret: Optional[str] = None,
            **kwargs: Any
    ) -> TokenResponse:
        """
        Async variant of fetch_token_client_credentials.

        Args:
            scope: (Optional) Overrides __init__ scope.
            client_id: (Optional) Overrides __init__ client_id.
            client_secret: (Optional) Overrides __init__ client_secret.
            **kwargs: Additional parameters passed to async HTTP client.

        Returns:
            TokenResponse.

        Raises:
            OAuthError: If token endpoint returns non-200 or invalid JSON.
        """
        token_scope = normalize_scope(scope or self.scope)
        headers = create_basic_auth_header(client_id or self.client_id,
                                           client_secret or self.client_secret)
        body = {"grant_type": "client_credentials", "scope": token_scope}
        return await fetch_token_async(self.http_client_async, self.token_url, body,
                                       headers, **kwargs)


# -------------------------------------------------------------------
# Resource Owner Password Credentials Flow Implementation
# -------------------------------------------------------------------
@insecure(
    FeatureFlag.ENABLE_LEGACY_FEATURES,
    "PasswordCredentialsFlow is insecure and should not be used in production."
)
class PasswordCredentialsFlow(PasswordCredentialsFlowProtocol):
    """
    Implementation of the Resource Owner Password Credentials grant (RFC 6749 §4.3).

    Satisfies:
        - PasswordCredentialsFlowProtocol
        - BaseAuthFlowProtocol
    """

    def __init__(
        self,
        token_url: str,
        *,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scope: Optional[Union[str, List[str]]] = None,
        http_client: Optional[Any] = None,  # Replaced problematic type annotation
        http_client_async: Optional[Any] = None,  # Replaced problematic type annotation
    ) -> None:
        """
        Updated constructor to remove reliance on `__orig_bases__`.
        """
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret

        if isinstance(scope, list):
            self.scope = " ".join(scope)
        else:
            self.scope = scope or ""

        self.http_client, self.http_client_async = settle_clients(http_client, http_client_async)

    def fetch_token_with_password(
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
            username: Resource owner's username.
            password: Resource owner's password.
            scope: (Optional) Overrides default scope.
            client_id: (Optional) Overrides default client_id.
            client_secret: (Optional) Overrides default client_secret.
            **kwargs: Additional params for HTTP client (e.g., headers).

        Returns:
            TokenResponse with at least:
              - access_token
              - token_type
              - expires_in
              - refresh_token (if issued)
              - scope

        Raises:
            OAuthError: If token request fails or JSON invalid.
        """
        req_scope = ""
        if scope:
            req_scope = " ".join(scope) if isinstance(scope, list) else scope
        elif self.scope:
            req_scope = self.scope

        cid = client_id or self.client_id
        csec = client_secret or self.client_secret

        headers: Dict[str, Any] = {"Content-Type": "application/x-www-form-urlencoded"}
        if cid and csec:
            credentials = f"{cid}:{csec}"
            basic_token = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {basic_token}"

        body: Dict[str, Any] = {
            "grant_type": "password",
            "username": username,
            "password": password,
        }
        if req_scope:
            body["scope"] = req_scope

        response = self.http_client.request(
            method="POST",
            url=self.token_url,
            data=body,
            headers=headers,
            **kwargs
        )

        if response.status_code != 200:
            raise OAuthError(
                f"Password credentials token request failed: "
                f"{response.status_code} {response.text}"
            )

        try:
            token_data = TokenResponse(**response.json(), token_response=response)
        except ValueError as e:
            raise OAuthError(f"Invalid JSON in token response: {e}")

        return token_data

    async def fetch_token_with_password_async(
        self,
        username: str,
        password: str,
        scope: Optional[Union[str, List[str]]] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        **kwargs: Any
    ) -> TokenResponse:
        """
        Async variant of fetch_token_with_password.

        Args:
            username: Resource owner's username.
            password: Resource owner's password.
            scope: (Optional) Overrides default scope.
            client_id: (Optional) Overrides default client_id.
            client_secret: (Optional) Overrides default client_secret.
            **kwargs: Additional params for async HTTP client.

        Returns:
            TokenResponse.
        """
        req_scope = ""
        if scope:
            req_scope = " ".join(scope) if isinstance(scope, list) else scope
        elif self.scope:
            req_scope = self.scope

        cid = client_id or self.client_id
        csec = client_secret or self.client_secret

        headers: Dict[str, Any] = {"Content-Type": "application/x-www-form-urlencoded"}
        if cid and csec:
            credentials = f"{cid}:{csec}"
            basic_token = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {basic_token}"

        body: Dict[str, Any] = {
            "grant_type": "password",
            "username": username,
            "password": password,
        }
        if req_scope:
            body["scope"] = req_scope

        response = await self.http_client_async.request(
            method="POST",
            url=self.token_url,
            data=body,
            headers=headers,
            **kwargs
        )

        if response.status_code != 200:
            raise OAuthError(
                f"Async password grant request failed: "
                f"{response.status_code} {response.text}"
            )

        try:
            token_data = TokenResponse(**response.json(), token_response=response)
        except ValueError as e:
            raise OAuthError(f"Invalid JSON in token response: {e}")

        return token_data


# -------------------------------------------------------------------
# Implicit Flow Implementation
# -------------------------------------------------------------------
@insecure(
    FeatureFlag.ENABLE_LEGACY_FEATURES,
    "ImplicitFlow is insecure and should not be used in production."
)
class ImplicitFlow(ImplicitFlowProtocol):
    """
    Implementation of the Implicit grant (RFC 6749 §4.2).

    Satisfies:
        - ImplicitFlowProtocol
        - BaseAuthFlowProtocol

    Builds an authorization URL and parses tokens from redirect URIs.
    """

    def __init__(
        self,
        authorization_endpoint: str,
        client_id: str,
        *,
        default_scope: Optional[Union[str, List[str]]] = None,
        response_type: str = "token",
    ) -> None:
        """
        Args:
            authorization_endpoint: The OAuth2 authorization endpoint URL.
            client_id: The OAuth2 client identifier.
            default_scope: (Optional) Default scope(s) to request.
            response_type: Must be "token" for implicit flow.
        """
        self.authorization_endpoint = authorization_endpoint
        self.client_id = client_id

        if isinstance(default_scope, list):
            self.default_scope = " ".join(default_scope)
        else:
            self.default_scope = default_scope or ""

        self.response_type = response_type

    def get_authorization_url(
        self,
        redirect_uri: str,
        scope: Union[str, List[str]],
        state: Optional[str] = None,
        **kwargs: Any
    ) -> str:
        """
        Build the OAuth2 implicit flow URL (RFC 6749 §4.2.1).

        Args:
            redirect_uri: The client redirect URI registered with the authorization server.
            scope: One or more scopes (space-delimited string or list of strings).
            state: (Optional) Opaque value to maintain state.
            **kwargs: Additional query parameters (e.g., response_type is implicitly "token").

        Returns:
            A fully qualified URL that returns an access token in the URI fragment.
        """
        if isinstance(scope, list):
            scope_str = " ".join(scope)
        else:
            scope_str = scope or self.default_scope

        query: Dict[str, Any] = {
            "response_type": self.response_type,
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": scope_str,
        }
        if state:
            query["state"] = state
        query.update(kwargs)

        parsed = urlparse(self.authorization_endpoint)
        new_query = urlencode(query)
        url = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            )
        )
        return url

    def parse_token_from_redirect(self, redirect_response_url: str) -> TokenResponse:
        """
        Extract the access token (and other fields) from the redirect URI fragment
        after the authorization server redirects the user-agent (RFC 6749 §4.2.2).

        Args:
            redirect_response_url: The full redirect URI including fragment.

        Returns:
            TokenResponse with at least:
              - access_token
              - token_type
              - expires_in (if provided)
              - scope (if provided)

        Raises:
            OAuthError: If required fields are missing or parsing fails.
        """
        parsed = urlparse(redirect_response_url)
        fragment = parsed.fragment
        if not fragment:
            raise OAuthError("No fragment found in redirect URL.")

        parsed_qs = parse_qs(fragment)
        access_token_list = parsed_qs.get("access_token")
        token_type_list = parsed_qs.get("token_type")

        if not access_token_list or not token_type_list:
            raise OAuthError("Missing required token fields in redirect fragment.")

        token_response: TokenResponse = TokenResponse(**{
            "access_token": access_token_list[0],
            "token_type": token_type_list[0],
            "expires_in": int(parsed_qs.get("expires_in", ["0"])[0]),
            "scope": parsed_qs.get("scope", [self.default_scope])[0],
        })
        return token_response

    async def parse_token_from_redirect_async(self, redirect_response_url: str) -> TokenResponse:
        """
        Asynchronous variant of parse_token_from_redirect.

        Args:
            redirect_response_url: Full redirect URI including fragment.

        Returns:
            TokenResponse.

        Raises:
            OAuthError: If required fields are missing or parsing fails.
        """
        # Same logic as sync version (no HTTP calls needed)
        return self.parse_token_from_redirect(redirect_response_url)
