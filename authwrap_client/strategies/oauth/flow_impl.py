from __future__ import annotations

import base64
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
import requests

from authwrap_client.strategies.oauth.common import TokenResponse, OAuthError
from authwrap_client.strategies.oauth.flow_protocol import (
    ClientCredentialsFlowProtocol,
    PasswordCredentialsFlowProtocol,
    ImplicitFlowProtocol
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
        http_client: Optional[ClientCredentialsFlowProtocol.__orig_bases__[0].__args__[0]] = None,
        http_client_async: Optional[ClientCredentialsFlowProtocol.__orig_bases__[0].__args__[1]] = None,
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

        if isinstance(scope, list):
            self.scope = " ".join(scope)
        else:
            self.scope = scope or ""

        # Default to requests.Session and httpx.AsyncClient if none provided
        self.http_client = http_client or requests.Session()
        self.http_client_async = http_client_async or httpx.AsyncClient()

    def fetch_token_client_credentials(
            self,
            *,
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
        # Determine which client_id and client_secret to use
        cid = client_id or self.client_id
        csec = client_secret or self.client_secret

        # Determine scope string
        token_scope = ""
        if scope:
            token_scope = " ".join(scope) if isinstance(scope, list) else scope
        elif self.scope:
            token_scope = self.scope

        # Prepare Basic Auth header
        credentials = f"{cid}:{csec}"
        basic_token = base64.b64encode(credentials.encode()).decode()
        headers = {
            "Authorization": f"Basic {basic_token}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        body: Dict[str, Any] = {"grant_type": "client_credentials"}
        if token_scope:
            body["scope"] = token_scope

        response = self.http_client.request(
            method="POST",
            url=self.token_url,
            data=body,
            headers=headers,
            **kwargs
        )

        if response.status_code != 200:
            raise OAuthError(
                f"Client Credentials token request failed: {response.status_code} {response.text}"
            )

        try:
            token_data = response.json()
        except ValueError as e:
            raise OAuthError(f"Invalid JSON in token response: {e}")

        return {
            "access_token": token_data.get("access_token", ""),
            "token_type": token_data.get("token_type", ""),
            "expires_in": token_data.get("expires_in", 0),
            "refresh_token": token_data.get("refresh_token", ""),
            "scope": token_data.get("scope", token_scope),
        }

    async def fetch_token_client_credentials_async(
        self,
        *,
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
        cid = client_id or self.client_id
        csec = client_secret or self.client_secret

        token_scope = ""
        if scope:
            token_scope = " ".join(scope) if isinstance(scope, list) else scope
        elif self.scope:
            token_scope = self.scope

        credentials = f"{cid}:{csec}"
        basic_token = base64.b64encode(credentials.encode()).decode()
        headers = {
            "Authorization": f"Basic {basic_token}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        body: Dict[str, Any] = {"grant_type": "client_credentials"}
        if token_scope:
            body["scope"] = token_scope

        response = await self.http_client_async.request(
            method="POST",
            url=self.token_url,
            data=body,
            headers=headers,
            **kwargs
        )

        if response.status_code != 200:
            raise OAuthError(
                f"Async client credentials request failed: {response.status_code} {response.text}"
            )

        try:
            token_data = response.json()
        except ValueError as e:
            raise OAuthError(f"Invalid JSON in async token response: {e}")

        return {
            "access_token": token_data.get("access_token", ""),
            "token_type": token_data.get("token_type", ""),
            "expires_in": token_data.get("expires_in", 0),
            "refresh_token": token_data.get("refresh_token", ""),
            "scope": token_data.get("scope", token_scope),
        }


# -------------------------------------------------------------------
# Resource Owner Password Credentials Flow Implementation
# -------------------------------------------------------------------

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
        http_client: Optional[PasswordCredentialsFlowProtocol.__orig_bases__[0].__args__[0]] = None,
        http_client_async: Optional[PasswordCredentialsFlowProtocol.__orig_bases__[0].__args__[1]] = None,
    ) -> None:
        """
        Args:
            token_url: The OAuth2 token endpoint URL.
            client_id: (Optional) OAuth2 client identifier.
            client_secret: (Optional) OAuth2 client secret.
            scope: (Optional) Space-delimited string or list of scopes.
            http_client: (Optional) Sync HTTP client (defaults to requests.Session()).
            http_client_async: (Optional) Async HTTP client (defaults to httpx.AsyncClient()).
        """
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret

        if isinstance(scope, list):
            self.scope = " ".join(scope)
        else:
            self.scope = scope or ""

        self.http_client = http_client or requests.Session()
        self.http_client_async = http_client_async or httpx.AsyncClient()

    def fetch_token_with_password(
        self,
        username: str,
        password: str,
        *,
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
            token_data = response.json()
        except ValueError as e:
            raise OAuthError(f"Invalid JSON in password grant response: {e}")

        return {
            "access_token": token_data.get("access_token", ""),
            "token_type": token_data.get("token_type", ""),
            "expires_in": token_data.get("expires_in", 0),
            "refresh_token": token_data.get("refresh_token", ""),
            "scope": token_data.get("scope", req_scope),
        }

    async def fetch_token_with_password_async(
        self,
        username: str,
        password: str,
        *,
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
            token_data = response.json()
        except ValueError as e:
            raise OAuthError(f"Invalid JSON in async password grant response: {e}")

        return {
            "access_token": token_data.get("access_token", ""),
            "token_type": token_data.get("token_type", ""),
            "expires_in": token_data.get("expires_in", 0),
            "refresh_token": token_data.get("refresh_token", ""),
            "scope": token_data.get("scope", req_scope),
        }


# -------------------------------------------------------------------
# Implicit Flow Implementation
# -------------------------------------------------------------------

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

        token_response: TokenResponse = {
            "access_token": access_token_list[0],
            "token_type": token_type_list[0],
            "expires_in": int(parsed_qs.get("expires_in", ["0"])[0]),
            "scope": parsed_qs.get("scope", [self.default_scope])[0],
        }
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
