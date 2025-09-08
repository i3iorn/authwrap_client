from typing import Optional, Union, List, Any, Dict

from ..common import TokenResponse, OAuthError
from . import settle_clients, _basic_auth_header, sanitize_token_response
from ..flow_protocol import BaseAuthFlowProtocol


class ClientCredentialsFlow(BaseAuthFlowProtocol):
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
        http_client: Optional[Any] = None,
        http_client_async: Optional[Any] = None,
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

        self.http_client, self.http_client_async = settle_clients(http_client, http_client_async)



    def fetch_token(
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

        headers = _basic_auth_header(cid, csec)

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

        return sanitize_token_response(token_data, token_scope)

    async def fetch_token_async(
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

        headers = _basic_auth_header(cid, csec)

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

        return sanitize_token_response(token_data, token_scope)
