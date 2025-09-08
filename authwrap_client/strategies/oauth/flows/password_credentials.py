from typing import Optional, Union, List, Any, Dict

from authwrap_client.config import FeatureFlag
from authwrap_client.strategies.oauth import OAuthError
from authwrap_client.strategies.oauth.common import TokenResponse
from authwrap_client.strategies.oauth.flows import settle_clients, _basic_auth_header, sanitize_token_response
from authwrap_client.utils import insecure


@insecure(
    FeatureFlag.ENABLE_LEGACY_FEATURES | FeatureFlag.ENABLE_PASSWORD_FLOW,
    "PasswordCredentialsFlow is insecure and should not be used in production."
)
class PasswordCredentialsFlow:
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
        http_client: Optional[Any] = None,
        http_client_async: Optional[Any] = None,
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

        self.http_client, self.http_client_async = settle_clients(http_client, http_client_async)

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
            headers.update(_basic_auth_header(cid, csec))

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

        return sanitize_token_response(token_data, req_scope)

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
            headers.update(_basic_auth_header(cid, csec))

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

        return sanitize_token_response(token_data, req_scope)
