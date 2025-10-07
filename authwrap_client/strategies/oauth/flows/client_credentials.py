from __future__ import annotations
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

    # ---------------------------- internal helpers ----------------------------
    def _resolve_scope(self, scope: Optional[Union[str, List[str]]]) -> str:
        if scope:
            return " ".join(scope) if isinstance(scope, list) else scope
        return self.scope or ""

    def _build_body(self, token_scope: str) -> Dict[str, Any]:
        body: Dict[str, Any] = {"grant_type": "client_credentials"}
        if token_scope:
            body["scope"] = token_scope
        return body

    def _perform_request_sync(self, headers: Dict[str, str], body: Dict[str, Any], **kwargs: Any) -> Any:
        return self.http_client.request(
            method="POST",
            url=self.token_url,
            data=body,
            headers=headers,
            **kwargs,
        )

    async def _perform_request_async(self, headers: Dict[str, str], body: Dict[str, Any], **kwargs: Any) -> Any:
        return await self.http_client_async.request(
            method="POST",
            url=self.token_url,
            data=body,
            headers=headers,
            **kwargs,
        )

    def _parse_response(self, response: Any, token_scope: str, async_label: str = "") -> TokenResponse:
        if response.status_code != 200:
                        label = "async " if async_label else ""
            raise OAuthError(
                f"{label}client credentials request failed: {response.status_code} {response.text}"
            )
        try:
            token_data = response.json()
        except ValueError as e:
            label = "async " if async_label else ""
            raise OAuthError(f"Invalid JSON in {label}token response: {e}")
        return sanitize_token_response(token_data, token_scope)

    # ------------------------------ public API --------------------------------
    def fetch_token(
        self,
        *,
        scope: Optional[Union[str, List[str]]] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        **kwargs: Any,
    ) -> TokenResponse:
        """
        Obtain an access token using client credentials (RFC 6749 §4.4.2).
        """
        cid = client_id or self.client_id
        csec = client_secret or self.client_secret
        token_scope = self._resolve_scope(scope)
        headers = _basic_auth_header(cid, csec)
        body = self._build_body(token_scope)
        response = self._perform_request_sync(headers, body, **kwargs)
        return self._parse_response(response, token_scope)

    async def fetch_token_async(
        self,
        *,
        scope: Optional[Union[str, List[str]]] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        **kwargs: Any,
    ) -> TokenResponse:
        """
        Async variant of fetch_token_client_credentials.
        """
        cid = client_id or self.client_id
        csec = client_secret or self.client_secret
        token_scope = self._resolve_scope(scope)
        headers = _basic_auth_header(cid, csec)
        body = self._build_body(token_scope)
        response = await self._perform_request_async(headers, body, **kwargs)
        return self._parse_response(response, token_scope, async_label="async")
