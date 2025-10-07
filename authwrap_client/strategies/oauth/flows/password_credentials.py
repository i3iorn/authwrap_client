from __future__ import annotations
from typing import Optional, Union, List, Any, Dict

from authwrap_client.config import FeatureFlag
from authwrap_client.strategies.oauth import OAuthError
from authwrap_client.strategies.oauth.common import TokenResponse
from authwrap_client.strategies.oauth.flows import settle_clients, _basic_auth_header, sanitize_token_response
from authwrap_client.utils import insecure


@insecure(
    FeatureFlag.ENABLE_LEGACY_FEATURES | FeatureFlag.ENABLE_PASSWORD_FLOW,
    "PasswordCredentialsFlow is insecure and should not be used in production.",
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
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = self._normalize_scope(scope)
        self.http_client, self.http_client_async = settle_clients(http_client, http_client_async)

    # ---------------------------- internal helpers ----------------------------
    def _normalize_scope(self, scope: Optional[Union[str, List[str]]]) -> str:
        if isinstance(scope, list):
            return " ".join(scope)
        return scope or ""

    def _resolve_scope(self, scope: Optional[Union[str, List[str]]]) -> str:
        return self._normalize_scope(scope) or self.scope

    def _headers(self, cid: Optional[str], csec: Optional[str]) -> Dict[str, Any]:
        headers: Dict[str, Any] = {"Content-Type": "application/x-www-form-urlencoded"}
        if cid and csec:
            headers.update(_basic_auth_header(cid, csec))
        return headers

    def _body(self, username: str, password: str, req_scope: str) -> Dict[str, Any]:
        body: Dict[str, Any] = {"grant_type": "password", "username": username, "password": password}
        if req_scope:
            body["scope"] = req_scope
        return body

    def _request_sync(self, body: Dict[str, Any], headers: Dict[str, Any], **kwargs: Any) -> Any:
        return self.http_client.request(method="POST", url=self.token_url, data=body, headers=headers, **kwargs)

    async def _request_async(self, body: Dict[str, Any], headers: Dict[str, Any], **kwargs: Any) -> Any:
        return await self.http_client_async.request(method="POST", url=self.token_url, data=body, headers=headers, **kwargs)

    def _parse_response(self, response: Any, label: str, req_scope: str) -> TokenResponse:
        if response.status_code != 200:
            raise OAuthError(f"{label}password grant request failed: {response.status_code} {response.text}")
        try:
            token_data = response.json()
        except ValueError as e:
            raise OAuthError(f"Invalid JSON in {label}password grant response: {e}") from e
        return sanitize_token_response(token_data, req_scope)

    # --------------------------------- API ------------------------------------
    def fetch_token_with_password(
        self,
        username: str,
        password: str,
        *,
        scope: Optional[Union[str, List[str]]] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        **kwargs: Any,
    ) -> TokenResponse:
        req_scope = self._resolve_scope(scope)
        cid = client_id or self.client_id
        csec = client_secret or self.client_secret
        headers = self._headers(cid, csec)
        body = self._body(username, password, req_scope)
        response = self._request_sync(body, headers, **kwargs)
        return self._parse_response(response, label="", req_scope=req_scope)

    async def fetch_token_with_password_async(
        self,
        username: str,
        password: str,
        *,
        scope: Optional[Union[str, List[str]]] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        **kwargs: Any,
    ) -> TokenResponse:
        req_scope = self._resolve_scope(scope)
        cid = client_id or self.client_id
        csec = client_secret or self.client_secret
        headers = self._headers(cid, csec)
        body = self._body(username, password, req_scope)
        response = await self._request_async(body, headers, **kwargs)
        return self._parse_response(response, label="async ", req_scope=req_scope)
