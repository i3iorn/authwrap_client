from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from ...validate.service_protocol import ValidationProtocol
from authwrap_client.base import ResponseProtocol
from authwrap_client.exceptions import InjectionError
from authwrap_client.strategies.oauth.common import OAuthError, TokenResponse
from authwrap_client.validate.validator import BaseValidatorService
from authwrap_client.strategies.bearer_token import BearerTokenAuth
from .flow_protocol import ClientCredentialsFlowProtocol, ImplicitFlowProtocol, PasswordCredentialsFlowProtocol

from .flows import ClientCredentialsFlow, PasswordCredentialsFlow, ImplicitFlow

__all__ = [
    "OAuth2Auth",
    "ClientCredentialsFlow",
    "PasswordCredentialsFlow",
    "ImplicitFlow",
]

logger = logging.getLogger(__name__)


class OAuth2Auth(BearerTokenAuth):
    """
    OAuth 2.0 token injection using pluggable Flow implementations.

    Supports:
      - Client Credentials (RFC 6749 §4.4)
      - Resource Owner Password Credentials (RFC 6749 §4.3)
      - Implicit Flow (RFC 6749 §4.2)

    Args:
        authorization_server (str): The token endpoint (for client-credentials/password)
                                    or authorization endpoint (for implicit).
        client_id (Optional[str]): OAuth2 client identifier.
        client_secret (Optional[str]): OAuth2 client secret.
        username (Optional[str]): Username for password grant.
        password (Optional[str]): Password for password grant.
        authorization_code (Optional[str]): (Not used here; provided for validation.)
        implicit (bool): If True, uses Implicit Flow.
        access_token (Optional[str]): Existing access token.
        refresh_token (Optional[str]): Refresh token to obtain new access token.
        token_expiry_time (Optional[float]): UNIX timestamp when existing token expires.
        grant_type (str): One of "client_credentials", "password", or "implicit".
        scope (Optional[str]): Space-delimited scopes to request.
        additional_headers (Optional[Dict[str, str]]): Extra headers for BearerTokenAuth.
        validation_service (Optional[ValidationProtocol]): Validates parameter combinations.
        http_client (Optional[Any]): Sync HTTP client with `.request()`. Defaults to requests.Session().
        allow_rewrite (bool): Passed to BearerTokenAuth.
        **request_kwargs: Any extra keyword args forwarded to flow implementations.

    Raises:
        InjectionError: If validation fails or required parameters are missing.
    """

    def __init__(
        self,
        authorization_server: str,
        *,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        authorization_code: Optional[str] = None,
        implicit: bool = False,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        grant_type: str = "client_credentials",
        scope: Optional[str] = None,
        additional_headers: Optional[Dict[str, str]] = None,
        validation_service: Optional[ValidationProtocol] = None,
        http_client: Optional[Any] = None,
        allow_rewrite: bool = False,
        allow_overwrite: Optional[bool] = None,
        **request_kwargs: Any,
    ) -> None:
        # Validate and prepare HTTP client
        try:
            self._validate_parameters(
                authorization_server=authorization_server,
                client_id=client_id,
                client_secret=client_secret,
                username=username,
                password=password,
                authorization_code=authorization_code,
                scope=scope,
                implicit=implicit,
                access_token=access_token,
                refresh_token=refresh_token,
                grant_type=grant_type,
                validation_service=validation_service,
            )
        except Exception as e:
            raise InjectionError(f"Invalid OAuth2 parameters: {e}") from e
        self._http_client = self._initialize_http_client(http_client)

        # Determine token and initialize Bearer auth
        self.token_response = self._acquire_token_response(
            authorization_server,
            client_id,
            client_secret,
            username,
            password,
            implicit,
            access_token,
            refresh_token,
            grant_type,
            scope,
            request_kwargs,
        )
        token = self.token_response.json()["access_token"]
        headers = additional_headers or {}
        logger.debug("Initializing BearerTokenAuth with token=%s.", bool(token))
        super().__init__(token=token, allow_rewrite=allow_rewrite, allow_overwrite=allow_overwrite, **headers)

    # --------------------------- internal orchestration ---------------------------
    def _acquire_token_response(
        self,
        authorization_server: str,
        client_id: Optional[str],
        client_secret: Optional[str],
        username: Optional[str],
        password: Optional[str],
        implicit: bool,
        access_token: Optional[TokenResponse],
        refresh_token: Optional[str],
        grant_type: str,
        scope: Optional[str],
        request_kwargs: Dict[str, Any],
    ) -> ResponseProtocol:
        token = self._use_existing_if_valid(access_token)
        if token:
            return token
        token = self._refresh_if_requested(
            authorization_server, client_id, client_secret, refresh_token, scope, request_kwargs
        )
        if token:
            return token
        return self._from_grant_or_implicit(
            authorization_server,
            client_id,
            client_secret,
            username,
            password,
            implicit,
            grant_type,
            scope,
            request_kwargs,
        )

    def _use_existing_if_valid(self, access_token: Optional[TokenResponse]) -> Optional[TokenResponse]:
        if not access_token:
            return None
        if not isinstance(access_token, TokenResponse):
            raise InjectionError("Provided access_token is invalid.")
        return access_token if access_token.is_valid else None

    def _refresh_if_requested(
        self,
        authorization_server: str,
        client_id: Optional[str],
        client_secret: Optional[str],
        refresh_token: Optional[str],
        scope: Optional[str],
        request_kwargs: Dict[str, Any],
    ) -> Optional[TokenResponse]:
        if not refresh_token:
            return None
        return self._handle_refresh(
            authorization_server=authorization_server,
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=refresh_token,
            scope=scope,
            request_kwargs=request_kwargs,
        )

    def _from_grant_or_implicit(
        self,
        authorization_server: str,
        client_id: Optional[str],
        client_secret: Optional[str],
        username: Optional[str],
        password: Optional[str],
        implicit: bool,
        grant_type: str,
        scope: Optional[str],
        request_kwargs: Dict[str, Any],
    ) -> TokenResponse:
        if implicit:
            return self._handle_implicit(
                authorization_endpoint=authorization_server,
                client_id=client_id,
                scope=scope,
                request_kwargs=request_kwargs,
            )
        grant = grant_type.lower()
        if grant == "password" and username and password:
            return self._handle_password(
                token_url=authorization_server,
                username=username,
                password=password,
                client_id=client_id,
                client_secret=client_secret,
                scope=scope,
                request_kwargs=request_kwargs,
            )
        if grant == "client_credentials" and client_id and client_secret:
            return self._handle_client_credentials(
                token_url=authorization_server,
                client_id=client_id,
                client_secret=client_secret,
                scope=scope,
                request_kwargs=request_kwargs,
            )
        raise InjectionError("Unsupported grant_type or missing required parameters for OAuth2Auth.")

    # ------------------------------ validation --------------------------------
    def _validate_parameters(
        self,
        authorization_server: str,
        client_id: Optional[str],
        client_secret: Optional[str],
        username: Optional[str],
        password: Optional[str],
        authorization_code: Optional[str],
        scope: Optional[str],
        implicit: bool,
        access_token: Optional[str],
        refresh_token: Optional[str],
        grant_type: str,
        validation_service: Optional[ValidationProtocol],
    ) -> None:
        service = validation_service or BaseValidatorService()
        service.validate_oauth_parameters(
            authorization_server=authorization_server,
            client_id=client_id,
            client_secret=client_secret,
            username=username,
            password=password,
            authorization_code=authorization_code,
            scope=scope,
            implicit=implicit,
            access_token=access_token,
            refresh_token=refresh_token,
            grant_type=grant_type,
        )

    def _initialize_http_client(self, http_client: Optional[Any]) -> Any:
        if http_client:
            if not hasattr(http_client, "request"):
                raise InjectionError("HTTP client must have a 'request' method.")
            return http_client
        import requests
        return requests.Session()

    # ------------------------------ flow helpers ------------------------------
    def _handle_refresh(
        self,
        authorization_server: str,
        client_id: Optional[str],
        client_secret: Optional[str],
        refresh_token: str,
        scope: Optional[str],
        request_kwargs: Dict[str, Any],
    ) -> ResponseProtocol:
        logger.debug("Refreshing token using refresh_token.")
        flow: ClientCredentialsFlow = ClientCredentialsFlow(
            token_url=authorization_server,
            client_id=client_id or "",
            client_secret=client_secret or "",
            http_client=self._http_client,
        )
        try:
            refreshed: TokenResponse = flow.refresh_access_token(
                refresh_token=refresh_token, scope=scope, **request_kwargs
            )
        except OAuthError as e:
            raise InjectionError(f"Failed to refresh token: {e}")
        if not refreshed or not refreshed.access_token:
            raise InjectionError("Refresh token did not return a valid access token.")
        return refreshed

    def _handle_implicit(
        self,
        authorization_endpoint: str,
        client_id: Optional[str],
        scope: Optional[str],
        request_kwargs: Dict[str, Any],
    ) -> TokenResponse:
        if not scope:
            raise InjectionError("Scope is required for implicit flow.")
        logger.debug("Building Implicit Flow authorization URL.")
        flow: ImplicitFlow = ImplicitFlow(
            authorization_endpoint=authorization_endpoint,
            client_id=client_id or "",
            default_scope=scope,
        )
        auth_url = flow.get_authorization_url(
            redirect_uri=request_kwargs.get("redirect_uri", ""),
            scope=scope,
            state=request_kwargs.get("state"),
        )
        raise InjectionError("Implicit Flow requires interactive redirect. Visit:\n" f"{auth_url}")

    def _handle_password(
        self,
        token_url: str,
        username: str,
        password: str,
        client_id: Optional[str],
        client_secret: Optional[str],
        scope: Optional[str],
        request_kwargs: Dict[str, Any],
    ) -> TokenResponse:
        logger.debug("Using PasswordCredentialsFlow for username/password grant.")
        flow: PasswordCredentialsFlow = PasswordCredentialsFlow(
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            http_client=self._http_client,
        )
        try:
            token_response = flow.fetch_token_with_password(
                username=username,
                password=password,
                scope=scope,
                client_id=client_id,
                client_secret=client_secret,
                **request_kwargs,
            )
        except OAuthError as e:
            raise InjectionError(f"Password Credentials flow failed: {e}")
        return token_response

    def _handle_client_credentials(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: Optional[str],
        request_kwargs: Dict[str, Any],
    ) -> TokenResponse:
        if not scope:
            raise InjectionError("Scope must be provided for client credentials flow.")
        logger.debug("Using ClientCredentialsFlow for client credentials grant.")
        flow: ClientCredentialsFlow = ClientCredentialsFlow(
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            http_client=self._http_client,
        )
        try:
            token_response = flow.fetch_token(
                scope=scope, client_id=client_id, client_secret=client_secret, **request_kwargs
            )
        except OAuthError as e:
            raise InjectionError(f"Client Credentials flow failed: {e}")
        return token_response

    @staticmethod
    def _is_token_expired(token_expiry_time: float, grace_period: int = 60) -> bool:
        return time.time() >= (token_expiry_time - grace_period)
