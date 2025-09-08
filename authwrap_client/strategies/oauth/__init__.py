from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Union

from authwrap_client import ValidationProtocol
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
        token_expiry_time: Optional[float] = None,
        grant_type: str = "client_credentials",
        scope: Optional[str] = None,
        additional_headers: Optional[Dict[str, str]] = None,
        validation_service: Optional[ValidationProtocol] = None,
        http_client: Optional[Any] = None,
        allow_rewrite: bool = False,
        **request_kwargs: Any,
    ) -> None:
        # 1. Validate all incoming parameters
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

        # 2. Initialize or verify the HTTP client
        self._http_client = self._initialize_http_client(http_client)

        # 3. Determine which token to use or fetch
        token = self._determine_token(
            authorization_server=authorization_server,
            client_id=client_id,
            client_secret=client_secret,
            username=username,
            password=password,
            implicit=implicit,
            access_token=access_token,
            refresh_token=refresh_token,
            token_expiry_time=token_expiry_time,
            grant_type=grant_type,
            scope=scope,
            request_kwargs=request_kwargs,
        )

        # 4. Initialize the BearerTokenAuth superclass
        additional_headers = additional_headers or {}
        logger.debug("Initializing BearerTokenAuth with token=%s.", bool(token))
        super().__init__(token=token, allow_rewrite=allow_rewrite, **additional_headers)

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
        """
        Validate the OAuth2 parameters using the provided or default validation service.

        Raises:
            InjectionError: If validation fails.
        """
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
        """
        Verify that the provided HTTP client has a 'request' method, or default to requests.Session().

        Raises:
            InjectionError: If the provided client does not have a 'request' method.
        """
        if http_client:
            if not hasattr(http_client, "request"):
                raise InjectionError("HTTP client must have a 'request' method.")
            return http_client

        # Default to requests.Session()
        import requests
        return requests.Session()

    def _determine_token(
        self,
        authorization_server: str,
        client_id: Optional[str],
        client_secret: Optional[str],
        username: Optional[str],
        password: Optional[str],
        implicit: bool,
        access_token: Optional[str],
        refresh_token: Optional[str],
        token_expiry_time: Optional[float],
        grant_type: str,
        scope: Optional[str],
        request_kwargs: Dict[str, Any],
    ) -> str:
        """
        Determine which access token to use (existing, refreshed, or newly fetched).

        Raises:
            InjectionError: If no valid token can be obtained.
        """
        # 3a. Reuse existing token if not expired
        if access_token and token_expiry_time is not None and not self._is_token_expired(token_expiry_time):
            logger.debug("Reusing existing non-expired access token.")
            return access_token

        # 3b. Refresh via refresh_token if provided
        if refresh_token:
            return self._handle_refresh(
                authorization_server=authorization_server,
                client_id=client_id,
                client_secret=client_secret,
                refresh_token=refresh_token,
                scope=scope,
                request_kwargs=request_kwargs,
            )

        # 3c. Otherwise, select flow based on grant_type or implicit flag
        if implicit:
            return self._handle_implicit(
                authorization_endpoint=authorization_server,
                client_id=client_id,
                scope=scope,
                request_kwargs=request_kwargs,
            )

        if grant_type.lower() == "password" and username and password:
            return self._handle_password(
                token_url=authorization_server,
                username=username,
                password=password,
                client_id=client_id,
                client_secret=client_secret,
                scope=scope,
                request_kwargs=request_kwargs,
            )

        if grant_type.lower() == "client_credentials" and client_id and client_secret:
            return self._handle_client_credentials(
                token_url=authorization_server,
                client_id=client_id,
                client_secret=client_secret,
                scope=scope,
                request_kwargs=request_kwargs,
            )

        raise InjectionError("Unsupported grant_type or missing required parameters for OAuth2Auth.")

    def _handle_refresh(
        self,
        authorization_server: str,
        client_id: Optional[str],
        client_secret: Optional[str],
        refresh_token: str,
        scope: Optional[str],
        request_kwargs: Dict[str, Any],
    ) -> str:
        """
        Refresh an access token using a refresh token.

        Raises:
            InjectionError: If refresh fails or no token is returned.
        """
        logger.debug("Refreshing token using refresh_token.")
        # Use ClientCredentialsFlowProtocol to refresh (token_url is authorization_server)
        flow: ClientCredentialsFlowProtocol = ClientCredentialsFlow(
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

        token = refreshed.get("access_token", "")
        if not token:
            raise InjectionError("Refresh flow did not return an access_token.")

        logger.debug("Obtained new access token via refresh.")
        return token

    def _handle_implicit(
        self,
        authorization_endpoint: str,
        client_id: Optional[str],
        scope: Optional[str],
        request_kwargs: Dict[str, Any],
    ) -> str:
        """
        Build the Implicit Flow authorization URL and raise an exception instructing the user.

        Raises:
            InjectionError: Always, since Implicit Flow requires interactive redirect.
        """
        if not scope:
            raise InjectionError("Scope is required for implicit flow.")

        logger.debug("Building Implicit Flow authorization URL.")
        flow: ImplicitFlowProtocol = ImplicitFlow(
            authorization_endpoint=authorization_endpoint,
            client_id=client_id or "",
            default_scope=scope,
        )
        auth_url = flow.get_authorization_url(
            redirect_uri=request_kwargs.get("redirect_uri", ""),
            scope=scope,
            state=request_kwargs.get("state"),
        )
        raise InjectionError(
            "Implicit Flow requires interactive redirect. Visit:\n" f"{auth_url}"
        )

    def _handle_password(
        self,
        token_url: str,
        username: str,
        password: str,
        client_id: Optional[str],
        client_secret: Optional[str],
        scope: Optional[str],
        request_kwargs: Dict[str, Any],
    ) -> str:
        """
        Use Resource Owner Password Credentials to fetch a token.

        Raises:
            InjectionError: If password flow fails or no token is returned.
        """
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

        token = token_response.get("access_token", "")
        if not token:
            raise InjectionError("Password flow did not return an access_token.")

        logger.debug("Obtained access token via Password Credentials grant.")
        return token

    def _handle_client_credentials(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: Optional[str],
        request_kwargs: Dict[str, Any],
    ) -> str:
        """
        Use Client Credentials grant to fetch a token.

        Raises:
            InjectionError: If client credentials flow fails or no token is returned.
        """
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

        token = token_response.get("access_token", "")
        if not token:
            raise InjectionError("Client credentials flow did not return an access_token.")

        logger.debug("Obtained access token via Client Credentials grant.")
        return token

    @staticmethod
    def _is_token_expired(token_expiry_time: float, grace_period: int = 60) -> bool:
        """
        Check if the token is expired or within the grace period.
        """
        return time.time() >= (token_expiry_time - grace_period)
