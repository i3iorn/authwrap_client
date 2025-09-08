from typing import Optional, Union, List, Any, Dict
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

from authwrap_client.config import FeatureFlag
from authwrap_client.strategies.oauth import OAuthError
from authwrap_client.strategies.oauth.flow_protocol import ImplicitFlowProtocol, TokenResponse
from authwrap_client.utils import insecure


@insecure(
    FeatureFlag.ENABLE_LEGACY_FEATURES | FeatureFlag.ENABLE_IMPLICIT_FLOW,
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
