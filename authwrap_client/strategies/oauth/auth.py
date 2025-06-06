from typing import Any

from authwrap_client.exceptions import InjectionError
from authwrap_client.strategies import BearerTokenAuth


class OAuth2AuthV2(BearerTokenAuth):
    """
    OAuth 2.0 token injection with support for multiple flows.

    Args:
        auth_flow (AuthFlow): The authentication flow to use, such as client
            credentials, resource owner password, or authorization code.
        **kwargs: Additional parameters required for the selected flow.
    """
    def __init__(self, auth_flow: str, **kwargs: Any) -> None:
        from .flow_impl import get_auth_flow_class

        flow_class = get_auth_flow_class(auth_flow)
        if not flow_class:
            raise InjectionError(f"Unsupported OAuth flow: {auth_flow}")

        self.auth_flow = flow_class(**kwargs)
        token = self.auth_flow.get_token()
        super().__init__(token=token, **self.auth_flow.additional_headers)
