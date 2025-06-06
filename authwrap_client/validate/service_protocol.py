from typing import Dict, Protocol, Any, Optional


class ValidationProtocol(Protocol):
    """
    Protocol for validating input parameters for authentication and authorization strategies.
    """
    def validate_oauth_parameters(
        self,
            authorization_server: str,
            client_id: Optional[str] = None,
            client_secret: Optional[str] = None,
            username: Optional[str] = None,
            password: Optional[str] = None,
            authorization_code: Optional[str] = None,
            scope: Optional[str] = None,
            implicit: bool = False,
            access_token: Optional[str] = None,
            refresh_token: Optional[str] = None,
            grant_type: str = "client_credentials",
            additional_headers: Dict[str, str] = None
    ) -> bool:
        """
        Validate the parameters required for OAuth 2.0 authentication.

        Args:
            authorization_server (str): The URL of the authorization server.
            client_id (Optional[str]): The client ID for the OAuth application.
            client_secret (Optional[str]): The client secret for the OAuth application.
            username (Optional[str]): The username for resource owner password credentials grant.
            password (Optional[str]): The password for resource owner password credentials grant.
            authorization_code (Optional[str]): The authorization code for the authorization code grant.
            implicit (bool): Whether to use implicit flow.
            access_token (Optional[str]): An existing access token.
            refresh_token (Optional[str]): A refresh token to obtain a new access token.
            grant_type (str): The type of OAuth grant to use, default is "client_credentials".
            additional_headers (Dict[str, str], optional): Additional headers to include in the request.

        Returns:
            bool: True if the parameters are valid, False otherwise.
        """
        ...
