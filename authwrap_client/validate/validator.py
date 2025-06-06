from typing import Dict, Any, Optional

from authwrap_client.validate.service_protocol import ValidationProtocol


class BaseValidatorService(ValidationProtocol):
    """
    Base class for validation services that implements the ValidationProtocol.
    This class provides a foundation for validating authentication and authorization strategies.
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
            scope (Optional[str]): The scope of the access request.
            implicit (bool): Whether to use implicit flow.
            access_token (Optional[str]): An existing access token.
            refresh_token (Optional[str]): A refresh token to obtain a new access token.
            grant_type (str): The type of OAuth grant to use, default is "client_credentials".
            additional_headers (Dict[str, str], optional): Additional headers to include in the request.
        Raises:
            ValueError: If any of the required parameters are invalid or missing.
            TypeError: If the types of the parameters are incorrect.

        Returns:
            bool: True if the parameters are valid, False otherwise.
        """
        if not authorization_server:
            raise ValueError("Authorization server must not be empty.")
        if not isinstance(authorization_server, str):
            raise TypeError("Authorization server must be a string.")
        if not any([client_id, username, access_token, refresh_token, implicit]):
            raise ValueError("Either client_id or access_token must be provided.")
        if client_secret and not client_id:
            raise ValueError("client_secret must be provided with client_id.")
        if username and not password:
            raise ValueError("If username is provided, password must also be provided.")
        if password and not username:
            raise ValueError("If password is provided, username must also be provided.")
        if authorization_code and not implicit:
            raise ValueError("authorization_code can only be used with implicit flow.")
        if implicit and (client_id or client_secret or access_token or refresh_token):
            raise ValueError("Implicit flow does not require client_id, client_secret, access_token, or refresh_token.")
        if additional_headers is None:
            additional_headers = {}
        if not isinstance(additional_headers, dict):
            raise TypeError("additional_headers must be a dictionary.")
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in additional_headers.items()):
            raise TypeError("All keys and values in additional_headers must be strings.")

        # Make sure all input parameters are strings or None except for additional_headers
        for key, param in {
            "authorization_server": authorization_server
            , "client_id": client_id
            , "client_secret": client_secret
            , "username": username
            , "password": password
            , "authorization_code": authorization_code
            , "scope": scope
            , "access_token": access_token
            , "refresh_token": refresh_token
            , "grant_type": grant_type
        }.items():
            if param is not None and not isinstance(param, str):
                raise TypeError(f"{key} must be a string or None.")

        return True
