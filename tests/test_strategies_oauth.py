import pytest
from unittest.mock import MagicMock, patch

from authwrap_client.config import State, FeatureFlag
from authwrap_client.exceptions import InjectionError
from authwrap_client.strategies import OAuth2Auth
from authwrap_client.strategies.oauth.flow_impl import ClientCredentialsFlow, \
    PasswordCredentialsFlow, ImplicitFlow
from authwrap_client.strategies.oauth.flow_protocol import TokenResponse
from authwrap_client import ValidationProtocol


# Test Initialization of OAuth2Auth
@pytest.fixture
def oauth2auth_params():
    return {
        'authorization_server': 'https://example.com/oauth/token',
        'client_id': 'test-client-id',
        'client_secret': 'test-client-secret',
        'grant_type': 'client_credentials',
        'scope': 'read write',
        'implicit': False,
        'access_token': None,
        'refresh_token': None,
    }


@patch("authwrap_client.strategies.oauth.ClientCredentialsFlow")
@patch("requests.Session")
def test_oauth2auth_init(mock_session, mock_flow_class, oauth2auth_params):
    mock_token_response = MagicMock(spec=TokenResponse)
    mock_flow_instance = MagicMock()
    mock_flow_instance.fetch_token_client_credentials.return_value = mock_token_response
    mock_flow_class.return_value = mock_flow_instance

    oauth2auth = OAuth2Auth(**oauth2auth_params)

    mock_session.assert_called_once()
    mock_flow_instance.fetch_token_client_credentials.assert_called_once()
    assert oauth2auth.token_response == mock_token_response



# Test Invalid Parameters Validation
@pytest.mark.parametrize(
    "grant_type, client_id, client_secret, should_raise",
    [
        ("client_credentials", None, None, InjectionError),
        # Missing client_id and client_secret
        ("password", None, None, InjectionError),  # Missing username and password
        ("implicit", None, None, InjectionError),  # Missing scope
    ]
)
def test_validate_parameters(grant_type, client_id, client_secret, should_raise,
                             oauth2auth_params):
    oauth2auth_params.update({
        'grant_type': grant_type,
        'client_id': client_id,
        'client_secret': client_secret
    })

    with pytest.raises(should_raise):
        OAuth2Auth(**oauth2auth_params)


def test_initialize_http_client(oauth2auth_params):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "test-access-token",
        "expires_in": 3600,
        "token_type": "Bearer",
        "refresh_token": "test-refresh-token",
        "scope": "read write"
    }

    custom_http_client = MagicMock()
    custom_http_client.request = MagicMock(return_value=mock_response)

    oauth2auth_params["http_client"] = custom_http_client

    auth = OAuth2Auth(**oauth2auth_params)

    assert auth.token_response.access_token == "test-access-token"
    assert auth.token_response.scope == "read write"


@pytest.mark.parametrize(
    "access_token, refresh_token, implicit, grant_type, expected_flow",
    [
        (None, "valid_refresh_token", False, "client_credentials", "_handle_refresh"),
        (None, None, True, "implicit", "_handle_implicit"),
        ("valid_token", None, False, "password", "_handle_password"),
        ("valid_token", None, False, "client_credentials", "_handle_client_credentials"),
    ]
)
def test_determine_token_flow(oauth2auth_params, access_token, refresh_token, implicit,
                              grant_type, expected_flow):
    if access_token == "valid_token":
        access_token = TokenResponse(
            access_token="valid_token",
            token_type="Bearer",
            expires_in=3600,
            scope="read write",
            refresh_token=None,
            token_response=None
        )

    oauth2auth_params.update({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'implicit': implicit,
        'grant_type': grant_type
    })


# Test _handle_refresh method
def test_handle_refresh(oauth2auth_params):
    oauth2auth_params['refresh_token'] = "valid_refresh_token"
    oauth2auth_params['client_id'] = "test-client-id"
    oauth2auth_params['client_secret'] = "test-client-secret"

    with patch(
            'authwrap_client.strategies.oauth.flow_impl.ClientCredentialsFlow.refresh_access_token') as mock_refresh:
        mock_refresh.return_value = MagicMock(spec=TokenResponse)
        oauth2auth = OAuth2Auth(**oauth2auth_params)
        assert mock_refresh.called


# Test _handle_implicit method (raises InjectionError)
def test_handle_implicit(oauth2auth_params):
    oauth2auth_params['implicit'] = True
    oauth2auth_params['scope'] = "read write"

    with pytest.raises(InjectionError):
        OAuth2Auth(**oauth2auth_params)


def test_handle_password(oauth2auth_params):
    oauth2auth_params['grant_type'] = "password"
    oauth2auth_params['username'] = "user"
    oauth2auth_params['password'] = "pass"

    # Set flags manually for test
    State().flags = {FeatureFlag.ENABLE_LEGACY_FEATURES}

    with patch(
        'authwrap_client.strategies.oauth.flow_impl.PasswordCredentialsFlow.fetch_token_with_password'
    ) as mock_password_flow:
        mock_password_flow.return_value = MagicMock(spec=TokenResponse)
        auth = OAuth2Auth(**oauth2auth_params)


# Test _handle_client_credentials method
def test_handle_client_credentials(oauth2auth_params):
    oauth2auth_params['grant_type'] = "client_credentials"

    with patch(
            'authwrap_client.strategies.oauth.flow_impl.ClientCredentialsFlow.fetch_token_client_credentials') as mock_client_credentials_flow:
        mock_client_credentials_flow.return_value = MagicMock(spec=TokenResponse)
        oauth2auth = OAuth2Auth(**oauth2auth_params)
        assert mock_client_credentials_flow.called


# Test token determination with invalid access_token
def test_invalid_access_token(oauth2auth_params):
    oauth2auth_params['access_token'] = "invalid_token"

    with pytest.raises(InjectionError):
        OAuth2Auth(**oauth2auth_params)

