import pytest
from authwrap_client.validate.validator import BaseValidatorService

def test_validate_oauth_parameters_with_valid_inputs():
    validator = BaseValidatorService()
    assert validator.validate_oauth_parameters(
        authorization_server="https://auth.example.com",
        client_id="client123",
        client_secret="secret123",
        grant_type="client_credentials"
    )

def test_validate_oauth_parameters_missing_authorization_server_raises_value_error():
    validator = BaseValidatorService()
    with pytest.raises(ValueError):
        validator.validate_oauth_parameters(
            authorization_server="",
            client_id="client123"
        )

def test_validate_oauth_parameters_invalid_authorization_server_type_raises_type_error():
    validator = BaseValidatorService()
    with pytest.raises(TypeError):
        validator.validate_oauth_parameters(
            authorization_server=123,
            client_id="client123"
        )

def test_validate_oauth_parameters_missing_client_id_and_access_token_raises_value_error():
    validator = BaseValidatorService()
    with pytest.raises(ValueError):
        validator.validate_oauth_parameters(
            authorization_server="https://auth.example.com"
        )

def test_validate_oauth_parameters_client_secret_without_client_id_raises_value_error():
    validator = BaseValidatorService()
    with pytest.raises(ValueError):
        validator.validate_oauth_parameters(
            authorization_server="https://auth.example.com",
            client_secret="secret123"
        )

def test_validate_oauth_parameters_username_without_password_raises_value_error():
    validator = BaseValidatorService()
    with pytest.raises(ValueError):
        validator.validate_oauth_parameters(
            authorization_server="https://auth.example.com",
            username="user123"
        )

def test_validate_oauth_parameters_password_without_username_raises_value_error():
    validator = BaseValidatorService()
    with pytest.raises(ValueError):
        validator.validate_oauth_parameters(
            authorization_server="https://auth.example.com",
            password="pass123"
        )

def test_validate_oauth_parameters_authorization_code_without_implicit_raises_value_error():
    validator = BaseValidatorService()
    with pytest.raises(ValueError):
        validator.validate_oauth_parameters(
            authorization_server="https://auth.example.com",
            authorization_code="code123"
        )

def test_validate_oauth_parameters_implicit_with_disallowed_params_raises_value_error():
    validator = BaseValidatorService()
    with pytest.raises(ValueError):
        validator.validate_oauth_parameters(
            authorization_server="https://auth.example.com",
            implicit=True,
            client_id="client123"
        )

def test_validate_oauth_parameters_invalid_additional_headers_type_raises_type_error():
    validator = BaseValidatorService()
    with pytest.raises(ValueError):
        validator.validate_oauth_parameters(
            authorization_server="https://auth.example.com",
            additional_headers="not_a_dict"
        )

def test_validate_oauth_parameters_invalid_additional_headers_content_raises_type_error():
    validator = BaseValidatorService()
    with pytest.raises(ValueError):
        validator.validate_oauth_parameters(
            authorization_server="https://auth.example.com",
            additional_headers={"key": 123}
        )
