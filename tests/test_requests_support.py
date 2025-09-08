import requests
from authwrap_client import wrap_with_bearer_token

def test_requests_support():
    """Test that requests library works correctly after wrapping."""
    # Create a wrapped requests session
    session = wrap_with_bearer_token(requests.Session(), token="test_token")

    # Mock a simple HTTP server response
    from requests_mock import Mocker
    with Mocker() as mock:
        mock.get("https://httpbin.org/headers", json={"Authorization": "Bearer test_token"})

        # Perform a GET request
        response = session.get("https://httpbin.org/headers")

        # Assert the response is as expected
        assert response.status_code == 200
        assert response.json()["Authorization"] == "Bearer test_token"

def test_requests_support_with_custom_headers():
    """Test that requests library works correctly with custom headers."""
    # Create a wrapped requests session with additional headers
    session = wrap_with_bearer_token(requests.Session(), token="test_token", custom_header="custom_value")

    # Mock a simple HTTP server response
    from requests_mock import Mocker
    with Mocker() as mock:
        mock.get("https://httpbin.org/headers", json={"Authorization": "Bearer test_token", "Custom-Header": "custom_value"})

        # Perform a GET request
        response = session.get("https://httpbin.org/headers")

        # Assert the response is as expected
        assert response.status_code == 200
        assert response.json()["Authorization"] == "Bearer test_token"
        assert response.json()["Custom-Header"] == "custom_value"

def test_requests_support_with_allow_rewrite():
    """Test that requests library works correctly with allow_rewrite."""
    # Create a wrapped requests session with allow_rewrite
    session = wrap_with_bearer_token(requests.Session(), token="test_token", allow_rewrite=True)

    # Mock a simple HTTP server response
    from requests_mock import Mocker
    with Mocker() as mock:
        mock.get("https://httpbin.org/headers", json={"Authorization": "Bearer test_token"})

        # Perform a GET request
        response = session.get("https://httpbin.org/headers")

        # Assert the response is as expected
        assert response.status_code == 200
        assert response.json()["Authorization"] == "Bearer test_token"

def test_requests_support_with_invalid_token():
    """Test that requests library raises an error with an invalid token."""
    try:
        # Attempt to create a wrapped requests session with an empty token
        wrap_with_bearer_token(requests.Session(), token="")
    except ValueError as e:
        assert str(e) == "Token must be provided and cannot be empty."
    else:
        assert False, "Expected ValueError was not raised."
