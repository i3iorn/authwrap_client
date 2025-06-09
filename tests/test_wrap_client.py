import pytest
from authwrap_client import wrap_client
from authwrap_client.strategies.basic import BasicAuth
from authwrap_client.strategies.bearer_token import BearerTokenAuth
from authwrap_client.strategies.oauth import OAuth2Auth

class DummyClient:
    def request(self, *args, **kwargs):
        return 'ok'

def test_wrap_with_basic_auth():
    client = DummyClient()
    wrapped = wrap_client.wrap_client(client, 'basic', username='user', password='pass')
    assert hasattr(wrapped, 'request')

def test_wrap_with_bearer_token():
    client = DummyClient()
    wrapped = wrap_client.wrap_client(client, 'bearer_token', token='abc')
    assert hasattr(wrapped, 'request')

def test_wrap_with_oauth():
    client = DummyClient()
    wrapped = wrap_client.wrap_client(client, 'oauth', token_url='https://example.com/token')
    assert hasattr(wrapped, 'request')

def test_invalid_strategy():
    client = DummyClient()
    with pytest.raises(ValueError):
        wrap_client.wrap_client(client, 'invalid')

def test_invalid_client():
    with pytest.raises(ValueError):
        wrap_client.wrap_client(None, 'basic', username='user', password='pass')
    class NoRequest: pass
    with pytest.raises(TypeError):
        wrap_client.wrap_client(NoRequest(), 'basic', username='user', password='pass')
    class NotCallable:
        request = 'not_callable'
    with pytest.raises(TypeError):
        wrap_client.wrap_client(NotCallable(), 'basic', username='user', password='pass')

def test_string_validation():
    client = DummyClient()
    with pytest.raises(ValueError):
        wrap_client.wrap_client(client, 'basic', username='', password='pass')
    with pytest.raises(TypeError):
        wrap_client.wrap_client(client, 'basic', username=123, password='pass')
    with pytest.raises(ValueError):
        wrap_client.wrap_client(client, 'basic', username='a'*257, password='pass')

