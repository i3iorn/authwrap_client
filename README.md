# AuthWrap Client

AuthWrap Client is a Python library designed to simplify adding authentication to HTTP client requests. It provides a flexible, pluggable interface for strategies like Basic Auth, OAuth2, Bearer Tokens, and API keys.

## Features
- Transparent wrapper for HTTP clients to inject authentication headers.
- Support for synchronous and asynchronous HTTP clients (via separate adapters).
- Pluggable authentication strategies.
- Configurable exception handling policies.

## Requirements
- Python 3.8 or higher
- See pyproject.toml for optional development dependencies

## Installation
To install the library, use pip:

```bash
pip install .
```

## Usage

### Wrapping an HTTP Client
AuthWrap Client provides convenience wrappers for common auth strategies. Use environment variables for secrets in examples.

Example (requests + OAuth2):

```python
import os
from authwrap_client import wrap_with_oauth2
import requests

TOKEN_URL = os.environ.get("AUTH_TOKEN_URL")
CLIENT_ID = os.environ.get("AUTH_CLIENT_ID")
CLIENT_SECRET = os.environ.get("AUTH_CLIENT_SECRET")

session = requests.Session()
client = wrap_with_oauth2(
    session,
    token_url=TOKEN_URL,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    scope="read",
)

resp = client.post("https://api.example.com/data", json={"key": "value"})
print(resp.status_code)
```

### Available Wrappers
- `wrap_with_basic_auth(client, username, password)`
- `wrap_with_bearer_token(client, token)`
- `wrap_with_oauth2(client, token_url, ...)`
- `wrap_client(client, auth_strategy, **kwargs)`  # generic entrypoint

### Exception Handling
The library supports a configurable exception policy via the `AUTHWRAP_EXCEPTION_POLICY` environment variable:
- `raise`: raise exceptions on auth failures (default)
- `log`: log exceptions and continue
- `ignore`: ignore exceptions silently

## Examples
See the `examples/` directory for concrete usage with requests, httpx, and urllib3.

## Contributing
Please read `CONTRIBUTING.md` for guidelines. Run tests with pytest and format code with black/ruff.

## License
MIT — see the LICENSE file.
