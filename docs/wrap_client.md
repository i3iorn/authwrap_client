# wrap_client.py

This module implements wrapper functions to add authentication headers to HTTP clients.

## Contents

- `wrap_with_basic_auth(client, username, password)`: Wraps client with Basic Auth.
- `wrap_with_oauth2(client, token_url, client_id, client_secret)`: Wraps client for OAuth2 flows.
- `wrap_with_bearer_token(client, token)`: Wraps client with Bearer Token Auth.
- Internal helpers for header injection.

## Usage

```python
from authwrap_client.wrap_client import wrap_with_bearer_token
```
