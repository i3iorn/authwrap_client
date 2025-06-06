# AuthWrap Client

AuthWrap Client is a Python library designed to simplify the process of adding authentication headers to HTTP client requests. It provides a flexible and pluggable interface for various authentication strategies, such as Basic Auth, OAuth2, and Bearer Tokens.

## Features
- Transparent wrapper for HTTP clients to inject authentication headers.
- Support for both synchronous and asynchronous HTTP clients.
- Pluggable authentication strategies.
- Configurable exception handling policies.

## Requirements
- Python 3.8 or higher
- `wrapt` library (version 1.14.1 or higher)

## Installation
To install the library, use pip:

```bash
pip install authwrap-client
```

Ensure you have Python 3.8 or higher installed.

## Usage

### Wrapping an HTTP Client
AuthWrap Client provides a `wrap_with_*` function for each supported authentication strategy. Below is an example of how to use it with an `httpx.AsyncClient`:

```python
import httpx
from authwrap_client import wrap_with_bearer_token

# Wrap the client with Bearer Token authentication
client = wrap_with_bearer_token(httpx.AsyncClient(), token="your_token_here")

async def main():
    response = await client.get("https://httpbin.org/headers")
    print(response.json())

# Run the async function
import asyncio
asyncio.run(main())
```

### Available Wrappers
- `wrap_with_basic_auth`: For Basic Authentication.
- `wrap_with_oauth2`: For OAuth2 Authentication.
- `wrap_with_bearer_token`: For Bearer Token Authentication.

### Exception Handling
The library supports configurable exception handling policies via the `AUTHWRAP_EXCEPTION_POLICY` environment variable:
- `raise`: Raise exceptions when authentication fails.
- `log`: Log exceptions and continue.
- `ignore`: Ignore exceptions silently.

Set the policy as follows:

```bash
export AUTHWRAP_EXCEPTION_POLICY=log
```

## Examples
Examples of using the library with different HTTP clients are available in the `examples/` directory:
- `httpx_async_example.py`
- `requests_example.py`
- `urllib3_example.py`

## Project Metadata
- **Name**: AuthWrap Client
- **Version**: 0.1.0
- **Description**: Transparent authorization wrapper for any Python HTTP client.

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Submit a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
