import httpx
import asyncio
from authwrap_client import wrap_with_oauth2, wrap_client


# Example of using wrap_with_oauth with httpx in an asynchronous context
client: httpx.AsyncClient = wrap_with_oauth2(
    httpx.AsyncClient(verify=False),
    token_url="https://example.com/auth/login",
    client_id="METhKEGS",
    client_secret="MJlO3binatD9jk1",
)

# Example of using wrap_client with httpx in an asynchronous context
client: httpx.AsyncClient = wrap_client(
    httpx.AsyncClient(verify=False),
    auth_strategy="oauth",
    token_url="https://example.com/auth/login",
    client_id="METhKEGS",
    client_secret="MJlO3binatD9jk1",
)

async def main():
    response: httpx.Response = await client.get(
        'https://example.com/api/data',
    )

asyncio.run(main())
