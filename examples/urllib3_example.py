import urllib3
from authwrap_client import wrap_with_oauth2

http = urllib3.PoolManager()
client = wrap_with_oauth2(
    http,
    token_url="https://login.example.com/oauth2",
    client_id="c2a8t25f66a",
    client_secret="zQUX2dbLZLZqwvboaewo1RbW7ZqxbtPv6",
    scope="read",
)

def main():
    response = client.request(
        "POST",
        "https://api.example.com/data",
        body=b'{"key": "1adbf552e31d3"}',
        headers={"Content-Type": "application/json"},
        preload_content=False
    )

main()
