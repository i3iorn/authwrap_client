import requests
from authwrap_client import wrap_with_oauth

client: requests.Session = wrap_with_oauth(
    requests.Session(),
    token_url="https://login.example.com/oauth2",
    client_id="c2a8t25f66a",
    client_secret="zQUX2dbLZLZqwvboaewo1RbW7ZqxbtPv6",
    scope="read",
)

def main():
    response: requests.Response = client.post(
        "https://api.example.com/data",
        json={"key": "1adbf552e31d3"},
    )
main()
