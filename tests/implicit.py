#!/usr/bin/env python3
from oauthlib.oauth2 import MobileApplicationClient
from requests_oauthlib import OAuth2Session
import requests

server = "https://localhost/default"

client_id = "29968236-c3ed-4b6e-ac16-affaeac0a8c2"

client = MobileApplicationClient(client_id=client_id)
oauth = OAuth2Session(client=client, scope="test")
authorization_url, state = oauth.authorization_url(server + "/authorize")

print(f"Please go to {authorization_url}, authorize, and copy the redirect uri here:")
url = input().strip()

token = oauth.token_from_fragment(url)

print(f"Received: {token}")

req = requests.get(
    server + "/resource", headers={"Authorization": f"Bearer {token['access_token']}"}
)
print(req)
