#!/usr/bin/env python3
from oauthlib.oauth2 import BackendApplicationClient
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
import requests

server = 'https://localhost/default'

client_id = '29968236-c3ed-4b6e-ac16-affaeac0a8c2'
client_secret = 'secret'

auth = HTTPBasicAuth(client_id, client_secret)
client = BackendApplicationClient(client_id=client_id)
oauth = OAuth2Session(client=client)
response = oauth.fetch_token(token_url=server+'/token', auth=auth)

token = response['access_token']

req = requests.get(server+'/resource', headers={"Authorization": f"Bearer {token}"})
print (req)
