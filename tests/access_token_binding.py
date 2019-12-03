#!/usr/bin/env python3
from oauthlib.oauth2 import BackendApplicationClient
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
import requests
from urllib import parse

server = 'https://localhost/mtlsbinding'

client_id = 'e8799908-158b-4970-90a9-d44e6842625a'
client_secret = 'secret'
cert = ('testsomething.example-client.pem', 'testsomething.example-client-key.pem')

auth = HTTPBasicAuth(client_id, client_secret)
client = BackendApplicationClient(client_id=client_id)
oauth = OAuth2Session(client=client)
response = oauth.fetch_token(token_url=server+'/token', auth=auth, include_client_id=True, cert=cert)

token = response['access_token']

req = requests.get(server+'/resource', headers={"Authorization": f"Bearer {token}"}, cert=cert)
print (req)
