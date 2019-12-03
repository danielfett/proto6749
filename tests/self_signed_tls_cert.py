#!/usr/bin/env python3
from oauthlib.oauth2 import BackendApplicationClient
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
import requests
from urllib import parse

server = 'https://localhost/default'

client_id = '668a597c-8986-4dd4-b227-5ab76d9b8c79'
    
client = BackendApplicationClient(client_id=client_id)
oauth = OAuth2Session(client=client)
response = oauth.fetch_token(server+'/token', include_client_id=True, cert=('testsomething.example-client.pem', 'testsomething.example-client-key.pem'))

token = response['access_token']

req = requests.get(server+'/resource', headers={"Authorization": f"Bearer {token}"})
print (req)
