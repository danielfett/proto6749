from django.db import models
from django.conf import settings
from django.contrib.postgres.fields import JSONField, ArrayField
from django.contrib.auth.models import User
from django.utils.crypto import get_random_string
from django.utils.timezone import now
from datetime import timedelta
from enum import Enum
from base64 import urlsafe_b64encode
from hashlib import sha256
from json import loads
from .client_authentication import TLSClientAuth, client_auth_methods_supported

import uuid

class ResponseType(Enum):
    CODE = "code"

    @classmethod
    def choices(cls):
        return [(c.value, c.value) for c in cls]

class Server(models.Model):
    id = models.SlugField(max_length=32, primary_key=True)
    pkce_required = models.BooleanField("PKCE required", default=True)
    tls_client_certificate_bound_access_tokens = models.BooleanField("Bind Access Tokens to TLS Client Certificate", default=False)

    def __str__(self):
        return self.id

class Client(models.Model):
    id = models.UUIDField(primary_key=True, db_index=True, default=uuid.uuid4)
    name = models.CharField(max_length=128)
    server = models.ForeignKey(Server, on_delete=models.CASCADE)
    token_endpoint_auth_method = models.CharField(
        "Client authentication method",
        max_length=128,
        choices=client_auth_methods_supported,
        help_text="Used at the token endpoint and the pushed authorization request endpoint."
    )
    secret = models.CharField(
        blank=True,
        default='',
        max_length=128,
        help_text="Only used if token_endpoint_auth_method is client_secret_basic or client_secret_post."
    )  # TODO: client secrets should be stored hashed/salted
    tls_certificate = models.TextField(
        "TLS Certificate",
        blank=True,
        help_text="Only used if token_endpoint_auth_method is self_signed_tls_client_auth.",
    )
    tls_client_auth_attribute_name = models.CharField(
        "TLS Client Authentication Attribute Name",
        max_length=128,
        blank=True,
        choices=TLSClientAuth.attributes,
        help_text="Defined in draft-ietf-oauth-mtls and only used if token_endpoint_auth_method is tls_client_auth: The name of the attribute of the certificate presented by the client that is compared.",
    )
    tls_client_auth_attribute_value = models.CharField(
        "TLS Client Authentication Attribute Value",
        max_length=128,
        blank=True,
        help_text="Defined in draft-ietf-oauth-mtls and only used if token_endpoint_auth_method is tls_client_auth: The value of the attribute of the certificate presented by the client that is compared.",
    )
    redirect_uris = ArrayField(models.URLField(), blank=True, default=list)
    locations = ArrayField(models.URLField(), blank=True, null=True)

    def __str__(self):
        return f"{self.name} · {self.id} · {self.locations}"

class Session(models.Model):
    AT_LENGTH = 32 # produces about 190 bits of randomness
    CODE_LENGTH = 24
    URN_LENGTH = 24
    CODE_CHALLENGE_METHODS = [('S256', 'S256'), ('plain', 'plain')]
    MAX_LIFETIME = timedelta(seconds=3600)
    
    def generate_access_token(self):
        self.access_token = get_random_string(length=self.AT_LENGTH)

    def generate_refresh_token(self):
        self.refresh_token = get_random_string(length=self.AT_LENGTH)

    def generate_code(self):
        self.authorization_code = get_random_string(length=self.CODE_LENGTH)
    
    def generate_urn(self):
        self.request_uri = "urn:django_oauth:" + get_random_string(length=self.URN_LENGTH)

    server = models.ForeignKey(Server, on_delete=models.CASCADE)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, null=True, default=None, blank=True)
    client_location = models.URLField(null=True, default=None, blank=True)
    depends_on = models.ForeignKey('self', related_name='dependent_sessions', on_delete=models.CASCADE, null=True, default=None)
    code_challenge = models.CharField(max_length=1024, blank=True)
    code_challenge_method = models.TextField(max_length=5, choices=CODE_CHALLENGE_METHODS, blank=True)
    redirect_uri = models.URLField(null=True, default=None, blank=True)
    response_type = models.CharField(
        max_length=24,
        choices=ResponseType.choices(),
        null=True,
        default=None
    )
    state = models.CharField(max_length=1024, blank=True)
    access_token = models.CharField(max_length=AT_LENGTH, db_index=True, unique=True, null=True, blank=True)
    refresh_token = models.CharField(max_length=AT_LENGTH, db_index=True, unique=True, null=True, blank=True)
    authorization_code = models.CharField(max_length=CODE_LENGTH, db_index=True, unique=True, null=True, blank=True)
    tls_certificate = models.TextField(
        "TLS Certificate to bind the access token to",
        blank=True,
    )
    authorized = models.BooleanField(default=False)
    scope = ArrayField(models.CharField(max_length=128), blank=True)
    claims = JSONField(default=dict, blank=True)
    authorization_details = JSONField(default=list, blank=True)
    request_uri = models.CharField(max_length=1024, db_index=True, unique=True, null=True, blank=True)
    user = models.ForeignKey(User, null=True, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)

    def expires_in(self):
        return ((now() - self.created) - self.MAX_LIFETIME).seconds

    def expired(self):
        return self.expires_in < 0

    REQUEST_PARAMETERS = ('response_type', 'state', 'code_challenge', 'code_challenge_method', 'redirect_uri')
    REQUEST_PARAMETERS_JSON = ('claims', 'authorization_details')
    
    @classmethod
    def create_from_request(cls, server, authenticated_client=None, kwargs={}):
        if 'response_type' not in kwargs:
            raise Exception("Missing parameter: response_type")
        if kwargs['response_type'] != 'code':
            raise Exception(f"Illegal response type: {kwargs['response_type']}")
        
        if 'client_id' not in kwargs:
            raise Exception("Missing parameter: client_id")
        client_from_clientid = Client.objects.get(id=kwargs['client_id'])
        if authenticated_client is not None and client_from_clientid != client:
            raise Exception("Illegal client_id for authenticated client")
            
        if 'state' not in kwargs and 'code_challenge' not in kwargs:
            raise Exception("Missing CSRF protection (state or PKCE)")
            
        if server.pkce_required and 'code_challenge' not in kwargs:
            raise Exception("Server requires use of PKCE")
            
        if 'code_challenge' in kwargs and (not 'code_challenge_method' in kwargs or kwargs['code_challenge_method'] != 'S256'):
            raise Exception(f"Missing or illegal code_challenge_method ('{kwargs.get('code_challenge_method', '')}')")
        
        if 'redirect_uri' in kwargs:
            if not kwargs['redirect_uri'] in client_from_clientid.redirect_uris:
                raise Exception(f"Redirect URI not in client's allowed redirect URIs.")

        session = cls(client=client_from_clientid, server=server)
        
        for parameter in cls.REQUEST_PARAMETERS:
            if parameter in kwargs:
                setattr(session, parameter, kwargs[parameter])
        
        for parameter in cls.REQUEST_PARAMETERS_JSON:
            if parameter in kwargs:
                setattr(session, parameter, loads(kwargs[parameter]))
            
        if 'scope' in kwargs:
            session.scope = kwargs['scope'].split(' ')

        session.save()
        session.build_dependent_authorizations()
        return session

    def pkce_verify(self, code_verifier):
        # TODO: plain is not implemented
        compare = urlsafe_b64encode(sha256(code_verifier.encode('ascii')).digest())
        compare = compare.decode('ascii').strip('=')
        if not self.code_challenge == compare:
            raise Exception(f"Wrong PKCE verifier '{compare}' does not equal '{self.code_challenge}'")
        
    def build_dependent_authorizations(self):
        '''
        Method exclusive for universal authorization prototype.
        '''
        
        for ad in self.authorization_details:
            for rule in settings.AUTHZ_DEPENDENCIES:
                if rule['type'] != ad['type'] or rule.get('locations', '') not in ad.get('location', ''):
                    continue
                for creation_rule in rule['depends_on']:
                    session = Session()
                    session.depends_on = self
                    session.server = self.server
                    session.user = self.user
                    #session.client = Client.objects.get(id=creation_rule['client_id'])
                    session.client_location = rule['location']
                    session.scope = creation_rule.get('scope', '')
                    session.claims = creation_rule.get('claims', {})
                    session.authorization_details = creation_rule.get('authorization_details', [])
                    session.save()
                    session.build_dependent_authorizations()
                        
    def find_dependent_session(self, client, location):
        """Method exclusive for universal authorization prototype.

        Return all dependent sessions where the client is the given
        client and where the location, if given, matches.

        May return (yield) more than one session. Background: If there
        is more then one session, the access tokens cannot be returned
        in a useful way. Therefore, an error is thrown by the caller
        of this function in this case.

        """
        
        for session in self.dependent_sessions.all():
            if client is not None and session.client != client:
                continue
            if location is not None:
                for ad in session.authorization_details:
                    if ad['location'] == location:
                        break
                else:  # no matching authorization_details were found!
                    continue
            yield session

    def __str__(self):
        myname = f"{self.id}→{self.client.name if self.client else self.client_location}"
        if self.depends_on:
            return str(self.depends_on) + " · " + myname
        else:
            return myname
