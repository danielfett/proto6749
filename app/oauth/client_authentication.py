from django.http import HttpResponse
from base64 import b64decode
from urllib.parse import unquote_plus
from django.conf import settings
from .utils import same_certificate


class ClientAuthMethod:
    def __init__(self, client):
        self.client_unverified = client

    @staticmethod
    def get_authenticator(request):
        from .models import Client

        if "Authorization" in request.headers:
            client_id = ClientSecretBasic.get_client_id(request)
            client = Client.objects.get(id=client_id)
            return ClientSecretBasic(client)
        else:
            client_id = request.POST["client_id"]
            client = Client.objects.get(id=client_id)
            for cls in [
                ClientSecretPost,
                TLSClientAuth,
                SelfSignedTLSClientAuth,
            ]:
                if cls.ID == client.token_endpoint_auth_method:
                    return cls(client)

        raise Exception("Client authentication method not found.")


class ClientAuthSecret(ClientAuthMethod):
    """
    Checks if client_id and client_secret match.

    TODO: client secrets should be stored hashed/salted
    """

    def check_secret(self, client_id, client_secret):
        if self.client_unverified.secret != client_secret:
            return None
        if self.client_unverified.token_endpoint_auth_method != self.ID:
            raise Exception(
                "Client is not allowed to use this client authentication method."
            )
        return self.client_unverified  # is now verified


class ClientSecretBasic(ClientAuthSecret):
    """
    Defined in RFC6749:

    Clients in possession of a client password MAY use the HTTP Basic
    authentication scheme as defined in [RFC2617] to authenticate with
    the authorization server.  The client identifier is encoded using the
    "application/x-www-form-urlencoded" encoding algorithm per
    Appendix B, and the encoded value is used as the username; the client
    password is encoded using the same algorithm and used as the
    password.  The authorization server MUST support the HTTP Basic
    authentication scheme for authenticating clients that were issued a
    client password.
    """

    ID = "client_secret_basic"  # https://tools.ietf.org/html/rfc7591#section-2
    NAME = "Client secret contained in Basic Authorization header"

    @staticmethod
    def get_client_id_and_secret(request):
        header_value = request.headers["Authorization"].split(" ")[1]
        decoded = str(b64decode(header_value), "ascii")
        client_id_enc, client_secret_enc = decoded.split(":")
        client_id, client_secret = (
            unquote_plus(client_id_enc),
            unquote_plus(client_secret_enc),
        )
        return client_id, client_secret

    @staticmethod
    def get_client_id(request):
        return ClientSecretBasic.get_client_id_and_secret(request)[0]

    def check(self, request):
        return self.check_secret(*ClientSecretBasic.get_client_id_and_secret(request))


class ClientSecretPost(ClientAuthSecret):
    """
    Defined in RFC6749:
    
    Alternatively, the authorization server MAY support including the
    client credentials in the request-body using the following
    parameters:

    client_id
          REQUIRED.  The client identifier issued to the client during
          the registration process described by Section 2.2.

    client_secret
          REQUIRED.  The client secret.  The client MAY omit the
          parameter if the client secret is an empty string.
    """

    ID = "client_secret_post"  # https://tools.ietf.org/html/rfc7591#section-2
    NAME = "Client secret contained in form post parameters."

    def check(self, request):
        client_id = request.POST["client_id"]
        client_secret = request.POST["client_secret"]
        return self.check_secret(client_id, client_secret)


class SelfSignedTLSClientAuth(ClientAuthMethod):
    """
    Defined in draft-ietf-oauth-mtls:

    This method of mutual-TLS OAuth client authentication is intended
    to support client authentication using self-signed certificates.
    As a prerequisite, the client registers its X.509 certificates
    (using "jwks" defined in [RFC7591]) or a reference to a trusted
    source for its X.509 certificates (using "jwks_uri" from
    [RFC7591]) with the authorization server. During authentication,
    TLS is utilized to validate the client's possession of the private
    key corresponding to the public key presented within the
    certificate in the respective TLS handshake. In contrast to the
    PKI method, the client's certificate chain is not validated by the
    server in this case. The client is successfully authenticated if
    the certificate that it presented during the handshake matches one
    of the certificates configured or registered for that particular
    client.

    For all requests to the authorization server utilizing mutual-TLS
    client authentication, the client MUST include the "client_id"
    parameter, described in OAuth 2.0, Section 2.2 [RFC6749].
    """

    ID = "self_signed_tls_client_auth"  # https://tools.ietf.org/html/draft-ietf-oauth-mtls-17#section-2.2.1
    NAME = "Mutual TLS with a self-signed certificate"

    def check(self, request):
        try:
            tls_cert = request.headers[settings.TLS_CLIENT_CERTIFICATE_HEADER]
        except KeyError:
            raise Exception("TLS Certificate not sent by client")

        try:
            client_id = request.POST["client_id"]
        except KeyError:
            raise Exception("client_id not sent by client in POST data")

        if not same_certificate(self.client_unverified.tls_certificate, tls_cert):
            print("Client certificates do not match.")
            return None
        if not client_id == self.client_unverified.id:
            return None

        return self.client_unverified  # is now verified


class TLSClientAuth(ClientAuthMethod):
    """
    Defined in draft-ietf-oauth-mtls:

    The PKI (public key infrastructure) method of mutual-TLS OAuth client
    authentication adheres to the way in which X.509 certificates are
    traditionally used for authentication.  It relies on a validated
    certificate chain [RFC5280] and a single subject distinguished name
    (DN) or a single subject alternative name (SAN) to authenticate the
    client.  Only one subject name value of any type is used for each
    client.  The TLS handshake is utilized to validate the client's
    possession of the private key corresponding to the public key in the
    certificate and to validate the corresponding certificate chain.  The
    client is successfully authenticated if the subject information in
    the certificate matches the single expected subject configured or
    registered for that particular client.
    """

    ID = "tls_client_auth"  # https://tools.ietf.org/html/draft-ietf-oauth-mtls-17#section-2.1.1
    NAME = "Mutual TLS with PKI certificates (NOT IMPLEMENTED)"

    attributes = [
        ("tls_client_auth_subject_dn", "subject distinguished name of the certificate"),
        ("tls_client_auth_san_dns", "dNSName SAN entry in the certificate"),
        (
            "tls_client_auth_san_uri",
            "uniformResourceIdentifier SAN entry in the certificate",
        ),
        (
            "tls_client_auth_san_ip",
            "IP address in IPAddress SAN entry in the certificate",
        ),
        ("tls_client_auth_san_email", "rfc822Name SAN entry in the certificate"),
    ]

    def check(self, request):
        # TODO: Implement
        raise Exception("Not implemented")


class ClientAuthRequiredMixin:
    def check_client_authentication(self, request):
        authenticator = ClientAuthMethod.get_authenticator(request)
        try:
            return authenticator.check(request)
        except Exception:
            raise Exception("Client authentication failed.")

    def dispatch(self, request, *args, **kwargs):
        client = self.check_client_authentication(request)
        if client is None:
            return HttpResponse("Unauthorized", status=401)
        if client.server != self.server:
            print(
                f"Client is registered for {client.server}, not for this server ({self.server})."
            )
            return HttpResponse("Unauthorized", status=401)

        self.client_verified = client
        return super().dispatch(request, *args, **kwargs)


client_auth_methods_supported = [
    (cls.ID, cls.NAME)
    for cls in [
        ClientSecretBasic,
        ClientSecretPost,
        TLSClientAuth,
        SelfSignedTLSClientAuth,
    ]
]
