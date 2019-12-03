from django.shortcuts import render, redirect
from .models import Server, Client, Session
from django.http import JsonResponse, HttpResponse
from django.views import View
from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from urllib.parse import urlencode
from django.urls import reverse
from .consentbuilder import ConsentBuilder
from .client_authentication import ClientAuthRequiredMixin, client_auth_methods_supported
from django.conf import settings
from .utils import same_certificate

# TODO: only auth code flow supported for now


class AuthzServerView(View):
    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        self.server = Server.objects.get(id=kwargs['server'])

    def reverse(self, name):
        return reverse(name, kwargs={'server':self.server.id})

class AccessTokenRequiredMixin:
    def dispatch(self, request, *args, **kwargs):
        try:
            auth_header = request.headers['Authorization']
        except KeyError:
            return HttpResponse('Unauthorized', status=401)

        token_type, access_token = auth_header.split(' ')

        if token_type != 'Bearer':
            raise Exception(f"Unknown token type: {token_type}")

        session = Session.objects.get(
                access_token=access_token,
        )
        
        if self.server.tls_client_certificate_bound_access_tokens:
            try:
                tls_cert = request.headers[settings.TLS_CLIENT_CERTIFICATE_HEADER]
            except KeyError:
                raise Exception("TLS Certificate not sent by client")
            if not same_certificate(session.tls_certificate, tls_cert):
                raise Exception("TLS client certificate does not match.")

        self.session_from_token_verified = session
        return super().dispatch(request, *args, **kwargs)


class MetadataEndpoint(AuthzServerView):
    def get(self, request, *args, **kwargs):
        response = {}
        for name in [
                'issuer',
                'authorization_endpoint',
                'pushed_authorization_request_endpoint',
                'token_endpoint',
                'introspection_endpoint',
                'userinfo_endpoint']:
            response[name] = request.build_absolute_uri(self.reverse(name))
        response['token_endpoint_auth_methods_supported'] = [method[0] for method in client_auth_methods_supported]
        response['code_challenge_methods_supported'] = ['S256']
        response['tls_client_certificate_bound_access_tokens'] = self.server.tls_client_certificate_bound_access_tokens
        return JsonResponse(response)
            
        
class PushedRequestEndpoint(ClientAuthRequiredMixin, AuthzServerView):

    def post(self, request, *args, **kwargs):
        session = Session.create_from_request(self.server,
                                              self.client_verified,
                                              request.POST)
        session.generate_urn()
        session.save()

        helper_uri = request.build_absolute_uri( + "?request_uri=" + session.request_uri)

        return JsonResponse({
            'request_uri': session.request_uri,
            'expires_in': session.expires_in(),
            'HELPER_authz_url': helper_uri,
        })


@method_decorator(csrf_protect, name='dispatch')
@method_decorator(login_required, name='dispatch')
class AuthorizationEndpoint(AuthzServerView):    
    def get(self, request, *args, **kwargs):
        if 'request_uri' in request.GET:
            # retrieve session from request_uri
            session = Session.objects.get(
                request_uri=request.GET['request_uri'])
        else:
            session = Session.create_from_request(
                self.server,
                authenticated_client=None,
                kwargs=request.GET)
            session.save()

        request.session['oauth_session_id'] = session.id

        consent = ConsentBuilder(session)
        
        context = {
            'session': session,
            'user': request.user,
            'consent': consent,
        }
        return render(request, 'oauth/authorize.html', context)

    def post(self, request, *args, **kwargs):
        session_id = request.session['oauth_session_id']
        session = Session.objects.get(
            id=session_id,
            server=self.server
        )
        # TODO: Check if/which button was clicked
        session.user = request.user
        session.generate_code()
        session.save()
        parameters = {
            'code': session.authorization_code,
            'state': session.state,
        }
        if session.redirect_uri is None:
            redirect_uri = session.client.redirect_uris[0]
        else:
            redirect_uri = session.redirect_uri
        final_redirect = redirect_uri + '?' + urlencode(parameters)
        # TODO: correct assembling of redirect_uri (when parameters exist)
        return redirect(final_redirect)


class TokenEndpoint(ClientAuthRequiredMixin, AuthzServerView):
    def post(self, request, *args, **kwargs):
        if 'grant_type' not in request.POST:
            raise Exception(f"Missing grant_type.")

        grant_type = request.POST['grant_type']

        # dispatch request to respective function, fails if grant_type is unknown
        session = {
            'authorization_code': self.authorization_code,
            'client_credentials': self.client_credentials,
            'urn:ietf:params:oauth:grant-type:token-exchange': self.token_exchange,
        }[grant_type](request)

        # TODO: limit tokens by resource requested
        # TODO: RT/AT expiration

        if self.server.tls_client_certificate_bound_access_tokens:
            try:
                session.tls_certificate = request.headers[settings.TLS_CLIENT_CERTIFICATE_HEADER]
            except KeyError:
                raise Exception("TLS Certificate not sent by client")

        session.generate_access_token()
        session.generate_refresh_token()
        session.save()
        return JsonResponse({
            'access_token': session.access_token,
            'token_type': 'Bearer',
            'expires_in': 9999999,
            'refresh_token': session.refresh_token,
            'issued_token_type': 'urn:ietf:params:oauth:token-type:access_token',
        })

    def authorization_code(self, request):
        if 'code' not in request.POST:
            raise Exception("Missing code.")

        session = Session.objects.get(
            client=self.client_verified,
            server=self.server,
            authorization_code=request.POST['code'],
        )

        if session.redirect_uri is not None:
            if 'redirect_uri' not in request.POST:
                raise Exception("Missing redirect_uri")
            if request.POST['redirect_uri'] != session.redirect_uri:
                raise Exception("Wrong redirect uri")

        if session.code_challenge:
            if 'code_verifier' not in request.POST:
                raise Exception("Missing code verifier")
            session.pkce_verify(request.POST['code_verifier'])

        # TODO: redirect_uri can be skipped in auth request
        session.authorization_code = None
        return session

    def token_exchange(self, request):
        if request.POST.get('subject_token_type') != 'urn:ietf:params:oauth:token-type:access_token':
            raise Exception("Invalid or missing subject_token_type")
            
        subject_token = request.POST['subject_token']
        master_session = Session.objects.get(
            access_token=subject_token
        )
        sessions = list(master_session.find_dependent_session(
            client=self.client_verified,
            location=request.POST.get('resource', None)
        ))

        if len(sessions) != 1:
            raise Exception(f"Expected to find exactly 1 session, but found {len(sessions)}.")

        return sessions[0]

    def client_credentials(self, request):
        session = Session(
            client=self.client_verified,
            server=self.server,
            user=None,
            scope=request.POST.get('scope', '').split(' '),
        )
        session.authorized = True
        return session


class IntrospectionEndpoint(ClientAuthRequiredMixin, AuthzServerView):
    def post(self, request, *args, **kwargs):
        token = request.POST['token']
        session = Session.objects.get(access_token=token)
        if session.client_location not in self.client_verified.location:
            raise Exception("Client does not own authorized location.")
        return JsonResponse({
            'active': True,
            'scope': session.scope,
            'authorization_details': session.authorization_details,
            'client_id': session.client.id,
            'username': session.user.username,
        })


def get_user_claims(user, claims):
    if 'sub' not in claims:
        claims['sub'] = None
        
    def get_claim(claim, value):
        if claim in ('verified_claims', 'userinfo', 'claims'):
            return {c:get_claim(c, v) for c, v in value.items()}
        if claim == 'email':
            return user.email
        if claim == 'given_name':
            return user.first_name
        if claim == 'family_name':
            return user.last_name
        if claim == 'sub':
            return user.username
        
    return {c:get_claim(c,v) for c, v in claims.items()}


class UserInfoEndpoint(AccessTokenRequiredMixin, AuthzServerView):
    def post(self, request, *args, **kwargs):
        session = self.session_from_token_verified
        user_claims = get_user_claims(session.user, session.claims)
        return JsonResponse(user_claims)


class DummyResourceEndpoint(AccessTokenRequiredMixin, AuthzServerView):
    def get(self, request, *args, **kwargs):
        from django.core import serializers
        sessions = [self.session_from_token_verified]
        for session in self.session_from_token_verified.find_dependent_session(None, None):
            sessions.append(session)
        data = serializers.serialize("python", sessions)

        context = {
            'sessions': data,
        }
        return render(request, 'oauth/dummy_resource.html', context)
