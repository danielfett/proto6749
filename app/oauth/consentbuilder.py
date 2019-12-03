from django.template import Template, Context
from django.conf import settings

class ConsentBuilder:
    def __init__(self, request):
        self.request = request

    def html(self, session=None):
        if session is None:
            session = self.request
        yield from self.consent_for_scopes(session)
        yield from self.consent_for_authorization_details(session)
        for dependent_session in session.dependent_sessions.all():
            yield from self.html(dependent_session)

    def consent_for_scopes(self, session):
        scopes = session.scope
        for scope in scopes:
            match = lambda ct: ct['match'].get('scope', '') == scope
            data = {
                'client': session.client
            }
            if scope == 'openid':
                data["claims"] = session.claims
            yield self.filter_and_render(match, data)
            

    def consent_for_authorization_details(self, session):
        authorization_detail_elements = session.authorization_details
        for ad in authorization_detail_elements:
            def match(ct):
                if 'authorization_details' not in ct['match']:
                    return False
                if ct['match']['authorization_details']['type'] != ad['type']:
                    return False
                if 'location' in ct['match']['authorization_details'] and ct['match']['authorization_details']['location'] not in ad.get('locations'):
                    return False
                return True
            data = {
                'authorization_details_matched': ad, 
                'client': session.client
            }
            yield self.filter_and_render(match, data)

    def filter_and_render(self, filter, data):
        templates = [c['template'] for c in settings.CONSENT_TEMPLATES if filter(c)]
        if len(templates) != 1:
            raise Exception(f"Expected to find one template, found {len(templates)} instead!'")
        template = templates[0]
        return self.render(template, data)

    def render(self, template, data):
        t = Template(template)
        out = t.render(Context(data))
        print (out)
        return out
