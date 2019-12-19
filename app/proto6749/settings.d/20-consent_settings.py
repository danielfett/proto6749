CONSENT_TEMPLATES = [
    {
        "match": {"scope": "test",},
        "template": """
Sie autorisieren test.
""",
    },
    {
        "match": {"scope": "value",},
        "template": """
Sie autorisieren value.
""",
    },
    {
        "match": {  # important security property: there must be
            # exactly one matching template, and if that is
            # tied to a specific location, it must be
            # provided by the provider at that location.
            "scope": ["openid"],
        },
        # important security property: cannot access arbitrary client
        # data, like secret
        "template": """
Folgende Benutzerdaten werden an '{{ client.name }}' weitergegeben:
<ul>
{% for claimname in claims.userinfo %}
{% if not claimname == 'verified_claims' %}
<li>{{ claimname }}</li>
{% endif %}
{% endfor %}
{% for claimname in claims.userinfo.verified_claims %}
<li>{{ claimname }} (verifiziert)</li>
{% endfor %}
</ul>
""",
    },
    {
        "match": {"authorization_details": {"type": "account_information",}},
        "template": """
Sie geben '{{ client.name }}' Zugriff auf folgende Kontoinformationen:
<ul>
{% for dataname in authorization_details_matched.access %}
<li>{{ dataname }}</li>
{% endfor %}
</ul>
""",
    },
    {
        "match": {
            "authorization_details": {
                "type": "sign",
                "location": "https://qtsp1.example/",
            }
        },
        "template": """
QTSP1 erzeugt eine elektronische Signatur in Ihrem Namen für folgende Dokumente:
<ul>
{% for obj in authorization_details_matched.documentDigests %}
<li>{{ obj.label }}</li>
{% endfor %}
</ul>
""",
    },
]
