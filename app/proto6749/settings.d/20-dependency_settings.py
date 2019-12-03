AUTHZ_DEPENDENCIES = [
    {
        "type": "sign",
        "location": "https://qtsp1.example/",
        "depends_on": [
            {
                "scope": "openid",
                "claims": {
                    "userinfo": {
                        "verified_claims": {
                            "claims": {
                                "given_name": None,
                                "family_name": None,
                            }
                        }
                    }
                }
            }
        ]
    },
    {
        "type": "scoring",
        "location": "https://scoring",
        "depends_on": [
            {
                "scope": "openid",
                "claims": {
                    "userinfo": {
                        "verified_claims": {
                            "claims": {
                                "given_name": None,
                                "family_name": None,
                            }
                        }
                    }
                }
            },
            {
                "authorization_details": [{
                    "type": "account_information",
                    "access": {
                        "accounts": [],
                        "balances": [],
                        "transactions": []
                    }
                }]
            }
        ]
    }
]
