from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

def add_url_parameters(url, parameters, location='query'):
    if not location in ('query', 'fragment'):
        raise Exception(f"Unknown url part: {location}")
    
    parsed = urlparse(url)
    part = getattr(parsed, location)

    """Split the query string or urlencoded fragment string into its
    components, update the components with the values from parameters,
    and assemble everything again. Note: parse_qsl returns (name,
    value) tuples.

    """
    
    split = parse_qsl(part, keep_blank_values=True)
    split += (parameters.items())
    assembled = urlencode(split)

    updated = parsed._replace(**{location: assembled})

    return urlunparse(updated)
