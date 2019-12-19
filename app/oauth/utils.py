def same_certificate(compare, received):
    # We receive each line of the TLS certificate preceded by a
    # number of spaces. Probably caused by HTTP header handling by
    # Django. This is a quick and dirty hack to remove them. We do
    # the same for the stored certificate to remove differences
    # with newlines.
    def clean(cert):
        return "\n".join(line.strip() for line in cert.split("\n"))

    return clean(received) == clean(compare)
