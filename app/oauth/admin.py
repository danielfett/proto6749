from django.contrib import admin

from .models import *

admin.site.register(Session)


class ServerAdmin(admin.ModelAdmin):
    list_display = ('id', 'pkce_required', 'tls_client_certificate_bound_access_tokens',)

    
admin.site.register(Server, ServerAdmin)


class ClientAdmin(admin.ModelAdmin):
    list_display = ('name', 'server', 'id', 'token_endpoint_auth_method',)

    fieldsets = [
        (None, {'fields': ['id', 'name', 'server', 'redirect_uris', 'locations']}),
        ('Authentication', {'fields': ['token_endpoint_auth_method', 'secret', 'tls_certificate', 'tls_client_auth_attribute_name', 'tls_client_auth_attribute_value']}),
    ]

    
admin.site.register(Client, ClientAdmin)
