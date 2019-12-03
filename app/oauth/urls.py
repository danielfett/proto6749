"""OAuth URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from .views import *

urlpatterns = [
    path('<slug:server>', MetadataEndpoint.as_view(), name='issuer'),
    path('.well-known/oauth-authorization-server/<slug:server>', MetadataEndpoint.as_view(), name='metadata_endpoint'),
    path('.well-known/openid-configuration/<slug:server>', MetadataEndpoint.as_view(), name='metadata_endpoint'),
    path('<slug:server>/push', PushedRequestEndpoint.as_view(), name='pushed_authorization_request_endpoint'),
    path('<slug:server>/authorize', AuthorizationEndpoint.as_view(), name='authorization_endpoint'),
    path('<slug:server>/token', TokenEndpoint.as_view(), name='token_endpoint'),
    path('<slug:server>/introspect', IntrospectionEndpoint.as_view(), name='introspection_endpoint'),
    path('<slug:server>/userinfo', UserInfoEndpoint.as_view(), name='userinfo_endpoint'),
    path('<slug:server>/resource', DummyResourceEndpoint.as_view(), name='resource_endpoint'),        
]
