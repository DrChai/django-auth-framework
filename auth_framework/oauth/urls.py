__author__ = 'Carrycat'

from django.urls import re_path
from oauth2_provider.views import JwksInfoView

from . import views

urlpatterns = [
    re_path(r'^token/$', views.GrantUserWToken.as_view(), name="token"),
    re_path(r'^revoke/$', views.RevokeTokenView.as_view(), name="revoke-token"),
    # reuse oauth2_provider jwks url
    re_path(r"^\.well-known/jwks.json$", JwksInfoView.as_view(), name="jwks-info"),
]
