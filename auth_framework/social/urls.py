from django.urls import re_path

from .views import FacebookLogin, GoogleLogin, AppleLogin, SocialConnections

urlpatterns = [
    re_path('^connections/$', SocialConnections.as_view(), name='social_connections'),
    re_path(r'^facebook/$', FacebookLogin.as_view(), name='fb_login'),
    re_path(r'^google/$', GoogleLogin.as_view(), name='gl_login'),
    re_path(r'^apple/$', AppleLogin.as_view(), name='apple_login'),
]