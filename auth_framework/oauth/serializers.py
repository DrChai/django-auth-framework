__author__ = 'Carrycat'
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from oauth2_provider.models import AccessToken

from ..settings import app_settings, import_callable

# user_serializers = import_callable(app_settings.SERIALIZERS.get('USERINFO_SERIALIZER'))


class AccessTokenSerializer(serializers.ModelSerializer):
    access_token = serializers.CharField(source='token')
    refresh_token = serializers.CharField(source='refresh_token.token')
    expires_in = serializers.DateTimeField(source='expires')

    def __init__(self, *args, **kwargs):
        if app_settings.SERIALIZERS.get('USERINFO_SERIALIZER'):
            self.fields['user'] = app_settings.SERIALIZERS.get('USERINFO_SERIALIZER')()
        super().__init__(*args, **kwargs)

    class Meta:
        model = AccessToken
        fields = ('user', 'access_token', 'refresh_token', 'expires_in', 'scope')
        read_only_fields = ('user', 'access_token', 'refresh_token', 'expires_in', 'scope')
