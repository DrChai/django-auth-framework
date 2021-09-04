
__author__ = 'Carrycat'

import json
import time
import uuid

from django.db import transaction
from django.http import HttpRequest
from django.urls import NoReverseMatch
from django.utils import dateformat, timezone
from django.utils.functional import SimpleLazyObject
from jwcrypto import jwt
from jwcrypto.common import JWException
from jwcrypto.jwt import JWTExpired
from oauth2_provider.settings import oauth2_settings as oauth2_provider_settings, oauth2_settings
from oauth2_provider.exceptions import FatalClientError
from oauth2_provider.models import get_refresh_token_model
from oauth2_provider.oauth2_validators import OAuth2Validator as DefaultOAuth2Validator
from oauthlib.oauth2.rfc6749 import errors
from django.contrib.auth import authenticate

from ..backends.auth_backends import AuthenticationBackend
from ..settings import app_settings, import_callable

RefreshToken = get_refresh_token_model()


class LazyAuthenticatedUser(SimpleLazyObject):
    '''
                 ▄              ▄
                  ▌▒█           ▄▀▒▌
                  ▌▒▒█        ▄▀▒▒▒▐
                 ▐▄▀▒▒▀▀▀▀▄▄▄▀▒▒▒▒▒▐
               ▄▄▀▒░▒▒▒▒▒▒▒▒▒█▒▒▄█▒▐
             ▄▀▒▒▒░░░▒▒▒░░░▒▒▒▀██▀▒▌
            ▐▒▒▒▄▄▒▒▒▒░░░▒▒▒▒▒▒▒▀▄▒▒▌
            ▌░░▌█▀▒▒▒▒▒▄▀█▄▒▒▒▒▒▒▒█▒▐
           ▐░░░▒▒▒▒▒▒▒▒▌██▀▒▒░░░▒▒▒▀▄▌
           ▌░▒▄██▄▒▒▒▒▒▒▒▒▒░░░░░░▒▒▒▒▌
          ▌▒▀▐▄█▄█▌▄░▀▒▒░░░░░░░░░░▒▒▒▐
          ▐▒▒▐▀▐▀▒░▄▄▒▄▒▒▒▒▒▒░▒░▒░▒▒▒▒▌
          ▐▒▒▒▀▀▄▄▒▒▒▄▒▒▒▒▒▒▒▒░▒░▒░▒▒▐
           ▌▒▒▒▒▒▒▀▀▀▒▒▒▒▒▒░▒░▒░▒░▒▒▒▌
    '''
    is_authenticated = True
    is_active = True

    def __bool__(self):
        return True


class OauthValidator(DefaultOAuth2Validator):
    def validate_user(self, username, password, client, request, *args, **kwargs):
        error_msg = 'credentials not correct'
        email = getattr(request, 'email', None)
        phone_number = getattr(request, 'phone_number', None)
        credentials = {
            'email': email,
            'phone_number': phone_number,
            'username': username,
            'password': password
        }
        user = authenticate(**credentials)
        if not user:
            raise errors.InvalidGrantError(error_msg, request=request)
        request.user = user
        return True

    def validate_id_token(self, token, scopes, request):
        """
        When users try to access resources, check that provided id_token is valid
        """
        if not token:
            return False
        if app_settings.OAUTH_SAVE_ID_TOKEN:
            return super().validate_id_token(token, scopes, request)
        # validate application by client_id
        key = self._get_key_for_token(token)
        if not key:
            return False
        try:
            jwt_token = jwt.JWT(key=key, jwt=token)
            claims = json.loads(jwt_token.claims)
        except (JWException, JWTExpired):
            return False
        backend = AuthenticationBackend()
        request.user = LazyAuthenticatedUser(lambda: backend.get_user(claims['sub']))

        # this is needed by django rest framework
        request.access_token = token
        return True

    def _save_id_token(self, jti, request, expires, *args, **kwargs):
        if app_settings.OAUTH_SAVE_ID_TOKEN:
            super()._save_id_token(jti, request, expires, *args, **kwargs)

    def save_token(self, token, request, *args, **kwargs):
        super().save_token(token, request, *args, **kwargs)
        user_serializers = app_settings.SERIALIZERS.get('USERINFO_SERIALIZER')
        if user_serializers:
            token['user'] = user_serializers(instance=request.user).data
        if app_settings.USE_ID_TOKEN and oauth2_provider_settings.OIDC_ENABLED and request.client.algorithm:
            token['id_token'] = self.get_id_token(token, None, request, **kwargs)

    @transaction.atomic
    def save_jwt_token(self, token, request, *args, **kwargs):
        """
        Of course we dont save jwt code itself. we only update its refresh token
        """

        if "scope" not in token:
            raise FatalClientError("Failed to renew access token: missing scope")

        if request.grant_type == "client_credentials":
            request.user = None

        refresh_token_instance = getattr(request, "refresh_token_instance", None)

        refresh_token_code = token.get("refresh_token", None)
        if isinstance(refresh_token_instance, RefreshToken):
            if (
                    self.rotate_refresh_token(request)
                    and isinstance(refresh_token_instance, RefreshToken)
            ):
                refresh_token_instance = RefreshToken.objects.select_for_update().get(
                    id=refresh_token_instance.id
                )
                request.refresh_token_instance = refresh_token_instance
                try:
                    refresh_token_instance.revoke()
                except (RefreshToken.DoesNotExist):
                    pass
                else:
                    setattr(request, "refresh_token_instance", None)
        self._create_refresh_token(request, refresh_token_code, None)

    def get_id_token_dictionary(self, token, token_handler, request):
        """
        Get the claims to put in the ID Token.

        These claims are in addition to the claims automatically added by
        ``oauthlib`` - aud, iat, nonce, at_hash, c_hash.

        This function adds in iss, exp and auth_time, plus any claims added from
        calling ``get_oidc_claims()``
        """
        claims = self.get_oidc_claims(token, token_handler, request)

        expiration_time = timezone.now() + timezone.timedelta(seconds=oauth2_settings.ID_TOKEN_EXPIRE_SECONDS)
        # Required ID Token claims
        claims.update(
            **{
                "iss": self.get_oidc_issuer_endpoint(request),
                "exp": int(dateformat.format(expiration_time, "U")),
                "jti": str(uuid.uuid4()),
            }
        )

        return claims, expiration_time

    def get_id_token(self, token, token_handler, request, nonce=None):
        id_token = {}
        id_token['aud'] = request.client_id
        id_token['iat'] = int(time.time())
        if nonce is not None:
            id_token["nonce"] = nonce
        return self.finalize_id_token(id_token, token, token_handler, request)

    def get_oidc_issuer_endpoint(self, request):
        try:
            return super().get_oidc_issuer_endpoint(request)
        except (NoReverseMatch, TypeError):
            if hasattr(request, 'build_absolute_uri'):
                return request.build_absolute_uri('account/oauth')
            django_request = HttpRequest()
            django_request.META = request.headers
            django_request._scheme = 'https'
            return django_request.build_absolute_uri('account/oauth')

    def get_additional_claims(self, request):
        return {
            "email": request.user.email,
            "last_name": request.user.last_name,
            "first_name": request.user.first_name,
        }
