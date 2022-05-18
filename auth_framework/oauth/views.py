import json

from django.contrib.auth import logout
from oauth2_provider.models import get_application_model
from oauth2_provider.views.mixins import OAuthLibMixin
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from .utils import get_access_token
from ..serializers.signup_serializers import SignUpSerializer
from ..social.providers.abstract_adapter import deserialize_social_acct
from ..social.serializers import SocialSignUpSerializer

Application = get_application_model()


class RevokeTokenView(APIView, OAuthLibMixin):
    # permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        url, headers, body, code_status = self.create_revocation_response(request)
        content = {}
        if body:
            content = json.loads(body)
            if 'error_description' in content:
                content = {'message': content['error_description']}
        try:
            logout(request)
        except AttributeError:
            # no session object in Request, pypass
            pass
        return Response(content, status=code_status)


class GrantUserWToken(APIView, OAuthLibMixin):

    def post(self, request, *args, **kwargs):
        if not request.data.get('username'):
            if hasattr(request.data, '_mutable'):
                request.data._mutable = True
            request.data['username'] = 'dummy'  # NOQA: ResourceOwnerPasswordCredentialsGrant requires username
        url, headers, body, code_status = self.create_token_response(request)
        content = json.loads(body)
        if code_status == 200:
            return Response(content)
        return Response({'message': content.get('error_description', content['error'])}, status=code_status)


class CreateUserWToken(GenericAPIView):
    # required_scopes = ['account.signup']

    def get_serializer_class(self):
        if 'social_login' in self.request.data:  # originally was .POST
            return SocialSignUpSerializer
        else:
            return SignUpSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()
        # TODO: reedit
        if 'social_login' in self.request.data:  # originally was .POST but not friendly for Web Api
            context.update({'social_data': deserialize_social_acct(json.loads(self.request.data['social_login']))})
        return context

    def validate_client(self, raise_exception=False):
        # TODO: less confidential skip validate client(validate_client_id) for performance
        _errors = ""
        client_id = self.request.data.get('client_id')
        if not client_id:
            client = Application.objects.get(pk=1)
        else:
            client = Application.objects.get(client_id=client_id)
        if _errors and raise_exception:
            raise AuthenticationFailed(_errors)
        self.request.client = client
        self.request.client_id = client.client_id
        return client

    def post(self, *args, **kwargs):

        client = self.validate_client(raise_exception=True)
        serializer = self.get_serializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_access_token(user, request=self.request)
        # token_serializer = AccessTokenSerializer(token)
        return Response(token, status=status.HTTP_201_CREATED)