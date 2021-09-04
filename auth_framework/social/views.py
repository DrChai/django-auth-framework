from oauth2_provider.models import get_application_model
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from .providers.apple.adapter import AppleOauthAdapter
from .providers.facebook.adapter import FacebookOauthAdapter
from .providers.google.adapter import GoogleOauthAdapter
from .serializers import SocialConnectionSerializer, SocialLoginSerializer
from ..oauth.serializers import AccessTokenSerializer
from ..oauth.utils import get_access_token

Application = get_application_model()


class SocialLoginView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = SocialLoginSerializer
    response_serializer = AccessTokenSerializer
    process = 'login'

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

    def perform_login(self, user):
        self.validate_client(raise_exception=True)
        token = get_access_token(user, request=self.request)
        # login(self.request, user) TODO: here
        if 'user' in token:
            token['user']['linked_social'] = [sc.provider for sc in user.socialaccount_set.all()]
        return token

    def post(self, request, *args, **kwargs):
        process = request.GET.get('process', self.process)
        serializer = self.get_serializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        resp = {}
        if process == 'login':
            resp = self.perform_login(user)
        else:
            resp['linked_social'] = [sc.provider for sc in self.request.user.socialaccount_set.all()]
        return Response(resp, status=status.HTTP_200_OK)


class SocialConnections(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = SocialConnectionSerializer

    def get(self, request):
        data = {'linked_social': [sc.provider for sc in request.user.socialaccount_set.all()]}
        return Response(data)

    def post(self, request):
        data = request.data
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'message': 'success'})


class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOauthAdapter


class FacebookLogin(SocialLoginView):
    adapter_class = FacebookOauthAdapter


class AppleLogin(SocialLoginView):
    adapter_class = AppleOauthAdapter

