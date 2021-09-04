__author__ = 'Carrycat'
from django.contrib.auth import login as django_login, logout as django_logout
from rest_framework.authentication import SessionAuthentication
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from ..permissions import IsAuthenticatedAndActive
from ..serializers.account_serializers import SessionLoginSerializer
from ..settings import import_callable, app_settings

user_serializers = import_callable(app_settings.SERIALIZERS.get('USERINFO_SERIALIZER'))


class SessionLogin(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = SessionLoginSerializer
    validated_user = None

    def perform_login(self, user):
        django_login(self.request, user, backend='django.contrib.auth.backends.ModelBackend')

    def post(self, *args, **kwargs):
        login_serializer = self.get_serializer(data=self.request.data)
        login_serializer.is_valid(raise_exception=True)
        self.validated_user = login_serializer.validated_data
        self.perform_login(self.validated_user)
        data = user_serializers(instance=self.validated_user).data if user_serializers else {}
        return Response(data)


class SessionLogout(APIView):
    permission_classes = (IsAuthenticatedAndActive,)
    authentication_classes = (SessionAuthentication,)
    # authentication_classes = (CsrfExemptSessionAuthentication,)

    def perform_logout(self):
        django_logout(self.request)

    def post(self, request, *args, **kwargs):
        self.perform_logout()
        return Response({})
