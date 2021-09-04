__author__ = 'Carrycat'
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.generics import RetrieveUpdateAPIView, get_object_or_404, GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from ..permissions import IsSelfOrReadOnly
from ..serializers.account_serializers import UpdatePhoneSerializer, DefaultUserinfoSerializer
from ..settings import app_settings

User = get_user_model()


class UserDetails(RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated, IsSelfOrReadOnly)  # for scopes favor: ScopesIsSelfOrReadOnly,
    queryset = User.objects.filter(is_active=True)
    # required_scopes = ['account.get_user_details']

    def get_serializer_class(self):
        return app_settings.SERIALIZERS.get('USERINFO_SERIALIZER') or DefaultUserinfoSerializer

    def get_object(self):
        if self.kwargs['pk'] == 'self':
            obj = self.request.user
        else:
            obj = get_object_or_404(User, pk=self.kwargs['pk'])
        self.check_object_permissions(self.request, obj)
        return obj

    def get(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        data = serializer.data
        return Response(data)


class EmailCheck(GenericAPIView):
    def post(self, *args, **kwargs):
        exist = User.objects.filter(email=self.request.data.get('email', '')).exists()
        return Response(not exist)


class PhoneChangeView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UpdatePhoneSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "New phone number has been saved."})