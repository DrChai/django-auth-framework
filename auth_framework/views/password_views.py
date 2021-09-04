from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import base36_to_int
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from ..serializers.password_serializers import PasswordChangeSerializer, CreateResetPinSerializer, \
    CreateResetLinkSerializer, ResetPasswordByPinSerializer, ResetPasswordByLinkSerializer
from ..settings import app_settings

User = get_user_model()


class ChangePassword(GenericAPIView):
    """
    Accepts the following POST parameters: new_password1, new_password2
    Returns the success/fail message.
    """

    permission_classes = (IsAuthenticated,)
    serializer_class = PasswordChangeSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "New password has been saved."})


class CreateResetEntryPoint(GenericAPIView):
    """
    Create a temporary pin for password reset.
    pin will be sent on save() by sms/email which configured on settings.py(WITH_PHONENUMBER_FIELD)
    Returns the success/fail message.
    """

    def get_serializer_class(self):
        try:
            method = self.kwargs.get('method') or self.args[0]
        except IndexError:
            method = app_settings.RESET_PASSWORD_BY
        if method == 'pin':
            return CreateResetPinSerializer
        else:
            return CreateResetLinkSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": 'Message has been sent'}, status=status.HTTP_202_ACCEPTED)


class ResetPasswordByPin(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = ResetPasswordByPinSerializer

    def post(self, request, *args, **kwargs):
        # Create a serializer with request.data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "New password has been saved."})


class ResetPasswordByLink(GenericAPIView):
    serializer_class = ResetPasswordByLinkSerializer
    permission_classes = (AllowAny,)

    def get_reset_user(self, uidb36):
        try:
            pk = base36_to_int(uidb36)
            return User.objects.get(pk=pk)
        except (ValueError, User.DoesNotExist):
            return None

    def is_link_valid(self, uidb36, token):
        user = self.get_reset_user(uidb36)
        if user is None or not default_token_generator.check_token(user, token):
            return Response({'message': "The password reset token was invalid."},
                            status=status.HTTP_400_BAD_REQUEST)
        return user

    def get(self, request, uidb36, token):
        resp = self.is_link_valid(uidb36, token)
        if isinstance(resp,Response):
            return resp
        else:
            return Response({'message': 'valid url'})

    def post(self, request, *args, **kwargs):
        resp = self.is_link_valid(kwargs.get('uidb36'), kwargs.get('token'))
        if isinstance(resp, Response):
            return resp
        reset_user = resp
        context = self.get_serializer_context()
        context.update({'user': reset_user})
        serializer = self.get_serializer(data=request.data, context=context)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "New password has been saved."})
