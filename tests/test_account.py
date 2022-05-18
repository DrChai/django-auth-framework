import re

from django.contrib.auth import get_user_model
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core import mail
from django.core.cache import cache
from django.db import transaction
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from oauth2_provider.models import get_access_token_model
from oauth2_provider.settings import oauth2_settings
from rest_framework import serializers

from auth_framework.serializers.mixin_serializers import EmailMixin
from auth_framework.serializers.password_serializers import PasswordChangeSerializer
from .test_oauth import BaseTest, UserInfoTestSerializer

AccessToken = get_access_token_model()
UserModel = get_user_model()


class EmailMixinTestSerializer(EmailMixin, UserInfoTestSerializer):
    pass


class BaseAccountTest(BaseTest):
    def setUp(self):
        super().setUp()
        self.tok = AccessToken.objects.create(
            user=self.test_user,
            token="1234567890",
            application=self.application,
            expires=timezone.now() + timezone.timedelta(days=1),
            scope="read write",
        )

    def tearDown(self):
        super().tearDown()
        self.tok.delete()


class UserInfoTest(BaseAccountTest):

    @override_settings(AUTH_FRAMEWORK={"SERIALIZERS": {'USERINFO_SERIALIZER': EmailMixinTestSerializer}})
    def test_get_self_userinfo(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.tok.token)
        response = self.client.get(reverse("userinfo",args=['self']),)
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, {'first_name': '', 'last_name': '', 'email': 'test@example.com'})

    @override_settings(AUTH_FRAMEWORK={"UNIQUE_EMAIL": False,
                                    'SERIALIZERS': {'USERINFO_SERIALIZER': EmailMixinTestSerializer}})
    def test_patch_self_userinfo(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.tok.token)
        response = self.client.patch(reverse("userinfo", args=['self']),
                                     data={'last_name': 'patch',})
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, {'first_name': '', 'last_name': 'patch', 'email': 'test@example.com'})
        # since db migrations persist, we just check serializer validation
        serializer = EmailMixinTestSerializer(data={'email': 'dev@example.com',})
        self.assertEqual(serializer.is_valid(), True)

    @override_settings(AUTH_FRAMEWORK={"UNIQUE_EMAIL": True,
                                       'SERIALIZERS': {'USERINFO_SERIALIZER': EmailMixinTestSerializer}})
    def test_patch_unique_email(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.tok.token)
        response = self.client.patch(reverse("userinfo", args=['self']),
                                     data={'email': 'test@example.com'})
        self.assertDictEqual(response.data, {'first_name': '', 'last_name': '', 'email': 'test@example.com'})
        self.assertEqual(response.status_code, 200)
        response = self.client.patch(reverse("userinfo", args=['self']),
                                     data={'email': 'dev@example.com'})
        self.assertEqual(response.status_code, 400)

    @override_settings(AUTH_FRAMEWORK={"SERIALIZERS": {'USERINFO_SERIALIZER': EmailMixinTestSerializer}})
    def test_read_others_info(self):
        dev_pk=self.dev_user.pk
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.tok.token)
        response = self.client.get(reverse("userinfo", args=[dev_pk]), )
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, {'first_name': '', 'last_name': '', 'email': 'dev@example.com'})

    def test_403_patch_others_info(self):
        dev_pk = self.dev_user.pk
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.tok.token)
        response = self.client.patch(reverse("userinfo", args=[dev_pk]),
                                     data={'first_name': 'test', 'last_name': 'patch'})
        self.assertEqual(response.status_code, 403)

    def test_401_get_self_userinfo(self):
        response = self.client.get(reverse("userinfo",args=['self']),)
        self.assertEqual(response.status_code, 401)


class UserChangePasswordTest(BaseAccountTest):

    def _get_test_data(self):
        data = {
            'old_password': '123456',
            'password1': '1234qwes',
        }
        return data

    @override_settings(AUTH_FRAMEWORK={"USE_PASSWORD_TWICE_VALIDATION": False})
    def test_change_password(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.tok.token)
        response = self.client.post(reverse("change-password"), data=self._get_test_data())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {"message": "New password has been saved."})

    @override_settings(AUTH_FRAMEWORK={"USE_PASSWORD_TWICE_VALIDATION": False})
    def test_400_change_password(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.tok.token)
        data = self._get_test_data()
        data |= {'old_password': 'NOT_MY_PASSWORD'}
        response = self.client.post(reverse("change-password"), data=data)
        self.assertEqual(response.status_code, 400)

    @override_settings(AUTH_FRAMEWORK={"USE_PASSWORD_TWICE_VALIDATION": True})
    def test_change_password_twice_validation(self):
        data = self._get_test_data()
        request = self.factory.post(reverse("change-password"))
        request.user = self.test_user
        serializer_kwargs = {
            'data': data,
            'context': {'request': request}
        }
        serializer = PasswordChangeSerializer(**serializer_kwargs)
        self.assertEqual(serializer.is_valid(), False)
        data |= {'password2':  '1234qwes',}
        serializer = PasswordChangeSerializer(**serializer_kwargs)
        self.assertEqual(serializer.is_valid(), True)
        data |= {'password2': '1234qwec', }
        serializer = PasswordChangeSerializer(**serializer_kwargs)
        self.assertEqual(serializer.is_valid(), False)

    def test_401_get_self_userinfo(self):
        response = self.client.post(reverse("change-password"))
        self.assertEqual(response.status_code, 401)


@override_settings(AUTH_FRAMEWORK={"USE_PASSWORD_TWICE_VALIDATION": False})
class UserResetPasswordTest(BaseAccountTest):
    """
        skip testing on send reset pin to phone
    """
    def test_pin_reset_entrypoint(self):
        self.assertEqual(reverse("reset-password-entrypoint", args=['pin']),
                         reverse("reset-password-entrypoint", kwargs={'method': 'pin'}))
        response = self.client.post(reverse("reset-password-entrypoint", kwargs={'method': 'pin'}),
                                    data={'email': self.test_user.email})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [self.test_user.email])
        pin_regex = re.search(r'reset pin: (?P<pin>\d+)',mail.outbox[0].body)
        self.assertIsNotNone(pin_regex)
        self.assertEqual(int(pin_regex.groupdict()['pin']), cache.get('pin_verify:%s' % self.test_user.email))

    def test_400_pin_reset(self):
        response = self.client.post(reverse("reset-password-entrypoint", kwargs={'method': 'pin'}),
                                    data={'email': 'NOT_existed@not.existed'})
        self.assertEqual(response.status_code, 400)

    def test_pin_reset_password(self):
        cache.set('pin_verify:%s' % self.test_user.email, 123456)
        response = self.client.post(reverse("pin-reset-password"),
                                    data={
                                        'email': self.test_user.email,
                                        'pin': 123456,
                                        'password1': 'resetofpin',})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {"message": "New password has been saved."})
        self.assertIsNone(cache.get('pin_verify:%s' % self.test_user.email))
        user = UserModel.objects.get(pk=self.test_user.pk)
        self.assertTrue(user.check_password('resetofpin'))

    def test_400_pin_reset_password(self):
        cache.set('pin_verify:%s' % self.test_user.email, 333333)
        response = self.client.post(reverse("pin-reset-password"),
                                    data={
                                        'email': self.test_user.email,
                                        'pin': 123456,
                                        'password1': 'resetofpin', })
        self.assertEqual(response.status_code, 400)
        response = self.client.post(reverse("pin-reset-password"),
                                    data={
                                        'email': self.dev_user.email,
                                        'pin': 333333,
                                        'password1': 'resetofpin', })
        self.assertEqual(response.status_code, 400)
        self.test_user.email = 'new@email.com'
        self.test_user.save()
        response = self.client.post(reverse("pin-reset-password"),
                                    data={
                                        'email': 'new@email.com',
                                        'pin': 333333,
                                        'password1': 'resetofpin', })
        self.assertEqual(response.status_code, 400)

    def test_link_reset_entrypoint(self):
        self.assertEqual(reverse("reset-password-entrypoint", args=['link']),
                         reverse("reset-password-entrypoint", kwargs={'method': 'link'}))

        response = self.client.post(reverse("reset-password-entrypoint", kwargs={'method': 'link'}),
                                    data={'email': self.test_user.email})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [self.test_user.email])
        body = mail.outbox[0].body
        self.assertGreater(body.find("/password/reset/"), 0)

        # Extract URL for `password_reset_from_key` view and access it
        url = body[body.find("/password/reset/"):].split()[0]
        response = self.client.get(url)
        self.assertEqual(response.data, {'message': 'valid url'})
        response = self.client.post(url, {'password1': 'resetoflink',})
        self.assertEqual(response.status_code, 200)
        user = UserModel.objects.get(pk=self.test_user.pk)
        self.assertTrue(user.check_password('resetoflink'))
        response = self.client.post(url, {'password1': 'resetoflink', })
        self.assertEqual(response.status_code, 400)


class CustomSignUpSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField()


class UsernameTestValidator(UnicodeUsernameValidator):
    regex = r'^\w+$'


@override_settings(AUTH_FRAMEWORK={"USE_PASSWORD_TWICE_VALIDATION": False,
                                   "SERIALIZERS": {'USERINFO_SERIALIZER': UserInfoTestSerializer}})
class CreateUserWithToken(BaseTest):

    def _hard_reload_serializer_mod(self):
        from importlib import reload
        from auth_framework.oauth import views
        from auth_framework.serializers import signup_serializers
        reload(signup_serializers)
        reload(views)

    def test_create_user(self):
        self._hard_reload_serializer_mod()
        url = reverse('create-user')
        data1 = {'email': 'adb@ad.ca', 'password1': 'qwed678s',}
        response = self.client.post(url, data1,)
        self.assertEqual(response.status_code, 201)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertEqual(response.data["expires_in"], oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        self.assertTrue(UserModel.objects.filter(email='adb@ad.ca').exists())
        self.assertDictEqual(response.data["user"], {'first_name': '', 'last_name': '', 'email': 'adb@ad.ca'})

    @override_settings(AUTH_FRAMEWORK={"USE_PASSWORD_TWICE_VALIDATION": False,
                                    "SERIALIZERS": {'USERINFO_SERIALIZER': UserInfoTestSerializer,
                                                    'SIGNUP_SERIALIZER': CustomSignUpSerializer
                                                    }})
    def test_400_custom_field_on_creation(self):
        self._hard_reload_serializer_mod()
        url = reverse('create-user')
        data = {
            'email': 'adb@ad.ca', 'password1': 'qwed678s',
            }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 400)

    @override_settings(AUTH_FRAMEWORK={"SIGNUP_USERNAME_REQUIRED": True})
    def test_400_username_required_on_creation(self):
        url = reverse('create-user')
        data = {
            'email': 'adb@ad.ca', 'password1': 'qwed678s', 'password2': 'qwed678s',
            }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 400)

    @override_settings(AUTH_FRAMEWORK={"SIGNUP_USERNAME_VALIDATORS":
                                        ['tests.test_account.UsernameTestValidator']})
    def test_custom_username_validator(self):
        url = reverse('create-user')
        data = {
            'email': 'adb@ad.ca', 'password1': 'qwed678s', 'password2': 'qwed678s', 'username':'invalid.dot',
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 400)

    @override_settings(AUTH_FRAMEWORK={"USE_PASSWORD_TWICE_VALIDATION": False,
                                       "SERIALIZERS": {'USERINFO_SERIALIZER': UserInfoTestSerializer,
                                                       'SIGNUP_SERIALIZER': CustomSignUpSerializer
                                                       }})
    def test_custom_field_on_creation(self):
        self._hard_reload_serializer_mod()
        url = reverse('create-user')
        with transaction.atomic():
            data = {'email': 'adb@ad.ca', 'password1': 'qwed678s', 'last_name': 'custom'}
            response = self.client.post(url, data)
            self.assertEqual(response.status_code, 201)