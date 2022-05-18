import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from oauth2_provider.models import get_application_model, get_access_token_model, get_refresh_token_model
from oauth2_provider.settings import oauth2_settings
from rest_framework import serializers
from rest_framework.test import APITestCase, APIRequestFactory


Application = get_application_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()
UserModel = get_user_model()


class UserInfoTestSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserModel
        fields = ('first_name', 'last_name', 'email',)


@pytest.mark.django_db
class BaseTest(APITestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456",)
        self.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456",)
        self.client_secret = "1234567890abcdefghijklmnopqrstuvwxyz"
        self.application = Application.objects.create(
            name="Test Password Application",
            user=self.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            client_secret=self.client_secret,
            authorization_grant_type=Application.GRANT_PASSWORD,
        )

    def tearDown(self):
        self.application.delete()
        self.test_user.delete()
        self.dev_user.delete()


class AccessTokenTest(BaseTest):

    def test_401_invalid_client(self):
        """
        Request an access token using Resource Owner Password Flow
        """
        token_request_data = {
            "grant_type": "password",
            "username": "test_user",
            "password": "123456",
            "client_id": self.application.client_id,
        }

        response = self.client.post(reverse("token"), data=token_request_data)
        self.assertEqual(response.status_code, 401)
        token_request_data |= {
            "client_secret": self.client_secret,
            "client_id": "wrong_client_id"
        }
        response = self.client.post(reverse("token"), data=token_request_data)
        self.assertEqual(response.status_code, 401)

    @override_settings(AUTH_FRAMEWORK={"SERIALIZERS": {'USERINFO_SERIALIZER': None}})
    def test_get_token_only(self):
        """
        Request an access token using Resource Owner Password Flow
        """
        token_request_data = {
            "grant_type": "password",
            "username": "test_user",
            "password": "123456",
            "client_id": self.application.client_id,
            "client_secret": self.client_secret
        }

        response = self.client.post(reverse("token"), data=token_request_data)
        self.assertEqual(response.status_code, 200)
        content = response.data
        self.assertEqual(content["token_type"], "Bearer")
        self.assertEqual(content["expires_in"], oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        self.assertIn('access_token', content)
        self.assertIn('refresh_token', content)
        self.assertNotIn('user', content)

    @override_settings(AUTH_FRAMEWORK={"SERIALIZERS": {'USERINFO_SERIALIZER': UserInfoTestSerializer}})
    def test_get_token_with_userinfo(self):
        """
        Request an access token using Resource Owner Password Flow
        """
        token_request_data = {
            "grant_type": "password",
            "username": "test_user",
            "password": "123456",
            "client_id": self.application.client_id,
            "client_secret": self.client_secret
        }

        response = self.client.post(reverse("token"), data=token_request_data)
        self.assertEqual(response.status_code, 200)
        content = response.data
        self.assertIn('access_token', content)
        self.assertIn('refresh_token', content)
        self.assertDictEqual(content["user"], {'first_name': '', 'last_name': '', 'email': 'test@example.com'})

    def test_get_token_by_email(self):
        """
        Request an access token using Resource Owner Password Flow
        """
        token_request_data = {
            "grant_type": "password",
            "email": "test@example.com",
            "password": "123456",
            "client_id": self.application.client_id,
            "client_secret": self.client_secret
        }

        response = self.client.post(reverse("token"), data=token_request_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('access_token', response.data)

    def test_400_credentials(self):
        """
        Request an access token using Resource Owner Password Flow
        """
        token_request_data = {
            "grant_type": "password",
            "username": "test_user",
            "password": "NOT_MY_PASS",
            "client_id": self.application.client_id,
            "client_secret": self.client_secret
        }

        response = self.client.post(reverse("token"), data=token_request_data)
        self.assertEqual(response.status_code, 400)

    def test_revoke_access_token(self):
        tok = AccessToken.objects.create(
            user=self.test_user,
            token="1234567890",
            application=self.application,
            expires=timezone.now() + timezone.timedelta(days=1),
            scope="read write",
        )

        data = {
            "client_id": self.application.client_id,
            "client_secret": self.client_secret,
            "token": tok.token,
        }
        url = reverse("revoke-token")
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {})
        self.assertFalse(AccessToken.objects.filter(id=tok.id).exists())

    def test_revoke_refresh_token(self):
        tok = AccessToken.objects.create(
            user=self.test_user,
            token="1234567890",
            application=self.application,
            expires=timezone.now() + timezone.timedelta(days=1),
            scope="read write",
        )
        rtok = RefreshToken.objects.create(
            user=self.test_user, token="999999999", application=self.application, access_token=tok
        )

        data = {
            "client_id": self.application.client_id,
            "client_secret": self.client_secret,
            "token": rtok.token,
        }

        url = reverse("revoke-token")
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, 200)
        refresh_token = RefreshToken.objects.filter(id=rtok.id).first()
        self.assertIsNotNone(refresh_token.revoked)
        self.assertFalse(AccessToken.objects.filter(id=rtok.access_token.id).exists())

    def test_refresh_token_grant(self):
        tok = AccessToken.objects.create(
            user=self.test_user,
            token="1234567890",
            application=self.application,
            expires=timezone.now() + timezone.timedelta(days=1),
            scope="read write",
        )
        rtok = RefreshToken.objects.create(
            user=self.test_user, token="999999999", application=self.application, access_token=tok
        )
        token_request_data = {
            "grant_type": "refresh_token",
            "client_id": self.application.client_id,
            "client_secret": self.client_secret,
            'refresh_token': rtok.token
        }
        response = self.client.post(reverse("token"), data=token_request_data)
        self.assertEqual(response.status_code, 200)
        content = response.data
        self.assertEqual(content["token_type"], "Bearer")
        self.assertEqual(content["expires_in"], oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        self.assertNotEqual(content['access_token'], tok.token)
        self.assertNotEqual(content['refresh_token'], rtok.token)
        refresh_token = RefreshToken.objects.filter(id=rtok.id).first()
        self.assertIsNotNone(refresh_token.revoked)
        self.assertFalse(AccessToken.objects.filter(id=rtok.access_token.id).exists())

