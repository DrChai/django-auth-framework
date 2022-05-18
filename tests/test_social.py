import json

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from rest_framework import serializers

from auth_framework.models import get_socialaccount_model
from auth_framework.social.providers.facebook.adapter import GRAPH_API_URL
from .test_oauth import BaseTest
from unittest.mock import patch, Mock

UserModel = get_user_model()
SocialAccountModel = get_socialaccount_model()

TEST_KEY_PUB = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----'''

TEST_KEY = '''-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
-----END RSA PRIVATE KEY-----'''
#   "sub": "1234567890",
#   "name":{
#      "first_name": "New",
#     "last_name": "Tester"
#   },
#   "email":"test@social.com",
#   "iat": 1516239022
MOCKED_USER_JWT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6eyJmaXJzdF9uYW1lIjoiTmV3IiwibGFzdF9uYW1lIjoiVGVzdGVyIn0sImVtYWlsIjoidGVzdEBzb2NpYWwuY29tIiwiaWF0IjoxNTE2MjM5MDIyfQ.EEPLjGIfOrcmQOrp3cdJZTybo7EM-sLU90LxFUSI8AAnzMBW-9P1wMmz8qA0njWXh_N7wuwKmtxTQWExyCjq1xKYRIep4Jmi8WoWenTriobgFima-J6XT92pef2ojVoRZ9nDM7NkLnIUzIHeE16YCrLKlr8glXeKIOy3hPqUC1HSAVsxoVvgur-FN4RoL3_CtWBkvSt1rKIg-bon1zII-a5_bA0VuKTkGrBPkTgN-qJNC5usCqlnUl7bzPptHlnsVI-Z9guy1ScpsZ1immppboFCYdkzr6tSIxpvsmNpuwGgR-neAYoY87MPB8o5LVsdUaSzi0PoeAcR-yevDCKUaw'
APPLE_MOCKED_test_user_JWT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6eyJmaXJzdF9uYW1lIjoiTmV3IiwibGFzdF9uYW1lIjoiVGVzdGVyIn0sImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsImlhdCI6MTUxNjIzOTAyMn0.X4bUa9YfxDv9HGV_2bTJBFasvZegshlZBwCJuBzOfaCda5z3t9D79F3fBSA-PXsBxlvFczm-DrmbVjhoei5RKgpmZK-USdAodjxNVa5BTr1FkQkLKvhRS492sygOk0ZpX7s3Holk3fVURZ6djn0mH2SfvqUf2hAi7YOunWmaf6oFkJr2Bsq4Nszzcx4EwFNOqYloH4LRPQX60lIIN7nS0mWzwlaZFl01xhwlMg11EorRp6zPQnr_XXlNsyarFeV_uD6jEcQOXs2sT15hRseDHiTGBGkHPsuKY-pAcs_nSpsTjS0L1gIiMOeH1UdkDFEjbczuXx-7pkvOh6KBqKSc5g'
APPLE_MOCKED_JWKS = {
    "keys": [
        {
            "alg": "RS256",
            "use": "sig",
            "kid": "zFHVsM9dc4OlHIwvEnVqfKzRj1ujqYGsZnXAcgn_CqI",
            "e": "AQAB",
            "kty": "RSA",
            "n": 'nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9c'
                 'j5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8'
                 'nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv4'
                 '3qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw'
        }
    ]
}

FACEBOOK_MOCKED_USERINFO = {
    "id": "624123456789000", "name": "Tester Fb", "email": "test@social.com",
    "picture": {"data":
                    {"url": "https://platform-lookaside.fbsbx.com/",
                     "width": 50, "height": 50,
                    }
                },
    "last_name": "Fb",
    "first_name": "Tester"
}

def mock_requests_factory(provider: str) -> Mock:
    json_return_value = {
        'apple': APPLE_MOCKED_JWKS,
        'facebook': FACEBOOK_MOCKED_USERINFO,
        'google': APPLE_MOCKED_JWKS
    }
    return Mock(**{
        'json.return_value': json_return_value.get(provider),
        'content': json.dumps(json_return_value.get(provider)),
        'status_code': 200,
        'ok': True
    })


class UserSignupTestSerializer(serializers.Serializer):
    first_name = serializers.CharField(allow_blank=True)
    last_name = serializers.CharField()

    def validate_first_name(self, first_name):
        return 'Override'


class SocialTest(BaseTest):

    def _hard_reload_serializer_mod(self):
        from importlib import reload
        from auth_framework.social import serializers
        from auth_framework.serializers import signup_serializers
        reload(signup_serializers)
        reload(serializers)

    @patch('auth_framework.social.providers.abstract_adapter.requests.get', Mock(
        side_effect=lambda k: {'https://appleid.apple.com/auth/keys': mock_requests_factory('apple'),}.get(k)))
    def test_apple_new_user(self):
        response = self.client.post(reverse('apple_login'), data={'user_jwt': MOCKED_USER_JWT})
        self.assertEqual(response.status_code, 406)
        json_resp = response.json()
        self.assertEqual(json_resp['non_field_error']['message'], 'Auto SignUp disabled.')
        self.assertEqual(json_resp['non_field_error']['social_login'],
                         '{"account": {"uid": "1234567890", "provider": "apple", '
                         '"extra_data": {"sub": "1234567890", "name": {"first_name": "New", "last_name": "Tester"}, '
                         '"email": "test@social.com", "iat": 1516239022}},'
                         ' "user": {"email": "test@social.com", "first_name": "New", "last_name": "Tester"}}'
                         )

    @patch('auth_framework.social.providers.abstract_adapter.requests.get', Mock(
        side_effect=lambda k: {'https://appleid.apple.com/auth/keys': mock_requests_factory('apple'), }.get(
            k)))
    def test_apple_existed_email(self):
        response = self.client.post(reverse('apple_login'), data={'user_jwt': APPLE_MOCKED_test_user_JWT})
        self.assertEqual(response.status_code, 400)
        json_resp = response.json()
        self.assertIn('email', json_resp)
        self.assertEqual(response.content.find(b'social_login'), -1)

    @patch('auth_framework.social.providers.abstract_adapter.requests.get', Mock(
        side_effect=lambda k: {'https://appleid.apple.com/auth/keys': mock_requests_factory('apple'), }.get(
            k)))
    def test_apple_existed_account(self):
        """
        if uid existed return access_token as token api
        """
        SocialAccountModel.objects.create(user=self.test_user, provider='apple', uid='1234567890')
        response = self.client.post(reverse("apple_login"), data={'user_jwt': APPLE_MOCKED_test_user_JWT})
        self.assertEqual(response.status_code, 200)
        content = response.data
        self.assertIn('access_token', content)
        self.assertIn('refresh_token', content)

    def test_create_social(self):
        url = reverse('create-user')
        data = {'email': 'test@social.com', 'password1': '1234qwes', 'password2': '1234qwes',
                'social_login': '{"account": {"uid": "1234567890", "provider": "apple", '
                                '"extra_data": {"sub": "1234567890",'
                                ' "name": {"first_name": "New", "last_name": "Tester"}, '
                                '"email": "test@social.com", "iat": 1516239022}},'
                                ' "user": {"email": "test@social.com", "first_name": "New", "last_name": "Tester"}}'
                 }
        response = self.client.post(url, data,)
        self.assertEqual(response.status_code, 201)
        self.assertTrue(UserModel.objects.filter(email='test@social.com').exists())
        self.assertTrue(SocialAccountModel.objects.filter(uid='1234567890', provider='apple').exists())

    @patch('auth_framework.social.providers.abstract_adapter.requests.get', Mock(
        side_effect=lambda k: {'https://appleid.apple.com/auth/keys': mock_requests_factory('apple'), }.get(
            k)))
    def test_create_social_w_custom_email(self):
        """
        if email was not granted or user using alt email to create account
        """
        url = reverse('create-user')
        data = {'email': 'test_alt@social.com', 'password1': '1234qwes', 'password2': '1234qwes',
                'social_login': '{"account": {"uid": "1234567890", "provider": "apple", '
                                '"extra_data": {"sub": "1234567890",'
                                ' "name": {"first_name": "New", "last_name": "Tester"}, "iat": 1516239022}},'
                                ' "user": {"email": null, "first_name": "New", "last_name": "Tester"}}'
                 }
        response = self.client.post(url, data,)
        self.assertEqual(response.status_code, 201)
        self.assertTrue(UserModel.objects.filter(email='test_alt@social.com').exists())
        self.assertTrue(SocialAccountModel.objects.filter(uid='1234567890', provider='apple').exists())
        response = self.client.post(reverse("apple_login"), data={'user_jwt': MOCKED_USER_JWT})
        self.assertEqual(response.status_code, 200)
        self.assertIn('access_token', response.data)

    @patch('auth_framework.social.providers.facebook.adapter.requests.get', Mock(
        side_effect=lambda k, params: {GRAPH_API_URL + "/me": mock_requests_factory('facebook'), }.get(k)))
    def test_fb_new_user(self):
        response = self.client.post(reverse('fb_login'), data={'access_token': 'facebook_fake_access_token'})
        self.assertEqual(response.status_code, 406)
        json_resp = response.json()
        self.assertEqual(json_resp['non_field_error']['message'], 'Auto SignUp disabled.')
        self.assertEqual(json_resp['non_field_error']['social_login'],
                         '{"account": {"uid": "624123456789000", "provider": "facebook", '
                         '"extra_data": {"id": "624123456789000", "name": "Tester Fb",'
                         ' "email": "test@social.com", "picture": {"data": {"url": '
                         '"https://platform-lookaside.fbsbx.com/", "width": 50, "height": 50}}, '
                         '"last_name": "Fb", "first_name": "Tester"}},'
                         ' "user": {"email": "test@social.com", "first_name": "Tester", "last_name": "Fb"}}'
                         )

    @patch('auth_framework.social.providers.abstract_adapter.requests.get', Mock(
        side_effect=lambda k: {'https://www.googleapis.com/oauth2/v3/certs': mock_requests_factory('google'), }.get(k)))
    def test_gl_new_user(self):
        response = self.client.post(reverse('gl_login'), data={'user_jwt': MOCKED_USER_JWT})
        self.assertEqual(response.status_code, 406)
        json_resp = response.json()
        self.assertEqual(json_resp['non_field_error']['message'], 'Auto SignUp disabled.')
        self.assertEqual(json_resp['non_field_error']['social_login'],
                         '{"account": {"uid": "1234567890", "provider": "google", '
                         '"extra_data": {"sub": "1234567890", "name": {"first_name": "New", "last_name": "Tester"}, '
                         '"email": "test@social.com", "iat": 1516239022}},'
                         ' "user": {"email": "test@social.com", "first_name": "", "last_name": ""}}'
                         )

    @override_settings(AUTH_FRAMEWORK={"SOCIAL_AUTO_SIGNUP": True,})
    @patch('auth_framework.social.providers.abstract_adapter.requests.get', Mock(
        side_effect=lambda k: {'https://www.googleapis.com/oauth2/v3/certs': mock_requests_factory('google'), }.get(k)))
    def test_auto_signup(self):
        response = self.client.post(reverse('gl_login'), data={'user_jwt': MOCKED_USER_JWT})
        self.assertEqual(response.status_code, 200)
        json_resp = response.json()
        self.assertTrue(UserModel.objects.filter(email="test@social.com").exists())
        user = UserModel.objects.get(email="test@social.com")
        self.assertEqual(user.has_usable_password(), False)
        self.assertIn('access_token', json_resp)

    @override_settings(AUTH_FRAMEWORK={"SOCIAL_AUTO_SIGNUP": True, "SERIALIZERS": {
        'SIGNUP_SERIALIZER': UserSignupTestSerializer}})
    @patch('auth_framework.social.providers.abstract_adapter.requests.get', Mock(
        side_effect=lambda k: {'https://www.googleapis.com/oauth2/v3/certs': mock_requests_factory('google'),
                               'https://appleid.apple.com/auth/keys': mock_requests_factory('apple'),
                               }.get(k)))
    def test_custom_validation_auto_signup(self):
        self._hard_reload_serializer_mod()
        response = self.client.post(reverse('gl_login'), data={'user_jwt': MOCKED_USER_JWT})
        self.assertEqual(response.status_code, 400)
        response = self.client.post(reverse('apple_login'), data={'user_jwt': MOCKED_USER_JWT})
        self.assertEqual(response.status_code, 200)
        json_resp = response.json()
        self.assertTrue(UserModel.objects.filter(email="test@social.com", first_name='Override').exists())