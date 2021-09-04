import json

import requests
from django.contrib.auth import get_user_model
from django.db import transaction
from jwcrypto import jwk, jwt
from jwcrypto.common import JWException
from jwcrypto.jwt import JWTExpired

from auth_framework.exceptions import AuthFrameworkAuthException
from auth_framework.models import get_socialaccount_model
from auth_framework.settings import app_settings

User = get_user_model()
SocialAccount = get_socialaccount_model()

# TODO: reedit

def general_deserializer(model, data):
    ret = model()
    for k, v in data.items():
        setattr(ret, k, v)
    return ret


class OauthAdapterError(AuthFrameworkAuthException):
    pass


class InvalidPubKey(OauthAdapterError):
    pass


class InvalidJWT(OauthAdapterError):
    pass


class OauthAdapter:
    access_token_url = None
    callback_url = app_settings.SOCIAL_CALLBACK_URL
    public_key_url = None
    access_token_method = "POST"
    client_id = ''
    client_secret = ''
    id = None

    def __init__(self):
        self.user = User()
        self.social_acct = SocialAccount()

    @property
    def is_existed(self) -> bool:
        """
        New social acct to be stored in db.
        """
        return self.social_acct.pk is not None

    def get_current_social_acct(self, update=False) -> None:
        """
        get social account in db.
        """
        assert not self.is_existed
        try:
            social_acct = SocialAccount.objects.get(
                provider=self.id, uid=self.social_acct.uid
            )
            social_acct.extra_data = self.social_acct.extra_data
            self.social_acct = social_acct
            self.user = self.social_acct.user
            if update:
                social_acct.save()
        except SocialAccount.DoesNotExist:
            pass

    def populate_social_acct(self, **kwargs) -> tuple[SocialAccount, User]:
        """
        """
        uid, model_fields, extra_data = self.get_uid(kwargs)

        self.social_acct = SocialAccount(extra_data=extra_data, uid=uid, provider=self.id)
        self.populate_user(model_fields)
        return self.social_acct, self.user

    def populate_user(self, data: dict[str:str]) -> None:
        for field, value in data.items():
            setattr(self.user, field, value)
        return self.user

    def get_uid(self, data: dict[str:str]) -> tuple[str, dict[str:str], dict[str:str]]:
        user_jwt = data.get('user_jwt', None)
        key = self.get_pubkey()
        try:
            jwt_token = jwt.JWT(key=key, jwt=user_jwt)
            claims = json.loads(jwt_token.claims)
            return claims['sub'], self.get_model_fields(claims), claims
        except (JWException, JWTExpired):
            raise InvalidJWT("invalid user_jwt")

    def get_model_fields(self, data):
        raise NotImplementedError(
            "The provider must implement the `extract_uid()` method"
        )

    def get_pubkey(self) -> jwk.JWKSet:
        resp = requests.get(self.public_key_url)
        resp.raise_for_status()
        try:
            jwks = jwk.JWKSet()
            jwks.import_keyset(resp.content)
            return jwks
        except jwk.InvalidJWKValue:
            raise InvalidPubKey("failed to get pubkey")

    def get_access_token(self, code) -> str:
        data = {
            "redirect_uri": self.callback_url,
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
        }
        params = None
        url = self.access_token_url
        if self.access_token_method == "GET":
            params = data
            data = None
        resp = requests.request(
            self.access_token_method,
            url,
            params=params,
            data=data,
        )

        access_token = None
        if resp.status_code in [200, 201]:
            access_token = resp.json()
        if not access_token or "access_token" not in access_token:
            raise OauthAdapterError("Error retrieving access token: %s" % resp.json())
        return access_token['access_token']

    def save(self, connect_user: User = None) -> SocialAccount:
        assert not self.is_existed
        with transaction.atomic():
            if connect_user:
                self.user = connect_user
                self.social_acct.user = connect_user
            else:  # if auto signup enabled, we perform a quick user creation.
                self.user.set_unusable_password()
                self.user.save()
                self.social_acct.user = self.user
            self.social_acct.save()
            return self.social_acct

    def serialize(self) -> dict:
        def default_social_acct_serializer(social_acct:SocialAccount) -> dict:
            return {'uid': social_acct.uid, 'provider': social_acct.provider, 'extra_data': social_acct.extra_data }
        social_acct_serializer = getattr(SocialAccount, 'serializer', default_social_acct_serializer)
        ret = dict(
            account=social_acct_serializer(self.social_acct),
            user={'email':self.user.email, 'first_name':self.user.first_name, 'last_name':self.user.last_name,},
        )
        return ret

    @classmethod
    def deserialize(cls, data: dict):
        # todo: redit
        social_acct_deserializer = getattr(SocialAccount, 'deserializer',
                                           lambda acct: general_deserializer(SocialAccount, acct))
        social_acct = social_acct_deserializer(data["account"])
        user = User(email=data["user"]['email'], first_name=data["user"]['first_name'], last_name=data["user"]['last_name'])
        ret = cls()
        ret.social_acct = social_acct
        ret.user = user
        return ret


deserialize_social_acct = OauthAdapter.deserialize
