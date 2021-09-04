import hashlib
import hmac
import os

import requests

from ..abstract_adapter import OauthAdapter

GRAPH_API_VERSION = 'v11.0'
GRAPH_API_URL = "https://graph.facebook.com/" + GRAPH_API_VERSION


class FacebookOauthAdapter(OauthAdapter):
    client_id = os.environ.get('FACEBOOK_CLIENT_ID', '')
    client_secret = os.environ.get('FACEBOOK_CLIENT_SECRET', '')
    id = "facebook"
    profile_url = GRAPH_API_URL + "/me"
    access_token_url = GRAPH_API_URL + "/oauth/access_token"
    access_token_method = "GET"

    def get_user_fields(self):
        """
        available fields: https://developers.facebook.com/docs/graph-api/reference/user/
        """
        fields = [
            "id",
            "email",
            "name",
            "first_name",
            "last_name",
            "picture"
        ]
        return fields

    def get_uid(self, data: dict[str:str]):
        access_token = data.get('access_token', None)
        user_jwt = data.get('user_jwt', None)
        if access_token:
            appsecret_proof = hmac.new(self.client_secret.encode("utf-8"),
                                       msg=access_token.encode("utf-8"),
                                       digestmod=hashlib.sha256).hexdigest()
            resp = requests.get(
                self.profile_url,
                params={
                    "fields": ",".join(self.get_user_fields()),
                    "access_token": access_token,
                    "appsecret_proof": appsecret_proof,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data['id'], self.get_model_fields(data), data

    def get_model_fields(self, data):
        return dict(
            email=data.get("email"),
            last_name=data.get("last_name", ''),
            first_name=data.get("first_name", ''),
        )