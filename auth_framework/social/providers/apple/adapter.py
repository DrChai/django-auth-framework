import os

from ..abstract_adapter import OauthAdapter


class AppleOauthAdapter(OauthAdapter):
    client_id = os.environ.get('APPLE_CLIENT_ID', '')
    client_secret = os.environ.get('APPLE_CLIENT_SECRET', '')
    id = "apple"
    access_token_url = "https://appleid.apple.com/auth/token"
    authorize_url = "https://appleid.apple.com/auth/authorize"
    public_key_url = "https://appleid.apple.com/auth/keys"

    def get_model_fields(self, data:dict[str:str]) -> dict[str:str]:
        return dict(
            email=data.get("email"),
            first_name=data.get('name', {}).get('first_name', ''),
            last_name=data.get('name', {}).get('last_name', '')
        )