import os
import requests
from ..abstract_adapter import OauthAdapter

_GOOGLE_OAUTH2_CERTS_URL = "https://www.googleapis.com/oauth2/v1/certs"


class GoogleOauthAdapter(OauthAdapter):
    id = "google"
    access_token_url = "https://accounts.google.com/o/oauth2/token"
    profile_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    public_key_url = "https://www.googleapis.com/oauth2/v3/certs"
    scope = ['email', 'profile']
    client_id = os.environ.get('GOOGLE_CLIENT_ID', '')
    client_secret = os.environ.get('GOOGLE_CLIENT_SECRET', '')

    def get_default_scope(self) -> list[str]:
        return self.scope

    def get_uid(self, data: dict[str:str]):
        access_token = data.get('access_token', None)
        if access_token:
            resp = requests.get(
                self.profile_url,
                params={"access_token": access_token, "alt": "json"},
            )
            resp.raise_for_status()
            data = resp.json()
            return data['id'],self.get_model_fields(data), data
        else:
            return super().get_uid(data)

    def get_model_fields(self, data:dict[str:str]) -> dict[str:str]:
        return dict(
            email=data.get("email"),
            last_name=data.get("family_name", ''),
            first_name=data.get("given_name", ''),
        )

    # def get_pubkey(self, token: str) -> RSAPublicKey:

    #     """
    #     * Fetches certificates from Google API.
    #     * generate JWT key file for decoding.
    #     """
    #     from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    #     from cryptography.x509 import load_pem_x509_certificate
    #     from cryptography.hazmat.backends import default_backend
    #     jws = jwt.PyJWS()
    #     header = jws.get_unverified_header(token)
    #     key_id = header.get("kid")
    #     resp = requests.get(_GOOGLE_OAUTH2_CERTS_URL)
    #     resp.raise_for_status()
    #     try:
    #         certs_to_check = resp.json()[key_id]
    #         certs_to_check = str.encode(certs_to_check)
    #         cert_obj = load_pem_x509_certificate(certs_to_check, default_backend())
    #     except KeyError:
    #         raise InvalidPubKey("failed to get pubkey from Google with kid {kid}".format(kid=key_id))
    #     pub_key = cert_obj.public_key()
    #     return pub_key
