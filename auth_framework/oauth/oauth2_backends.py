__author__ = 'Carrycat'
from oauth2_provider.oauth2_backends import OAuthLibCore as DefaultOAuthLibCore


class OAuthLibCore(DefaultOAuthLibCore):
    """
    Extends the default OAuthLibCore to parse correctly requests with application/json Content-Type
    """
    def extract_body(self, request):
        """
        Using data instead of DATA, to support accept JSON body
        """
        if isinstance(request.data, dict):
            body = request.data.items()
        else:
            body = {'data': request.data}.items()
        return body
