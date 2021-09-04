from importlib import import_module

from django.conf import settings
from django.core.signals import setting_changed

SOCIALACCOUNT_MODEL = getattr(settings, "REST_AUTH_SOCIALACCOUNT_MODEL", "auth_framework.SocialAccount")

DEFAULTS = {
    'UNIQUE_EMAIL': True,
    'RESET_PASSWORD_BY': 'pin',  # 'url'| 'pin'
    'SERIALIZERS': {
        # 'SOCIAL_LOGIN_SERIALIZER': 'auth.social.serializers.DefaultSocialLoginSerializer',
        'SIGNUP_SERIALIZER': 'auth_framework.serializers.signup_serializers.DefaultSignUpSerializer',
        'USERINFO_SERIALIZER': None
    },
    'SOCIALACCOUNT_MODEL': SOCIALACCOUNT_MODEL,
    'SOCIALACCOUNT_ADMIN_CLASS': "auth_framework.admin.SocialAccountAdmin",
    # SOCIAL LOGINS
    'SOCIAL_CALLBACK_URL': None,  # eg: 'https://developers.google.com/oauthplayground'
    'SOCIAL_AUTO_SIGNUP': False,
    # SIGN UP
    # 'SIGNUP_EMAIL_VERIFICATION': 'none', # trimmed out email verification celery task in closed source. fewer usage
    'SIGNUP_USERNAME_REQUIRED': False,
    'SIGNUP_USERNAME_VALIDATORS': [],
    'USE_PASSWORD_TWICE_VALIDATION': True,
    # ADVANCES
    'USE_PHONENUMBER_FIELD': False,
    'USE_CELERY_EMAIL': False,
    'USE_ID_TOKEN': True,
    'OAUTH_SAVE_ID_TOKEN': False
}


def import_callable(path_or_callable):
    if path_or_callable is None:
        return None
    if hasattr(path_or_callable, '__call__'):
        return path_or_callable
    else:
        assert isinstance(path_or_callable, str)
        package, attr = path_or_callable.rsplit('.', 1)
        return getattr(import_module(package), attr)


class AuthSettings:
    """
    """
    def __init__(self, user_settings=None, defaults=None):
        if user_settings:
            self._user_settings = user_settings
        self.defaults = defaults or DEFAULTS
        self._cached_attrs = set()

    @property
    def user_settings(self):
        if not hasattr(self, '_user_settings'):
            self._user_settings = getattr(settings, 'AUTH_FRAMEWORK', {})
        return self._user_settings

    @property
    def username_validators(self):
        from django.core.exceptions import ImproperlyConfigured
        from django.contrib.auth import get_user_model
        validators = self.user_settings.get("SIGNUP_USERNAME_VALIDATORS", None)
        if validators:
            ret = []
            if not isinstance(validators, list):
                raise ImproperlyConfigured(
                    "SIGNUP_USERNAME_VALIDATORS is expected to be a list"
                )
            for path in validators:
                pkg, attr = path.rsplit(".", 1)
                validator = getattr(import_module(pkg), attr)
                ret.append(validator())
        else:
            ret = (
                get_user_model()._meta.get_field('username').validators
            )
        return ret

    def serializers(self, data):
        # Check if present in user settings
        for key, value in data.items():
            data[key] = import_callable(value)
        return data

    def __getattr__(self, attr):
        if attr not in self.defaults:
            raise AttributeError("Invalid setting: '%s'" % attr)

        try:
            # Check if present in user settings
            val = self.user_settings[attr]
            if isinstance(val, dict):
                val = self.defaults[attr].copy()
                val.update(self.user_settings[attr])
        except KeyError:
            # Fall back to defaults
            val = self.defaults[attr]
        if attr == 'SERIALIZERS':
            val = self.serializers(val)
        # Cache the result
        self._cached_attrs.add(attr)
        setattr(self, attr, val)
        return val

    def reload(self):
        for attr in self._cached_attrs:
            delattr(self, attr)
        self._cached_attrs.clear()
        if hasattr(self, '_user_settings'):
            delattr(self, '_user_settings')


app_settings = AuthSettings(None, DEFAULTS)


def reload_app_settings(*args, **kwargs):
    setting = kwargs['setting']
    if setting == 'AUTH_FRAMEWORK':
        app_settings.reload()


setting_changed.connect(reload_app_settings)
