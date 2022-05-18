from django.apps import apps
from django.db import models
from django.utils.translation import gettext_lazy as _

from .settings import app_settings, import_callable
from .abstract_models import DefaultAbstractUser, PhoneNumberMixin, AvatarMixin, AbstractSocialAccount


def base_class():
    bases = [DefaultAbstractUser,]
    if app_settings.USE_PHONENUMBER_FIELD:
        bases.append(PhoneNumberMixin)
    return tuple(bases)


def settings_default_value():
    return {
            "language": "en",
            "reminder": {
                "interval": 15,
                "sleep": 1260,
                "wakeUp": 540
            },
            "unit": "metric"
    }


class AbstractUser(*base_class()):
    class Meta(DefaultAbstractUser.Meta):
        abstract = True


class User(*base_class()):
    # settings = models.JSONField(_('account settings'), default=dict)

    class Meta(DefaultAbstractUser.Meta):
        verbose_name = _('user')
        verbose_name_plural = _('users')
        swappable = 'AUTH_USER_MODEL'

    @classmethod
    def get_fields(cls):
        return tuple(set(map(lambda field: field.name, cls._meta.local_fields)) -
                     {'password', 'is_superuser', 'is_active', 'last_login', 'is_staff', 'date_joined'})


class SocialAccount(AbstractSocialAccount):

    class Meta(AbstractSocialAccount.Meta):
        swappable = "REST_AUTH_SOCIAL_ACCOUNT"


def get_socialaccount_model():
    """ Return the RefreshToken model that is active in this project. """
    return apps.get_model(app_settings.SOCIALACCOUNT_MODEL)


def get_socialaccount_admin_class():
    """ Return the Application admin class that is active in this project. """
    socialaccount_admin_class = app_settings.SOCIALACCOUNT_ADMIN_CLASS
    return import_callable(socialaccount_admin_class)