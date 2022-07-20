from io import BytesIO
from django.conf import settings
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.files import File
from django.db import models
from django.contrib.auth.models import AbstractUser as DjangoAbstractUser
from django.utils.crypto import get_random_string
from django.utils.translation import gettext_lazy as _
try:
    from PIL import Image
except ImportError:
    Image = None
from .settings import app_settings


class CustomUnicodeUsernameValidator(UnicodeUsernameValidator):
    regex = r'^[\w.-]+$'
    message = _(
        'Enter a valid username. This value may contain only letters, '
        'numbers, and ./-/_ characters.'
    )


class DefaultAbstractUser(DjangoAbstractUser):
    username = models.CharField(_('username'), max_length=30, unique=True,
                           help_text=_('Required. 30 characters or fewer. Letters, digits and /./-/_ only.'),
                           validators=[CustomUnicodeUsernameValidator],
                           error_messages={'unique': _("A user with that username already exists."),},
                           )
    if app_settings.UNIQUE_EMAIL:
        email = models.EmailField(_('email address'), unique=True)

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        abstract = True


def avatar_dir_path(instance, filename):
    # add suffix to avoid unnecessary cache on CDN
    return 'avatars/{pk}_{suffix}.jpeg'.format(pk=instance.pk, suffix=get_random_string(5))


class AvatarMixin(models.Model):
    avatar = models.ImageField(_("logo"), upload_to=avatar_dir_path, blank=True, max_length=300,)

    @property
    def avatar_url(self):
        if self.avatar:
            return self.avatar.url
        else:
            return None

    def save(self,  *args, **kwargs):
        if Image and self.avatar and getattr(self, '_avatar_file_updated', False):
            avatar = Image.open(self.avatar)
            if avatar.mode != 'RGB':
                # Scale below in other worker or Taskqueue(Celery), when needed
                jpeg_image = avatar.convert('RGB')
                image_io = BytesIO()
                jpeg_image.save(image_io, format='JPEG', quality=90)
                self.avatar = File(image_io, name='avatar.jpeg')
        return super().save(*args, **kwargs)

    class Meta:
        abstract = True


try:
    from phonenumber_field.modelfields import PhoneNumberField

    class PhoneNumberMixin(models.Model):
        phone_number = PhoneNumberField(unique=True)

        class Meta:
            abstract = True
except ImportError:
    class PhoneNumberMixin(object):
        pass

class AbstractSocialAccount(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='socialaccount_set', on_delete=models.CASCADE)
    provider = models.CharField(_("provider slug"),max_length=30,)
    uid = models.CharField(_("uid"), max_length=191)
    date_joined = models.DateTimeField(_("date joined"), auto_now_add=True)
    extra_data = models.JSONField(verbose_name=_("extra data"), default=dict)

    class Meta:
        unique_together = ("provider", "uid")
        verbose_name = _("social account")
        verbose_name_plural = _("social accounts")
        abstract = True

    def __str__(self):
        return "{user} - {provider}".format(user=self.user, provider=self.provider)
