from random import randint

from django.urls import reverse

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.cache import cache
from django.utils.http import int_to_base36
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from ..exceptions import AuthFrameworkImproperlyConfigured
from .mixin_serializers import PasswordMixin, EmailMixin, PhoneNumMixin
from ..settings import app_settings
from ..utils import render_mail

User = get_user_model()


def send_email(email, **extra_kwargs) -> None:
    if extra_kwargs.get('template', None):
        if app_settings.USE_CELERY_EMAIL:
            try:
                from auth_framework.tasks import send_email_task
                send_email_task.apply_async([email,], kwargs=extra_kwargs)
                return
            except ImportError:
                pass
        template = extra_kwargs.pop('template', None)
        subject = extra_kwargs.pop('subject', 'No Title')
        msg = render_mail(subject, email, extra_kwargs, template)
        msg.send()


class PasswordChangeSerializer(PasswordMixin, serializers.Serializer):
    old_password = serializers.CharField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = getattr(self.context.get('request'), 'user', None)

    def validate_old_password(self, old_password):
        invalid_password_conditions = (
            self.user,
            not self.user.check_password(old_password)
        )

        if all(invalid_password_conditions):
            raise serializers.ValidationError({"message": _('Invalid password'), "code": "AP003"})
        return old_password

    def save(self):
        password = self.validated_data.get('password')
        self.user.set_password(password)
        self.user.save()


class CreateResetPinSerializer(PhoneNumMixin, EmailMixin, serializers.Serializer):
    def __init__(self, *args, **kwargs):
        kwargs.update({'check_existed': True})
        super().__init__(*args, **kwargs)
        if app_settings.USE_PHONENUMBER_FIELD:
            del self.fields['email']
            self.fields['phone_number'].required = True
            self.id_field = 'phone_number'
        else:
            if not app_settings.UNIQUE_EMAIL:
                raise AuthFrameworkImproperlyConfigured('Failed To determine the identity')
            del self.fields['phone_number']
            self.fields['email'].required = True
            self.id_field = 'email'

    def get_email_templ_kwargs(self, pin: int, email_to: str) -> dict:
        current_site = get_current_site(self.context['request'])
        return {
            'current_site': {'name': current_site.name, 'domain': current_site.domain},
            'template': 'auth/email_pin.txt',
            'subject': 'Set Up Your New Password',
            'pin': pin,
            # ...other_kwargs but 'email'
        }

    def send_reset_pin_email(self, pin, email):
        extra_kwargs = self.get_email_templ_kwargs(pin, email)
        send_email(email, **extra_kwargs)

    def save(self, **kwargs):
        pin = randint(10 ** 5, 10 ** 6 - 1)
        if self.id_field == 'phone_number':
            try:
                import os
                from twilio.base.exceptions import TwilioException, TwilioRestException
                from twilio.rest import Client
                account_sid = os.environ.get('TWILIO_CLIENT_ID')
                auth_token = os.environ.get('TWILIO_CLIENT_SECRET')
                from_number = os.environ.get('TWILIO_FROM_NUMBER')
                client = None
                if account_sid and auth_token:
                    client = Client(account_sid, auth_token)

                message = client.messages.create(
                    body="Your %s verification code is %s" % (get_current_site(self.context['request']), pin),
                    from_=from_number,
                    to=str(self.validated_data['phone_number'])
                )
                cache.set('pin_verify:%s' % self.validated_data['phone_number'], pin, 60 * 10)
            except ImportError as err:
                raise AuthFrameworkImproperlyConfigured('Missing Twilio package for sending sms for pin: %s' % err)
            except AttributeError as err:
                raise AuthFrameworkImproperlyConfigured('Missing Twilio Env Variables for sending sms for pin: %s' % err)
            except TwilioRestException:
                raise serializers.ValidationError(
                   _("%s, is not a correct mobile number." % str(self.validated_data['phone_number'])), code='AP004')
        else:  # we choose classic email to send ping
            self.send_reset_pin_email(pin, self.validated_data['email'])
            cache.set('pin_verify:%s' % self.validated_data['email'], pin, 60 * 10)


class ResetPasswordByPinSerializer(PhoneNumMixin, EmailMixin, PasswordMixin, serializers.Serializer):
    email = serializers.EmailField(required=False)
    pin = serializers.IntegerField(max_value=999999)

    def __init__(self, **kwargs):
        kwargs.update({'check_existed': True})
        self.user_found = None
        super().__init__(**kwargs)
        if app_settings.USE_PHONENUMBER_FIELD:
            del self.fields['email']
            self.fields['phone_number'].required = True
            self.id_field = 'phone_number'
        else:
            if not app_settings.UNIQUE_EMAIL:
                raise ProcessLookupError('Failed To determine the identity')
            del self.fields['phone_number']
            self.fields['email'].required = True
            self.id_field = 'email'
        self.user = None

    def validate(self, attrs):
        attrs = super().validate(attrs)
        pin = attrs.get("pin")
        lookup_field = attrs.get(self.id_field)
        if cache.get('pin_verify:%s' % lookup_field) == pin:
            cache.delete('pin_verify:%s' % lookup_field)
        else:
            raise serializers.ValidationError({'pin': {'message': _('pins do not match, please try to get new pin.'),
                                                       'code': 'AP05'}})

        return attrs

    def save(self):
        password = self.validated_data.get('password')
        self.user_found.set_password(password)
        self.user_found.save()


class CreateResetLinkSerializer(EmailMixin, serializers.Serializer):
    """
    Serializer for requesting a password reset e-mail.
    """
    def __init__(self, **kwargs):
        kwargs.update({'check_existed': True})
        self.user_found = None
        super().__init__(**kwargs)

    def get_email_templ_kwargs(self, uidb36: str, token: str, email_to: str, user: User) -> dict:
        request = self.context.get('request')
        current_site = get_current_site(request)
        path = reverse("link-reset-password", kwargs={'uidb36': uidb36, 'token': token})
        url = '{proto}://{domain}{url}'.format(
            proto=request.scheme,
            domain=current_site.domain,
            url=path)

        return {
            'current_site': {'name': current_site.name, 'domain': current_site.domain},
            "password_reset_url": url,
            'template': 'auth/email_reset_link.txt',
            'subject': 'Set Up Your New Password',
            'user': {
                'username': user.username,
                'full_name': user.get_full_name()
            },
            # ...other_kwargs
        }

    def save(self):
        user = self.user_found
        token = default_token_generator.make_token(user)
        uidb36 = int_to_base36(user.pk)
        email = self.validated_data["email"]
        extra_kwargs = self.get_email_templ_kwargs(uidb36, token, email, user)
        send_email(email, **extra_kwargs)
        return email


class ResetPasswordByLinkSerializer(PasswordMixin, serializers.Serializer):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = self.context.get('user')

    def save(self):
        password = self.validated_data.get('password')
        self.user.set_password(password)
        self.user.save()

