__author__ = 'Carrycat'
import re
import uuid
import unicodedata

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from .mixin_serializers import PasswordMixin, EmailMixin, PhoneNumPinMixin
from ..settings import app_settings

User = get_user_model()


class AbstractSignUpSerializer(PasswordMixin, EmailMixin, serializers.Serializer):
    username = serializers.CharField()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.error_messages.update({
            "username_taken": User._meta.get_field("username").error_messages[
                "unique"
            ],
            "email_taken": _("A user is already registered with this e-mail address."),
        })
        if not app_settings.UNIQUE_EMAIL:
            self.fields["email"].required = False
        if not app_settings.SIGNUP_USERNAME_REQUIRED:
            self.fields["username"].required = False

    def validate_username(self, username):
        try:
            for validator in app_settings.username_validators:
                validator(username)
        except ValidationError as e:
            raise serializers.ValidationError(
                e.message,
                code='ASU011'
            )
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError(
                self.error_messages['username_taken'],
                code='ASU001'
            )
        return username

    def validate(self, attrs):
        attrs = super().validate(attrs)
        return attrs


class DefaultSignUpSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('first_name', 'last_name',)


def base_serializers():
    custom_serializer = app_settings.SERIALIZERS['SIGNUP_SERIALIZER']
    base = [custom_serializer, AbstractSignUpSerializer]
    if app_settings.USE_PHONENUMBER_FIELD:
        base.insert(0, PhoneNumPinMixin)
    return tuple(base)


def base_fields():
    base_fields = ('email', 'password1', 'password2', 'username',)
    if app_settings.USE_PHONENUMBER_FIELD:
        base_fields += ('phone_number', 'pin')
    return base_fields


class SignUpSerializer(*base_serializers()):

    def populate_user(self):
        user = User()
        return user

    def save(self):
        user = self.populate_user()
        password = self.validated_data.pop("password", None)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        for attr, value in self.validated_data.items():
            setattr(user, attr, value)

        self.populate_username(user)
        user.save()
        return user

    def populate_username(self, user):
        """
        Fills in a valid username, if required and missing.  If the
        username is already present it is assumed to be valid
        (unique).
        """
        first_name = user.first_name
        last_name = user.last_name
        email = user.email
        user.username = user.username or self.generate_unique_username([email, last_name, first_name])

    def generate_unique_username(self, txts):
        regex = r'[^\w\s@+.-]'
        username = None
        txts = list(filter(None, txts))
        for txt in txts:
            if not txt:
                continue
            txt = unicodedata.normalize('NFKD', force_str(txt))
            txt = txt.encode('ascii', 'ignore').decode('ascii')
            txt = force_str(re.sub(regex, '', txt).lower())
            txt = txt.split('@')[0]
            txt = txt.strip()
            txt = re.sub(r'\s+', '_', txt)
            try:
                username = self.validate_username(txt)
                break
            except serializers.ValidationError:
                pass
        if not username:
            username = ''.join(txts)
            if username == '':
                username = 'user'
                username += str(uuid.uuid4())[:4]
        return username

    class Meta:
        model = User
        fields = base_fields() + tuple(app_settings.SERIALIZERS['SIGNUP_SERIALIZER']().fields.keys())

