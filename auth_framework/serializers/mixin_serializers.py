from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.cache import cache
from django.core.exceptions import ValidationError
from rest_framework import serializers
from django.utils.translation import gettext_lazy as _

try:
    from phonenumber_field.serializerfields import PhoneNumberField
except ImportError:
    class PhoneNumberField(serializers.CharField):
        pass
from ..settings import app_settings

User = get_user_model()


class EmailMixin(serializers.Serializer):
    email = serializers.EmailField()

    def __init__(self, *args, **kwargs):
        self.check_existed = getattr(self,'check_existed', None) or kwargs.pop('check_existed', False)
        super().__init__(*args, **kwargs)

    def validate_email(self, email):
        request_user = getattr(self.context.get('request', None), 'user', None)
        lookup_query = User.objects
        if request_user:
            lookup_query = lookup_query.exclude(pk=request_user.pk)
        try:
            existed_user = lookup_query.get(email__iexact=email)
        except User.DoesNotExist:
            existed_user = None
        if self.check_existed:
            if existed_user:
                if hasattr(self, 'user_found'):
                    self.user_found = existed_user
                return email
            else:
                raise serializers.ValidationError(
                    _("The e-mail address is not assigned to any user account"),
                    code='AE001'
                )
        else:
            if app_settings.UNIQUE_EMAIL and existed_user:
                raise serializers.ValidationError(
                    _("A user is already registered with this e-mail address."),
                    code='AE002'
                )
            return email


class PasswordMixin(serializers.Serializer):
    password1 = serializers.CharField()
    password2 = serializers.CharField()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not app_settings.USE_PASSWORD_TWICE_VALIDATION:
            del self.fields["password2"]

    def validate_password1(self, password1):
        try:
            validate_password(password1, user=getattr(self,'user', None))
        except ValidationError as error:
            message = getattr(error, 'message', error.messages[0])
            raise serializers.ValidationError(message, code='AP001')
        return password1

    def validate(self, attrs):
        password = attrs.pop("password1", None)
        if (
                app_settings.USE_PASSWORD_TWICE_VALIDATION
                and "password2" in attrs
        ):
            if password != attrs.pop("password2", None):
                raise serializers.ValidationError({'password2': {
                    'message': _("You must type the same password each time."), 'code': 'AP002'}})

        attrs['password'] = password
        return attrs


class PhoneNumMixin(serializers.Serializer):
    phone_number = PhoneNumberField()

    def __init__(self, *args, **kwargs):
        self.check_existed = getattr(self, 'check_existed', None) or kwargs.pop('check_existed', False)
        super().__init__(*args, **kwargs)

    def validate_phone_number(self, val):
        request_user = getattr(self.context.get('request', None), 'user', None)
        lookup_query = User.objects
        if request_user:
            lookup_query = lookup_query.exclude(pk=request_user.pk)
        try:
            existed_user = lookup_query.get(phone_number=val)
        except User.DoesNotExist:
            existed_user = None
        if self.check_existed:
            if existed_user:
                if hasattr(self, 'user_found'):
                    self.user_found = existed_user
                return val
            else:
                raise serializers.ValidationError(
                    _("The phone number is not assigned to any user account"),
                    code='AP001'
                )
        else:
            if existed_user:
                raise serializers.ValidationError(_("This phone number was already taken, please just login."),
                                                  code='AP002')
            else:
                return val


class PhoneNumPinMixin(PhoneNumMixin):
    pin = serializers.IntegerField(max_value=999999)

    def validate(self, attrs):
        pin = attrs.get("pin")
        phone_number = attrs.get("phone_number")
        if phone_number and cache.get('pin_verify:%s' % phone_number) == pin:
            cache.delete(phone_number)
        elif phone_number:
            raise serializers.ValidationError({'pin': {
                'message': _("Invalid or expired PIN number."), 'code': 'AP003'}})
        super().validate(attrs)
        return attrs
