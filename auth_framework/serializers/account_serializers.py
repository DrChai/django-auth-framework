__author__ = 'Carrycat'

from django.contrib.auth import authenticate, get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from ..models import settings_default_value
from .mixin_serializers import PhoneNumPinMixin, EmailMixin, PhoneNumberField

User = get_user_model()


class UpdatePhoneSerializer(PhoneNumPinMixin, serializers.Serializer):
    pin = serializers.IntegerField(max_value=999999)

    def __init__(self, *args, **kwargs):
        kwargs.update({'check_existed': False})
        request = self.context.get('request')
        self.user = getattr(request, 'user', None)
        super().__init__(**kwargs)

    def save(self):
        self.user.phone_number = self.validated_data.get("phone_number")
        self.user.save()
        return self.user


class SessionLoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=False)
    email = serializers.CharField(required=False)
    phone_number = PhoneNumberField(required=False)
    password = serializers.CharField()

    def validate(self, attrs):
        request = self.context.get('request')
        user = authenticate(request=request, **attrs)
        if not user:
            raise AuthenticationFailed('Unable to log in with provided credentials.')
        return user


class DefaultUserinfoSerializer(EmailMixin, serializers.ModelSerializer):
    # avatar = serializers.URLField(source='avatar_url', read_only=True)  # api_avatar_url
    phone_number = PhoneNumberField(read_only=True)

    class Meta:
        model = User
        fields = User.get_fields()

    def validate_username(self, value):
        user = self.context['request'].user
        if not User.objects.exclude(pk=user.pk).filter(**{'username': value}).exists():
            return value
        raise serializers.ValidationError(_("A user is already registered with this username."), code='AA001')

    def update(self, instance, validated_data):
        if 'avatar' in validated_data:
            # mark avatar as a update_field, since the kwarg 'update_fields'
            # cannot be passed to instance.save() from DRF.
            instance._avatar_file_updated = True
        return super().update(instance, validated_data)