import json

from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.db import transaction, IntegrityError
from django.utils.translation import gettext_lazy as _
from requests import HTTPError
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed, NotAcceptable

from ..models import get_socialaccount_model
from ..serializers.signup_serializers import SignUpSerializer
from ..settings import app_settings
from .providers.abstract_adapter import OauthAdapterError

User = get_user_model()
SocialAccount = get_socialaccount_model()


class SocialSignUpSerializer(SignUpSerializer):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from_auto_signup = self.context.get('auto_signup', False)
        if from_auto_signup:
            self.fields['password1'].required = False
            if 'password2' in self.fields:
                self.fields['password2'].required = False
        self.social_adapter = self.context.get('social_data', {})

    def populate_user(self):
        return self.social_adapter.user

    def save(self):
        with transaction.atomic():
            user = super().save()
            # TODO: reedit
            self.social_adapter.save(connect_user=user)
            return user


class SocialLoginSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=False, allow_blank=True)
    code = serializers.CharField(required=False, allow_blank=True)
    user_jwt = serializers.CharField(required=False, allow_blank=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        view = self.context.get('view')
        self.request = self.context.get('request')
        self.adapter_class = getattr(view, 'adapter_class')

    def complete_social_login(self, adapter):
        assert not adapter.is_existed
        adapter.get_current_social_acct()
        process = self.request.GET.get('process', 'login')
        if process == "connect":
            if self.request.user.is_anonymous:
                raise AuthenticationFailed
            if adapter.is_existed and adapter.user != self.request.user:
                    raise serializers.ValidationError(
                        {"non_field_error": {
                            'message': _('The social account is already connected to a different account.'),
                            'code': 'AOSL007',
                            }})
            else:
                adapter.save(connect_user=self.request.user)
            return adapter.social_acct
        else:
            if adapter.is_existed:
                pass  # TODO: call django_login() when required
            else:
                is_email_taken = User.objects.filter(email__iexact=adapter.user.email).exists()
                if not app_settings.SOCIAL_AUTO_SIGNUP:
                    # Since auto signup disabled, we dont have to preserve unique email,
                    # instead we return errors to frontend and waiting incoming request.
                    if adapter.user.email and is_email_taken:
                        raise serializers.ValidationError({'email':
                            {
                                'message': 'Social account email: %s already has an account with %s'
                                           % (adapter.user.email, get_current_site(self.request).name),
                                'code': 'AOSL001'
                            }
                        })
                    else:
                        serialized_sociallogin = adapter.serialize()
                        raise NotAcceptable(
                            {"non_field_error": {'message': _("Auto SignUp disabled."),
                                                 'code': 'AOSL002',
                                                 'social_login': json.dumps(serialized_sociallogin),
                                                 }}

                        )
                else:
                    # For Auto Signup, we have to assure at least email is granted and keep unique in db
                    if adapter.user.email and app_settings.UNIQUE_EMAIL:
                        if is_email_taken:
                            raise serializers.ValidationError(
                                {'description': 'Social account email: %s already has an account with %s'
                                                % (adapter.user.email, get_current_site(self.request).name),
                                 'email': adapter.user.email,
                                 'code': 'AOSL003'
                                 }
                            )
                        else:
                            social_signup_serializer = SocialSignUpSerializer(data=adapter.serialize()['user'],
                                                                              context={'social_data': adapter,
                                                                                       'auto_signup': True})
                            social_signup_serializer.is_valid(raise_exception=True)
                            social_signup_serializer.save()
                            # we perform a quick user creation
                            # social_acct = adapter.save()
                            # call django_login
                            # return social_acct
                    else:
                        serialized_socialdata = adapter.serialize()
                        raise serializers.ValidationError(
                            {'description': 'Please input email',
                             'social_login': json.dumps(serialized_socialdata),
                             'code': 'AOSL004'
                             }
                        )

    def validate(self, attrs):
        adapter = self.adapter_class()
        access_token = attrs.get('access_token', None)
        code = attrs.get('code', None)
        user_jwt = attrs.get('user_jwt', None)
        if access_token or user_jwt:
            pass
        # Case 2: We received the authorization code, though here is less likely called after google changed to JWT
        elif code:
            try:
                access_token = adapter.get_access_token(code)
            except OauthAdapterError as err:
                raise serializers.ValidationError(
                    {"code": {'message': err, 'code': 'AOSL001'}})
        else:
            raise serializers.ValidationError(
                {"non_field_error": {'message': _("Incorrect input. user_jwt or access_token or code is required."),
                                     'code': 'AOSL005'
                                     }})
        try:
            social_acct, user = adapter.populate_social_acct(access_token=access_token,user_jwt=user_jwt)

            self.complete_social_login(adapter)
        except HTTPError:
            raise serializers.ValidationError(
                {"non_field_error": {'message': _("Credentials failed with the provider."),
                                     'code': 'AOSL006'
                                     }})
        except IntegrityError as err:
            raise serializers.ValidationError('Duplicated Call %s' % err)
        # if not login.is_existing:
        #     login.lookup()
        #     login.save(request, connect=True)
        attrs['user'] = adapter.user
        return attrs


class SocialConnectionSerializer(serializers.Serializer):
    account = serializers.CharField(required=True)

    def __init__(self, *args, **kwargs):
        self.request = kwargs.get('context',{}).get('request')
        self.accounts = SocialAccount.objects.filter(user=self.request.user)
        super().__init__(*args, **kwargs)

    def validate_account(self, value):
        for sc in self.accounts:
            if sc.provider == value:
                return sc
        raise serializers.ValidationError("account name is not one of the available choices.", code='ASD001')

    def validate(self, attrs):
        account = attrs.get('account')
        accounts = self.accounts
        if account:
            if len(accounts) == 1:
                # No usable password happens on single auto signup account
                if not account.user.has_usable_password():
                    raise serializers.ValidationError({"non_field_error": {
                        'message': _("Your account has no password set up."), 'code': 'ASD002',}})
        return attrs

    def save(self):
        account = self.validated_data['account']
        account.delete()
