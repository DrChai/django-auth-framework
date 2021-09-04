from django.conf import settings
from django.utils import timezone
from oauth2_provider.models import Application, AccessToken, RefreshToken
from oauth2_provider.settings import oauth2_settings
from oauthlib.common import generate_token


DEFAULT_SCOPES = getattr(settings, 'OAUTH_DEFAULT_SCOPES', None)
DEFAULT_USER_SCOPES = getattr(settings, 'OAUTH_DEFAULT_USER_SCOPES', None)


# Used for Social Login and Sign Up, never validate the user, the expires date.
def get_access_token(user, request=None):
    """
    Takes a user instance and return an access_token as a JsonResponse
    instance.
    """
    validator_class = oauth2_settings.OAUTH2_VALIDATOR_CLASS
    # our oauth2 app
    validator = validator_class()


    # We delete the old access_token and refresh_token  # TODO: we just ignore old access token
    # try:
    #     old_access_token = AccessToken.objects.get(
    #         user=user, application=app)
    #     old_refresh_token = RefreshToken.objects.get(
    #         user=user, access_token=old_access_token
    #     )
    # except:
    #     pass
    # else:
    #     old_access_token.delete()
    #     old_refresh_token.delete()

    token = {
        'access_token': generate_token(),
        'refresh_token': generate_token(),
        'scope': ' '.join(oauth2_settings.SCOPES),
        'expires_in':  oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS
    }
    request.user = user
    request.grant_type = request.client.authorization_grant_type
    validator.save_token(token, request, nonce='server-gen')
    # we create the access token
    return token


# def import_callable(path_or_callable):
#     if hasattr(path_or_callable, '__call__'):
#         return path_or_callable
#     else:
#         assert isinstance(path_or_callable, str)
#         package, attr = path_or_callable.rsplit('.', 1)
#         return getattr(import_module(package), attr)


# def complete_social_login(request, sociallogin):
#     assert not sociallogin.is_existing
#     sociallogin.lookup()
#     try:
#         social_get_adapter().pre_social_login(request, sociallogin)
#         social_account_signals.pre_social_login.send(sender=SocialLogin,
#                                       request=request,
#                                       sociallogin=sociallogin)
#     except ImmediateHttpResponse as e:
#         return e.response
#     process = sociallogin.state.get('process')
#     if process == AuthProcess.REDIRECT:
#         return _social_login_redirect(request, sociallogin)
#     elif process == AuthProcess.CONNECT:
#         return _add_social_account(request, sociallogin)
#     else:
#         return _complete_social_login(request, sociallogin)
#
#
# def _process_signup(request, sociallogin):
#
#     if not social_app_settings.AUTO_SIGNUP:
#         if sociallogin.user.email and email_address_exists(sociallogin.user.email):
#             raise serializers.ValidationError({'email':
#                                                    {
#                                                        'message': 'Social account email: %s already has an account with %s'
#                                                                   % (sociallogin.user.email, get_current_site(request))}})
#         else:
#             serialized_sociallogin = sociallogin.serialize()
#             raise serializers.ValidationError(
#                 {'message': 'Auto SignUp disabled',
#                  'social_login': json.dumps(serialized_sociallogin)
#                  }
#             )
#     else:
#         auto_signup = social_get_adapter().is_auto_signup_allowed(request,
#                                                            sociallogin)
#         if not auto_signup:
#             if sociallogin.user.email:
#                 raise serializers.ValidationError(
#                     {'description': 'Social account email: %s already has an account with %s'
#                                     % (sociallogin.user.email, get_current_site(request)),
#                      'email': sociallogin.user.email
#                      }
#                 )
#             else:  # we should reject this request since no email input
#                 serialized_sociallogin = sociallogin.serialize()
#                 raise serializers.ValidationError(
#                     {'description': 'Please input email',
#                      'social_login': json.dumps(serialized_sociallogin)
#                      }
#                 )
#         else:
#             # Ok, auto signup it is, at least the e-mail address is ok.
#             # We still need to check the username though...
#             if account_settings.USER_MODEL_USERNAME_FIELD:
#                 username = user_username(sociallogin.user)
#                 try:
#                     get_adapter().clean_username(username)
#                 except ValidationError:
#                     # This username is no good ...
#                     user_username(sociallogin.user, '')
#             # FIXME: This part contains a lot of duplication of logic
#             # ("closed" rendering, create user, send email, in active
#             # etc..)
#             try:
#                 if not social_get_adapter().is_open_for_signup(request,
#                                                         sociallogin):
#                     # return render(request,
#                     #               "account/signup_closed.html")
#                     pass
#                     # FIXME: Shouldn't go here
#             except ImmediateHttpResponse as e:
#                 return e.response
#             social_get_adapter().save_user(request, sociallogin, form=None)
#             ret = complete_signup(request, sociallogin.user,
#                                   'none',
#                                   sociallogin.get_redirect_url(request),
#                                   signal_kwargs={'sociallogin': sociallogin})
#         return ret
#
#
# def _complete_social_login(request, sociallogin):
#     # if request.user.is_authenticated():
#         # get_account_adapter().logout(request)
#         # FIXME: Shouldn't go here. Request from facebook may be user = None !!!
#         # Since General Acrossor user is None.
#         # pass
#     if sociallogin.is_existing:
#         # Login existing user
#         ret = perform_login(request, sociallogin.user, email_verification=social_app_settings.EMAIL_VERIFICATION,
#                             redirect_url=sociallogin.get_redirect_url(request),
#                             signal_kwargs={"sociallogin": sociallogin})
#     else:
#         # New social user
#         ret = _process_signup(request, sociallogin)
#     return ret
#
#
# def _add_social_account(request, sociallogin):
#     if request.user.is_anonymous():
#         # This should not happen. Simply redirect to the connections
#         # view (which has a login required)
#         # return HttpResponseRedirect(reverse('socialaccount_connections'))
#         raise AuthenticationFailed
#     if sociallogin.is_existing:
#         if sociallogin.user != request.user:
#             # Social account of other user. For now, this scenario
#             # is not supported. Issue is that one cannot simply
#             # remove the social account from the other user, as
#             # that may render the account unusable.
#             raise serializers.ValidationError(
#                 {'description': 'The social account is already connected to a different account.'
#                  })
#         else:
#             # This account is already connected -- let's play along
#             # and render the standard "account connected" message
#             # without actually doing anything.
#             pass
#     else:
#         # New account, let's connect
#         sociallogin.connect(request, request.user)
#         try:
#             social_account_signals.social_account_added.send(sender=SocialLogin,
#                                               request=request,
#                                               sociallogin=sociallogin)
#         except ImmediateHttpResponse as e:
#             return e.response
#     # default_next = social_get_adapter() \
#     #     .get_connect_redirect_url(request,
#     #                               sociallogin.account)
#     # next_url = sociallogin.get_redirect_url(request) or default_next
#     # return HttpResponseRedirect(next_url)
#
#
# def perform_login(request, user, email_verification,
#                   redirect_url=None, signal_kwargs=None,
#                   signup=False):
#     """
#     Keyword arguments:
#
#     signup -- Indicates whether or not sending the
#     email is essential (during signup), or if it can be skipped (e.g. in
#     case email verification is optional and we are only logging in).
#     """
#     # Local users are stopped due to form validation checking
#     # is_active, yet, adapter methods could toy with is_active in a
#     # `user_signed_up` signal. Furthermore, social users should be
#     # stopped anyway.
#     if not user.is_active:
#         raise serializers.ValidationError({'description': 'User account is disabled.'})
#
#     from allauth.account.models import EmailAddress
#     has_verified_email = EmailAddress.objects.filter(user=user,
#                                                      verified=True).exists()
#     if email_verification == account_settings.EmailVerificationMethod.NONE:
#         pass
#     elif email_verification == account_settings.EmailVerificationMethod.OPTIONAL:
#         # In case of OPTIONAL verification: send on signup.
#         if not has_verified_email and signup:
#             send_email_confirmation(request, user, signup=signup)
#     elif email_verification == account_settings.EmailVerificationMethod.MANDATORY:
#         if not has_verified_email:
#             send_email_confirmation(request, user, signup=signup)
#             return HttpResponseRedirect(
#                 reverse('account_email_verification_sent'))
#     try:
#         get_adapter().login(request, user)
#         response = HttpResponseRedirect('/')
#         if signal_kwargs is None:
#             signal_kwargs = {}
#         signals.user_logged_in.send(sender=user.__class__,
#                                     request=request,
#                                     response=response,
#                                     user=user,
#                                     **signal_kwargs)
#         get_adapter().add_message(request,
#                                   messages.SUCCESS,
#                                   'account/messages/logged_in.txt',
#                                   {'user': user})
#     except ImmediateHttpResponse as e:
#         response = e.response
#     return response
#
#
# def complete_signup(request, user, email_verification, success_url,
#                     signal_kwargs=None):
#     if signal_kwargs is None:
#         signal_kwargs = {}
#     signals.user_signed_up.send(sender=user.__class__,
#                                 request=request,
#                                 user=user,
#                                 **signal_kwargs)
#     return perform_login(request, user,
#                          email_verification=email_verification,
#                          signup=True,
#                          redirect_url=success_url,
#                          signal_kwargs=signal_kwargs)
#
#
#
#
# def custom_exception_handler(exc, context):
#     """
#     Returns the response that should be used for any given exception.
#
#     By default we handle the REST framework `APIException`, and also
#     Django's built-in `Http404` and `PermissionDenied` exceptions.
#
#     Any unhandled exceptions may return `None`, which will cause a 500 error
#     to be raised.
#     """
#     if isinstance(exc, exceptions.APIException):
#         headers = {}
#         if getattr(exc, 'auth_header', None):
#             headers['WWW-Authenticate'] = exc.auth_header
#         if getattr(exc, 'wait', None):
#             headers['Retry-After'] = '%d' % exc.wait
#
#         if isinstance(exc.detail, (list, dict)):
#             data = exc.detail
#             # for key, value in exc.detail.items():
#             #     data[key] = value[0]
#         else:
#             data = {'detail': exc.detail}
#
#         set_rollback()
#         return Response(data, status=exc.status_code, headers=headers)
#
#     elif isinstance(exc, Http404):
#         msg = _('Not found.')
#         data = {'detail': str(msg)}
#
#         set_rollback()
#         return Response(data, status=status.HTTP_404_NOT_FOUND)
#
#     elif isinstance(exc, PermissionDenied):
#         msg = _('Permission denied.')
#         data = {'detail': str(msg)}
#
#         set_rollback()
#         return Response(data, status=status.HTTP_403_FORBIDDEN)
#
#     # Note: Unhandled exceptions will raise a 500 error.
#     return None
