from django.urls import re_path, include

from .oauth.views import CreateUserWToken
from .settings import app_settings
from .views import password_views, account_views, session_views

urlpatterns = [
    re_path('login/', session_views.SessionLogin.as_view(), name="account_login"),
    re_path('logout/', session_views.SessionLogout.as_view(), name="account_logout"),
    re_path('password/change/', password_views.ChangePassword.as_view(), name='change-password'),
    re_path('password/reset/pin/$', password_views.ResetPasswordByPin.as_view(), name='pin-reset-password'),
    re_path(r'^password/(?P<method>link|pin)/$', password_views.CreateResetEntryPoint.as_view(),
            name='reset-password-entrypoint'),
    re_path(r"^password/reset/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$",
            password_views.ResetPasswordByLink.as_view(),
            name="link-reset-password"),
    re_path('registration/', CreateUserWToken.as_view(), name="create-user"),
    re_path('email-verify/', account_views.EmailCheck.as_view()),
    re_path(r'^(?P<pk>\d+|self)/$', account_views.UserDetails.as_view(), name="userinfo"),
    re_path('oauth/', include('auth_framework.oauth.urls')),
    re_path('social/', include('auth_framework.social.urls'))
]
if app_settings.USE_PHONENUMBER_FIELD:
    urlpatterns += [
        re_path('phone/', account_views.PhoneChangeView.as_view(), name="edit_phone"),
    ]
