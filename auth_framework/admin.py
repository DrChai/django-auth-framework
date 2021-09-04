from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth.forms import UserChangeForm
from django.forms import CharField

from .models import get_socialaccount_model, User
from .settings import app_settings, import_callable

# Register your models here.
default_fields = ['username', 'email', 'first_name', 'last_name']
default_list_play = ['id',  'email', 'first_name', 'last_name']
default_search_fieldsets = ['email']
default_add_fieldsets = ['username', 'email', 'password1', 'password2']

SocialAccount = get_socialaccount_model()

if app_settings.USE_PHONENUMBER_FIELD:
    from phonenumber_field.formfields import PhoneNumberField
    default_fields.append('phone_number')
    default_list_play.append('phone_number')
    default_search_fieldsets.append('phone_number')
    default_add_fieldsets.insert(0,'phone_number')
else:
    class PhoneNumberField(CharField):
        pass


class UserChangeForm(UserChangeForm):
    phone_number = PhoneNumberField()

    class Meta:
        model = get_user_model()
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        if not app_settings.USE_PHONENUMBER_FIELD:
            self.declared_fields.pop('phone_number')
            self.base_fields.pop('phone_number')
        super().__init__(*args, **kwargs)


class UserAdmin(DjangoUserAdmin):
    list_display = tuple(default_list_play)
    fieldsets = (
        ('Personal info', {'fields': default_fields}),
        ('Extras', {'fields': ('id', 'password')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser'), 'classes': ['collapse']}),
    )
    search_fieldsets = tuple(default_search_fieldsets)
    add_fieldsets = (
        (None, {'fields': tuple(default_add_fieldsets)}),
        ('Personal info', {'fields': ('first_name', 'last_name',)}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser'), 'classes': ['collapse']}),
    )
    form = UserChangeForm
    readonly_fields = ('id', 'last_login', 'date_joined')


class SocialAccountAdmin(admin.ModelAdmin):
    search_fields = []
    raw_id_fields = ("user",)
    list_display = ("user", "uid", "provider")
    list_filter = ("provider",)


admin.site.register(User, UserAdmin)
admin.site.register(SocialAccount, import_callable(app_settings.SOCIALACCOUNT_ADMIN_CLASS))
