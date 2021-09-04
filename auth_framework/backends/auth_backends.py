from django.contrib.auth.backends import ModelBackend as DjangoModelBackend
from django.contrib.auth import get_user_model
try:
    from phonenumber_field.phonenumber import to_python
except ImportError:
    def to_python(data):
        return str(data)

User = get_user_model()


class AuthenticationBackend(DjangoModelBackend):

    def authenticate(self, request, password=None, **kwargs):
        username = kwargs.get("username")
        email = kwargs.get("email")
        phone_number = to_python(kwargs['phone_number']) if kwargs.get("phone_number") else None

        try:
            if phone_number and phone_number.is_valid():
                user = User.objects.get(phone_number=phone_number)
            elif email:
                user = User.objects.get(email__iexact=email)
            elif username:
                user = User.objects.get(username=username)
            else:
                return None
        except User.DoesNotExist:
            User().set_password(password)
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user
