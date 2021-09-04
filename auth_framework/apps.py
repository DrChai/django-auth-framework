from django.apps import AppConfig


class AuthFrameworkConfig(AppConfig):
    name = "auth_framework"
    verbose_name = "Django Auth Framework"

    def ready(self):
        import auth_framework.signals.handler