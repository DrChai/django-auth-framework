from django.conf import settings
from django.core.mail import EmailMessage
from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string


def render_mail(subject: str, email: str, context: dict[str:str], template: str, **kwargs):
    """
    Renders an e-mail to `email`.  `template_prefix` identifies the
    e-mail that is to be sent, e.g. "account/email/email_confirmation"
    """
    try:
        bodies = render_to_string(template, context).strip()
    except TemplateDoesNotExist:
        raise
    msg = EmailMessage(subject, bodies,
                       kwargs.get('from_email', settings.DEFAULT_FROM_EMAIL),
                       [email])
    msg.content_subtype = 'html'  # Main content is now text/html
    return msg
