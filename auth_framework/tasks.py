from .utils import render_mail
from celery import shared_task
from celery.utils.log import get_task_logger
logger = get_task_logger(name=__name__)


@shared_task
def send_email_task(email, template=None, subject='No title', **kwargs):
    if template:
        logger.info("Starting Send Email ", kwargs, template)
        msg = render_mail(subject, email, kwargs, template)
        msg.send()
