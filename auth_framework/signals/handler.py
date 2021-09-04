__author__ = 'Carrycat'

from django.contrib.auth import get_user_model
from django.db.models.signals import pre_save, pre_delete
from django.dispatch import receiver

User = get_user_model()


@receiver(pre_delete, sender=User)
def auto_delete_avatar_on_delete(sender, instance, **kwargs):
    # Pass false so FileField doesn't save the model.
    # delete file but dont save db it will be saved later.
    if hasattr(instance, 'avatar'):
        instance.avatar.delete(False)


@receiver(pre_save, sender=User)
def auto_delete_avatar_on_change(sender, instance, update_fields, **kwargs):
    if not hasattr(instance, 'avatar'):
        return False
    if not instance.pk:
        return False

    try:
        current_instance = sender.objects.get(pk=instance.pk)
        old_image = current_instance.avatar
    except sender.DoesNotExist:
        return False
    # if not instance.image:
    #     old_image.delete(save=False)
    if (instance.avatar and not instance.avatar._committed) or not instance.avatar:
        old_image.delete(save=False)
