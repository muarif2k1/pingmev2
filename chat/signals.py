from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import UserProfile, PrivateChat, ChatParticipant

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Create UserProfile when User is created"""
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Save UserProfile when User is saved"""
    if hasattr(instance, 'profile'):
        instance.profile.save()

@receiver(post_save, sender=PrivateChat)
def create_chat_participants(sender, instance, created, **kwargs):
    """Create ChatParticipant entries when PrivateChat is created"""
    if created:
        ChatParticipant.objects.get_or_create(
            private_chat=instance,
            user=instance.user1
        )
        ChatParticipant.objects.get_or_create(
            private_chat=instance,
            user=instance.user2
        )
