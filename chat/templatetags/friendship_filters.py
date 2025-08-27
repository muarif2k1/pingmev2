from django.db import models
from django import template
from django.contrib.auth.models import User
from chat.models import Friendship, UserProfile

register = template.Library()

@register.filter
def get_friendship_status(target_user_id, current_user_id):
    """
    Returns the friendship status between two users
    Possible return values: 'accepted', 'pending_sent', 'pending_received', 'none'
    """
    try:
        current_user = User.objects.get(id=current_user_id)
        target_user = User.objects.get(id=target_user_id)
        
        # Get the UserProfile objects
        current_profile = current_user.profile
        target_profile = target_user.profile
        
        # Check if friendship exists in either direction
        friendship = Friendship.objects.filter(
            (models.Q(from_user=current_profile, to_user=target_profile) |
             models.Q(from_user=target_profile, to_user=current_profile))
        ).first()
        
        if friendship:
            if friendship.status == 'accepted':
                return 'accepted'
            elif friendship.from_user == current_profile:
                return 'pending_sent'
            else:
                return 'pending_received'
        return 'none'
        
    except (User.DoesNotExist, UserProfile.DoesNotExist, Friendship.DoesNotExist):
        return 'none'