from django import template
from django.contrib.auth.models import User
from django.db.models import Q
from ..models import Friendship

register = template.Library()

@register.filter
def get_friendship_status(user_id, current_user_id):
    """Get friendship status between two users"""
    try:
        user = User.objects.get(id=user_id)
        current_user = User.objects.get(id=current_user_id)
        
        # Check if friendship exists
        friendship = Friendship.objects.filter(
            Q(from_user=current_user.profile, to_user=user.profile) |
            Q(from_user=user.profile, to_user=current_user.profile)
        ).first()
        
        if not friendship:
            return None
        
        if friendship.status == 'accepted':
            return 'accepted'
        elif friendship.from_user == current_user.profile:
            return 'pending_sent'
        else:
            return 'pending_received'
            
    except User.DoesNotExist:
        return None
