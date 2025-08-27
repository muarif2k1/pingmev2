from .models import Friendship

def notifications(request):
    """Add notification counts to context"""
    if request.user.is_authenticated:
        pending_requests = Friendship.objects.filter(
            to_user=request.user.profile,
            status='pending'
        ).count()
        
        return {
            'pending_friend_requests': pending_requests,
        }
    return {}