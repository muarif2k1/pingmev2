from django.utils import timezone
from django.contrib.auth import get_user_model

User = get_user_model()

class UpdateLastActivityMiddleware:
    """Update user's last activity timestamp"""
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            # Update last activity
            request.user.profile.last_activity = timezone.now()
            request.user.profile.save(update_fields=['last_activity'])

        response = self.get_response(request)
        return response
