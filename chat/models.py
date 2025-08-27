from django.db import models
from django.contrib.auth.models import User
import uuid
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db.models import Q

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    date_of_birth = models.DateField(null=True, blank=True)
    profile_photo = models.ImageField(
        upload_to='profile_photos/',
        null=True,
        blank=True,
        default=None,
        help_text="Upload your profile photo"
    )
    bio = models.TextField(blank=True)
    location = models.CharField(max_length=100, blank=True)
    last_activity = models.DateTimeField(auto_now=True)
    online = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Friends many-to-many relationship through Friendship model
    friends = models.ManyToManyField(
        'self',
        through='Friendship',
        through_fields=('from_user', 'to_user'),
        symmetrical=False
    )

    def get_friends(self):
        """Get all accepted friends"""
        return UserProfile.objects.filter(
            Q(friend_requests_sent__to_user=self, friend_requests_sent__status='accepted') |
            Q(friend_requests_received__from_user=self, friend_requests_received__status='accepted')
        ).distinct()

    def are_friends(self, other_user):
        """Check if two users are friends"""
        return Friendship.objects.filter(
            Q(from_user=self, to_user=other_user, status='accepted') |
            Q(from_user=other_user, to_user=self, status='accepted')
        ).exists()

    def __str__(self):
        return f"{self.user.username}'s Profile"

    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"

class Friendship(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
        ('blocked', 'Blocked'),
    ]
    
    from_user = models.ForeignKey(
        UserProfile, 
        on_delete=models.CASCADE, 
        related_name='friend_requests_sent'
    )
    to_user = models.ForeignKey(
        UserProfile, 
        on_delete=models.CASCADE, 
        related_name='friend_requests_received'
    )
    status = models.CharField(
        max_length=10, 
        choices=STATUS_CHOICES, 
        default='pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('from_user', 'to_user')
        verbose_name = "Friendship"
        verbose_name_plural = "Friendships"
        ordering = ['-updated_at']
    
    def __str__(self):
        return f"{self.from_user.user.username} → {self.to_user.user.username} ({self.status})"
    
    def clean(self):
        if self.from_user == self.to_user:
            raise ValidationError("Users cannot friend themselves.")
    
    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

class PrivateChat(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # Always store users in consistent order (lower ID first)
    user1 = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='private_chats_as_user1'
    )
    user2 = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='private_chats_as_user2'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['user1', 'user2'],
                name='unique_private_chat'
            ),
            models.CheckConstraint(
                check=models.Q(user1__lt=models.F('user2')),
                name='user1_less_than_user2'
            )
        ]
        verbose_name = "Private Chat"
        verbose_name_plural = "Private Chats"
        ordering = ['-updated_at']

    def clean(self):
        if self.user1 == self.user2:
            raise ValidationError("Users cannot create a chat with themselves.")

    def save(self, *args, **kwargs):
        # Ensure user1 always has the lower ID
        if self.user1_id and self.user2_id and self.user1_id > self.user2_id:
            self.user1, self.user2 = self.user2, self.user1
        self.clean()
        super().save(*args, **kwargs)

    @classmethod
    def get_or_create_chat(cls, user_a, user_b):
        """Get or create a private chat between two users"""
        if user_a.id > user_b.id:
            user_a, user_b = user_b, user_a
        
        chat, created = cls.objects.get_or_create(
            user1=user_a,
            user2=user_b
        )
        return chat, created

    def get_other_user(self, current_user):
        """Get the other user in this chat"""
        return self.user2 if current_user == self.user1 else self.user1

    def __str__(self):
        return f"Chat between {self.user1.username} and {self.user2.username}"

class Room(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    creator = models.ForeignKey(User, on_delete=models.CASCADE)
    is_private = models.BooleanField(default=False)
    allowed_users = models.ManyToManyField(User, related_name='allowed_rooms', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    description = models.TextField(blank=True)
    password = models.CharField(max_length=128, blank=True, null=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "Chat Room"
        verbose_name_plural = "Chat Rooms"
        ordering = ['-created_at']

class Message(models.Model):
    MESSAGE_TYPES = [
        ('TEXT', 'Text'),
        ('IMAGE', 'Image'),
        ('FILE', 'File'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    room = models.ForeignKey(
        Room, 
        related_name='messages', 
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    private_chat = models.ForeignKey(
        PrivateChat,
        related_name='messages',
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    image = models.ImageField(upload_to='message_images/', blank=True, null=True)
    file = models.FileField(upload_to='message_files/', blank=True, null=True)
    message_type = models.CharField(max_length=5, choices=MESSAGE_TYPES, default='TEXT')
    edited = models.BooleanField(default=False)
    edited_at = models.DateTimeField(null=True, blank=True)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)

    def soft_delete(self):
        """Soft delete the message"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.content = "[This message was deleted]"
        self.save()

    def edit_message(self, new_content):
        """Edit the message content"""
        self.content = new_content
        self.edited = True
        self.edited_at = timezone.now()
        self.save()

    def __str__(self):
        if self.is_deleted:
            return f"{self.user.username}: [Deleted message]"
        return f"{self.user.username}: {self.content[:50]}..."

    class Meta:
        verbose_name = "Message"
        verbose_name_plural = "Messages"
        ordering = ['timestamp']

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def clean(self):
        """Enhanced clean method for Message model"""
        if not (self.room or self.private_chat):
            raise ValidationError("Message must belong to either a room or private chat.")
        if self.room and self.private_chat:
            raise ValidationError("Message cannot belong to both a room and private chat.")
        
        # Validate message content based on type
        if self.message_type == 'TEXT' and not self.content.strip():
            raise ValidationError("Text messages must have content.")
        elif self.message_type == 'IMAGE' and not self.image:
            raise ValidationError("Image messages must have an image file.")
        elif self.message_type == 'FILE' and not self.file:
            raise ValidationError("File messages must have a file attachment.")

    def get_file_name(self):
        """Get the original filename for file messages"""
        if self.message_type == 'FILE' and self.file:
            return self.file.name.split('/')[-1]  # Get filename without path
        elif self.message_type == 'IMAGE' and self.image:
            return self.image.name.split('/')[-1]
        return None

    def get_file_size(self):
        """Get file size in bytes"""
        if self.message_type == 'FILE' and self.file:
            return self.file.size
        elif self.message_type == 'IMAGE' and self.image:
            return self.image.size
        return None

class MessageReadReceipt(models.Model):
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='read_receipts')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    read_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('message', 'user')
        verbose_name = "Read Receipt"
        verbose_name_plural = "Read Receipts"

    def __str__(self):
        return f"{self.user.username} read at {self.read_at}"

class RoomParticipant(models.Model):
    ROLE_CHOICES = [
        ('member', 'Member'),
        ('admin', 'Admin'),
        ('moderator', 'Moderator'),
    ]
    
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name='participants')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    joined_at = models.DateTimeField(auto_now_add=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='member')
    last_read = models.DateTimeField(null=True, blank=True)
    is_muted = models.BooleanField(default=False)

    class Meta:
        unique_together = ('room', 'user')
        verbose_name = "Room Participant"
        verbose_name_plural = "Room Participants"

    def __str__(self):
        return f"{self.user.username} in {self.room.name} ({self.role})"

# Additional model for better chat management
class ChatParticipant(models.Model):
    """Track participation in private chats"""
    private_chat = models.ForeignKey(PrivateChat, on_delete=models.CASCADE, related_name='participants')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    last_read = models.DateTimeField(null=True, blank=True)
    is_archived = models.BooleanField(default=False)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('private_chat', 'user')
        verbose_name = "Chat Participant"
        verbose_name_plural = "Chat Participants"

    def get_unread_count(self):
        """Get count of unread messages"""
        if not self.last_read:
            return self.private_chat.messages.filter(is_deleted=False).exclude(user=self.user).count()
        return self.private_chat.messages.filter(
            timestamp__gt=self.last_read,
            is_deleted=False
        ).exclude(user=self.user).count()

    def __str__(self):
        return f"{self.user.username} in chat {self.private_chat.id}"
    


class RoomInvitation(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
        ('expired', 'Expired'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name='invitations')
    invited_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_invitations')
    invited_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_invitations')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    message = models.TextField(blank=True, help_text="Optional invitation message")
    created_at = models.DateTimeField(auto_now_add=True)
    responded_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(help_text="When this invitation expires")
    
    class Meta:
        unique_together = ('room', 'invited_user')
        verbose_name = "Room Invitation"
        verbose_name_plural = "Room Invitations"
        ordering = ['-created_at']
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            # Set expiration to 7 days from creation
            self.expires_at = timezone.now() + timezone.timedelta(days=7)
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at and self.status == 'pending'
    
    def accept(self):
        """Accept the invitation and add user to room"""
        if self.status != 'pending' or self.is_expired():
            return False
        
        # Add user to room as member
        RoomParticipant.objects.get_or_create(
            room=self.room,
            user=self.invited_user,
            defaults={'role': 'member'}
        )
        
        # Update invitation status
        self.status = 'accepted'
        self.responded_at = timezone.now()
        self.save()
        
        return True
    
    def reject(self):
        """Reject the invitation"""
        if self.status != 'pending':
            return False
        
        self.status = 'rejected'
        self.responded_at = timezone.now()
        self.save()
        
        return True
    
    def __str__(self):
        return f"Invitation to {self.room.name} for {self.invited_user.username} ({self.status})"
