from django.db import models
from django.contrib.auth.models import User
import uuid
from django.core.exceptions import ValidationError
from django.db.models import Q
import random
import string
from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings

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

    def unfriend(self):
        """Remove friendship connection"""
        self.delete()
        
        reverse_friendship = Friendship.objects.filter(
            from_user=self.to_user,
            to_user=self.from_user
        ).first()
        if reverse_friendship:
            reverse_friendship.delete()

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
    deleted_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='deleted_messages',
        help_text="User who deleted this message"
    )
    
    # New field for read receipts
    read_by = models.ManyToManyField(
        User, 
        through='MessageReadReceipt',
        related_name='read_messages',
        blank=True
    )

    def soft_delete(self, deleted_by_user=None):
        """Enhanced soft delete with user information"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.deleted_by = deleted_by_user
        if deleted_by_user:
            self.content = f"This message was deleted by {deleted_by_user.username}"
        else:
            self.content = "This message was deleted"
        self.save()

    def edit_message(self, new_content):
        """Edit the message content"""
        self.content = new_content
        self.edited = True
        self.edited_at = timezone.now()
        self.save()

    def mark_as_read(self, user):
        """Mark message as read by a user"""
        if user != self.user:  # Don't mark own messages as read
            MessageReadReceipt.objects.get_or_create(
                message=self,
                user=user
            )
    
    def get_read_by_users(self):
        """Get users who have read this message (excluding sender)"""
        return self.read_by.exclude(id=self.user_id)
    
    def is_read_by(self, user):
        """Check if message has been read by specific user"""
        return self.read_receipts.filter(user=user).exists()

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
        if self.message_type == 'TEXT' and not self.content.strip() and not self.is_deleted:
            raise ValidationError("Text messages must have content.")
        elif self.message_type == 'IMAGE' and not self.image and not self.is_deleted:
            raise ValidationError("Image messages must have an image file.")
        elif self.message_type == 'FILE' and not self.file and not self.is_deleted:
            raise ValidationError("File messages must have a file attachment.")

    def get_file_name(self):
        """Get the original filename for file messages"""
        if self.message_type == 'FILE' and self.file:
            return self.file.name.split('/')[-1]
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


# Update the MessageReadReceipt model:
class MessageReadReceipt(models.Model):
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='read_receipts')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    read_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('message', 'user')
        verbose_name = "Read Receipt"
        verbose_name_plural = "Read Receipts"
        indexes = [
            models.Index(fields=['message', 'user']),
            models.Index(fields=['read_at']),
        ]

    def __str__(self):
        return f"{self.user.username} read message from {self.message.user.username} at {self.read_at}"


# Add a utility model for efficient read tracking
class ChatReadStatus(models.Model):
    """Track the last read message for each user in each chat"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    private_chat = models.ForeignKey(PrivateChat, on_delete=models.CASCADE, null=True, blank=True)
    room = models.ForeignKey(Room, on_delete=models.CASCADE, null=True, blank=True)
    last_read_message = models.ForeignKey(Message, on_delete=models.CASCADE)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = [
            ('user', 'private_chat'),
            ('user', 'room'),
        ]
        indexes = [
            models.Index(fields=['user', 'private_chat']),
            models.Index(fields=['user', 'room']),
            models.Index(fields=['updated_at']),
        ]
    
    def __str__(self):
        chat_name = self.private_chat or self.room
        return f"{self.user.username}'s last read in {chat_name}"


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



class OTPVerification(models.Model):
    OTP_TYPES = [
        ('registration', 'Registration'),
        ('password_reset', 'Password Reset'),
        ('email_verification', 'Email Verification'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField()
    otp_code = models.CharField(max_length=6)
    otp_type = models.CharField(max_length=20, choices=OTP_TYPES)
    is_verified = models.BooleanField(default=False)
    attempts = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=3)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    
    # Store registration data temporarily for registration OTPs
    temp_user_data = models.JSONField(null=True, blank=True, help_text="Temporary storage for registration data")
    
    class Meta:
        verbose_name = "OTP Verification"
        verbose_name_plural = "OTP Verifications"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email', 'otp_type']),
            models.Index(fields=['created_at']),
            models.Index(fields=['expires_at']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            # OTP expires in 10 minutes
            self.expires_at = timezone.now() + timedelta(minutes=10)
        if not self.otp_code:
            self.generate_otp()
        super().save(*args, **kwargs)
    
    def generate_otp(self):
        """Generate a 6-digit OTP code"""
        self.otp_code = ''.join(random.choices(string.digits, k=6))
        return self.otp_code
    
    def is_expired(self):
        """Check if OTP has expired"""
        return timezone.now() > self.expires_at
    
    def is_max_attempts_reached(self):
        """Check if maximum attempts reached"""
        return self.attempts >= self.max_attempts
    
    def verify_otp(self, provided_otp):
        """Verify the provided OTP"""
        if self.is_expired():
            return False, "OTP has expired"
        
        if self.is_max_attempts_reached():
            return False, "Maximum attempts reached"
        
        if self.is_verified:
            return False, "OTP already verified"
        
        self.attempts += 1
        self.save()
        
        if self.otp_code == provided_otp:
            self.is_verified = True
            self.save()
            return True, "OTP verified successfully"
        
        return False, f"Invalid OTP. {self.max_attempts - self.attempts} attempts remaining"
    
    def send_otp_email(self):
        """Send OTP via email"""
        subject_map = {
            'registration': 'ChatApp - Email Verification Code',
            'password_reset': 'ChatApp - Password Reset Code',
            'email_verification': 'ChatApp - Email Verification Code',
        }
        
        message_map = {
            'registration': f'''
Welcome to ChatApp!

Your verification code is: {self.otp_code}

This code will expire in 10 minutes. If you didn't request this code, please ignore this email.

Best regards,
ChatApp Team
            ''',
            'password_reset': f'''
Password Reset Request

Your password reset code is: {self.otp_code}

This code will expire in 10 minutes. If you didn't request a password reset, please ignore this email.

Best regards,
ChatApp Team
            ''',
            'email_verification': f'''
Email Verification

Your email verification code is: {self.otp_code}

This code will expire in 10 minutes.

Best regards,
ChatApp Team
            '''
        }
        
        subject = subject_map.get(self.otp_type, 'ChatApp - Verification Code')
        message = message_map.get(self.otp_type, f'Your verification code is: {self.otp_code}')
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[self.email],
                fail_silently=False,
            )
            return True
        except Exception as e:
            print(f"Failed to send email: {e}")
            return False
    
    @classmethod
    def create_otp(cls, email, otp_type, user=None, temp_data=None):
        """Create a new OTP verification"""
        # Invalidate existing OTPs for this email and type
        cls.objects.filter(
            email=email, 
            otp_type=otp_type, 
            is_verified=False
        ).update(is_verified=True)  # Mark as used to prevent reuse
        
        otp = cls.objects.create(
            email=email,
            otp_type=otp_type,
            user=user,
            temp_user_data=temp_data
        )
        
        # Send email
        if otp.send_otp_email():
            return otp
        else:
            otp.delete()  # Delete if email failed to send
            return None
    
    def __str__(self):
        return f"{self.email} - {self.otp_type} - {self.otp_code}"


class PasswordResetRequest(models.Model):
    """Track password reset requests for additional security"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp_verification = models.OneToOneField(OTPVerification, on_delete=models.CASCADE)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    class Meta:
        verbose_name = "Password Reset Request"
        verbose_name_plural = "Password Reset Requests"
        ordering = ['-created_at']
    
    def mark_as_used(self):
        """Mark this reset request as used"""
        self.is_used = True
        self.used_at = timezone.now()
        self.save()
    
    def is_expired(self):
        """Check if the reset request has expired"""
        return self.otp_verification.is_expired()
    
    def __str__(self):
        return f"Password reset for {self.user.username}"
    


class SupportTicket(models.Model):
    TICKET_TYPES = [
        ('general', 'General Inquiry'),
        ('technical', 'Technical Issue'),
        ('feature', 'Feature Request'),
        ('bug', 'Bug Report'),
        ('account', 'Account Issue'),
        ('privacy', 'Privacy Concern'),
        ('other', 'Other'),
    ]
    
    PRIORITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('urgent', 'Urgent'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('closed', 'Closed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # User information
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, 
                           related_name='support_tickets')
    name = models.CharField(max_length=100, help_text="Your full name")
    email = models.EmailField(help_text="We'll use this to respond to you")
    
    # Ticket details
    ticket_type = models.CharField(max_length=20, choices=TICKET_TYPES, default='general')
    subject = models.CharField(max_length=200, help_text="Brief description of your issue")
    message = models.TextField(help_text="Detailed description of your query or issue")
    priority = models.CharField(max_length=10, choices=PRIORITY_LEVELS, default='medium')
    
    # System information (auto-populated)
    user_agent = models.TextField(blank=True, help_text="Browser and device information")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    page_url = models.URLField(blank=True, help_text="Page where the issue occurred")
    
    # Status and tracking
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    # Admin fields
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                  related_name='assigned_tickets', limit_choices_to={'is_staff': True})
    admin_notes = models.TextField(blank=True, help_text="Internal notes for administrators")
    
    class Meta:
        verbose_name = "Support Ticket"
        verbose_name_plural = "Support Tickets"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'priority']),
            models.Index(fields=['created_at']),
            models.Index(fields=['email']),
            models.Index(fields=['ticket_type']),
        ]
    
    def __str__(self):
        return f"#{str(self.id)[:8]} - {self.subject} ({self.get_status_display()})"
    
    def get_ticket_number(self):
        """Return a shortened ticket number for display"""
        return f"#{str(self.id)[:8].upper()}"
    
    def mark_resolved(self):
        """Mark ticket as resolved"""
        self.status = 'resolved'
        self.resolved_at = timezone.now()
        self.save()
    
    def get_priority_color(self):
        """Return Bootstrap color class for priority"""
        colors = {
            'low': 'success',
            'medium': 'warning',
            'high': 'danger',
            'urgent': 'dark'
        }
        return colors.get(self.priority, 'secondary')
    
    def get_status_color(self):
        """Return Bootstrap color class for status"""
        colors = {
            'open': 'primary',
            'in_progress': 'warning',
            'resolved': 'success',
            'closed': 'secondary'
        }
        return colors.get(self.status, 'secondary')
