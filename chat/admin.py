from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from django.db.models import Count, Q
from .models import (
    UserProfile, Friendship, PrivateChat, Room, Message,
    MessageReadReceipt, RoomParticipant, ChatParticipant, RoomInvitation, SupportTicket
)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'location', 'online', 'last_activity', 'friends_count', 'created_at']
    list_filter = ['online', 'created_at', 'location']
    search_fields = ['user__username', 'user__first_name', 'user__last_name', 'user__email', 'location']
    readonly_fields = ['created_at', 'updated_at', 'last_activity']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('User Information', {
            'fields': ('user', 'date_of_birth', 'bio', 'location')
        }),
        ('Profile Media', {
            'fields': ('profile_photo',)
        }),
        ('Status', {
            'fields': ('online', 'last_activity')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def friends_count(self, obj):
        return obj.get_friends().count()
    friends_count.short_description = 'Friends'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

@admin.register(Friendship)
class FriendshipAdmin(admin.ModelAdmin):
    list_display = ['from_user_link', 'to_user_link', 'status', 'created_at', 'updated_at']
    list_filter = ['status', 'created_at', 'updated_at']
    search_fields = [
        'from_user__user__username', 'from_user__user__email',
        'to_user__user__username', 'to_user__user__email'
    ]
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'
    
    def from_user_link(self, obj):
        url = reverse('admin:your_app_userprofile_change', args=[obj.from_user.pk])  # Replace 'your_app' with your actual app name
        return format_html('<a href="{}">{}</a>', url, obj.from_user.user.username)
    from_user_link.short_description = 'From User'
    from_user_link.admin_order_field = 'from_user__user__username'
    
    def to_user_link(self, obj):
        url = reverse('admin:your_app_userprofile_change', args=[obj.to_user.pk])  # Replace 'your_app' with your actual app name
        return format_html('<a href="{}">{}</a>', url, obj.to_user.user.username)
    to_user_link.short_description = 'To User'
    to_user_link.admin_order_field = 'to_user__user__username'

@admin.register(PrivateChat)
class PrivateChatAdmin(admin.ModelAdmin):
    list_display = ['id', 'user1', 'user2', 'message_count', 'created_at', 'updated_at']
    list_filter = ['created_at', 'updated_at']
    search_fields = ['user1__username', 'user2__username', 'user1__email', 'user2__email']
    readonly_fields = ['id', 'created_at', 'updated_at']
    date_hierarchy = 'created_at'
    
    def message_count(self, obj):
        return obj.messages.filter(is_deleted=False).count()
    message_count.short_description = 'Messages'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user1', 'user2').annotate(
            msg_count=Count('messages', filter=Q(messages__is_deleted=False))
        )

@admin.register(Room)
class RoomAdmin(admin.ModelAdmin):
    list_display = ['name', 'creator', 'is_private', 'participant_count', 'message_count', 'created_at']
    list_filter = ['is_private', 'created_at']
    search_fields = ['name', 'description', 'creator__username']
    readonly_fields = ['id', 'created_at', 'updated_at']
    filter_horizontal = ['allowed_users']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'creator', 'description')
        }),
        ('Privacy Settings', {
            'fields': ('is_private', 'password', 'allowed_users')
        }),
        ('System Information', {
            'fields': ('id', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def participant_count(self, obj):
        return obj.participants.count()
    participant_count.short_description = 'Participants'
    
    def message_count(self, obj):
        return obj.messages.filter(is_deleted=False).count()
    message_count.short_description = 'Messages'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('creator').annotate(
            participant_count=Count('participants'),
            msg_count=Count('messages', filter=Q(messages__is_deleted=False))
        )

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'message_preview', 'message_type', 'chat_context', 'timestamp', 'is_deleted', 'edited']
    list_filter = ['message_type', 'is_deleted', 'edited', 'timestamp']
    search_fields = ['user__username', 'content', 'room__name']
    readonly_fields = ['id', 'timestamp', 'edited_at', 'deleted_at']
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Message Information', {
            'fields': ('user', 'room', 'private_chat', 'message_type')
        }),
        ('Content', {
            'fields': ('content', 'image', 'file')
        }),
        ('Status', {
            'fields': ('is_deleted', 'edited')
        }),
        ('Timestamps', {
            'fields': ('timestamp', 'edited_at', 'deleted_at'),
            'classes': ('collapse',)
        }),
    )
    
    def message_preview(self, obj):
        if obj.is_deleted:
            return "[Deleted message]"
        if obj.message_type == 'TEXT':
            return obj.content[:50] + "..." if len(obj.content) > 50 else obj.content
        elif obj.message_type == 'IMAGE':
            return f"[Image: {obj.get_file_name()}]"
        elif obj.message_type == 'FILE':
            return f"[File: {obj.get_file_name()}]"
        return obj.content[:50]
    message_preview.short_description = 'Content'
    
    def chat_context(self, obj):
        if obj.room:
            return f"Room: {obj.room.name}"
        elif obj.private_chat:
            return f"Private: {obj.private_chat.user1.username} & {obj.private_chat.user2.username}"
        return "Unknown"
    chat_context.short_description = 'Chat Context'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user', 'room', 'private_chat__user1', 'private_chat__user2')

@admin.register(MessageReadReceipt)
class MessageReadReceiptAdmin(admin.ModelAdmin):
    list_display = ['message_preview', 'user', 'read_at']
    list_filter = ['read_at']
    search_fields = ['user__username', 'message__content']
    readonly_fields = ['read_at']
    date_hierarchy = 'read_at'
    
    def message_preview(self, obj):
        return obj.message.content[:50] + "..." if len(obj.message.content) > 50 else obj.message.content
    message_preview.short_description = 'Message'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user', 'message', 'message__user')

@admin.register(RoomParticipant)
class RoomParticipantAdmin(admin.ModelAdmin):
    list_display = ['user', 'room', 'role', 'joined_at', 'last_read', 'is_muted']
    list_filter = ['role', 'is_muted', 'joined_at']
    search_fields = ['user__username', 'room__name']
    readonly_fields = ['joined_at']
    date_hierarchy = 'joined_at'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user', 'room')

@admin.register(ChatParticipant)
class ChatParticipantAdmin(admin.ModelAdmin):
    list_display = ['user', 'chat_participants', 'unread_messages', 'is_archived', 'joined_at', 'last_read']
    list_filter = ['is_archived', 'joined_at']
    search_fields = ['user__username', 'private_chat__user1__username', 'private_chat__user2__username']
    readonly_fields = ['joined_at']
    date_hierarchy = 'joined_at'
    
    def chat_participants(self, obj):
        return f"{obj.private_chat.user1.username} & {obj.private_chat.user2.username}"
    chat_participants.short_description = 'Chat Between'
    
    def unread_messages(self, obj):
        return obj.get_unread_count()
    unread_messages.short_description = 'Unread Count'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user', 'private_chat__user1', 'private_chat__user2')


@admin.register(SupportTicket)
class SupportTicketAdmin(admin.ModelAdmin):
    list_display = ['get_ticket_number', 'name', 'email', 'subject', 'ticket_type', 
                    'priority', 'status', 'created_at']
    list_filter = ['status', 'priority', 'ticket_type', 'created_at']
    search_fields = ['name', 'email', 'subject', 'message']
    readonly_fields = ['id', 'created_at', 'updated_at', 'user_agent', 'ip_address', 'page_url']
    ordering = ['-created_at']
    
    fieldsets = (
        ('Ticket Information', {
            'fields': ('id', 'ticket_type', 'subject', 'priority', 'status')
        }),
        ('User Information', {
            'fields': ('user', 'name', 'email')
        }),
        ('Message', {
            'fields': ('message',)
        }),
        ('System Information', {
            'fields': ('user_agent', 'ip_address', 'page_url'),
            'classes': ('collapse',)
        }),
        ('Admin Fields', {
            'fields': ('assigned_to', 'admin_notes', 'resolved_at'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['mark_as_resolved', 'mark_as_in_progress']
    
    def mark_as_resolved(self, request, queryset):
        updated = queryset.update(status='resolved', resolved_at=timezone.now())
        self.message_user(request, f'{updated} tickets marked as resolved.')
    mark_as_resolved.short_description = "Mark selected tickets as resolved"
    
    def mark_as_in_progress(self, request, queryset):
        updated = queryset.update(status='in_progress')
        self.message_user(request, f'{updated} tickets marked as in progress.')
    mark_as_in_progress.short_description = "Mark selected tickets as in progress"


@admin.register(RoomInvitation)
class RoomInvitationAdmin(admin.ModelAdmin):
    list_display = ['room', 'invited_user', 'invited_by', 'status', 'is_expired_status', 'created_at', 'responded_at']
    list_filter = ['status', 'created_at', 'expires_at']
    search_fields = ['room__name', 'invited_user__username', 'invited_by__username']
    readonly_fields = ['id', 'created_at', 'responded_at']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Invitation Details', {
            'fields': ('room', 'invited_by', 'invited_user', 'message')
        }),
        ('Status', {
            'fields': ('status', 'expires_at')
        }),
        ('Timestamps', {
            'fields': ('id', 'created_at', 'responded_at'),
            'classes': ('collapse',)
        }),
    )
    
    def is_expired_status(self, obj):
        if obj.is_expired():
            return format_html('<span style="color: red;">Expired</span>')
        elif obj.status == 'pending':
            return format_html('<span style="color: orange;">Active</span>')
        return obj.status.title()
    is_expired_status.short_description = 'Status'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('room', 'invited_user', 'invited_by')

# Optional: Custom admin actions
def mark_messages_as_deleted(modeladmin, request, queryset):
    for message in queryset:
        message.soft_delete()
    modeladmin.message_user(request, f"{queryset.count()} messages marked as deleted.")
mark_messages_as_deleted.short_description = "Mark selected messages as deleted"

def accept_pending_invitations(modeladmin, request, queryset):
    count = 0
    for invitation in queryset.filter(status='pending'):
        if invitation.accept():
            count += 1
    modeladmin.message_user(request, f"{count} invitations accepted.")
accept_pending_invitations.short_description = "Accept selected pending invitations"

# Add actions to respective admin classes
MessageAdmin.actions = [mark_messages_as_deleted]
RoomInvitationAdmin.actions = [accept_pending_invitations]

