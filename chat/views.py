from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.utils import timezone
from django.core.files.storage import default_storage
from django.urls import reverse
from .models import UserProfile, Friendship, PrivateChat, Room, Message, RoomParticipant, ChatParticipant, RoomInvitation, OTPVerification, PasswordResetRequest
from .forms import UserRegistrationForm, UserProfileForm, RoomCreationForm, MessageForm, EmailRegistrationForm, OTPVerificationForm, PasswordResetRequestForm, PasswordResetConfirmForm, ResendOTPForm
from django.http import FileResponse, Http404
from django.conf import settings
from datetime import datetime, date, timedelta
from django.contrib.auth import update_session_auth_hash
import json
import os
import logging

logger = logging.getLogger(__name__)



def media_serve(request, path):
    full_path = os.path.join(settings.MEDIA_ROOT, path)
    if os.path.exists(full_path):
        return FileResponse(open(full_path, 'rb'))
    raise Http404()

# Authentication Views
def register_view(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()
            
            # Create user profile
            UserProfile.objects.get_or_create(user=user)
            
            messages.success(request, 'Registration successful!')
            return redirect('login')
    else:
        form = UserRegistrationForm()
    
    return render(request, 'chat/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            user.profile.online = True
            user.profile.save()
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid credentials')
    
    return render(request, 'chat/login.html')

@login_required
def logout_view(request):
    request.user.profile.online = False
    request.user.profile.save()
    logout(request)
    return redirect('login')

# Dashboard and Profile Views
@login_required
def dashboard(request):
    # Get recent private chats
    private_chats = PrivateChat.objects.filter(
        Q(user1=request.user) | Q(user2=request.user)
    ).order_by('-updated_at')[:5]
    
    # Get user's rooms
    user_rooms = Room.objects.filter(
        Q(creator=request.user) | Q(participants__user=request.user)
    ).distinct().order_by('-updated_at')[:5]
    
    # Get friend requests
    pending_requests = Friendship.objects.filter(
        to_user=request.user.profile,
        status='pending'
    ).order_by('-created_at')[:5]

    pending_invitations_count = RoomInvitation.objects.filter(
        invited_user=request.user, 
        status='pending'
    ).count()
    
    context = {
        'private_chats': private_chats,
        'user_rooms': user_rooms,
        'pending_requests': pending_requests,
        'online_friends': request.user.profile.get_friends().filter(online=True)[:10],
        'pending_invitations_count': pending_invitations_count
    }
    
    return render(request, 'chat/dashboard.html', context)

@login_required
def profile_view(request, user_id=None):
    if user_id:
        profile_user = get_object_or_404(User, id=user_id)
        is_own_profile = False
    else:
        profile_user = request.user
        is_own_profile = True
    
    # Check friendship status
    friendship_status = None
    if not is_own_profile:
        try:
            friendship = Friendship.objects.get(
                Q(from_user=request.user.profile, to_user=profile_user.profile) |
                Q(from_user=profile_user.profile, to_user=request.user.profile)
            )
            friendship_status = friendship.status
        except Friendship.DoesNotExist:
            friendship_status = None
    
    if request.method == 'POST' and is_own_profile:
        form = UserProfileForm(request.POST, request.FILES, instance=profile_user.profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('profile')
    else:
        form = UserProfileForm(instance=profile_user.profile) if is_own_profile else None
    
    context = {
        'profile_user': profile_user,
        'is_own_profile': is_own_profile,
        'friendship_status': friendship_status,
        'form': form
    }
    
    return render(request, 'chat/profile.html', context)

# Friend System Views
@login_required
def friends_list(request):
    friends = request.user.profile.get_friends()
    pending_sent = Friendship.objects.filter(
        from_user=request.user.profile,
        status='pending'
    )
    pending_received = Friendship.objects.filter(
        to_user=request.user.profile,
        status='pending'
    )
    
    context = {
        'friends': friends,
        'pending_sent': pending_sent,
        'pending_received': pending_received
    }
    
    return render(request, 'chat/friends.html', context)

@login_required
def search_users(request):
    query = request.GET.get('q', '')
    users = []
    
    if query:
        users = User.objects.filter(
            Q(username__icontains=query) | Q(email__icontains=query)
        ).exclude(id=request.user.id)[:10]
    
    return render(request, 'chat/search_users.html', {'users': users, 'query': query})


@require_POST
@login_required
def send_friend_request(request):
    user_id = request.POST.get('user_id')
    target_user = get_object_or_404(User, id=user_id)
    
    # Check for existing friendship (including rejected ones)
    existing = Friendship.objects.filter(
        Q(from_user=request.user.profile, to_user=target_user.profile) |
        Q(from_user=target_user.profile, to_user=request.user.profile)
    ).first()
    
    if existing:
        if existing.status == 'accepted':
            return JsonResponse({'success': False, 'message': 'You are already friends'})
        elif existing.status == 'pending':
            return JsonResponse({'success': False, 'message': 'Friend request already sent'})
        elif existing.status == 'rejected':
            # Allow resending after rejection - update the existing request
            existing.from_user = request.user.profile
            existing.to_user = target_user.profile
            existing.status = 'pending'
            existing.created_at = timezone.now()
            existing.save()
            return JsonResponse({'success': True, 'message': 'Friend request sent!'})
        elif existing.status == 'blocked':
            return JsonResponse({'success': False, 'message': 'Cannot send friend request'})
    
    # Create new friendship request
    friendship = Friendship.objects.create(
        from_user=request.user.profile,
        to_user=target_user.profile
    )
    
    return JsonResponse({'success': True, 'message': 'Friend request sent!'})

@require_POST
@login_required
def respond_friend_request(request):
    friendship_id = request.POST.get('friendship_id')
    action = request.POST.get('action')
    
    friendship = get_object_or_404(
        Friendship,
        id=friendship_id,
        to_user=request.user.profile,
        status='pending'
    )
    
    if action == 'accept':
        friendship.status = 'accepted'
        message = 'Friend request accepted!'
    else:
        friendship.status = 'rejected'
        message = 'Friend request rejected!'
    
    friendship.save()
    
    return JsonResponse({'success': True, 'message': message})

# Chat Views
@login_required
def private_chat_view(request, user_id):
    other_user = get_object_or_404(User, id=user_id)
    
    chat, created = PrivateChat.get_or_create_chat(request.user, other_user)
    
    # Get or create chat participant for current user
    participant, _ = ChatParticipant.objects.get_or_create(
        private_chat=chat,
        user=request.user
    )
    
    # Get messages with read receipts prefetched
    messages_list = chat.messages.prefetch_related(
        'read_receipts__user'
    ).order_by('timestamp')
    
    # Mark messages as read
    unread_messages = messages_list.exclude(user=request.user).exclude(
        read_receipts__user=request.user
    )
    
    # Bulk mark as read
    for message in unread_messages:
        message.mark_as_read(request.user)
    
    # Update last read timestamp
    participant.last_read = timezone.now()
    participant.save()
    
    context = {
        'chat': chat,
        'other_user': other_user,
        'chat_messages': messages_list,
        'form': MessageForm(),
        'today': timezone.now().date(),
        'yesterday': timezone.now().date() - timedelta(days=1),
    }
    
    return render(request, 'chat/private_chat.html', context)

@login_required
def room_list(request):
    # Public rooms
    public_rooms = Room.objects.filter(is_private=False).order_by('-created_at')
    
    # User's private rooms
    user_rooms = Room.objects.filter(
        Q(creator=request.user) | Q(participants__user=request.user),
        is_private=True
    ).distinct().order_by('-created_at')
    
    context = {
        'public_rooms': public_rooms,
        'user_rooms': user_rooms,
        'form': RoomCreationForm()
    }
    
    return render(request, 'chat/room_list.html', context)

@login_required
def room_view(request, room_id):
    room = get_object_or_404(Room, id=room_id)
    
    # Check access permissions
    if room.is_private:
        if not (room.creator == request.user or 
                room.participants.filter(user=request.user).exists() or
                room.allowed_users.filter(id=request.user.id).exists()):
            messages.error(request, 'You do not have access to this room!')
            return redirect('room_list')
    
    # Get or create participant
    participant, created = RoomParticipant.objects.get_or_create(
        room=room,
        user=request.user,
        defaults={'role': 'admin' if room.creator == request.user else 'member'}
    )
    
    # Get messages with read receipts prefetched
    messages_list = room.messages.prefetch_related(
        'read_receipts__user'
    ).order_by('timestamp')
    
    # Mark messages as read
    unread_messages = messages_list.exclude(user=request.user).exclude(
        read_receipts__user=request.user
    )
    
    # Bulk mark as read
    for message in unread_messages:
        message.mark_as_read(request.user)
    
    # Update last read
    participant.last_read = timezone.now()
    participant.save()
    
    context = {
        'room': room,
        'chat_messages': messages_list,
        'participant': participant,
        'form': MessageForm(),
        'today': timezone.now().date(),
        'yesterday': timezone.now().date() - timedelta(days=1),
    }
    
    return render(request, 'chat/room.html', context)

@require_POST
@login_required
def create_room(request):
    form = RoomCreationForm(request.POST)
    if form.is_valid():
        room = form.save(commit=False)
        room.creator = request.user
        room.save()
        
        # Add creator as admin participant
        RoomParticipant.objects.create(
            room=room,
            user=request.user,
            role='admin'
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Room created successfully!',
            'room_id': str(room.id)
        })
    
    return JsonResponse({'success': False, 'errors': form.errors})


@require_POST
@login_required
def send_message(request):
    message_type = request.POST.get('type')  # 'private' or 'room'
    content = request.POST.get('content', '').strip()
    image = request.FILES.get('image')
    file = request.FILES.get('file')
    
    # Validate that we have some content
    if not content and not image and not file:
        return JsonResponse({'success': False, 'message': 'Message cannot be empty'})
    
    # Determine message type
    if image:
        msg_type = 'IMAGE'
    elif file:
        msg_type = 'FILE'
    else:
        msg_type = 'TEXT'
    
    try:
        if message_type == 'private':
            chat_id = request.POST.get('chat_id')
            chat = get_object_or_404(PrivateChat, id=chat_id)
            
            # Check if user is part of this chat
            if not (chat.user1 == request.user or chat.user2 == request.user):
                return JsonResponse({'success': False, 'message': 'Access denied'})
            
            message = Message.objects.create(
                private_chat=chat,
                user=request.user,
                content=content,
                image=image,
                file=file,
                message_type=msg_type
            )
            
            # Update chat timestamp
            chat.updated_at = timezone.now()
            chat.save()
            
        elif message_type == 'room':
            room_id = request.POST.get('room_id')
            room = get_object_or_404(Room, id=room_id)
            
            # Check access
            if room.is_private and not (
                room.creator == request.user or 
                room.participants.filter(user=request.user).exists()
            ):
                return JsonResponse({'success': False, 'message': 'Access denied'})
            
            message = Message.objects.create(
                room=room,
                user=request.user,
                content=content,
                image=image,
                file=file,
                message_type=msg_type
            )
        
        # Prepare response data
        response_data = {
            'success': True,
            'message_id': str(message.id),
            'content': message.content,
            'username': message.user.username,
            'timestamp': message.timestamp.isoformat(),
            'formatted_time': message.timestamp.strftime('%H:%M'),
            'message_type': message.message_type,
            'is_own': True,
            'edited': False,
            'read_count': 0,  # New message, no reads yet
            'read_by': [],
            'is_deleted': False
        }
        
        # Add file information if applicable
        if message.message_type == 'IMAGE' and message.image:
            response_data['file_url'] = message.image.url
            response_data['file_name'] = message.get_file_name()
        elif message.message_type == 'FILE' and message.file:
            response_data['file_url'] = message.file.url
            response_data['file_name'] = message.get_file_name()
        
        return JsonResponse(response_data)
        
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})



@require_POST
@login_required
def edit_message(request):
    message_id = request.POST.get('message_id')
    new_content = request.POST.get('content', '').strip()
    
    if not new_content:
        return JsonResponse({'success': False, 'message': 'Content cannot be empty'})
    
    try:
        message = get_object_or_404(Message, id=message_id, user=request.user)
        
        # Only allow editing text messages
        if message.message_type != 'TEXT':
            return JsonResponse({'success': False, 'message': 'Only text messages can be edited'})
        
        if message.is_deleted:
            return JsonResponse({'success': False, 'message': 'Cannot edit deleted messages'})
        
        message.edit_message(new_content)
        
        return JsonResponse({
            'success': True,
            'content': message.content,
            'edited_at': message.edited_at.strftime('%H:%M') if message.edited_at else ''
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})


@login_required
def get_chat_messages(request, chat_id):
    chat = get_object_or_404(PrivateChat, id=chat_id)
    
    if not (chat.user1 == request.user or chat.user2 == request.user):
        return JsonResponse({'error': 'Access denied'}, status=403)
    
    # Get pagination parameters
    page = int(request.GET.get('page', 1))
    limit = int(request.GET.get('limit', 50))
    offset = (page - 1) * limit
    
    # FIXED: Include deleted messages - remove the filter
    messages_queryset = chat.messages.prefetch_related(
        'read_receipts__user'
    ).order_by('-timestamp')  # Removed .filter(is_deleted=False)
    
    total_messages = messages_queryset.count()
    messages_list = list(messages_queryset[offset:offset + limit])
    messages_list.reverse()  # Reverse to get chronological order
    
    messages_data = []
    current_date = None
    other_user = chat.get_other_user(request.user)
    
    for msg in messages_list:
        message_date = msg.timestamp.date()
        
        # Add date header if date changed
        if current_date != message_date:
            current_date = message_date
            date_label = get_date_label(message_date)
            messages_data.append({
                'type': 'date_header',
                'date': message_date.isoformat(),
                'label': date_label
            })
        
        # Get read receipt info - fix the double tick to single tick issue
        read_by_users = []
        is_read_by_other = False
        
        if msg.user == request.user:
            # For own messages, check if other user has read it
            is_read_by_other = msg.read_receipts.filter(user=other_user).exists()
            if is_read_by_other:
                read_receipt = msg.read_receipts.filter(user=other_user).first()
                if read_receipt:
                    read_by_users = [{
                        'username': other_user.username,
                        'read_at': read_receipt.read_at.isoformat()
                    }]
        
        message_data = {
            'type': 'message',
            'id': str(msg.id),
            'content': msg.content,
            'username': msg.user.username,
            'timestamp': msg.timestamp.isoformat(),
            'formatted_time': msg.timestamp.strftime('%H:%M'),
            'is_own': msg.user == request.user,
            'edited': msg.edited,
            'message_type': msg.message_type,
            'read_by': read_by_users,
            'is_read_by_other': is_read_by_other,
            'is_deleted': msg.is_deleted
        }
        
        # Add file information
        if msg.message_type == 'IMAGE' and msg.image:
            message_data['file_url'] = msg.image.url
            message_data['file_name'] = msg.get_file_name()
        elif msg.message_type == 'FILE' and msg.file:
            message_data['file_url'] = msg.file.url
            message_data['file_name'] = msg.get_file_name()
        
        messages_data.append(message_data)
    
    # Only mark messages as read if this is the first page (recent messages)
    if page == 1:
        unread_messages = chat.messages.exclude(
            user=request.user
        ).exclude(read_receipts__user=request.user)
        
        for message in unread_messages:
            message.mark_as_read(request.user)
    
    return JsonResponse({
        'messages': messages_data,
        'has_more': offset + limit < total_messages,
        'total': total_messages
    })


@login_required
def get_room_messages(request, room_id):
    room = get_object_or_404(Room, id=room_id)
    
    # Check access
    if room.is_private and not (
        room.creator == request.user or 
        room.participants.filter(user=request.user).exists()
    ):
        return JsonResponse({'error': 'Access denied'}, status=403)
    
    # Get pagination parameters
    page = int(request.GET.get('page', 1))
    limit = int(request.GET.get('limit', 50))
    offset = (page - 1) * limit
    
    # FIXED: Include deleted messages - remove the filter
    messages_queryset = room.messages.prefetch_related(
        'read_receipts__user'
    ).order_by('-timestamp')  # Removed .filter(is_deleted=False)
    
    total_messages = messages_queryset.count()
    messages_list = list(messages_queryset[offset:offset + limit])
    messages_list.reverse()  # Reverse to get chronological order
    
    messages_data = []
    current_date = None
    
    for msg in messages_list:
        message_date = msg.timestamp.date()
        
        # Add date header if date changed
        if current_date != message_date:
            current_date = message_date
            date_label = get_date_label(message_date)
            messages_data.append({
                'type': 'date_header',
                'date': message_date.isoformat(),
                'label': date_label
            })
        
        # Get read receipt info for room messages - fix the tick mark issue
        read_by_users = []
        read_count = 0
        
        if msg.user == request.user:
            # For own messages, get consistent read count
            read_receipts = msg.read_receipts.exclude(user=request.user)
            read_count = read_receipts.count()
            read_by_users = [
                {
                    'username': receipt.user.username,
                    'read_at': receipt.read_at.isoformat()
                }
                for receipt in read_receipts[:3]  # Show only first 3
            ]
        
        message_data = {
            'type': 'message',
            'id': str(msg.id),
            'content': msg.content,
            'username': msg.user.username,
            'timestamp': msg.timestamp.isoformat(),
            'formatted_time': msg.timestamp.strftime('%H:%M'),
            'is_own': msg.user == request.user,
            'edited': msg.edited,
            'message_type': msg.message_type,
            'read_by': read_by_users,
            'read_count': read_count,
            'is_read': msg.is_read_by(request.user) if msg.user != request.user else True,
            'is_deleted': msg.is_deleted
        }
        
        # Add file information
        if msg.message_type == 'IMAGE' and msg.image:
            message_data['file_url'] = msg.image.url
            message_data['file_name'] = msg.get_file_name()
        elif msg.message_type == 'FILE' and msg.file:
            message_data['file_url'] = msg.file.url
            message_data['file_name'] = msg.get_file_name()
        
        messages_data.append(message_data)
    
    # Only mark messages as read if this is the first page (recent messages)
    if page == 1:
        unread_messages = room.messages.exclude(
            user=request.user
        ).exclude(read_receipts__user=request.user)
        
        for message in unread_messages:
            message.mark_as_read(request.user)
    
    return JsonResponse({
        'messages': messages_data,
        'has_more': offset + limit < total_messages,
        'total': total_messages
    })



@login_required
def get_unread_counts(request):
    # Get unread counts for private chats
    private_chats = ChatParticipant.objects.filter(user=request.user)
    private_counts = {}
    for participant in private_chats:
        unread_count = participant.get_unread_count()
        if unread_count > 0:
            private_counts[str(participant.private_chat.id)] = unread_count
    
    # Get unread counts for rooms
    room_participants = RoomParticipant.objects.filter(user=request.user)
    room_counts = {}
    for participant in room_participants:
        if participant.last_read:
            unread_count = participant.room.messages.filter(
                timestamp__gt=participant.last_read,
                is_deleted=False
            ).exclude(user=request.user).count()
        else:
            unread_count = participant.room.messages.filter(
                is_deleted=False
            ).exclude(user=request.user).count()
        
        if unread_count > 0:
            room_counts[str(participant.room.id)] = unread_count
    
    return JsonResponse({
        'private_chats': private_counts,
        'rooms': room_counts
    })


@login_required
def search_users_for_invite(request):
    query = request.GET.get('q', '').strip()
    room_id = request.GET.get('room_id')
    
    if not query or not room_id:
        return JsonResponse({'users': []})
    
    try:
        room = Room.objects.get(id=room_id)
        
        # Check if user has permission to invite
        if not (room.creator == request.user or 
                room.participants.filter(user=request.user, role__in=['admin', 'moderator']).exists()):
            return JsonResponse({'users': [], 'error': 'No permission to invite users'})
        
        # Get existing members and pending invitations
        existing_members = set(room.participants.values_list('user_id', flat=True))
        pending_invitations = set(room.invitations.filter(
            status='pending'
        ).values_list('invited_user_id', flat=True))
        
        # Search for users
        users = User.objects.filter(
            Q(username__icontains=query) | 
            Q(first_name__icontains=query) | 
            Q(last_name__icontains=query) |
            Q(email__icontains=query)
        ).exclude(id=request.user.id)[:20]
        
        users_data = []
        for user in users:
            is_member = user.id in existing_members
            has_pending_invite = user.id in pending_invitations
            
            user_data = {
                'id': user.id,
                'username': user.username,
                'full_name': user.get_full_name(),
                'email': user.email,
                'is_member': is_member,
                'has_pending_invite': has_pending_invite,
                'profile_photo': user.profile.profile_photo.url if user.profile.profile_photo else None
            }
            users_data.append(user_data)
        
        return JsonResponse({'users': users_data})
        
    except Room.DoesNotExist:
        return JsonResponse({'users': [], 'error': 'Room not found'})

# New view for sending room invitations
@require_POST
@login_required
def invite_users_to_room(request):
    room_id = request.POST.get('room_id')
    user_ids = request.POST.getlist('user_ids')
    invitation_message = request.POST.get('message', '').strip()
    
    if not room_id or not user_ids:
        return JsonResponse({'success': False, 'message': 'Missing required data'})
    
    try:
        room = get_object_or_404(Room, id=room_id)
        
        # Check permissions
        if not (room.creator == request.user or 
                room.participants.filter(user=request.user, role__in=['admin', 'moderator']).exists()):
            return JsonResponse({'success': False, 'message': 'No permission to invite users'})
        
        sent_count = 0
        errors = []
        
        for user_id in user_ids:
            try:
                invited_user = User.objects.get(id=user_id)
                
                # Check if user is already a member
                if room.participants.filter(user=invited_user).exists():
                    continue
                
                # Check if there's already a pending invitation
                if RoomInvitation.objects.filter(
                    room=room, 
                    invited_user=invited_user, 
                    status='pending'
                ).exists():
                    continue
                
                # Create invitation
                invitation = RoomInvitation.objects.create(
                    room=room,
                    invited_by=request.user,
                    invited_user=invited_user,
                    message=invitation_message
                )
                
                sent_count += 1
                
                # Here you could send email notifications
                # send_invitation_email(invitation)
                
            except User.DoesNotExist:
                errors.append(f'User with ID {user_id} not found')
            except Exception as e:
                errors.append(f'Error inviting user {user_id}: {str(e)}')
        
        if sent_count > 0:
            return JsonResponse({
                'success': True, 
                'sent_count': sent_count,
                'message': f'Successfully sent {sent_count} invitation(s)'
            })
        else:
            return JsonResponse({
                'success': False, 
                'message': 'No invitations were sent. Users may already be members or have pending invitations.'
            })
            
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})


@login_required
def my_invitations(request):
    invitations = RoomInvitation.objects.filter(
        invited_user=request.user,
        status='pending'
    ).order_by('-created_at')
    
    # Mark expired invitations
    for invitation in invitations:
        if invitation.is_expired():
            invitation.status = 'expired'
            invitation.save()
    
    # Get fresh queryset after potential updates
    active_invitations = RoomInvitation.objects.filter(
        invited_user=request.user,
        status='pending'
    ).order_by('-created_at')
    
    context = {
        'invitations': active_invitations
    }
    
    return render(request, 'chat/invitations.html', context)


@require_POST
@login_required
def respond_to_invitation(request):
    invitation_id = request.POST.get('invitation_id')
    action = request.POST.get('action')  # 'accept' or 'reject'
    
    if not invitation_id or action not in ['accept', 'reject']:
        return JsonResponse({'success': False, 'message': 'Invalid request'})
    
    try:
        invitation = get_object_or_404(
            RoomInvitation,
            id=invitation_id,
            invited_user=request.user,
            status='pending'
        )
        
        if invitation.is_expired():
            invitation.status = 'expired'
            invitation.save()
            return JsonResponse({'success': False, 'message': 'This invitation has expired'})
        
        if action == 'accept':
            success = invitation.accept()
            message = 'Invitation accepted! You have been added to the room.' if success else 'Failed to accept invitation.'
        else:
            success = invitation.reject()
            message = 'Invitation rejected.' if success else 'Failed to reject invitation.'
        
        return JsonResponse({'success': success, 'message': message})
        
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})



@require_POST
@login_required
def delete_message(request):
    message_id = request.POST.get('message_id')
    
    try:
        message = get_object_or_404(Message, id=message_id, user=request.user)
        
        if message.is_deleted:
            return JsonResponse({'success': False, 'message': 'Message already deleted'})
        
        message.is_deleted = True
        message.deleted_at = timezone.now()
        message.deleted_by = request.user
        deleted_content = f"This message was deleted by {request.user.username}"
        message.content = deleted_content
        message.save()
        
        return JsonResponse({
            'success': True, 
            'message': 'Message deleted',
            'deleted_content': deleted_content
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})
    
    
@require_POST
@login_required
def delete_room(request):
    room_id = request.POST.get('room_id')
    room = get_object_or_404(Room, id=room_id, creator=request.user)
    
    try:
        # Soft delete all messages in the room
        room.messages.update(
            is_deleted=True,
            deleted_at=timezone.now(),
            content="This message was deleted due to room deletion"
        )
        
        # Remove all participants
        room.participants.all().delete()
        
        # Delete the room
        room.delete()
        
        return JsonResponse({
            'success': True,
            'message': 'Room deleted successfully',
            'redirect_url': reverse('room_list')
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error deleting room: {str(e)}'
        })

@require_POST
@login_required
def leave_room(request):
    room_id = request.POST.get('room_id')
    room = get_object_or_404(Room, id=room_id)
    
    try:
        # Check if user is the creator
        if room.creator == request.user:
            return JsonResponse({
                'success': False,
                'message': 'Room creators cannot leave. You must delete the room or transfer ownership.'
            })
        
        # Remove user from participants
        participant = RoomParticipant.objects.filter(room=room, user=request.user).first()
        if participant:
            participant.delete()
            
            return JsonResponse({
                'success': True,
                'message': 'Left room successfully',
                'redirect_url': reverse('room_list')
            })
        else:
            return JsonResponse({
                'success': False,
                'message': 'You are not a member of this room'
            })
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error leaving room: {str(e)}'
        })


@require_POST
@login_required
def remove_friend(request):
    friend_id = request.POST.get('friend_id')
    friend_user = get_object_or_404(User, id=friend_id)
    
    # Find the friendship
    friendship = Friendship.objects.filter(
        Q(from_user=request.user.profile, to_user=friend_user.profile, status='accepted') |
        Q(from_user=friend_user.profile, to_user=request.user.profile, status='accepted')
    ).first()
    
    if not friendship:
        return JsonResponse({'success': False, 'message': 'Friendship not found'})
    
    try:
        # Delete the friendship
        friendship.delete()
        
        # Also delete any reverse friendship
        reverse_friendship = Friendship.objects.filter(
            Q(from_user=friend_user.profile, to_user=request.user.profile) |
            Q(from_user=request.user.profile, to_user=friend_user.profile)
        ).exclude(id=friendship.id if hasattr(friendship, 'id') else None)
        
        reverse_friendship.delete()
        
        return JsonResponse({
            'success': True,
            'message': f'{friend_user.get_full_name() or friend_user.username} has been removed from your friends list'
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})
    


@require_POST
@login_required
def mark_message_as_read(request):
    """Manually mark a message as read (for real-time updates)"""
    message_id = request.POST.get('message_id')
    
    try:
        message = get_object_or_404(Message, id=message_id)
        
        # Check if user has access to this message
        if message.private_chat:
            if not (message.private_chat.user1 == request.user or 
                   message.private_chat.user2 == request.user):
                return JsonResponse({'success': False, 'error': 'Access denied'})
        elif message.room:
            if not (message.room.creator == request.user or 
                   message.room.participants.filter(user=request.user).exists()):
                return JsonResponse({'success': False, 'error': 'Access denied'})
        
        # Mark as read
        message.mark_as_read(request.user)
        
        return JsonResponse({'success': True})
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

def get_date_label(message_date):
    """Get user-friendly date label like 'Today', 'Yesterday', etc."""
    if not isinstance(message_date, date):
        if isinstance(message_date, datetime):
            message_date = message_date.date()
        else:
            return "Invalid Date"
    
    today = timezone.now().date()
    yesterday = today - timedelta(days=1)
    
    if message_date == today:
        return "Today"
    elif message_date == yesterday:
        return "Yesterday"
    elif message_date > today - timedelta(days=7):
        return message_date.strftime("%A")  # Day name like "Monday"
    elif message_date.year == today.year:
        return message_date.strftime("%B %d")  # Like "January 15"
    else:
        return message_date.strftime("%B %d, %Y")  # Like "January 15, 2023"


def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

# Registration Views
def register_step1(request):
    """Step 1: Collect user information and send OTP"""
    if request.method == 'POST':
        form = EmailRegistrationForm(request.POST)
        if form.is_valid():
            # Store form data in session
            request.session['registration_data'] = {
                'username': form.cleaned_data['username'],
                'email': form.cleaned_data['email'],
                'first_name': form.cleaned_data['first_name'],
                'last_name': form.cleaned_data['last_name'],
                'password': form.cleaned_data['password']
            }
            
            # Create OTP verification
            otp = OTPVerification.create_otp(
                email=form.cleaned_data['email'],
                otp_type='registration',
                temp_data=request.session['registration_data']
            )
            
            if otp:
                request.session['otp_id'] = str(otp.id)
                messages.success(request, 
                    f'Verification code sent to {form.cleaned_data["email"]}. '
                    'Please check your email and enter the code.')
                return redirect('register_step2')
            else:
                messages.error(request, 
                    'Failed to send verification email. Please try again.')
    else:
        form = EmailRegistrationForm()
    
    return render(request, 'chat/register_step1.html', {'form': form})

def register_step2(request):
    """Step 2: Verify OTP and create account"""
    if 'otp_id' not in request.session or 'registration_data' not in request.session:
        messages.error(request, 'Registration session expired. Please start again.')
        return redirect('register_step1')
    
    try:
        otp = OTPVerification.objects.get(id=request.session['otp_id'])
        if otp.is_expired():
            messages.error(request, 'Verification code has expired. Please request a new one.')
            return redirect('register_step1')
    except OTPVerification.DoesNotExist:
        messages.error(request, 'Invalid verification session. Please start again.')
        return redirect('register_step1')
    
    if request.method == 'POST':
        form = OTPVerificationForm(request.POST, otp_verification=otp)
        if form.is_valid():
            # Create user account
            reg_data = request.session['registration_data']
            user = User.objects.create_user(
                username=reg_data['username'],
                email=reg_data['email'],
                first_name=reg_data['first_name'],
                last_name=reg_data['last_name'],
                password=reg_data['password']
            )
            
            # Create user profile
            UserProfile.objects.get_or_create(user=user)
            
            # Clean up session
            del request.session['otp_id']
            del request.session['registration_data']
            
            # Log the user in
            login(request, user)
            
            messages.success(request, 
                'Account created successfully! Welcome to ChatApp!')
            return redirect('dashboard')
    else:
        form = OTPVerificationForm()
    
    context = {
        'form': form,
        'email': otp.email,
        'otp_id': str(otp.id),
        'resend_form': ResendOTPForm(initial={
            'email': otp.email,
            'otp_type': 'registration'
        })
    }
    
    return render(request, 'chat/register_step2.html', context)

# Password Reset Views
def password_reset_request(request):
    """Request password reset - send OTP to email"""
    if request.method == 'POST':
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            user = form.user
            
            # Create OTP verification
            otp = OTPVerification.create_otp(
                email=user.email,
                otp_type='password_reset',
                user=user
            )
            
            if otp:
                # Create password reset request
                reset_request = PasswordResetRequest.objects.create(
                    user=user,
                    otp_verification=otp,
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                request.session['reset_request_id'] = str(reset_request.id)
                messages.success(request, 
                    f'Password reset code sent to {user.email}. '
                    'Please check your email and enter the code.')
                return redirect('password_reset_verify')
            else:
                messages.error(request, 
                    'Failed to send reset email. Please try again.')
    else:
        form = PasswordResetRequestForm()
    
    return render(request, 'chat/password_reset_request.html', {'form': form})

def password_reset_verify(request):
    """Verify OTP for password reset"""
    if 'reset_request_id' not in request.session:
        messages.error(request, 'Password reset session expired. Please start again.')
        return redirect('password_reset_request')
    
    try:
        reset_request = PasswordResetRequest.objects.get(
            id=request.session['reset_request_id']
        )
        if reset_request.is_expired() or reset_request.is_used:
            messages.error(request, 'Password reset request has expired. Please start again.')
            return redirect('password_reset_request')
    except PasswordResetRequest.DoesNotExist:
        messages.error(request, 'Invalid password reset request. Please start again.')
        return redirect('password_reset_request')
    
    otp = reset_request.otp_verification
    
    if request.method == 'POST':
        form = OTPVerificationForm(request.POST, otp_verification=otp)
        if form.is_valid():
            request.session['otp_verified'] = True
            return redirect('password_reset_confirm')
    else:
        form = OTPVerificationForm()
    
    context = {
        'form': form,
        'email': otp.email,
        'otp_id': str(otp.id),
        'resend_form': ResendOTPForm(initial={
            'email': otp.email,
            'otp_type': 'password_reset'
        })
    }
    
    return render(request, 'chat/password_reset_verify.html', context)

def password_reset_confirm(request):
    """Set new password after OTP verification"""
    if ('reset_request_id' not in request.session or 
        'otp_verified' not in request.session):
        messages.error(request, 'Password reset session expired. Please start again.')
        return redirect('password_reset_request')
    
    try:
        reset_request = PasswordResetRequest.objects.get(
            id=request.session['reset_request_id']
        )
        if reset_request.is_used:
            messages.error(request, 'This password reset has already been used.')
            return redirect('login')
    except PasswordResetRequest.DoesNotExist:
        messages.error(request, 'Invalid password reset request.')
        return redirect('password_reset_request')
    
    user = reset_request.user
    
    if request.method == 'POST':
        form = PasswordResetConfirmForm(user, request.POST)
        if form.is_valid():
            form.save()
            
            # Mark reset request as used
            reset_request.mark_as_used()
            
            # Clean up session
            del request.session['reset_request_id']
            del request.session['otp_verified']
            
            messages.success(request, 
                'Password reset successful! You can now log in with your new password.')
            return redirect('login')
    else:
        form = PasswordResetConfirmForm(user)
    
    context = {
        'form': form,
        'user': user
    }
    
    return render(request, 'chat/password_reset_confirm.html', context)

# AJAX Views
@require_POST
def resend_otp(request):
    """Resend OTP code"""
    try:
        data = json.loads(request.body)
        email = data.get('email')
        otp_type = data.get('otp_type')
        
        if not email or not otp_type:
            return JsonResponse({
                'success': False,
                'message': 'Missing required information'
            })
        
        # Find user for password reset
        user = None
        temp_data = None
        
        if otp_type == 'password_reset':
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'message': 'No account found with this email'
                })
        elif otp_type == 'registration':
            # Get temp data from session
            if 'registration_data' in request.session:
                temp_data = request.session['registration_data']
        
        # Create new OTP
        otp = OTPVerification.create_otp(
            email=email,
            otp_type=otp_type,
            user=user,
            temp_data=temp_data
        )
        
        if otp:
            # Update session with new OTP ID
            request.session['otp_id'] = str(otp.id)
            
            return JsonResponse({
                'success': True,
                'message': f'New verification code sent to {email}'
            })
        else:
            return JsonResponse({
                'success': False,
                'message': 'Failed to send verification email'
            })
    
    except Exception as e:
        logger.error(f"Error resending OTP: {e}")
        return JsonResponse({
            'success': False,
            'message': 'An error occurred while sending the verification code'
        })

@require_GET
def check_otp_status(request):
    """Check OTP verification status"""
    otp_id = request.GET.get('otp_id')
    if not otp_id:
        return JsonResponse({'success': False, 'message': 'No OTP ID provided'})
    
    try:
        otp = OTPVerification.objects.get(id=otp_id)
        return JsonResponse({
            'success': True,
            'is_expired': otp.is_expired(),
            'attempts_remaining': otp.max_attempts - otp.attempts,
            'is_verified': otp.is_verified
        })
    except OTPVerification.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Invalid OTP'})

# Enhanced login view with better error handling
def new_login_view(request):
    # Redirect if already logged in
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        
        if not username or not password:
            messages.error(request, 'Please enter both username and password.')
            return render(request, 'chat/login.html')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            if user.is_active:
                login(request, user)
                
                # Update user profile status
                if hasattr(user, 'profile'):
                    user.profile.online = True
                    user.profile.save()
                
                # Redirect to next page or dashboard
                next_page = request.GET.get('next', 'dashboard')
                return redirect(next_page)
            else:
                messages.error(request, 'Your account has been deactivated.')
        else:
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'chat/new_login.html')

# Clean up expired OTPs (call this periodically via management command)
def cleanup_expired_otps():
    """Clean up expired OTP verifications"""
    expired_otps = OTPVerification.objects.filter(
        expires_at__lt=timezone.now()
    )
    count = expired_otps.count()
    expired_otps.delete()
    return count