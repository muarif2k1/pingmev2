from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.utils import timezone
from django.core.files.storage import default_storage
from django.urls import reverse
from .models import UserProfile, Friendship, PrivateChat, Room, Message, RoomParticipant, ChatParticipant, RoomInvitation
from .forms import UserRegistrationForm, UserProfileForm, RoomCreationForm, MessageForm
from django.http import FileResponse, Http404
from django.conf import settings
import json
import os

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
    
    # Check if friendship already exists
    existing = Friendship.objects.filter(
        Q(from_user=request.user.profile, to_user=target_user.profile) |
        Q(from_user=target_user.profile, to_user=request.user.profile)
    ).first()
    
    if existing:
        return JsonResponse({'success': False, 'message': 'Friendship already exists'})
    
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
    
    # Check if users are friends or allow any user to chat
    # if not request.user.profile.are_friends(other_user.profile):
    #     messages.error(request, 'You can only chat with friends!')
    #     return redirect('dashboard')
    
    chat, created = PrivateChat.get_or_create_chat(request.user, other_user)
    
    # Get or create chat participant for current user
    participant, _ = ChatParticipant.objects.get_or_create(
        private_chat=chat,
        user=request.user
    )
    
    # Get messages
    messages_list = chat.messages.filter(is_deleted=False).order_by('timestamp')
    
    # Mark as read
    participant.last_read = timezone.now()
    participant.save()
    
    context = {
        'chat': chat,
        'other_user': other_user,
        'chat_messages': messages_list,
        'form': MessageForm()
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
    
    # Get messages
    messages_list = room.messages.filter(is_deleted=False).order_by('timestamp')
    
    # Update last read
    participant.last_read = timezone.now()
    participant.save()
    
    context = {
        'room': room,
        'chat_messages': messages_list,
        'participant': participant,
        'form': MessageForm()
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

# # AJAX Views for messaging
# @require_POST
# @login_required
# def send_message(request):
#     message_type = request.POST.get('type')  # 'private' or 'room'
#     content = request.POST.get('content', '').strip()
    
#     if not content:
#         return JsonResponse({'success': False, 'message': 'Message cannot be empty'})
    
#     if message_type == 'private':
#         chat_id = request.POST.get('chat_id')
#         chat = get_object_or_404(PrivateChat, id=chat_id)
        
#         # Check if user is part of this chat
#         if not (chat.user1 == request.user or chat.user2 == request.user):
#             return JsonResponse({'success': False, 'message': 'Access denied'})
        
#         message = Message.objects.create(
#             private_chat=chat,
#             user=request.user,
#             content=content
#         )
        
#         # Update chat timestamp
#         chat.updated_at = timezone.now()
#         chat.save()
        
#     elif message_type == 'room':
#         room_id = request.POST.get('room_id')
#         room = get_object_or_404(Room, id=room_id)
        
#         # Check access
#         if room.is_private and not (
#             room.creator == request.user or 
#             room.participants.filter(user=request.user).exists()
#         ):
#             return JsonResponse({'success': False, 'message': 'Access denied'})
        
#         message = Message.objects.create(
#             room=room,
#             user=request.user,
#             content=content
#         )
    
#     return JsonResponse({
#         'success': True,
#         'message_id': str(message.id),
#         'content': message.content,
#         'username': message.user.username,
#         'timestamp': message.timestamp.strftime('%H:%M')
#     })

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
            'timestamp': message.timestamp.strftime('%H:%M'),
            'message_type': message.message_type
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
def delete_message(request):
    message_id = request.POST.get('message_id')
    message = get_object_or_404(Message, id=message_id, user=request.user)
    
    message.soft_delete()
    
    return JsonResponse({'success': True, 'message': 'Message deleted'})

@require_POST
@login_required
def edit_message(request):
    message_id = request.POST.get('message_id')
    new_content = request.POST.get('content', '').strip()
    
    if not new_content:
        return JsonResponse({'success': False, 'message': 'Content cannot be empty'})
    
    message = get_object_or_404(Message, id=message_id, user=request.user)
    message.edit_message(new_content)
    
    return JsonResponse({
        'success': True,
        'content': message.content,
        'edited_at': message.edited_at.strftime('%H:%M')
    })


@login_required
def get_chat_messages(request, chat_id):
    chat = get_object_or_404(PrivateChat, id=chat_id)
    
    if not (chat.user1 == request.user or chat.user2 == request.user):
        return JsonResponse({'error': 'Access denied'}, status=403)
    
    messages_list = chat.messages.filter(is_deleted=False).order_by('timestamp')
    
    messages_data = []
    for msg in messages_list:
        message_data = {
            'id': str(msg.id),
            'content': msg.content,
            'username': msg.user.username,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'is_own': msg.user == request.user,
            'edited': msg.edited,
            'message_type': msg.message_type
        }
        
        # Add file information
        if msg.message_type == 'IMAGE' and msg.image:
            message_data['file_url'] = msg.image.url
            message_data['file_name'] = msg.get_file_name()
        elif msg.message_type == 'FILE' and msg.file:
            message_data['file_url'] = msg.file.url
            message_data['file_name'] = msg.get_file_name()
        
        messages_data.append(message_data)
    
    return JsonResponse({'messages': messages_data})


@login_required
def get_room_messages(request, room_id):
    room = get_object_or_404(Room, id=room_id)
    
    # Check access
    if room.is_private and not (
        room.creator == request.user or 
        room.participants.filter(user=request.user).exists()
    ):
        return JsonResponse({'error': 'Access denied'}, status=403)
    
    messages_list = room.messages.filter(is_deleted=False).order_by('timestamp')
    
    messages_data = []
    for msg in messages_list:
        message_data = {
            'id': str(msg.id),
            'content': msg.content,
            'username': msg.user.username,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'is_own': msg.user == request.user,
            'edited': msg.edited,
            'message_type': msg.message_type
        }
        
        # Add file information
        if msg.message_type == 'IMAGE' and msg.image:
            message_data['file_url'] = msg.image.url
            message_data['file_name'] = msg.get_file_name()
        elif msg.message_type == 'FILE' and msg.file:
            message_data['file_url'] = msg.file.url
            message_data['file_name'] = msg.get_file_name()
        
        messages_data.append(message_data)
    
    return JsonResponse({'messages': messages_data})



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
