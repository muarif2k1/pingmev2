from django.urls import path
from . import views

urlpatterns = [
    # Authentication URLs
    path('', views.dashboard, name='dashboard'),
    # path('register/', views.register_view, name='register'),
    # path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Profile URLs
    path('profile/', views.profile_view, name='profile'),
    path('profile/<int:user_id>/', views.profile_view, name='user_profile'),
    
    # Friend system URLs
    path('friends/', views.friends_list, name='friends_list'),
    path('search-users/', views.search_users, name='search_users'),
    path('send-friend-request/', views.send_friend_request, name='send_friend_request'),
    path('respond-friend-request/', views.respond_friend_request, name='respond_friend_request'),
    path('remove-friend/', views.remove_friend, name='remove_friend'),
    
    # Chat URLs
    path('chat/<int:user_id>/', views.private_chat_view, name='private_chat'),
    path('rooms/', views.room_list, name='room_list'),
    path('room/<uuid:room_id>/', views.room_view, name='room_view'),
    path('create-room/', views.create_room, name='create_room'),
    path('room/delete/', views.delete_room, name='delete_room'),
    path('room/leave/', views.leave_room, name='leave_room'),
    
    # Message handling URLs
    path('send-message/', views.send_message, name='send_message'),
    path('delete-message/', views.delete_message, name='delete_message'),
    path('edit-message/', views.edit_message, name='edit_message'),
    path('mark-message-read/', views.mark_message_as_read, name='mark_message_as_read'),
    
    # API URLs
    path('api/chat/<uuid:chat_id>/messages/', views.get_chat_messages, name='get_chat_messages'),
    path('api/room/<uuid:room_id>/messages/', views.get_room_messages, name='get_room_messages'),
    path('api/unread-counts/', views.get_unread_counts, name='get_unread_counts'),

    # Invitation URLs
    path('invitations/', views.my_invitations, name='my_invitations'),
    path('invitations/respond/', views.respond_to_invitation, name='respond_to_invitation'),
    
    # User search and invitation URLs
    path('search-users-invite/', views.search_users_for_invite, name='search_users_for_invite'),
    path('invite-users/', views.invite_users_to_room, name='invite_users_to_room'),

    # Enhanced Authentication URLs with OTP
    path('register/', views.register_step1, name='register_step1'),
    path('register/verify/', views.register_step2, name='register_step2'),
    path('login/', views.new_login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Password Reset URLs
    path('password-reset/', views.password_reset_request, name='password_reset_request'),
    path('password-reset/verify/', views.password_reset_verify, name='password_reset_verify'),
    path('password-reset/confirm/', views.password_reset_confirm, name='password_reset_confirm'),
    
    # AJAX URLs
    path('api/resend-otp/', views.resend_otp, name='resend_otp'),
    path('api/check-otp-status/', views.check_otp_status, name='check_otp_status'),

    path('about/', views.about_view, name='about'),
    path('support-tickets/', views.support_tickets_view, name='support_tickets'),
]

