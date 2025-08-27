from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from .models import UserProfile, Room, Message, RoomInvitation
import os

class UserRegistrationForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Password'
        })
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm Password'
        })
    )
    
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Username'
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'Email'
            }),
            'first_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'First Name'
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Last Name'
            }),
        }
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        
        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError("Passwords don't match")
        
        return cleaned_data

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['date_of_birth', 'profile_photo', 'bio', 'location']
        widgets = {
            'date_of_birth': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date'
            }),
            'profile_photo': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': 'image/*'
            }),
            'bio': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Tell us about yourself...'
            }),
            'location': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Your location'
            }),
        }

class RoomCreationForm(forms.ModelForm):
    class Meta:
        model = Room
        fields = ['name', 'description', 'is_private', 'password']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Room Name'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Room Description (optional)'
            }),
            'is_private': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'password': forms.PasswordInput(attrs={
                'class': 'form-control',
                'placeholder': 'Password (optional)'
            }),
        }
    
    def clean_name(self):
        name = self.cleaned_data['name']
        if Room.objects.filter(name=name).exists():
            raise forms.ValidationError("A room with this name already exists.")
        return name

# class MessageForm(forms.ModelForm):
#     class Meta:
#         model = Message
#         fields = ['content']
#         widgets = {
#             'content': forms.TextInput(attrs={
#                 'class': 'form-control',
#                 'placeholder': 'Type your message...',
#                 'autocomplete': 'off'
#             })
#         }

class SearchUserForm(forms.Form):
    query = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search users...'
        })
    )


class MessageForm(forms.ModelForm):
    class Meta:
        model = Message
        fields = ['content', 'image', 'file']
        widgets = {
            'content': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Type your message...',
                'autocomplete': 'off'
            }),
            'image': forms.FileInput(attrs={
                'accept': 'image/*',
                'class': 'form-control'
            }),
            'file': forms.FileInput(attrs={
                'class': 'form-control'
            }),
        }
    
    def clean(self):
        cleaned_data = super().clean()
        content = cleaned_data.get('content', '').strip()
        image = cleaned_data.get('image')
        file = cleaned_data.get('file')
        
        # At least one of content, image, or file must be provided
        if not content and not image and not file:
            raise ValidationError("Please provide a message, image, or file.")
        
        # Don't allow both image and file
        if image and file:
            raise ValidationError("Please upload either an image or a file, not both.")
        
        return cleaned_data
    
    def clean_image(self):
        image = self.cleaned_data.get('image')
        if image:
            # Check file size (max 10MB)
            if image.size > 10 * 1024 * 1024:
                raise ValidationError("Image file size cannot exceed 10MB.")
            
            # Check file extension
            valid_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
            ext = os.path.splitext(image.name)[1].lower()
            if ext not in valid_extensions:
                raise ValidationError("Please upload a valid image file (JPG, PNG, GIF, WebP).")
        
        return image
    
    def clean_file(self):
        file = self.cleaned_data.get('file')
        if file:
            # Check file size (max 25MB)
            if file.size > 25 * 1024 * 1024:
                raise ValidationError("File size cannot exceed 25MB.")
            
            # Check for potentially dangerous files
            dangerous_extensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com']
            ext = os.path.splitext(file.name)[1].lower()
            if ext in dangerous_extensions:
                raise ValidationError("This file type is not allowed for security reasons.")
        
        return file

class RoomInvitationForm(forms.ModelForm):
    user_ids = forms.CharField(widget=forms.HiddenInput())
    
    class Meta:
        model = RoomInvitation
        fields = ['message']
        widgets = {
            'message': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Optional invitation message...',
                'rows': 3
            })
        }
    
    def __init__(self, *args, **kwargs):
        self.room = kwargs.pop('room', None)
        self.invited_by = kwargs.pop('invited_by', None)
        super().__init__(*args, **kwargs)
    
    def clean_user_ids(self):
        user_ids = self.cleaned_data.get('user_ids', '')
        if not user_ids:
            raise ValidationError("No users selected for invitation.")
        
        try:
            user_id_list = [int(uid) for uid in user_ids.split(',') if uid.strip()]
        except ValueError:
            raise ValidationError("Invalid user IDs.")
        
        if not user_id_list:
            raise ValidationError("No valid users selected.")
        
        return user_id_list