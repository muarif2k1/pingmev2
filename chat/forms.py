from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, SetPasswordForm
from django.core.exceptions import ValidationError
from .models import UserProfile, Room, Message, RoomInvitation, OTPVerification, PasswordResetRequest
import os
import re


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
    


class EmailRegistrationForm(forms.Form):
    """Initial registration form - collects user data and sends OTP"""
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Username'
        })
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Email'
        })
    )
    first_name = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'First Name'
        })
    )
    last_name = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Last Name'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Password'
        }),
        min_length=8
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm Password'
        })
    )
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise ValidationError("A user with this username already exists.")
        
        # Username validation
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            raise ValidationError("Username can only contain letters, numbers, and underscores.")
        
        return username
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError("A user with this email already exists.")
        return email
    
    def clean_password(self):
        password = self.cleaned_data.get('password')
        
        # Password strength validation
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long.")
        
        if not re.search(r'[A-Z]', password):
            raise ValidationError("Password must contain at least one uppercase letter.")
        
        if not re.search(r'[a-z]', password):
            raise ValidationError("Password must contain at least one lowercase letter.")
        
        if not re.search(r'\d', password):
            raise ValidationError("Password must contain at least one number.")
        
        return password
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        
        if password and confirm_password and password != confirm_password:
            raise ValidationError("Passwords don't match.")
        
        return cleaned_data


class OTPVerificationForm(forms.Form):
    """Form for OTP verification"""
    otp_code = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-control text-center',
            'placeholder': '000000',
            'style': 'font-size: 1.5rem; letter-spacing: 0.5rem;',
            'maxlength': '6',
            'autocomplete': 'off'
        })
    )
    
    def __init__(self, *args, **kwargs):
        self.otp_verification = kwargs.pop('otp_verification', None)
        super().__init__(*args, **kwargs)
    
    def clean_otp_code(self):
        otp_code = self.cleaned_data.get('otp_code')
        
        if not otp_code or not otp_code.isdigit():
            raise ValidationError("OTP must be a 6-digit number.")
        
        if len(otp_code) != 6:
            raise ValidationError("OTP must be exactly 6 digits.")
        
        # Verify OTP if verification object is provided
        if self.otp_verification:
            is_valid, message = self.otp_verification.verify_otp(otp_code)
            if not is_valid:
                raise ValidationError(message)
        
        return otp_code


class PasswordResetRequestForm(forms.Form):
    """Form to request password reset"""
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email address'
        })
    )
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        try:
            user = User.objects.get(email=email)
            self.user = user
        except User.DoesNotExist:
            raise ValidationError("No account found with this email address.")
        return email


class PasswordResetConfirmForm(SetPasswordForm):
    """Form to set new password after OTP verification"""
    new_password1 = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'New Password'
        }),
        strip=False,
        help_text="Password must be at least 8 characters long and contain uppercase, lowercase, and numbers."
    )
    new_password2 = forms.CharField(
        label="Confirm new password",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm New Password'
        }),
        strip=False,
    )
    
    def clean_new_password1(self):
        password = self.cleaned_data.get('new_password1')
        
        # Password strength validation
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long.")
        
        if not re.search(r'[A-Z]', password):
            raise ValidationError("Password must contain at least one uppercase letter.")
        
        if not re.search(r'[a-z]', password):
            raise ValidationError("Password must contain at least one lowercase letter.")
        
        if not re.search(r'\d', password):
            raise ValidationError("Password must contain at least one number.")
        
        return password


class ResendOTPForm(forms.Form):
    """Form to resend OTP"""
    email = forms.EmailField(widget=forms.HiddenInput())
    otp_type = forms.CharField(widget=forms.HiddenInput())
    
    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        otp_type = cleaned_data.get('otp_type')
        
        if not email or not otp_type:
            raise ValidationError("Missing required information.")
        
        return cleaned_data


class ContactForm(forms.Form):
    """Contact form for support"""
    name = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Your Name'
        })
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Your Email'
        })
    )
    subject = forms.CharField(
        max_length=200,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Subject'
        })
    )
    message = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'placeholder': 'Your message...',
            'rows': 5
        })
    )