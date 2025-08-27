from django import template

register = template.Library()

@register.filter
def get_other_user(chat, current_user):
    return chat.get_other_user(current_user)