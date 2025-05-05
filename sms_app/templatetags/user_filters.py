from django import template

register = template.Library()

@register.filter
def get_nested_value(dictionary, key):
    """
    Custom template filter to safely get a nested value from a dictionary.
    Usage: {{ user.mt_messaging_cred.authorization|get_nested_value:'http_send' }}
    """
    if not dictionary or not isinstance(dictionary, dict):
        return ""
    
    return dictionary.get(key, "")