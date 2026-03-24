from django import template

register = template.Library()


@register.filter(name='split')
def split(value, arg):
    if isinstance(value, str):
        return value.split(arg)
    return value
