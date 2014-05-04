from django import template
register = template.Library()

@register.filter(name='hexed')
def hexed(fp):
    hexed = "\\x"
    for c in fp:
        hexed += ('%2s' % hex(ord(c))[2:]).replace(' ', '0')
    return hexed

