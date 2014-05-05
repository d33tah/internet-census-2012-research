import string
from django import template
register = template.Library()

@register.filter(name='isbinary')
def isbinary(fp):
    return set(fp).difference(set(string.printable).union(set(string.whitespace))) != set()
