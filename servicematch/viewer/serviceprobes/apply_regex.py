from django import forms
from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.contrib.admin.helpers import ACTION_CHECKBOX_NAME
from django.db import transaction
import re

class RegexForm(forms.Form):
    _selected_action = forms.CharField(widget=forms.MultipleHiddenInput)
    from_regex = forms.CharField(label='From', required=True)
    to_regex = forms.CharField(label='To', required=True)
    #flags = forms.CharField(label='Flags')

def apply_regex_global(admin, request, queryset, fieldname):
    _selected_action = map(str, queryset.values_list('product_id', flat=True))
    form = None
    if 'apply' in request.POST:
        form = RegexForm(request.POST)
        if form.is_valid():
            with transaction.commit_manually():
                try:
                    for o in queryset:
                        old_value = getattr(o, fieldname)
                        new_value = re.sub(form.data['from_regex'],
                                           form.data['to_regex'], old_value)
                        setattr(o, fieldname, new_value)
                        o.save()
                    transaction.commit()
                finally:
                    transaction.rollback()
            admin.message_user(request, "Successfully applied a regex.")
            return HttpResponseRedirect(request.get_full_path())
    if not form:
        form = RegexForm(initial={'_selected_action': _selected_action})
    return render(request, "apply_regex.html", {
        'form': form,
        'title': 'Apply regex'}
    )
