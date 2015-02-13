from django.contrib import admin
from django import forms
from serviceprobes.models import OperatingSystem, Vendor, DeviceType, Service, Payload, Product
from django.db import models
from apply_regex import apply_regex_global
#from serviceprobes.apply_regex import apply_regex_global

make_textarea_use_textinput = {
    models.TextField: {'widget': forms.TextInput}
}

class OperatingSystemAdmin(admin.ModelAdmin):
    list_display = ('os', )
    formfield_overrides = make_textarea_use_textinput
admin.site.register(OperatingSystem, OperatingSystemAdmin)

class VendorAdmin(admin.ModelAdmin):
    list_display = ('vendor', )
    formfield_overrides = make_textarea_use_textinput
admin.site.register(Vendor, VendorAdmin)

class DeviceTypeAdmin(admin.ModelAdmin):
    list_display = ('devicetype', )
    formfield_overrides = make_textarea_use_textinput
admin.site.register(DeviceType, DeviceTypeAdmin)

class ServiceAdmin(admin.ModelAdmin):
    list_display = ('service', )
    formfield_overrides = make_textarea_use_textinput
admin.site.register(Service, ServiceAdmin)

class PayloadAdmin(admin.ModelAdmin):
    list_display = ('payload', )
    formfield_overrides = make_textarea_use_textinput
admin.site.register(Payload, PayloadAdmin)

class ProductAdmin(admin.ModelAdmin):
    list_per_page = 100
    list_display = ('product', 'vendor', 'devicetype', 'domains_with_product',
                    'pattern_lines')
    search_fields = ['product', ]
    formfield_overrides = make_textarea_use_textinput
    readonly_fields = ['domains_with_product', 'pattern_lines']

    actions = ['apply_regex', 'merge']
    def apply_regex(self, request, queryset):
        return apply_regex_global(self, request, queryset, "product")

    def domains_with_product(self, obj):
        return '''<a href="/view_product?product_id={}">List
                domains</a>'''.format(obj.product_id)
    domains_with_product.allow_tags = True

    def pattern_lines(self, obj):
        lines_as_str = map(str, obj.pattern_lines())
        ret = ""
        for line in lines_as_str:
            if ret != "":
                 ret += ", "
            ret += ("<a href='/static/nmap-service-" +
                    "probes-r33771.html#L%s'>%s</a>") % (line, line)
        return ret
    pattern_lines.allow_tags = True

    def merge(self, request, queryset):
        # take first ID
        #   update match
        #   sum precomputed_product_eld_count and precomputed_product_eld_agg
        # remove remaining
        return None

admin.site.register(Product, ProductAdmin)
