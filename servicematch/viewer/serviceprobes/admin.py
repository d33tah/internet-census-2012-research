from django.contrib import admin
from django import forms
from serviceprobes.models import OperatingSystem, Vendor, DeviceType, Service, Payload, Product
from django.db import models

#from serviceprobes.apply_regex import apply_regex_global

make_textarea_use_textinput = {
    models.TextField: {'widget': forms.TextInput}
}

class OperatingSystemAdmin(admin.ModelAdmin):
    list_display = ('os', )
    formfield_overrides = make_textarea_use_textinput

class VendorAdmin(admin.ModelAdmin):
    list_display = ('vendor', )
    formfield_overrides = make_textarea_use_textinput

class DeviceTypeAdmin(admin.ModelAdmin):
    list_display = ('devicetype', )
    formfield_overrides = make_textarea_use_textinput

class ServiceAdmin(admin.ModelAdmin):
    list_display = ('service', )
    formfield_overrides = make_textarea_use_textinput

class PayloadAdmin(admin.ModelAdmin):
    list_display = ('payload', )
    formfield_overrides = make_textarea_use_textinput

from apply_regex import apply_regex_global
from django.db import transaction
from django.db import connection as conn
from serviceprobes.models import run_query
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
        product_ids = map(str, queryset.values_list('product_id', flat=True))
        first_product_id = product_ids[0]
        remaining_product_ids = product_ids[1:]
        with transaction.commit_manually():
            try:
                cur = conn.cursor()
                cur.execute("""UPDATE precomputed_product_rdns_count p
                                   SET count=(SELECT SUM(count)
                                              FROM precomputed_product_rdns_count
                                              WHERE product_id IN %s
                                             )
                                   WHERE product_id=%s""",
                          (tuple(product_ids),
                           first_product_id)
                         )
                cur.execute("""DELETE FROM precomputed_product_rdns_count
                                   WHERE product_id IN %s""",
                          (tuple(remaining_product_ids),)
                         )
                cur.execute("""UPDATE precomputed_product_rdns_aggregate p
                                   SET sum=(SELECT SUM(sum)
                                              FROM precomputed_product_rdns_aggregate
                                              WHERE product_id IN %s
                                             )
                                   WHERE product_id=%s""",
                          (tuple(product_ids),
                           first_product_id)
                         )
                cur.execute("""UPDATE precomputed_product_rdns_aggregate p
                                   SET sld_count=(SELECT SUM(sld_count)
                                              FROM precomputed_product_rdns_aggregate
                                              WHERE product_id IN %s
                                             )
                                   WHERE product_id=%s""",
                          (tuple(product_ids),
                           first_product_id)
                         )
                cur.execute("""DELETE FROM precomputed_product_rdns_aggregate
                                 WHERE product_id in %s""",
                          (tuple(remaining_product_ids),)
                         )
                cur.execute("""UPDATE product_proxy
                                   SET product_id=%s
                                   WHERE product_id IN %s""",
                          (first_product_id, tuple(remaining_product_ids),)
                         )
                cur.execute("""DELETE FROM product
                                 WHERE product_id in %s""",
                          (tuple(remaining_product_ids),)
                         )
                transaction.commit()
                self.message_user(request, "Product merging successful.")
            finally:
                transaction.rollback()


admin.site.register(Vendor, VendorAdmin)
admin.site.register(DeviceType, DeviceTypeAdmin)
#admin.site.register(Service, ServiceAdmin)
#admin.site.register(Payload, PayloadAdmin)
admin.site.register(Product, ProductAdmin)
