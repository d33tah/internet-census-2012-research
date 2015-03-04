from django.conf.urls import patterns, include, url

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    url(r'^$', 'serviceprobes.views.index', name='index'),
    url(r'^show_ip$', 'serviceprobes.views.show_ip', name='show_ip'),
    url(r'^show_sld$', 'serviceprobes.views.show_sld', name='show_sld'),
    url(r'^one_ip$', 'serviceprobes.views.one_ip', name='one_ip'),
    url(r'^show_fp$', 'serviceprobes.views.show_fp', name='show_fp'),
    url(r'^get_pcap$', 'serviceprobes.views.get_pcap', name='get_pcap'),
    url(r'^product_list$', 'serviceprobes.views.product_list', name='product_list'),
    url(r'^view_product$', 'serviceprobes.views.view_product', name='view_product'),
    url(r'^by_eld$', 'serviceprobes.views.by_eld', name='by_eld'),
    url(r'^devicetypes_by_eld$', 'serviceprobes.views.devicetypes_by_eld', name='devicetypes_by_eld'),
    url(r'^distinct_products_for_rdns_by_kw$', 'serviceprobes.views.distinct_products_for_rdns_by_kw', name='distinct_products_for_rdns_by_kw'),
    # url(r'^serviceprobes/', include('serviceprobes.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),
    url(r'^admin/', include("massadmin.urls")),
)
