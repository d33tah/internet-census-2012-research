from django.conf.urls import patterns, include, url

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    url(r'^$', 'serviceprobes.views.index', name='index'),
    url(r'^show_ip$', 'serviceprobes.views.show_ip', name='show_ip'),
    url(r'^show_fp$', 'serviceprobes.views.show_fp', name='show_fp'),
    # url(r'^serviceprobes/', include('serviceprobes.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
)
