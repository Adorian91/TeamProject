from django.conf.urls import patterns, include, url
from django.conf.urls.static import static
from django.conf import settings
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^admin/', include(admin.site.urls)),
    (r'^polls/', 'polls.views.detail'),
    (r'^login/$', 'polls.views.custom_login'),
    (r'^logout/$', 'django.contrib.auth.views.logout', {'next_page': '/loggedout/'}),
    (r'^/$', 'django.contrib.auth.views.logout'),
    (r'^about/$', 'polls.views.about'),
    (r'^contact/$', 'polls.views.contact'),
    (r'^loggedout/$', 'polls.views.logout_view'),
    (r'^index/$', 'polls.views.index'),
)

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root = settings.STATIC_ROOT)
    # urlpatterns += static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)
