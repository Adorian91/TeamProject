from django.conf.urls import patterns, include, url
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic.base import TemplateView

from django.contrib import admin
from polls import views
admin.autodiscover()


urlpatterns = patterns('',
    url(r'^$', views.polls, name='polls'),
    url(r'^(?P<pk>\d+)/$', views.DetailView.as_view(), name='detail'),
    url(r'^(?P<pk>\d+)/results/$', views.ResultsView.as_view(), name='results'),
    url(r'^(?P<poll_id>\d+)/vote/$', views.vote, name='vote'),
    # url(r'^polls/', include('polls.urls', namespace="polls")),
    url(r'^$', TemplateView.as_view(template_name='base.html')),
   # url(r'^polls/about/$', views.about, name='about'),

)

