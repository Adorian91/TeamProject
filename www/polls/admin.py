from django.contrib import admin
from polls.models import Poll
from polls.models import Choice

admin.site.register(Choice)
admin.site.register(Poll)