#-*- coding: utf-8 -*-
from django.shortcuts import render
from django.http import HttpResponseRedirect, Http404, HttpResponse
from django.template import Context, loader
from django.shortcuts import render_to_response, get_object_or_404
from polls.models import Choice, Poll
from django.core.urlresolvers import reverse
from django.views import generic
from django.contrib.auth import authenticate, login, logout
from django.template import RequestContext
from django.shortcuts import redirect
from django.contrib import messages
import ldap
import ldap.sasl


def index(request):
    return render(request, 'rest/index.html')


def polls(request):
    if request.user.is_authenticated():
        latest_poll_list = Poll.objects.all().order_by('-pub_date')[:5]
        return render_to_response('polls/polls.html', {'latest_poll_list': latest_poll_list})
    else:
        return redirect("/login")
        #return render(request, 'registration/login.html')
        #print "A"

def detail(request):
    if request.user.is_authenticated():
        try:
            p = Poll.objects.get(pk=1)
        except Poll.DoesNotExist:
            raise Http404
        return render_to_response('polls/detail.html', {'poll': p})
    else:
        return redirect("/login")

class DetailView(generic.DetailView):

    model = Poll
    template_name = 'polls/detail.html'



class ResultsView(generic.DetailView):
    model = Poll
    template_name = 'polls/results.html'


def vote(request, poll_id):
    p = get_object_or_404(Poll, pk=poll_id)
    try:
        selected_choice = p.choice_set.get(pk=request.POST['choice'])
    except (KeyError, Choice.DoesNotExist):
        # Redisplay the poll voting form.
        return render(request, 'polls/detail.html', {
            'poll': p,
            'error_message': "You didn't select a choice.",
        })
    else:
        selected_choice.votes += 1
        selected_choice.save()
        # Always return an HttpResponseRedirect after successfully dealing
        # with POST data. This prevents data from being posted twice if a
        # user hits the Back button.
        return HttpResponseRedirect(reverse('polls:results', args=(p.id,)))

def about(request):
    return render(request, 'rest/about.html')

def contact(request):
    return render(request, 'rest/contact.html')

def logout_view(request):
    messages.success(request, 'wylogowano')
    return render(request, 'registration/loggedout.html')

def my_view(request):
    return render(request,'registration/login.html')

##########################################################
##########################################################
from django.contrib.auth.models import User

def authenticate(username=None,password=None):
    if len(password) == 0:
        return None
    servers = ["ldap://dc1.labs.wmi.amu.edu.pl", "ldap://dc2.labs.wmi.amu.edu.pl"]
    suffix =  "@labs.wmi.amu.edu.pl";
    port = 636;
    root = "OU=Students,OU=People,DC=labs,DC=wmi,DC=amu,DC=edu,DC=pl";

    ldap.PORT = port

    ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, "./labs.wmi.amu.edu.pl.pem")
    for i in range(len(servers)):
        try:
            ldap_handler = ldap.initialize(servers[i])
            break
        except ldap.SERVER_DOWN, e:
            print e

    ldap_handler.set_option(ldap.OPT_X_TLS_DEMAND, True)
    ldap_handler.start_tls_s()

    try:
        if password:
            # authorized
            try:
                exists = ldap_handler.simple_bind_s(login, password)
                if exists:
                    user = User.objects.get_or_create(username=login, password=password)
                    return user
                else:
                    return None

            except ldap.INVALID_CREDENTIALS:
                print "Invalid credentials"
                exit(1)
        else:
            # anonymous
            return ldap_handler.bind_s('','', ldap.AUTH_SIMPLE)
    except ldap.LDAPError, e:
        return e

# from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login
from django import forms

class LoginForm(forms.Form):
    username = forms.CharField(max_length=20, label=u"Użytkownik")
    password = forms.CharField(widget=forms.PasswordInput, label=u"Hasło")

def custom_login(request):
	if request.method=="POST":
		form = LoginForm(request.POST)
		if form.is_valid():
			username = form.cleaned_data['username']
			password = form.cleaned_data['password']
			user = authenticate(username=username, password=password)
			if user is not None:
				if user.is_active:
					login(request, user)
					# Redirect to a success page.
			else:
				messages.error(request, "NIE MA CHUJA")
				return render(request, 'registration/login.html', {'form': form})
	else:
		form = LoginForm()
	return render(request, 'registration/login.html', {'form': form})


"""
def index(request):
    print "A"
    latest_poll_list = Poll.objects.all().order_by('-pub_date')[:5]
    return render_to_response('polls/index.html', {'latest_poll_list': latest_poll_list})




def results(request, poll_id):
    print "Results"
    p = get_object_or_404(Poll, pk=poll_id)
    return render_to_response('polls/results.html', {'poll': p})
"""
