# views.py
from django.http import HttpResponse

def welcome_view(request):
    return HttpResponse("Welcome to our application!")
