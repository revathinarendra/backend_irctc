# views.py
from django.http import HttpResponse

def welcome_view(request):
    return HttpResponse("welcome to our applications")
