from django.urls import path
from . import views

urlpatterns = [
    path('',               views.index,           name='dashboard'),
    path('requests/',      views.requests_view,   name='requests'),
    path('attacks/',       views.attacks_view,    name='attacks'),
    path('ml/',            views.ml_view,         name='ml'),
    path('ip-reputation/', views.ip_view,         name='ip'),
    path('exceptions/',    views.exceptions_view, name='exceptions'),
    path('alerts/',        views.alerts_view,     name='alerts'),
]
