from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),
    path('sender-details/', views.sender_details_list, name='sender_details_list'),
    path('sender-details/create/', views.create_sender_details, name='create_sender_details'),
    path('sender-details/<int:pk>/edit/', views.edit_sender_details, name='edit_sender_details'),
    path('sender-details/<int:pk>/delete/', views.delete_sender_details, name='delete_sender_details'),
]