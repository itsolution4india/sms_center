from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path("logs/", views.view_logs, name="view_logs"),
    path('logout/', views.logout_view, name='logout'),
    path('sender-details/', views.sender_details_list, name='sender_details_list'),
    path('sender-details/create/', views.create_sender_details, name='create_sender_details'),
    path('sender-details/<int:pk>/edit/', views.edit_sender_details, name='edit_sender_details'),
    path('sender-details/<int:pk>/delete/', views.delete_sender_details, name='delete_sender_details'),
    path('manage-jasmin-users/', views.list_users, name='list_users'),
    path('users/add/', views.add_user, name='add_user'),
    path('users/delete/<str:uid>/', views.delete_user, name='delete_user'),
]