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
    path('manage-jasmin-users/', views.list_jasmin_users, name='list_users'),
    path('users/add/', views.add_user, name='add_user'),
    path('users/delete/<str:uid>/', views.delete_jasmin_user, name='delete_user'),
    path('report-analytics/', views.user_list, name='user_list'),
    path('analytics/<str:username>/', views.user_analytics, name='user_analytics'),
    path('api/analytics/', views.get_analytics_data, name='get_analytics_data'),
    path('manage-whatsapp-users/', views.list_users, name='list_users'),
    path('create/', views.create_user, name='create_user'),
    path('edit/<str:username>/', views.edit_user, name='edit_user'),
    path('delete/<str:username>/', views.delete_user, name='delete_user'),
    path('balance/', views.credit_debit_coins, name='coin_transaction'),
]