from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, Account, CoinHistory


class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'phone_number', 'is_staff')
    fieldsets = UserAdmin.fieldsets + (
        ('Extra Fields', {'fields': ('phone_number', 'failed_login_attempts', 'last_failed_attempt', 'locked_until')}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Extra Fields', {'fields': ('email', 'phone_number')}),
    )
    search_fields = ('username', 'email', 'phone_number')

class AccountAdmin(admin.ModelAdmin):
    list_display = ('account_holder_name', 'account_number', 'account_id', 'gui_balance', 'user')
    search_fields = ('account_holder_name', 'account_number', 'account_id')

class CoinHistoryAdmin(admin.ModelAdmin):
    list_display = ('transaction_id', 'user', 'transaction_type', 'coins', 'created_at')
    list_filter = ('transaction_type', 'user')
    search_fields = ('transaction_id', 'user__username', 'reason')
    readonly_fields = ('transaction_id', 'created_at')
    date_hierarchy = 'created_at'
    
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Account, AccountAdmin)
admin.site.register(CoinHistory, CoinHistoryAdmin)