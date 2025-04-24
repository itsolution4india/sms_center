from django.db import models
from django.contrib.auth.models import AbstractUser
import random
import string

class CustomUser(AbstractUser):
    created_at = models.DateTimeField(auto_now_add=True)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=13)
    failed_login_attempts = models.IntegerField(default=0)
    last_failed_attempt = models.DateTimeField(null=True, blank=True)
    locked_until = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.username
    
class Account(models.Model):
    account_number = models.CharField(max_length=16)
    account_holder_name = models.CharField(max_length=255)
    account_id = models.CharField(max_length=255, unique=True)
    gui_balance = models.DecimalField(max_digits=12, decimal_places=4)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.account_holder_name} - {self.account_number}"
    
class CoinHistory(models.Model):
    TRANSACTION_TYPE_CHOICES = [
        ('credit', 'Credit'),
        ('debit', 'Debit'),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    coins = models.DecimalField(max_digits=12, decimal_places=4)
    reason = models.TextField()
    transaction_id = models.CharField(max_length=16, unique=True)
    transaction_type = models.CharField(max_length=6, choices=TRANSACTION_TYPE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.transaction_id:
            self.transaction_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        super(CoinHistory, self).save(*args, **kwargs)

    def __str__(self):
        return f"Transaction {self.transaction_id} - {self.user.username}"
    
class SenderDetails(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    sender_id = models.CharField(max_length=20, unique=True)
    webhook_url = models.URLField()
    optional_value_one = models.CharField(max_length=100, blank=True, null=True)
    optional_value_two = models.CharField(max_length=100, blank=True, null=True)
    optional_value_three = models.CharField(max_length=100, blank=True, null=True)
    
    def __str__(self):
        return f"{self.sender_id} → {self.webhook_url}"