from django import forms
from .models import CoinHistory, SenderDetails, CustomUser

class CoinHistoryForm(forms.ModelForm):
    class Meta:
        model = CoinHistory
        fields = ['user', 'coins', 'transaction_type']

class SenderWebhookForm(forms.ModelForm):
    class Meta:
        model = SenderDetails
        fields = ['sender_id', 'webhook_url']
        
class SenderDetailsForm(forms.ModelForm):
    user = forms.ModelChoiceField(
        queryset=CustomUser.objects.all(),
        widget=forms.Select(attrs={'class': 'form-control'}),
        label="User"
    )
    
    class Meta:
        model = SenderDetails
        fields = ['user', 'sender_id', 'webhook_url', 'optional_value_one', 
                 'optional_value_two', 'optional_value_three']
        widgets = {
            'sender_id': forms.TextInput(attrs={'class': 'form-control'}),
            'webhook_url': forms.URLInput(attrs={'class': 'form-control'}),
            'optional_value_one': forms.TextInput(attrs={'class': 'form-control'}),
            'optional_value_two': forms.TextInput(attrs={'class': 'form-control'}),
            'optional_value_three': forms.TextInput(attrs={'class': 'form-control'}),
        }