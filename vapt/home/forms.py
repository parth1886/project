from django import forms

class WebsiteForm(forms.Form):
    url = forms.URLField(label='Website URL ')


class SSLScanForm(forms.Form):
    url = forms.URLField(label='Website URL ')
    


class PortScanForm(forms.Form):
    target_host = forms.CharField(max_length=255)
    
class DnsReconForm(forms.Form):
    url = forms.URLField(label='Website URL')    
    
class WebsiteInfoForm(forms.Form):
    url = forms.CharField(label='Website URL', max_length=255)    