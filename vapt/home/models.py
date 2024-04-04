from django.db import models

# Create your models here.
class Contact(models.Model):
    name = models.CharField(max_length=122)
    email = models.CharField(max_length=122)
    subject = models.CharField(max_length=122)
    message = models.TextField()
    date = models.DateField()
    
    def __str__(self):
        return self.name
    
class MyModel(models.Model):
    my_field = models.CharField(max_length=50, default='my default value')

class Website(models.Model):
    url = models.URLField()
    subdirectories = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url
   


class SSLScanResult(models.Model):
    url = models.URLField()
    result = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)  
    


class Subdomain(models.Model):
    url = models.CharField(max_length=255)
    subdomains = models.TextField()

    def __str__(self):
        return self.url

    

class PortScanResult(models.Model):
    target_host = models.CharField(max_length=255)
    open_ports = models.TextField()
    scan_time = models.DateTimeField(auto_now_add=True) 
    
class DnsReconResult(models.Model):
    url = models.CharField(max_length=255)
    dns_record = models.CharField(max_length=255)
    dns_value = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.url} - {self.dns_record}: {self.dns_value}'   


class WebsiteInfo(models.Model):
    url = models.CharField(max_length=255)
    info = models.TextField(default='') # Add a default value here
    created_at = models.DateTimeField(auto_now_add=True)
    
    
class DNSServer(models.Model):
    domain = models.CharField(max_length=255)
    ip_address = models.CharField(max_length=255)
    hostname = models.CharField(max_length=255)
    provider = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.domain} - {self.ip_address}'

    class Meta:
        ordering = ['-created_at']  