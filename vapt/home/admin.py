from django.contrib import admin
from home.models import Contact
from home.models import Website
from home.models import SSLScanResult
from home.models import PortScanResult
from home.models import Subdomain
from home.models import DNSServer



admin.site.register(Contact)
admin.site.register(Website)
admin.site.register(SSLScanResult)
admin.site.register(Subdomain)
admin.site.register(PortScanResult)
admin.site.register(DNSServer)