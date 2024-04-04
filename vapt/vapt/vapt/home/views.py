from django.shortcuts import render, HttpResponse,redirect
from datetime import datetime
from home.models import Contact
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from reportlab.pdfgen import canvas
from .forms import WebsiteForm
from .models import Website
from bs4 import BeautifulSoup, SoupStrainer
from .models import SSLScanResult
from .forms import SSLScanForm
from io import BytesIO
from subprocess import Popen, PIPE
from .forms import PortScanForm
from .models import PortScanResult
from .models import Subdomain
from .forms import DnsReconForm
from .models import DnsReconResult
from django.http import HttpResponse
from .models import WebsiteInfo
from .forms import WebsiteInfoForm
from .models import WebsiteInfo
import psycopg2
# Create your views here.
import subprocess
import tempfile
import pdfkit
import requests
import nmap
import re
import os 
import webbrowser
import sqlite3



def index(request):
    return render(request, 'index.html')


#find subdir
def find_subdirectories(url):
    subdirectories = []
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    for link in soup.find_all('a'):
        href = link.get('href')
        if href is not None and href.endswith('/'):
            subdirectories.append(href)
    return subdirectories

def store_subdirectories(url, subdirectories):
    website = Website(url=url, subdirectories='\n'.join(subdirectories))
    website.save()

def download_pdf(url):
    response = requests.get(url)
    if response.headers['Content-Type'] == 'application/pdf':
        content_disposition = response.headers['Content-Disposition']
        filename = content_disposition.split('=')[1]
        response = HttpResponse(response.content, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    else:
        return HttpResponse('Not a PDF')

def tool(request):
    if request.method == 'POST':
        url = request.POST['url']
        subdirectories = find_subdirectories(url)
        store_subdirectories(url, subdirectories)
        return render(request, 'result.html', {'subdirectories': subdirectories})
    else:
        return render(request, 'domain.html')

def pdf(request):
    if request.method == 'GET':
        url = request.GET['url']
        return download_pdf(url)
    else:
        return HttpResponse('Invalid request')  

#find subdomains
 


def get_subdomains(domain):
    subdomains = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        for d in data:
            subdomains.append(d['name_value'])
    return subdomains


def tool2(request):
    if request.method == 'POST':
        domain = request.POST.get('domain')
        subdomains = get_subdomains(domain)
        subdomains = sorted(set(subdomains))
        website = Subdomain(url=domain, subdomains='\n'.join(subdomains))
        website.save()
        return render(request, 'subdomainresult.html', {'subdomains': subdomains})
    else:
        return render(request, 'subdomain.html')

#find tcp port
def tool3(request):
    if request.method == 'POST':
        form = PortScanForm(request.POST)
        if form.is_valid():
            target_host = form.cleaned_data['target_host']
            nm = nmap.PortScanner()
            nm.scan(hosts=target_host, arguments='-p 1-65535')
            open_ports = []
            for host in nm.all_hosts():
                for port in nm[host]['tcp']:
                    if nm[host]['tcp'][port]['state'] == 'open':
                        open_ports.append(port)
            open_ports = ','.join(map(str, open_ports))
            result = PortScanResult(target_host=target_host, open_ports=open_ports)
            result.save()
            return render(request, 'port_scan_result.html', {'result': result})
    else:
        form = PortScanForm()
    return render(request, 'tcpscanner.html', {'form': form})

def port_scan_result(request):
    results = PortScanResult.objects.all()
    return render(request, 'port_scan_result.html', {'results': results})


#find udp ports
def scan_ports1(url):
    nm = nmap.PortScanner()
    nm.scan(url, arguments='-p 1-65535')
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append(port)
    return open_ports
def tool4(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        open_ports = scan_ports1(url)
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="open_ports.pdf"'
        p = canvas.Canvas(response)
        p.drawString(100, 750, f'Open TCP ports of {url}:')
        y = 700
        for port in open_ports:
            p.drawString(100, y, str(port))
            y -= 20
        p.showPage()
        p.save()
        return response
    return render(request, 'UDPScanner.html')

#xss scanner
def tool5(request):
       return render(request, 'XSSScanner.html')
   
   
#SSLscanner   
def tool6(request):
    if request.method == 'POST':
        form = SSLScanForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            # Run the SSL scan using sslyze
            process = Popen(['sslyze', 'target', url], stdout=PIPE)
            output, _ = process.communicate()
            result = output.decode('utf-8')
            # Save the scan result to the database
            scan_result = SSLScanResult.objects.create(url=url, result=result)
            # Generate a PDF report from the scan result
            buffer = BytesIO()
            report = canvas.Canvas(buffer)
            report.drawString(100, 750, f'SSL Scan Report for {url}')
            report.drawString(100, 700, result)
            report.save()
            buffer.seek(0)
            # Serve the PDF report as a download
            response = HttpResponse(buffer, content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename=ssl_scan_report_{scan_result.id}.pdf'
            return response
    else:
        form = SSLScanForm()
    return render(request, 'SSLScanner.html', {'form': form})
 

def tool7(request):
    if request.method == 'POST':
        form = DnsReconForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            # send POST request to DNSDumpster
            data = {'remoteAddress': url}
            response = requests.post('https://dnsdumpster.com/', data=data)
            # scrape DNS recon results
            soup = BeautifulSoup(response.content, 'html.parser')
            results_table = soup.find_all('table')[0]
            results_rows = results_table.find_all('tr')[1:]
            for row in results_rows:
                columns = row.find_all('td')
                dns_record = columns[0].text
                dns_value = columns[1].text
                DnsReconResult.objects.create(url=url, dns_record=dns_record, dns_value=dns_value)
            # display results to user
            results = DnsReconResult.objects.filter(url=url)
            return render(request, 'dns_info.html', {'results': results})
    else:
        form = DnsReconForm()
    return render(request, 'dnsscan.html', {'form': form})

def tool8(request):
    if request.method == 'POST':
        form = WebsiteInfoForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            result = subprocess.check_output(['vulnx', '-u', url])
            website_info = WebsiteInfo(url=url, info=result.decode('utf-8'))
            website_info.save()
            return render(request, 'website_info.html', {'result': website_info})
    else:
        form = WebsiteInfoForm()
    return render(request, 'webinfo.html', {'form': form})


 
 
 
 
 
 
 
 
 
 
 
def about(request):
    return render(request, 'about.html')
def services(request):
    return render(request, 'services.html')
def team(request):
    return render(request, 'team.html')
def contact(request):
    if request.method == "POST":
        name = request.POST.get('name')
        email = request.POST.get('email')
        subject = request.POST.get('subject')
        message = request.POST.get('message')
        contact = Contact(name=name, email=email, subject=subject, message=message, date= datetime.today())
        contact.save()
        messages.success(request, 'Your message has been sent.')
        
    return render(request, 'contact.html')

def handleSignup(request):
            if request.method == 'POST':
                username = request.POST['username']
                fname = request.POST['fname']
                lname = request.POST['lname']
                email = request.POST['email']
                pass1 = request.POST['pass1']
                pass2 = request.POST['pass2']   
                
                if len(username) > 10:
                    messages.error(request, "username must be under 10 characters")
                    return redirect('home')
                
                if not username.isalnum():
                    messages.error(request, "username should only contain letters and numbers")
                    return redirect('home')
                
                if pass1 != pass2:
                    messages.error(request, "password do not match")
                    return redirect('home')
                
                myuser = User.objects.create_user(username, email, pass1)
                myuser.first_name = fname
                myuser.last_name = lname
                myuser.save()
                messages.success(request, "your account has been successfully created")
                return redirect('home')
                
            else:

            
                 return render(request, 'signup.html')
    
def handleSignin(request):
        if request.method == 'POST':
            loginusername = request.POST['loginusername']
            loginpass = request.POST['loginpass'] 
        
            user  = authenticate(username=loginusername, password=loginpass)
        
            if user is not None:
                login(request, user)
                messages.success(request, "successfully logged In")
                return redirect('home')
            else:
                messages.error(request,"invalid credentials, please try again")
                return redirect('home')
        
           
        return render(request, 'signin.html')
        

def handleLogout(request):
        logout(request)
        messages.success(request, "successfully logout ")
        return redirect('home')
    