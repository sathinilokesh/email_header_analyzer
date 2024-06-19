from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
import os
from fpdf import FPDF
import email
from email import policy
from email.parser import BytesParser
import re
from email.utils import parsedate_to_datetime
import json
from datetime import datetime
import requests
import dns.resolver
import logging

# Configure logging
logging.basicConfig(filename='email_analysis.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'eml'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def extract_email_headers(raw_email):
    try:
        headers = BytesParser(policy=policy.default).parsebytes(raw_email)
        return headers
    except Exception as e:
        logging.error(f"Error extracting email headers: {e}")
        raise

def analyze_email_headers(headers, raw_email):
    analysis = {}
    try:
        # Basic fields
        analysis['From'] = headers['From']
        analysis['To'] = headers['To']
        analysis['Subject'] = headers['Subject']
        analysis['Date'] = headers['Date']

        # Convert date to a datetime object
        if headers['Date']:
            analysis['Date_Parsed'] = parsedate_to_datetime(headers['Date'])

        # Received headers (for tracing the email path)
        analysis['Received'] = headers.get_all('Received', [])

        # Extract IP addresses from Received headers
        ip_addresses = []
        for received in analysis['Received']:
            ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', received)
            ip_addresses.extend(ips)
        analysis['IP_Addresses'] = ip_addresses
        analysis['IP_Info'] = analyze_ip_addresses(ip_addresses)

        # SPF, DKIM, DMARC
        from_domain = headers['From'].split('@')[-1]
        analysis['SPF'] = check_spf(from_domain)
        # DKIM and DMARC checks can be added similarly

        # Email content analysis
        analysis['Content'] = analyze_email_content(raw_email)

    except Exception as e:
        logging.error(f"Error analyzing email headers: {e}")
        raise

    return analysis

def default_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def generate_report(analysis, output_file='email_analysis_report.json'):
    with open(output_file, 'w') as f:
        json.dump(analysis, f, default=default_serializer, indent=4)

def analyze_ip_addresses(ip_addresses):
    ip_info = []
    for ip in ip_addresses:
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            if response.status_code == 200:
                ip_info.append(response.json())
            else:
                ip_info.append({"ip": ip, "error": "Unable to retrieve info"})
        except Exception as e:
            logging.error(f"Error retrieving IP info for {ip}: {e}")
            ip_info.append({"ip": ip, "error": str(e)})
    return ip_info

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if "v=spf1" in rdata.to_text():
                return rdata.to_text()
    except dns.resolver.NoAnswer:
        logging.error(f"No TXT record found for domain: {domain}")
        return "No TXT record found"
    except dns.resolver.NXDOMAIN:
        logging.error(f"Domain does not exist: {domain}")
        return "Domain does not exist"
    except dns.resolver.Timeout:
        logging.error(f"DNS query timed out for domain: {domain}")
        return "DNS query timed out"
    except Exception as e:
        logging.error(f"An error occurred while checking SPF for domain {domain}: {e}")
        return f"An error occurred: {e}"
    return "No SPF record found"

def analyze_email_content(raw_email):
    msg = email.message_from_bytes(raw_email)
    content = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                content = part.get_payload(decode=True).decode(errors='replace')
                break
    else:
        content = msg.get_payload(decode=True).decode(errors='replace')
    return content



class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Email Analysis Report', 0, 1, 'C')
        self.ln(10)

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(5)

    def chapter_body(self, body):
        self.set_font('Arial', '', 12)
        self.multi_cell(0, 10, body)
        self.ln()

    def add_section(self, title, content):
        self.chapter_title(title)
        
        if isinstance(content, list):
            for item in content:
                self.chapter_body(safe_encode(str(item)))  # Convert each item to string
        elif isinstance(content, dict):
            for key, value in content.items():
                self.chapter_body(safe_encode(f'{key}: {value}'))
        else:
            self.chapter_body(safe_encode(str(content)))  # Convert content to string

def safe_encode(text):
    return text.encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(analysis, output_file):
    pdf = PDF()
    pdf.set_left_margin(10)
    pdf.set_right_margin(10)
    pdf.add_page()  # Add an initial page
    
    pdf.add_section('From', analysis.get('From', 'N/A'))
    pdf.add_section('To', analysis.get('To', 'N/A'))
    pdf.add_section('Subject', analysis.get('Subject', 'N/A'))
    pdf.add_section('Date', analysis.get('Date', 'N/A'))
    pdf.add_section('Parsed Date', analysis.get('Date_Parsed', 'N/A'))
    pdf.add_section('Received Headers', analysis.get('Received', []))
    pdf.add_section('IP Addresses', analysis.get('IP_Addresses', []))
    pdf.add_section('IP Info', analysis.get('IP_Info', []))
    pdf.add_section('SPF', analysis.get('SPF', 'N/A'))
    pdf.add_section('Content', analysis.get('Content', 'N/A'))

    pdf.output(output_file)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            with open(filepath, 'rb') as f:
                raw_email = f.read()
            headers = extract_email_headers(raw_email)
            analysis = analyze_email_headers(headers, raw_email)
            generate_report(analysis)
            generate_pdf_report(analysis, os.path.join(app.config['UPLOAD_FOLDER'], 'email_analysis_report.pdf'))
            return render_template('report.html', analysis=analysis)
    return render_template('index.html')



@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(port=5000, debug=True)
