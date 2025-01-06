# Web Application Security Scanner Website

from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    results = []

    # Basic SQL Injection test
    test_payload = "' OR '1'='1"
    response = requests.get(url, params={'test': test_payload})
    if "SQL syntax" in response.text or "mysql" in response.text:
        results.append({'vulnerability': 'SQL Injection', 'url': url, 'solution': 'Use prepared statements or parameterized queries.'})

    # XSS test
    xss_payload = "<script>alert('XSS')</script>"
    response = requests.get(url, params={'test': xss_payload})
    if xss_payload in response.text:
        results.append({'vulnerability': 'Cross-Site Scripting (XSS)', 'url': url, 'solution': 'Sanitize and validate all user inputs and encode output properly.'})

    # Form scanning for CSRF checks
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        if not form.find('input', {'type': 'hidden', 'name': 'csrf_token'}):
            results.append({'vulnerability': 'CSRF', 'form': str(form), 'solution': 'Implement CSRF tokens in forms to prevent unauthorized actions.'})

    # Open Redirect vulnerability test
    redirect_test_url = urljoin(url, "/redirect?url=http://malicious.com")
    response = requests.get(redirect_test_url)
    if "http://malicious.com" in response.url:
        results.append({'vulnerability': 'Open Redirect', 'url': redirect_test_url, 'solution': 'Validate and sanitize user-provided URLs to prevent redirection to untrusted domains.'})

    # Security Headers check
    headers_to_check = ['X-Content-Type-Options', 'Content-Security-Policy', 'X-Frame-Options']
    missing_headers = [header for header in headers_to_check if header not in response.headers]
    if missing_headers:
        results.append({'vulnerability': 'Missing Security Headers', 'headers': missing_headers, 'solution': 'Ensure the server includes recommended security headers.'})

    # Directory Traversal test
    traversal_payload = "../etc/passwd"
    traversal_url = urljoin(url, traversal_payload)
    response = requests.get(traversal_url)
    if "root:" in response.text:
        results.append({'vulnerability': 'Directory Traversal', 'url': traversal_url, 'solution': 'Validate and sanitize file paths to prevent unauthorized access.'})

    return render_template('results.html', results=results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
