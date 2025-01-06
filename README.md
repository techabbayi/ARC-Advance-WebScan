# ARC-Advance-WebScan

This web application performs a security scan of a specified URL to check for various vulnerabilities in the target web application. The application is built using Flask, a Python web framework, and employs BeautifulSoup for parsing HTML to detect certain security issues. 

# Below are the key features and tests it performs:

# Key Features:

# 1.	Web Interface:

o	Users can input a URL into a form on the homepage.
o	Upon submitting, the form sends the URL to the /scan endpoint for scanning.

# 2.	Security Scan Results:

o	The results are displayed on a new page (results.html) after scanning the URL. If vulnerabilities are found, they are listed with a brief description of the issue and recommended solutions.

# 3.	Security Tests:

o	SQL Injection Test: Tests if the application is vulnerable to SQL injection by appending a common SQL injection payload (' OR '1'='1) to the URL's query string and checking for specific error messages or behaviors in the response.

o	Cross-Site Scripting (XSS) Test: Checks if the application is vulnerable to XSS by injecting a simple <script>alert('XSS')</script> payload in the URL's query parameters and checking if the payload is reflected back in the response.

o	Cross-Site Request Forgery (CSRF) Check: Scans for the presence of CSRF tokens in form submissions. If a form is found without a hidden input field for a CSRF token, it flags it as vulnerable to CSRF.

o	Open Redirect Test: Attempts to trigger an open redirect vulnerability by appending a malicious URL to the /redirect endpoint and checking if the application redirects to that URL. If it does, it indicates an open redirect vulnerability.

o	Security Headers Check: Checks for the presence of important security headers (X-Content-Type-Options, Content-Security-Policy, X-Frame-Options). Missing headers are flagged as vulnerabilities.

o	Directory Traversal Test: Checks for directory traversal vulnerabilities by attempting to access system files (like /etc/passwd) via URL manipulation (e.g., ../etc/passwd). If the content of the file is found, it indicates a directory traversal vulnerability.
