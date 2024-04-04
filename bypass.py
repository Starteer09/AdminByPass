#!/usr/bin/env python3
import mechanize
import cookielib
import sys
import requests
from bs4 import BeautifulSoup

def load_wordlist(filename):
    try:
        with open(filename, 'r') as file:
            return [line.strip() for line in file]
    except FileNotFoundError:
        print(f"[-] Wordlist '{filename}' not found!")
        sys.exit(1)

def check_url_protocol(url):
    if not url.startswith('http://') and not url.startswith('https://'):
        return 'http://' + url
    return url

def detect_waf(url):
    noise = "?=<script>alert()</script>"
    fuzzed_url = url + noise
    response = requests.get(fuzzed_url)
    if response.status_code == 406 or response.status_code == 501:
        print("[WAF Detected] Mod_Security")
    elif response.status_code == 999:
        print("[WAF Detected] WebKnight")
    elif response.status_code == 419:
        print("[WAF Detected] F5 BIG IP")
    elif response.status_code == 403:
        print("[Unknown WAF Detected]")

def find_forms(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        if len(forms) == 0:
            print("[-] No forms found on the webpage")
            return
        for form in forms:
            print(f"[!] Form found: {form}")
            # Your form processing logic here
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching webpage: {e}")

def main():
    print('\033[1;93m')
    print('''\
     ____  _ _____ _
    / ___|(_)_   _| |__  _   _
    \___ \| | | | | '_ \| | | |
     ___) | | | | | | | | |_| |
    |____/|_| |_| |_| |_|\__,_|
    ''')
    print('\033[1;34m')

    target_url = input("[?] Enter target URL: ")
    target_url = check_url_protocol(target_url)

    try:
        br = mechanize.Browser()
        br.set_cookiejar(cookielib.LWPCookieJar())
        br.set_handle_equiv(True)
        br.set_handle_redirect(True)
        br.set_handle_referer(True)
        br.set_handle_robots(False)
        br.set_debug_http(False)
        br.set_debug_responses(False)
        br.set_debug_redirects(False)
        br.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
                         ('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
                         ('Accept-Encoding','br')]
        br.open(target_url, timeout=10.0)

        headers = br.response().info().headers
        if 'x-frame-options:' not in headers:
            print('[+] Heuristic found a Clickjacking Vulnerability')
        if 'cloudflare-nginx' in str(headers).lower():
            print('[-] Target is protected by Cloudflare')
        data = br.response().read()
        if b'type="hidden"' not in data:
            print('[+] Heuristic found a CSRF Vulnerability')

        detect_waf(target_url)
        find_forms(target_url)

    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    main()
