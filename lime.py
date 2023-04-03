#!/usr/bin/env python3

import sys
import argparse
import os
import re
import ssl
import socket
import requests
import subprocess

from datetime import datetime

def check_cert(url):
    print("--------------------------")
    print("SSL/TLS Certificate check:")
    print("--------------------------")

    context = ssl.create_default_context()

    with socket.create_connection((url, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=url) as sslsock:
            cert = sslsock.getpeercert()

    cert_info = ssl.DER_cert_to_PEM_cert(cert)

    is_self_signed = re.search("Issuer: CN=.*", cert_info)
    if is_self_signed:
        issuer = re.search("Issuer: .*", cert_info).group(0)
        subject = re.search("Subject: .*", cert_info).group(0)
        hostname = re.search("DNS:.*", cert_info).group(0)[4:]
        print("Issuer:", issuer)
        print("Subject:", subject)
        if issuer == subject and hostname == url and issuer.split("=")[1] == url.split(".")[0]:
            print("\033[31m Certificate is self-signed:", is_self_signed.group(0), "\033[0m")
        else:
            print("Certificate is not self-signed")

    is_wildcard = re.search("DNS:\*\..*", cert_info)
    if is_wildcard:
        print("\033[31m Certificate uses a wildcard:", is_wildcard.group(0), "\033[0m")
    else:
        print("Certificate does not use a wildcard")

    cert_start = re.search("Not Before.*", cert_info).group(0)
    cert_end = re.search("Not After.*", cert_info).group(0)
    print("Certificate Date")
    print(cert_start)
    print(cert_end)

    cert_end_date = datetime.strptime(cert_end.split(" ")[-3], "%b %d %H:%M:%S %Y").timestamp()
    current_date = datetime.now().timestamp()
    if cert_end_date < current_date:
        print("\033[31m", cert_end, "(SSL Certificate has expired)", "\033[0m")
    else:
        print(cert_end)

    return
    pass

def check_algorithm(url):
    print("--------------------------------")
    print("SSL/TLS hashing algorithm check:")
    print("--------------------------------")
    cert_info = subprocess.check_output(f"echo | openssl s_client -servername {url} -connect {url}:443 2>/dev/null", shell=True)
    if not cert_info:
        print("Certificate is untrusted or not available")
    else:
        cert_text = subprocess.check_output(f"echo '{cert_info.decode()}' | openssl x509 -noout -text", shell=True).decode()
        lines = cert_text.split('\n')
        for i, line in enumerate(lines):
            if "Signature Algorithm" in line:
                algorithm = line.split(": ")[1]
                if algorithm in ["MD5", "SHA1"]:
                    cve = subprocess.check_output(f"grep -i {algorithm} /usr/share/nmap/nmap-service-probes | head -n 1 | cut -d' ' -f2", shell=True).decode().strip()
                    print(f" Hashing algorithm {algorithm} is vulnerable to {cve}")
                else:
                    print(f" Hashing algorithm {algorithm} is strong.")
            elif line.startswith("Public-Key"):
                key_length = int(line.split(' ')[1])
                if key_length < 2048:
                    print(f" Diffie-Hellman parameter is weak: {key_length} bits")
    pass

def check_weak_ciphers(url):

    weak_ciphers = ['RC4', 'DES', 'RC2', 'IDEA', 'SEED', '3DES', 'ADH', 'LOW', 'EXP']

    print("------------------------------")
    print("SSL/TLS weak ciphers check:")
    print("------------------------------")

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=url)
        conn.connect((url, 443))
        cipher_name = conn.cipher()[0]
        if cipher_name in weak_ciphers:
            print(f"{url} supports weak SSL/TLS cipher: {cipher_name}")
        else:
            print(f"{url} does not support weak SSL/TLS ciphers.")
        conn.close()
    except (ssl.SSLError, socket.error) as error:
        print(f"Error: {error}")
    pass 

def check_protocols(url):
    print("-------------------------------")
    print("SSL/TLS protocol version check:")
    print("-------------------------------")

    # Map of protocol name to version constant
    protocols = {
        "SSLv2": ssl.PROTOCOL_SSLv2,
        "SSLv3": ssl.PROTOCOL_SSLv3,
        "TLSv1": ssl.PROTOCOL_TLSv1,
        "TLSv1.1": ssl.PROTOCOL_TLSv1_1,
        "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
        "TLSv1.3": ssl.PROTOCOL_TLSv1_3,
    }

    # Test connection with each protocol version
    for name, version in protocols.items():
        try:
            context = ssl.SSLContext(version)
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((url, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=url) as ssock:
                    ssock.do_handshake()
        except ssl.SSLError:
            print(f"{name}: Not supported")
        except Exception as e:
            print(f"{name}: Error: {e}")
        else:
            print(f"{name}: Supported")
    pass 

def check_headers(url):
    print("-------------------------------")
    print("Security headers check:")
    print("-------------------------------")
    
    # Set headers to send with request
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }

    # Make request to the url
    response = requests.get(url, headers=headers, allow_redirects=True)

    # Check for security headers in response
    if "Strict-Transport-Security" in response.headers:
        print("HSTS header found")
    else:
        print("HSTS header not found")
    
    if "X-Frame-Options" in response.headers:
        print("X-Frame-Options header found")
    else:
        print("X-Frame-Options header not found")
        
    if "X-XSS-Protection" in response.headers:
        print("X-XSS-Protection header found")
    else:
        print("X-XSS-Protection header not found")
        
    if "X-Content-Type-Options" in response.headers:
        print("X-Content-Type-Options header found")
    else:
        print("X-Content-Type-Options header not found")
        
    if "Content-Security-Policy" in response.headers:
        print("Content-Security-Policy header found")
    else:
        print("Content-Security-Policy header not found")
    pass 

def check_compression(url):
    print("--------------------------")
    print("Checking HTTP compression...")
    print("--------------------------")

    response = requests.get(url)

    if "Content-Encoding" in response.headers:
        encoding = response.headers["Content-Encoding"]
        if "gzip" in encoding:
            print("Gzip compression is enabled.")
        elif "deflate" in encoding:
            print("Deflate compression is enabled.")
        else:
            print("Unknown compression algorithm: " + encoding)
    else:
        print("No compression is enabled.")
    pass 

def check_options(url):
    print("Checking HTTP OPTIONS...")
    response = requests.options(url)
    if response.status_code == 200:
        print("HTTP OPTIONS is enabled.")
    elif response.status_code == 405:
        print("HTTP OPTIONS is disabled.")
    else:
        print("Unable to determine if HTTP OPTIONS is enabled.")
    pass 

def main():
    parser = argparse.ArgumentParser(description='Check website security.')
    parser.add_argument('url', type=str, help='URL to check')

    # Optional arguments
    parser.add_argument('--cert', action='store_true', help='Check SSL certificate')
    parser.add_argument('--algorithm', action='store_true', help='Check SSL certificate signature algorithm')
    parser.add_argument('--ciphers', action='store_true', help='Check weak SSL/TLS ciphers')
    parser.add_argument('--protocols', action='store_true', help='Check SSL/TLS protocols')
    parser.add_argument('--headers', action='store_true', help='Check HTTP headers')
    parser.add_argument('--compression', action='store_true', help='Check compression settings')
    parser.add_argument('--options', action='store_true', help='Check allowed HTTP methods')

    args = parser.parse_args()

    url = args.url

    if args.cert:
        check_cert(url)

    if args.algorithm:
        check_algorithm(url)

    if args.ciphers:
        check_weak_ciphers(url)

    if args.protocols:
        check_protocols(url)

    if args.headers:
        check_headers(url)

    if args.compression:
        check_compression(url)

    if args.options:
        check_options(url)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
