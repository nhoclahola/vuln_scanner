import sys
import io
import requests
import re
import json
import ssl
import socket
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from crewai.tools import tool

# No longer overriding sys.stdout/sys.stderr here

@tool("HTTP Headers Fetcher")
def http_header_fetcher(url: str) -> str:
    """
    Fetches HTTP header information from a URL.
    
    Args:
        url (str): The URL to inspect.
        
    Returns:
        str: Information about HTTP headers in JSON format.
    """
    
    try:
        # Add schema if not present
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        result = {
            "url": url,
            "status_code": response.status_code,
            "headers": dict(response.headers)
        }
        
        # Analyze security headers
        security_headers = {
            "X-XSS-Protection": response.headers.get("X-XSS-Protection"),
            "X-Content-Type-Options": response.headers.get("X-Content-Type-Options"),
            "X-Frame-Options": response.headers.get("X-Frame-Options"),
            "Content-Security-Policy": response.headers.get("Content-Security-Policy"),
            "Strict-Transport-Security": response.headers.get("Strict-Transport-Security"),
            "Referrer-Policy": response.headers.get("Referrer-Policy")
        }
        
        # Remove None headers
        security_headers = {k: v for k, v in security_headers.items() if v is not None}
        
        result["security_headers"] = security_headers
        result["security_headers_present"] = len(security_headers)
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    
    except Exception as e:
        return json.dumps({"error": f"Error fetching HTTP headers: {str(e)}"}, ensure_ascii=False)

@tool("SSL/TLS Analyzer")
def ssl_tls_analyzer(url: str) -> str:
    """
    Analyzes the SSL/TLS configuration of a URL.
    
    Args:
        url (str): The URL to inspect.
        
    Returns:
        str: Information about the SSL/TLS configuration in JSON format.
    """
    
    try:
        # Parse URL to get hostname
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # If URL has no schema and netloc, treat url as a hostname
        if not hostname:
            hostname = url.split('/')[0].split(':')[0]
            
        # Default to port 443 for HTTPS
        port = 443
        
        # Create connection to server
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate information
                cert = ssock.getpeercert()
                # Get cipher information
                cipher = ssock.cipher()
                # Get SSL/TLS protocol
                protocol = ssock.version()
            
        # Convert certificate information to a readable format
        cert_info = {
            "subject": dict(x[0] for x in cert['subject']),
            "issuer": dict(x[0] for x in cert['issuer']),
            "version": cert['version'],
            "notBefore": cert['notBefore'],
            "notAfter": cert['notAfter']
        }
        
        # Get important extensions
        extensions = {}
        for ext in cert.get('extensions', []):
            extensions[ext[0]] = ext[1]
            
        # Evaluate configuration strength
        cipher_info = {
            "name": cipher[0],
            "version": cipher[1],
            "bits": cipher[2]
        }
        
        # Check if TLS 1.2 or higher is used
        uses_modern_tls = protocol in ['TLSv1.2', 'TLSv1.3']
        
        # Check expiration date
        not_after = cert['notAfter']
        
        result = {
            "hostname": hostname,
            "protocol": protocol,
            "cipher": cipher_info,
            "certificate": cert_info,
            "extensions": extensions,
            "analysis": {
                "uses_modern_tls": uses_modern_tls,
                "expires": not_after
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    
    except ssl.SSLError as e:
        return json.dumps({"error": f"SSL Error: {str(e)}"}, ensure_ascii=False)
    except socket.timeout:
        return json.dumps({"error": "Timeout error when connecting to server"}, ensure_ascii=False)
    except socket.gaierror:
        return json.dumps({"error": "Error resolving domain name"}, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": f"Error analyzing SSL/TLS: {str(e)}"}, ensure_ascii=False)

@tool("CMS Detector")
def cms_detector(url: str) -> str:
    """
    Detects the Content Management System (CMS) of a website.
    
    Args:
        url (str): The URL of the website to check.
        
    Returns:
        str: Information about the website's CMS in JSON format.
    """
    
    try:
        # Add schema if not present
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        # List of signatures to identify CMS
        cms_signatures = {
            'WordPress': [
                'wp-content', 'wp-includes', 'wordpress', 
                'wp-login.php', '<meta name="generator" content="WordPress'
            ],
            'Joomla': [
                'com_content', 'com_contact', 'Joomla!', 
                '/templates/system/css/system.css', '<meta name="generator" content="Joomla'
            ],
            'Drupal': [
                'sites/all', 'drupal.js', 'drupal.min.js', 
                '<meta name="Generator" content="Drupal', 'Drupal.settings'
            ],
            'Magento': [
                'skin/frontend', 'Mage.', 'magento', 
                '/js/varien/', '/skin/frontend/default/'
            ],
            'Shopify': [
                'cdn.shopify.com', 'shopify.com', 
                'Shopify.theme', '<meta name="shopify-digital-wallet"'
            ],
            'WooCommerce': [
                'woocommerce', 'wc-api', 'wc_add_to_cart',
                'class="woocommerce"', 'wc-checkout'
            ],
            'PrestaShop': [
                'prestashop', '/themes/prestashop/', 
                'var prestashop', 'PrestaShop'
            ],
            'OpenCart': [
                'route=product', 'opencart', 
                'catalog/view/theme', 'catalog/view/javascript'
            ],
            'Squarespace': [
                'squarespace.com', 'static.squarespace.com', 
                'squarespace-cdn.com', 'Static.SQUARESPACE_CONTEXT'
            ],
            'Wix': [
                'wix.com', 'wixsite.com', 'wix-bolt', 
                '_wixCIDX', '_wix_browser_sess'
            ]
        }
        
        # Analyze HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        html_content = response.text
        
        detected_cms = {}
        confidence_scores = {}
        
        # Check each CMS
        for cms, signatures in cms_signatures.items():
            detected = 0
            for signature in signatures:
                if signature in html_content:
                    detected += 1
            
            if detected > 0:
                confidence = (detected / len(signatures)) * 100
                confidence_scores[cms] = confidence
                if confidence >= 30:  # Detection threshold
                    detected_cms[cms] = confidence
        
        # Check meta tags for generators
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator:
            generator_content = meta_generator.get('content', '')
            for cms in cms_signatures:
                if cms.lower() in generator_content.lower():
                    if cms not in detected_cms:
                        detected_cms[cms] = 90  # High confidence if found in meta generator
                    else:
                        detected_cms[cms] = max(detected_cms[cms], 90)
        
        # Check WordPress using /wp-json/
        wp_api_url = urljoin(url, '/wp-json/')
        try:
            wp_api_resp = requests.get(wp_api_url, headers=headers, timeout=5)
            if wp_api_resp.status_code == 200 and 'wp/v2' in wp_api_resp.text:
                if 'WordPress' not in detected_cms:
                    detected_cms['WordPress'] = 95
                else:
                    detected_cms['WordPress'] = max(detected_cms['WordPress'], 95)
        except:
            pass
            
        # Sort by confidence
        detected_cms = dict(sorted(detected_cms.items(), key=lambda x: x[1], reverse=True))
            
        result = {
            "url": url,
            "detected_cms": detected_cms,
            "highest_match": list(detected_cms.keys())[0] if detected_cms else "Unknown",
            "highest_confidence": list(detected_cms.values())[0] if detected_cms else 0,
            "cms_details": {
                "confidence_scores": confidence_scores
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    
    except Exception as e:
        return json.dumps({"error": f"Error detecting CMS: {str(e)}"}, ensure_ascii=False)

@tool("Port Scanner")
def port_scanner(host: str, scan_type: str = "basic") -> str:
    """
    Scans common ports on a host.
    
    Args:
        host (str): Hostname or IP address to scan
        scan_type (str, optional): Scan type - "basic" or "full"
        
    Returns:
        str: Scan result in JSON format
    """
    
    try:
        # Remove schema if present
        parsed_host = urlparse(host)
        if parsed_host.netloc:
            target = parsed_host.netloc
        else:
            target = host.split('/')[0]
        
        # Remove port from hostname if present
        if ':' in target:
            target = target.split(':')[0]
        
        result = {
            "host": target,
            "scan_type": scan_type,
            "open_ports": [],
            "closed_ports": [],
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        }
        
        # Common ports to scan
        if scan_type == "basic":
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
        else:  # full scan
            ports = list(range(1, 1001))  # Scan first 1000 ports
        
        # Set short timeout for faster scanning
        timeout = 0.5  # 500ms
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            try:
                # Try connecting to port
                conn_result = sock.connect_ex((target, port))
                
                # If connection successful (conn_result = 0)
                if conn_result == 0:
                    # Try to determine service
                    service = socket.getservbyport(port, "tcp") if port < 1024 else "unknown"
                    
                    port_info = {
                        "port": port,
                        "service": service,
                        "state": "open"
                    }
                    
                    result["open_ports"].append(port_info)
                else:
                    result["closed_ports"].append(port)
            except:
                result["closed_ports"].append(port)
            finally:
                sock.close()
        
        # Summarize results
        result["total_open"] = len(result["open_ports"])
        result["total_closed"] = len(result["closed_ports"])
        result["total_scanned"] = len(ports)
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    
    except Exception as e:
        return json.dumps({"error": f"Error scanning ports: {str(e)}"}, ensure_ascii=False)

@tool("Security Headers Analyzer")
def security_headers_analyzer(url: str) -> str:
    """
    Analyzes the HTTP security headers of a website.
    
    Args:
        url (str): The URL of the website to check
        
    Returns:
        str: Result of security header analysis in JSON format
    """
    
    try:
        # Add schema if not present
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        # List of security headers to check
        security_headers = {
            'Strict-Transport-Security': {
                'header': response.headers.get('Strict-Transport-Security'),
                'description': 'Protect against downgrade HTTPS->HTTP attacks',
                'recommendations': 'max-age=31536000; includeSubDomains'
            },
            'Content-Security-Policy': {
                'header': response.headers.get('Content-Security-Policy'),
                'description': 'Protect against XSS and data injection',
                'recommendations': 'Set up strict source whitelist'
            },
            'X-Content-Type-Options': {
                'header': response.headers.get('X-Content-Type-Options'),
                'description': 'Protect against MIME-sniffing',
                'recommendations': 'nosniff'
            },
            'X-Frame-Options': {
                'header': response.headers.get('X-Frame-Options'),
                'description': 'Protect against clickjacking',
                'recommendations': 'DENY or SAMEORIGIN'
            },
            'X-XSS-Protection': {
                'header': response.headers.get('X-XSS-Protection'),
                'description': 'Protect against XSS on old browsers',
                'recommendations': '1; mode=block'
            },
            'Referrer-Policy': {
                'header': response.headers.get('Referrer-Policy'),
                'description': 'Control HTTP Referer information',
                'recommendations': 'strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'header': response.headers.get('Permissions-Policy') or response.headers.get('Feature-Policy'),
                'description': 'Control browser features and APIs',
                'recommendations': 'Set up necessary feature limits'
            }
        }
        
        # Evaluate each header
        result = {
            "url": url,
            "headers": {},
            "missing_headers": [],
            "score": 0,
            "max_score": len(security_headers) * 2,
            "recommendations": []
        }
        
        for header, data in security_headers.items():
            if data['header']:
                result["headers"][header] = data['header']
                
                # Check for valid value and add points
                if header == 'Strict-Transport-Security' and 'max-age=' in data['header']:
                    result["score"] += 2
                elif header == 'X-Content-Type-Options' and 'nosniff' in data['header']:
                    result["score"] += 2
                elif header == 'X-Frame-Options' and ('DENY' in data['header'] or 'SAMEORIGIN' in data['header']):
                    result["score"] += 2
                elif header == 'X-XSS-Protection' and '1' in data['header']:
                    result["score"] += 2
                elif header == 'Content-Security-Policy':
                    result["score"] += 2  # Any CSP is better than no CSP
                elif header == 'Referrer-Policy':
                    result["score"] += 2
                elif header == 'Permissions-Policy' or header == 'Feature-Policy':
                    result["score"] += 2
                else:
                    result["score"] += 1  # Header present but value not optimal
            else:
                result["missing_headers"].append({
                    "header": header,
                    "description": data['description'],
                    "recommendation": data['recommendations']
                })
                result["recommendations"].append(f"Add {header}: {data['recommendations']}")
        
        # Calculate percentage score
        result["score_percent"] = round((result["score"] / result["max_score"]) * 100, 2)
        
        # Overall evaluation
        if result["score_percent"] >= 80:
            result["rating"] = "Good"
        elif result["score_percent"] >= 50:
            result["rating"] = "Average"
        else:
            result["rating"] = "Poor"
            
        return json.dumps(result, indent=2, ensure_ascii=False)
    
    except Exception as e:
        return json.dumps({"error": f"Error analyzing security headers: {str(e)}"}, ensure_ascii=False)

@tool("Request URL")
def request_url(url: str) -> str:
    """
    Sends a request to a URL and returns the content.
    
    Args:
        url (str): The URL to request
        
    Returns:
        str: Content of the URL
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        content_type = response.headers.get('Content-Type', '')
        
        # Process only text content
        if 'text' in content_type or 'json' in content_type or 'xml' in content_type or 'html' in content_type:
            return response.text
        else:
            return f"Unsupported content type: {content_type}"
    
    except requests.exceptions.RequestException as e:
        return f"Error requesting URL: {str(e)}" 