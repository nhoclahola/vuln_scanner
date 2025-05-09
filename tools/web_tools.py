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

# Không ghi đè sys.stdout/sys.stderr ở đây nữa

@tool("HTTP Headers Fetcher")
def http_header_fetcher(url: str) -> str:
    """
    Thu thập thông tin HTTP header từ một URL.
    
    Args:
        url (str): URL để kiểm tra
        
    Returns:
        str: Thông tin về các HTTP header dạng JSON
    """
    
    try:
        # Thêm schema nếu chưa có
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
        
        # Phân tích các header bảo mật
        security_headers = {
            "X-XSS-Protection": response.headers.get("X-XSS-Protection"),
            "X-Content-Type-Options": response.headers.get("X-Content-Type-Options"),
            "X-Frame-Options": response.headers.get("X-Frame-Options"),
            "Content-Security-Policy": response.headers.get("Content-Security-Policy"),
            "Strict-Transport-Security": response.headers.get("Strict-Transport-Security"),
            "Referrer-Policy": response.headers.get("Referrer-Policy")
        }
        
        # Loại bỏ các header None
        security_headers = {k: v for k, v in security_headers.items() if v is not None}
        
        result["security_headers"] = security_headers
        result["security_headers_present"] = len(security_headers)
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    
    except Exception as e:
        return json.dumps({"error": f"Lỗi khi thu thập HTTP header: {str(e)}"}, ensure_ascii=False)

@tool("SSL/TLS Analyzer")
def ssl_tls_analyzer(url: str) -> str:
    """
    Phân tích cấu hình SSL/TLS của một URL.
    
    Args:
        url (str): URL để kiểm tra
        
    Returns:
        str: Thông tin về cấu hình SSL/TLS dạng JSON
    """
    
    try:
        # Phân tích URL để lấy hostname
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # Nếu URL không có schema và netloc, xử lý url như một hostname
        if not hostname:
            hostname = url.split('/')[0].split(':')[0]
            
        # Mặc định là port 443 cho HTTPS
        port = 443
        
        # Tạo kết nối đến server
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Lấy thông tin chứng chỉ
                cert = ssock.getpeercert()
                # Lấy thông tin phiên bản SSL/TLS
                cipher = ssock.cipher()
                # Lấy giao thức SSL/TLS
                protocol = ssock.version()
            
        # Chuyển đổi thông tin chứng chỉ sang định dạng dễ đọc
        cert_info = {
            "subject": dict(x[0] for x in cert['subject']),
            "issuer": dict(x[0] for x in cert['issuer']),
            "version": cert['version'],
            "notBefore": cert['notBefore'],
            "notAfter": cert['notAfter']
        }
        
        # Lấy các extension quan trọng
        extensions = {}
        for ext in cert.get('extensions', []):
            extensions[ext[0]] = ext[1]
            
        # Đánh giá độ mạnh của cấu hình
        cipher_info = {
            "name": cipher[0],
            "version": cipher[1],
            "bits": cipher[2]
        }
        
        # Kiểm tra xem có sử dụng TLS 1.2 trở lên không
        uses_modern_tls = protocol in ['TLSv1.2', 'TLSv1.3']
        
        # Kiểm tra ngày hết hạn
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
        return json.dumps({"error": f"Lỗi SSL: {str(e)}"}, ensure_ascii=False)
    except socket.timeout:
        return json.dumps({"error": "Lỗi timeout khi kết nối đến server"}, ensure_ascii=False)
    except socket.gaierror:
        return json.dumps({"error": "Lỗi khi phân giải tên miền"}, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": f"Lỗi khi phân tích SSL/TLS: {str(e)}"}, ensure_ascii=False)

@tool("CMS Detector")
def cms_detector(url: str) -> str:
    """
    Phát hiện hệ thống quản lý nội dung (CMS) của một website.
    
    Args:
        url (str): URL của website cần kiểm tra
        
    Returns:
        str: Thông tin về CMS của website dạng JSON
    """
    
    try:
        # Thêm schema nếu chưa có
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        # Danh sách các dấu hiệu để nhận biết CMS
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
        
        # Phân tích HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        html_content = response.text
        
        detected_cms = {}
        confidence_scores = {}
        
        # Kiểm tra từng CMS
        for cms, signatures in cms_signatures.items():
            detected = 0
            for signature in signatures:
                if signature in html_content:
                    detected += 1
            
            if detected > 0:
                confidence = (detected / len(signatures)) * 100
                confidence_scores[cms] = confidence
                if confidence >= 30:  # Ngưỡng phát hiện
                    detected_cms[cms] = confidence
        
        # Kiểm tra meta tags cho các generator
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator:
            generator_content = meta_generator.get('content', '')
            for cms in cms_signatures:
                if cms.lower() in generator_content.lower():
                    if cms not in detected_cms:
                        detected_cms[cms] = 90  # Độ tin cậy cao nếu tìm thấy trong meta generator
                    else:
                        detected_cms[cms] = max(detected_cms[cms], 90)
        
        # Kiểm tra wordpress bằng /wp-json/
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
            
        # Sắp xếp theo độ tin cậy
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
        return json.dumps({"error": f"Lỗi khi phát hiện CMS: {str(e)}"}, ensure_ascii=False)

@tool("Port Scanner")
def port_scanner(host: str, scan_type: str = "basic") -> str:
    """
    Quét các cổng thông dụng trên một host.
    
    Args:
        host (str): Hostname hoặc địa chỉ IP cần quét
        scan_type (str, optional): Loại quét - "basic" hoặc "full"
        
    Returns:
        str: Kết quả quét cổng dạng JSON
    """
    
    try:
        # Loại bỏ schema nếu có
        parsed_host = urlparse(host)
        if parsed_host.netloc:
            target = parsed_host.netloc
        else:
            target = host.split('/')[0]
        
        # Loại bỏ port từ hostname nếu có
        if ':' in target:
            target = target.split(':')[0]
        
        result = {
            "host": target,
            "scan_type": scan_type,
            "open_ports": [],
            "closed_ports": [],
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        }
        
        # Các cổng thông dụng để quét
        if scan_type == "basic":
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
        else:  # full scan
            ports = list(range(1, 1001))  # Quét 1000 cổng đầu tiên
        
        # Thiết lập timeout ngắn để tăng tốc quét
        timeout = 0.5  # 500ms
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            try:
                # Thử kết nối đến port
                conn_result = sock.connect_ex((target, port))
                
                # Nếu kết nối thành công (conn_result = 0)
                if conn_result == 0:
                    # Thử xác định dịch vụ
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
        
        # Tổng hợp kết quả
        result["total_open"] = len(result["open_ports"])
        result["total_closed"] = len(result["closed_ports"])
        result["total_scanned"] = len(ports)
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    
    except Exception as e:
        return json.dumps({"error": f"Lỗi khi quét cổng: {str(e)}"}, ensure_ascii=False)

@tool("Security Headers Analyzer")
def security_headers_analyzer(url: str) -> str:
    """
    Phân tích các HTTP security header của một website.
    
    Args:
        url (str): URL của website cần kiểm tra
        
    Returns:
        str: Kết quả phân tích security header dạng JSON
    """
    
    try:
        # Thêm schema nếu chưa có
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        # Danh sách các security header cần kiểm tra
        security_headers = {
            'Strict-Transport-Security': {
                'header': response.headers.get('Strict-Transport-Security'),
                'description': 'Bảo vệ chống lại tấn công downgrade HTTPS->HTTP',
                'recommendations': 'max-age=31536000; includeSubDomains'
            },
            'Content-Security-Policy': {
                'header': response.headers.get('Content-Security-Policy'),
                'description': 'Bảo vệ chống lại XSS và data injection',
                'recommendations': 'Thiết lập source whitelist nghiêm ngặt'
            },
            'X-Content-Type-Options': {
                'header': response.headers.get('X-Content-Type-Options'),
                'description': 'Bảo vệ chống lại MIME-sniffing',
                'recommendations': 'nosniff'
            },
            'X-Frame-Options': {
                'header': response.headers.get('X-Frame-Options'),
                'description': 'Bảo vệ chống lại clickjacking',
                'recommendations': 'DENY hoặc SAMEORIGIN'
            },
            'X-XSS-Protection': {
                'header': response.headers.get('X-XSS-Protection'),
                'description': 'Bảo vệ chống lại XSS trên trình duyệt cũ',
                'recommendations': '1; mode=block'
            },
            'Referrer-Policy': {
                'header': response.headers.get('Referrer-Policy'),
                'description': 'Kiểm soát thông tin trong HTTP Referer',
                'recommendations': 'strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'header': response.headers.get('Permissions-Policy') or response.headers.get('Feature-Policy'),
                'description': 'Kiểm soát các tính năng và API của trình duyệt',
                'recommendations': 'Thiết lập giới hạn các tính năng cần thiết'
            }
        }
        
        # Đánh giá từng header
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
                
                # Kiểm tra giá trị hợp lý và thêm điểm
                if header == 'Strict-Transport-Security' and 'max-age=' in data['header']:
                    result["score"] += 2
                elif header == 'X-Content-Type-Options' and 'nosniff' in data['header']:
                    result["score"] += 2
                elif header == 'X-Frame-Options' and ('DENY' in data['header'] or 'SAMEORIGIN' in data['header']):
                    result["score"] += 2
                elif header == 'X-XSS-Protection' and '1' in data['header']:
                    result["score"] += 2
                elif header == 'Content-Security-Policy':
                    result["score"] += 2  # Bất kỳ CSP nào cũng là tốt hơn không có
                elif header == 'Referrer-Policy':
                    result["score"] += 2
                elif header == 'Permissions-Policy' or header == 'Feature-Policy':
                    result["score"] += 2
                else:
                    result["score"] += 1  # Có header nhưng giá trị không tối ưu
            else:
                result["missing_headers"].append({
                    "header": header,
                    "description": data['description'],
                    "recommendation": data['recommendations']
                })
                result["recommendations"].append(f"Thêm {header}: {data['recommendations']}")
        
        # Tính điểm phần trăm
        result["score_percent"] = round((result["score"] / result["max_score"]) * 100, 2)
        
        # Đánh giá tổng thể
        if result["score_percent"] >= 80:
            result["rating"] = "Tốt"
        elif result["score_percent"] >= 50:
            result["rating"] = "Trung bình"
        else:
            result["rating"] = "Kém"
            
        return json.dumps(result, indent=2, ensure_ascii=False)
    
    except Exception as e:
        return json.dumps({"error": f"Lỗi khi phân tích security headers: {str(e)}"}, ensure_ascii=False)

@tool("Request URL")
def request_url(url: str) -> str:
    """
    Gửi request đến URL và trả về nội dung.
    
    Args:
        url (str): URL cần request
        
    Returns:
        str: Nội dung của URL
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        content_type = response.headers.get('Content-Type', '')
        
        # Chỉ xử lý nội dung văn bản
        if 'text' in content_type or 'json' in content_type or 'xml' in content_type or 'html' in content_type:
            return response.text
        else:
            return f"Không hỗ trợ nội dung kiểu: {content_type}"
    
    except requests.exceptions.RequestException as e:
        return f"Lỗi khi request URL: {str(e)}" 