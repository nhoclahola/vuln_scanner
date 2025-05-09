import sys
import io
import requests
from bs4 import BeautifulSoup
import re
import json
import os
import time
import random
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from crewai.tools import tool

# Không ghi đè sys.stdout/sys.stderr ở đây nữa

def get_base_url(url):
    """Trả về base URL từ URL đầy đủ"""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

class WebSiteCrawler:
    """Web crawler specialized for website structure discovery"""
    
    def __init__(self, start_url, max_pages=20, max_depth=3, respect_robots=True, 
                 passive_only=False, fuzz_params=True, js_analysis_depth=2):
        self.start_url = start_url
        self.base_url = get_base_url(start_url)
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.respect_robots = respect_robots
        self.passive_only = passive_only  # Chế độ quét thụ động (không tạo request mới)
        self.fuzz_params = fuzz_params    # Thử thay đổi tham số URL
        self.js_analysis_depth = js_analysis_depth  # Độ sâu phân tích JavaScript
        
        # Lưu trữ trạng thái
        self.visited = set()
        self.found_urls = []
        self.to_visit = []
        self.forms_found = []
        self.api_endpoints = []
        self.disallowed_paths = []
        self.observed_requests = []  # Lưu trữ các request đã thấy trong passive mode
        self.parameter_patterns = {} # Lưu trữ mẫu tham số URL đã thấy
        self.js_processed = set()    # JavaScript đã xử lý
        
        # Session để lưu trữ cookies và headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Đọc robots.txt nếu cần
        if self.respect_robots:
            self.parse_robots_txt()
    
    def parse_robots_txt(self):
        """Parse robots.txt to respect the rules"""
        try:
            robots_url = urljoin(self.base_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=10)
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            self.disallowed_paths.append(path)
                print(f"Parsed robots.txt: {len(self.disallowed_paths)} disallowed paths")
        except Exception as e:
            print(f"Error parsing robots.txt: {str(e)}")
    
    def is_allowed(self, url):
        """Check if URL is allowed by robots.txt"""
        if not self.respect_robots:
            return True
            
        parsed_url = urlparse(url)
        path = parsed_url.path
        
        for disallowed in self.disallowed_paths:
            if path.startswith(disallowed):
                return False
        return True
    
    def normalize_url(self, url):
        """Normalize URL to avoid duplicates"""
        parsed = urlparse(url)
        # Remove fragment
        normalized = parsed._replace(fragment='').geturl()
        return normalized
    
    def extract_urls_from_page(self, url, html_content):
        """Trích xuất tất cả URL từ nội dung HTML"""
        soup = BeautifulSoup(html_content, 'html.parser')
        urls = []
        
        # Trích xuất từ thẻ a
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(url, href)
            urls.append(full_url)
        
        # Trích xuất từ thẻ form
        for form_tag in soup.find_all('form', action=True):
            action = form_tag.get('action', '')
            if action:
                full_url = urljoin(url, action)
                urls.append(full_url)
        
        # Trích xuất từ JavaScript
        script_urls = extract_urls_from_scripts(soup)
        for script_url in script_urls:
            full_url = urljoin(url, script_url)
            urls.append(full_url)
        
        # Trích xuất từ CSS background
        for style_tag in soup.find_all(['style', 'link'], rel='stylesheet'):
            if style_tag.string:
                urls.extend([urljoin(url, u) for u in re.findall(r'url\([\'"]?([^\'"*)]+)[\'"]?\)', style_tag.string)])
        
        # Chuẩn hóa và lọc URL
        normalized_urls = []
        for u in urls:
            normalized = self.normalize_url(u)
            parsed = urlparse(normalized)
            # Chỉ giữ lại URL cùng domain và không phải external resources
            if parsed.netloc == urlparse(self.base_url).netloc:
                if not any(ext in parsed.path for ext in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js']):
                    normalized_urls.append(normalized)
        
        return list(set(normalized_urls))
    
    def extract_forms(self, url, html_content):
        """Extract and analyze forms from the page"""
        soup = BeautifulSoup(html_content, 'html.parser')
        forms_info = []
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action) if action else url
            
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', '')
                input_name = input_tag.get('name', '')
                input_value = input_tag.get('value', '')
                if input_name:
                    inputs.append({
                        'name': input_name,
                        'type': input_type,
                        'value': input_value
                    })
            
            form_data = {
                'url': form_url,
                'method': method,
                'inputs': inputs
            }
            
            forms_info.append(form_data)
        
        return forms_info
    
    def submit_forms(self, forms_info):
        """Try submitting forms with sample data to discover more URLs"""
        discovered_urls = []
        
        for form in forms_info:
            url = form['url']
            method = form['method']
            
            # Create sample data for the form
            data = {}
            for input_field in form['inputs']:
                name = input_field['name']
                input_type = input_field.get('type', '')
                
                # Generate fake values based on input type
                if input_type == 'email':
                    data[name] = 'test@example.com'
                elif input_type == 'password':
                    data[name] = 'Password123!'
                elif input_type in ['text', 'search']:
                    data[name] = 'test'
                elif input_type == 'number':
                    data[name] = '1'
                elif input_type == 'checkbox':
                    data[name] = 'on'
                else:
                    # Keep original value if present
                    data[name] = input_field.get('value', '')
            
            try:
                if method == 'post':
                    response = self.session.post(url, data=data, timeout=10, allow_redirects=True)
                else:
                    response = self.session.get(url, params=data, timeout=10, allow_redirects=True)
                
                # Save current URL and redirect URLs
                history_urls = [self.normalize_url(r.url) for r in response.history] + [self.normalize_url(response.url)]
                discovered_urls.extend(history_urls)
                
                # Extract more URLs from response content
                if 'text/html' in response.headers.get('Content-Type', ''):
                    page_urls = self.extract_urls_from_page(response.url, response.text)
                    discovered_urls.extend(page_urls)
                
            except Exception as e:
                print(f"Error submitting form {url}: {str(e)}")
        
        return list(set(discovered_urls))
    
    def crawl(self):
        """Perform website crawling process"""
        self.to_visit = [(self.start_url, 0)]  # (url, depth)
        
        while self.to_visit and len(self.visited) < self.max_pages:
            url, depth = self.to_visit.pop(0)
            normalized_url = self.normalize_url(url)
            
            if normalized_url in self.visited or depth > self.max_depth:
                continue
                
            if not self.is_allowed(normalized_url):
                print(f"Skipping disallowed URL: {normalized_url}")
                continue
            
            print(f"Crawling [{depth}/{self.max_depth}]: {normalized_url}")
            
            try:
                # Add a small delay to avoid being blocked
                time.sleep(random.uniform(0.5, 1.5))
                
                # Analyze URL parameters to learn patterns
                self.analyze_parameters(normalized_url)
                
                # If in passive mode, we don't actually send requests
                if self.passive_only:
                    # In passive mode, we only analyze the URL and add it to the list of found URLs
                    self.found_urls.append(normalized_url)
                    self.visited.add(normalized_url)
                    continue
                
                response = self.session.get(normalized_url, timeout=10, allow_redirects=True)
                self.visited.add(normalized_url)
                
                # Record traffic for passive analysis
                self.record_traffic({
                    'method': 'GET', 
                    'url': normalized_url, 
                    'headers': dict(self.session.headers)
                }, response)
                
                # If it's a redirect URL, add the target URL to the results
                if len(response.history) > 0:
                    for r in response.history:
                        self.found_urls.append(self.normalize_url(r.url))
                
                # Add current URL to results
                if normalized_url not in self.found_urls:
                    self.found_urls.append(normalized_url)
                
                # Only parse HTML content
                if 'text/html' in response.headers.get('Content-Type', ''):
                    # Extract URLs from the page
                    page_urls = self.extract_urls_from_page(response.url, response.text)
                    
                    # Extract form information
                    forms = self.extract_forms(response.url, response.text)
                    for form in forms:
                        if form not in self.forms_found:
                            self.forms_found.append(form)
                    
                    # Try submitting forms to discover more URLs
                    if forms and depth < self.max_depth and not self.passive_only:
                        form_urls = self.submit_forms(forms)
                        page_urls.extend(form_urls)
                    
                    # Analyze JavaScript to find URLs
                    for script in BeautifulSoup(response.text, 'html.parser').find_all('script'):
                        if script.get('src'):
                            script_url = urljoin(response.url, script['src'])
                            if script_url not in self.js_processed and len(self.js_processed) < 50:  # Giới hạn
                                try:
                                    script_response = self.session.get(script_url, timeout=10)
                                    if script_response.status_code == 200:
                                        js_urls = self.analyze_javascript(script_response.text, response.url)
                                        page_urls.extend(js_urls)
                                        self.js_processed.add(script_url)
                                except Exception as js_error:
                                    print(f"Error analyzing JavaScript {script_url}: {str(js_error)}")
                        elif script.string:
                            js_urls = self.analyze_javascript(script.string, response.url)
                            page_urls.extend(js_urls)
                    
                    # Try fuzzing URLs if configured
                    if self.fuzz_params and not self.passive_only:
                        fuzz_urls = self.generate_fuzz_urls(normalized_url)
                        if fuzz_urls:
                            print(f"Trying with {len(fuzz_urls)} URL fuzz parameters")
                            page_urls.extend(fuzz_urls)
                    
                    # Add new URL to queue
                    for new_url in page_urls:
                        if (self.normalize_url(new_url) not in self.visited and 
                            urlparse(new_url).netloc == urlparse(self.base_url).netloc):
                            self.to_visit.append((new_url, depth + 1))
            
            except Exception as e:
                print(f"Error crawling {normalized_url}: {str(e)}")
        
        # Final results
        self.found_urls = list(set(self.found_urls))
        print(f"Found {len(self.found_urls)} URLs and {len(self.forms_found)} forms.")
        
        return {
            "urls": self.found_urls,
            "forms": self.forms_found,
            "api_endpoints": list(set(self.api_endpoints))
        }

    def record_traffic(self, request, response):
        """Record HTTP traffic (for passive scanning)"""
        req_info = {
            'method': request.get('method', 'GET'),
            'url': request.get('url', ''),
            'headers': request.get('headers', {}),
            'body': request.get('body', '')
        }
        
        resp_info = {
            'status_code': getattr(response, 'status_code', 0),
            'headers': dict(getattr(response, 'headers', {})),
            'content_type': response.headers.get('Content-Type', ''),
            'body_preview': getattr(response, 'text', '')[:1000] if hasattr(response, 'text') else ''
        }
        
        traffic_record = {
            'request': req_info,
            'response': resp_info,
            'timestamp': time.time()
        }
        
        self.observed_requests.append(traffic_record)
        
        # Analyze response to find URLs
        if hasattr(response, 'text') and response.headers.get('Content-Type', '').startswith('text/html'):
            urls = self.extract_urls_from_page(req_info['url'], response.text)
            forms = self.extract_forms(req_info['url'], response.text)
            self.found_urls.extend(urls)
            self.forms_found.extend(forms)
            
        # Analyze JSON response
        if hasattr(response, 'text') and response.headers.get('Content-Type', '').startswith('application/json'):
            try:
                json_data = response.json()
                urls = self.extract_urls_from_json(json_data, req_info['url'])
                self.found_urls.extend(urls)
            except:
                pass
        
    def extract_urls_from_json(self, json_obj, base_url):
        """Extract URLs from JSON data"""
        urls = []
        if isinstance(json_obj, dict):
            for key, value in json_obj.items():
                if isinstance(value, str) and (
                    value.startswith('/') or 
                    value.startswith('http') or 
                    key.lower() in ['url', 'href', 'link', 'path', 'endpoint', 'uri']):
                    if value.startswith('/'):
                        full_url = urljoin(base_url, value)
                        urls.append(full_url)
                    elif value.startswith('http'):
                        urls.append(value)
                elif isinstance(value, (dict, list)):
                    urls.extend(self.extract_urls_from_json(value, base_url))
        elif isinstance(json_obj, list):
            for item in json_obj:
                if isinstance(item, (dict, list)):
                    urls.extend(self.extract_urls_from_json(item, base_url))
                elif isinstance(item, str) and (item.startswith('/') or item.startswith('http')):
                    if item.startswith('/'):
                        full_url = urljoin(base_url, item)
                        urls.append(full_url)
                    else:
                        urls.append(item)
        return urls

    def analyze_parameters(self, url):
        """Phân tích tham số URL và xây dựng mẫu để fuzz"""
        parsed = urlparse(url)
        path = parsed.path
        query = parsed.query
        
        # Lưu mẫu path: /user/123/profile -> /user/{id}/profile
        path_parts = path.split('/')
        pattern_path = []
        for part in path_parts:
            if part.isdigit():
                pattern_path.append('{id}')
            elif part and not part.isalpha():
                pattern_path.append('{param}')
            else:
                pattern_path.append(part)
        
        path_pattern = '/'.join(pattern_path)
        if path_pattern not in self.parameter_patterns:
            self.parameter_patterns[path_pattern] = {'params': {}, 'count': 0}
        
        self.parameter_patterns[path_pattern]['count'] += 1
        
        # Phân tích query params
        if query:
            params = parse_qs(query)
            for param, values in params.items():
                if param not in self.parameter_patterns[path_pattern]['params']:
                    self.parameter_patterns[path_pattern]['params'][param] = {
                        'seen_values': [],
                        'numeric': True,
                        'count': 0
                    }
                
                param_info = self.parameter_patterns[path_pattern]['params'][param]
                param_info['count'] += 1
                
                for val in values:
                    if val not in param_info['seen_values']:
                        param_info['seen_values'].append(val)
                    if not val.isdigit():
                        param_info['numeric'] = False
    
    def generate_fuzz_urls(self, url):
        """Tạo thêm URL để thử dựa trên mẫu đã học được"""
        parsed = urlparse(url)
        path = parsed.path
        query = parsed.query
        fuzz_urls = []
        
        # Tìm mẫu path phù hợp nhất
        matching_pattern = None
        path_parts = path.split('/')
        for pattern, info in self.parameter_patterns.items():
            pattern_parts = pattern.split('/')
            if len(pattern_parts) == len(path_parts):
                matches = True
                for i, (pattern_part, path_part) in enumerate(zip(pattern_parts, path_parts)):
                    if pattern_part not in ['{id}', '{param}'] and pattern_part != path_part:
                        matches = False
                        break
                
                if matches:
                    matching_pattern = pattern
                    break
        
        if not matching_pattern:
            return fuzz_urls
        
        # Thử thay đổi giá trị tham số trong path
        if '{id}' in matching_pattern:
            pattern_parts = matching_pattern.split('/')
            for i, part in enumerate(pattern_parts):
                if part == '{id}' and path_parts[i].isdigit():
                    # Thử với id khác
                    original_id = int(path_parts[i])
                    test_ids = [original_id + 1, original_id - 1, 0, 1, 999]
                    for test_id in test_ids:
                        if test_id < 0:
                            continue
                        new_path_parts = path_parts.copy()
                        new_path_parts[i] = str(test_id)
                        new_path = '/'.join(new_path_parts)
                        new_url = parsed._replace(path=new_path).geturl()
                        fuzz_urls.append(new_url)
        
        # Thử thay đổi giá trị tham số trong query
        if query:
            params = parse_qs(query)
            for param, values in params.items():
                param_info = self.parameter_patterns.get(matching_pattern, {}).get('params', {}).get(param)
                if not param_info:
                    continue
                
                for value in values:
                    new_params = params.copy()
                    
                    # Thử với các giá trị đã thấy ở endpoint khác
                    for seen_value in param_info.get('seen_values', [])[:3]:  # Giới hạn 3
                        if seen_value != value:
                            new_params[param] = [seen_value]
                            query_string = urlencode(new_params, doseq=True)
                            new_url = parsed._replace(query=query_string).geturl()
                            fuzz_urls.append(new_url)
                    
                    # Nếu tham số là số
                    if param_info.get('numeric', False) and value.isdigit():
                        val_int = int(value)
                        test_vals = [val_int + 1, val_int - 1, 0, 1]
                        for test_val in test_vals:
                            if test_val < 0:
                                continue
                            new_params[param] = [str(test_val)]
                            query_string = urlencode(new_params, doseq=True)
                            new_url = parsed._replace(query=query_string).geturl()
                            fuzz_urls.append(new_url)
                            
        return fuzz_urls

    def analyze_javascript(self, js_content, base_url):
        """Phân tích sâu mã JavaScript để tìm endpoint"""
        urls = []
        
        # Các mẫu regex thông thường
        standard_patterns = [
            # URL hoặc path literals
            r'[\'"](https?://[^\'"]+)[\'"]',
            r'[\'"]([/][^\'"]+)[\'"]',
            
            # API endpoints
            r'[\'"]api/[^\'"]+[\'"]',
            r'[\'"]v[0-9]+/[^\'"]+[\'"]',
            
            # Fetch/XHR requests 
            r'fetch\([\'"]([^\'"]+)[\'"]\)',
            r'fetch\([^,]+,[\'"]([^\'"]+)[\'"]\)',
            r'\.open\([\'"](?:GET|POST|PUT|DELETE)[\'"],\s*[\'"]([^\'"]+)[\'"]\)',
            
            # Axios/jQuery
            r'axios\.(?:get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]\)',
            r'\$\.(?:get|post|put|delete|ajax)\([\'"]([^\'"]+)[\'"]\)',
            
            # Route definitions in frameworks
            r'\.route\([\'"]([^\'"]+)[\'"]\)',
            r'path:\s*[\'"]([^\'"]+)[\'"]',
            
            # URL construction
            r'const\s+(?:url|endpoint|api|path)\s*=\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        # Tìm các URL từ các mẫu tiêu chuẩn
        for pattern in standard_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                clean_url = match.strip('\'"')
                if clean_url:
                    if clean_url.startswith('/') or not urlparse(clean_url).netloc:
                        full_url = urljoin(base_url, clean_url)
                        urls.append(full_url)
                    else:
                        urls.append(clean_url)
        
        # Tìm các mẫu phức tạp hơn - URL được xây dựng từ các biến
        js_lines = js_content.split('\n')
        route_patterns = {}
        base_route = None
        
        # Phân tích từng dòng JS để tìm khai báo
        for line in js_lines:
            # Tìm khai báo baseURL/API URLs
            base_match = re.search(r'(?:const|let|var)\s+(\w+)\s*=\s*[\'"]([^\'"]*/)[\'"]', line)
            if base_match:
                var_name = base_match.group(1)
                var_value = base_match.group(2)
                if var_name.lower() in ['baseurl', 'apiurl', 'apibase', 'baseapi', 'endpoint']:
                    base_route = var_value
                    route_patterns[var_name] = var_value
            
            # Tìm khai báo endpoint
            endpoint_match = re.search(r'(?:const|let|var)\s+(\w+)\s*=\s*[\'"]([^\'"]*)[\'"]', line)
            if endpoint_match:
                var_name = endpoint_match.group(1)
                var_value = endpoint_match.group(2)
                if var_name.lower() in ['endpoint', 'url', 'api', 'path', 'route']:
                    route_patterns[var_name] = var_value
            
            # Tìm các string concatenation để tạo URL
            concat_match = re.search(r'(\w+)\s*\+\s*[\'"]([^\'"]+)[\'"]', line)
            if concat_match:
                var_name = concat_match.group(1)
                segment = concat_match.group(2)
                if var_name in route_patterns:
                    combined_route = route_patterns[var_name] + segment
                    # Nếu có dấu hiệu là API endpoint
                    if any(substr in combined_route for substr in ['/api/', '/v1/', '/v2/', '/auth/', '/users/']):
                        if combined_route.startswith('/'):
                            full_url = urljoin(base_url, combined_route)
                            urls.append(full_url)
                            self.api_endpoints.append(full_url)
                        else:
                            urls.append(combined_route)
                            self.api_endpoints.append(combined_route)
            
            # Tìm templated routes - ví dụ: `${baseUrl}/users/${id}`
            template_match = re.findall(r'\${(\w+)}', line)
            if template_match and '`' in line:
                template_str = line[line.find('`'):line.rfind('`')+1]
                for var in template_match:
                    if var in route_patterns:
                        template_str = template_str.replace('${' + var + '}', route_patterns[var])
                
                # Thay các biến còn lại bằng giá trị mẫu
                template_str = re.sub(r'\${[^}]+}', '{param}', template_str)
                template_str = template_str.strip('`')
                
                if '/' in template_str:
                    if template_str.startswith('/'):
                        full_url = urljoin(base_url, template_str)
                        urls.append(full_url)
                    else:
                        urls.append(template_str)
        
        # Tìm fetch hoặc XHR request với URL/route đã được định nghĩa trong object
        config_obj_pattern = r'fetch\(\s*(\w+)'
        config_matches = re.findall(config_obj_pattern, js_content)
        for var_name in config_matches:
            if var_name in route_patterns:
                endpoint = route_patterns[var_name]
                if endpoint.startswith('/'):
                    full_url = urljoin(base_url, endpoint)
                    urls.append(full_url)
                    self.api_endpoints.append(full_url)
                else:
                    urls.append(endpoint)
                    self.api_endpoints.append(endpoint)
        
        # Nếu tìm thấy baseRoute/apiBase, thử kết hợp với các path pattern đã biết
        common_api_patterns = ['/users', '/auth/login', '/auth/register', '/products', '/items', 
                             '/api/data', '/settings', '/config', '/v1/users', '/v2/items']
        if base_route:
            for pattern in common_api_patterns:
                if base_route.endswith('/') and pattern.startswith('/'):
                    combined = base_route + pattern[1:]
                else:
                    combined = base_route + pattern
                
                if combined.startswith('/'):
                    full_url = urljoin(base_url, combined)
                    urls.append(full_url)
                    self.api_endpoints.append(full_url)
                else:
                    urls.append(combined)
                    self.api_endpoints.append(combined)
        
        # Loại bỏ trùng lặp và lọc URL
        urls = list(set(urls))
        filtered_urls = []
        for u in urls:
            parsed = urlparse(u)
            
            # Chỉ giữ URL cùng domain và không phải static resource
            if parsed.netloc == urlparse(base_url).netloc or not parsed.netloc:
                if not any(ext in parsed.path for ext in ['.jpg', '.jpeg', '.png', '.gif', '.css']):
                    filtered_urls.append(u)
            
            # Trích xuất và lưu API endpoints
            if any(pattern in parsed.path for pattern in ['/api/', '/v1/', '/v2/', '/auth/']):
                self.api_endpoints.append(u)
        
        return filtered_urls

@tool("Web Crawler")
def web_crawler(url=None, max_pages=20, max_depth=3, passive_only=False, fuzz_params=True):
    """
    Dò tìm các endpoint trên trang web sử dụng kỹ thuật tương tự Burp Suite.
    
    Args:
        url (str, optional): URL trang web cần quét. Nếu không cung cấp, sẽ sử dụng từ target_url hoặc url trong inputs.
        max_pages (int, optional): Số trang tối đa cần quét. Mặc định là 20.
        max_depth (int, optional): Độ sâu tối đa khi dò tìm. Mặc định là 3.
        passive_only (bool, optional): Nếu True, chỉ thực hiện passive scan. Mặc định là False.
        fuzz_params (bool, optional): Nếu True, thử thay đổi tham số trong URLs để tìm thêm endpoints. Mặc định là True.
        
    Returns:
        list: Danh sách các URL, form và API endpoints
    """
    try:
        # Kiểm tra URL từ nhiều nguồn
        if url is None or url.strip() == "":
            # Thử lấy URL từ biến môi trường
            env_url = os.environ.get("TARGET_URL")
            if env_url and env_url.strip() != "":
                url = env_url
                print(f"Sử dụng URL từ biến môi trường: {url}")
            else:
                url = "https://google.com"
                print(f"Không tìm thấy URL. Sử dụng URL mặc định: {url}")
        else:
            # Đảm bảo URL bắt đầu bằng http hoặc https
            if not url.startswith(('http://', 'https://')):
                url = "https://" + url
            print(f"Bắt đầu dò tìm endpoint trên: {url}")
        
        scan_mode = "Passive" if passive_only else "Active"
        print(f"Chế độ: {scan_mode}")
        
        # Sử dụng crawler mới
        crawler = WebSiteCrawler(
            url, 
            max_pages=max_pages, 
            max_depth=max_depth,
            passive_only=passive_only,
            fuzz_params=fuzz_params
        )
        
        results = crawler.crawl()
        
        # Trích xuất và trả về danh sách URL
        return results["urls"]
        
    except Exception as e:
        print(f"Lỗi khi dò tìm: {str(e)}")
        return []

def extract_urls_from_scripts(soup):
    """Extract URLs from script tags"""
    urls = []
    for script in soup.find_all('script'):
        if script.string:
            # Find URLs in script content
            urls.extend(re.findall(r'(https?://[^\s\'"]+)', script.string))
            urls.extend(re.findall(r'[\'"](/[^\'"]+)[\'"]', script.string))
            # Find API endpoints
            urls.extend(re.findall(r'[\'"]api/[^\'"]+[\'"]', script.string))
            urls.extend(re.findall(r'[\'"]v[0-9]/[^\'"]+[\'"]', script.string))
    return urls

@tool("JavaScript Analyzer")
def javascript_analyzer(url=None):
    """
    Phân tích mã JavaScript để tìm các endpoint API.
    
    Args:
        url (str, optional): URL trang web cần phân tích. Nếu không cung cấp, sẽ sử dụng từ target_url hoặc url trong inputs.
        
    Returns:
        list: Danh sách các API endpoint tìm thấy
    """
    try:
        # Kiểm tra URL từ nhiều nguồn
        if url is None or url.strip() == "":
            # Thử lấy URL từ biến môi trường
            env_url = os.environ.get("TARGET_URL")
            if env_url and env_url.strip() != "":
                url = env_url
                print(f"Sử dụng URL từ biến môi trường: {url}")
            else:
                url = "https://google.com"
                print(f"Không tìm thấy URL. Sử dụng URL mặc định: {url}")
        else:
            # Đảm bảo URL bắt đầu bằng http hoặc https
            if not url.startswith(('http://', 'https://')):
                url = "https://" + url
            print(f"Phân tích JavaScript trên: {url}")
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code != 200:
            return []
            
        soup = BeautifulSoup(response.text, 'html.parser')
        api_endpoints = []
        
        # Tìm tất cả thẻ script
        for script in soup.find_all('script'):
            if script.get('src'):
                # Tải nội dung script từ URL
                script_url = urljoin(url, script['src'])
                try:
                    script_response = requests.get(script_url, headers=headers, timeout=10)
                    if script_response.status_code == 200:
                        script_content = script_response.text
                        # Tìm các mẫu API endpoint
                        api_patterns = [
                            r'api/[a-zA-Z0-9_/]+',
                            r'(/v[0-9]+/[a-zA-Z0-9_/]+)',
                            r'(/api[a-zA-Z0-9_/]+)',
                            r'([\'"]https?://[^\'"]+/api[^\'"]+[\'"])',
                            r'[\'"](/[a-zA-Z0-9_/]+\.[a-zA-Z]+)[\'"]',
                        ]
                        
                        for pattern in api_patterns:
                            matches = re.findall(pattern, script_content)
                            for match in matches:
                                if isinstance(match, tuple):
                                    match = match[0]
                                api_endpoints.append(match.strip('\'"'))
                                
                except requests.exceptions.RequestException:
                    continue
                
            elif script.string:
                # Phân tích nội dung script nội tuyến
                script_content = script.string
                # Tìm các mẫu API endpoint
                api_patterns = [
                    r'api/[a-zA-Z0-9_/]+',
                    r'(/v[0-9]+/[a-zA-Z0-9_/]+)',
                    r'(/api[a-zA-Z0-9_/]+)',
                    r'([\'"]https?://[^\'"]+/api[^\'"]+[\'"])',
                    r'[\'"](/[a-zA-Z0-9_/]+\.[a-zA-Z]+)[\'"]',
                ]
                
                for pattern in api_patterns:
                    matches = re.findall(pattern, script_content)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        api_endpoints.append(match.strip('\'"'))
                        
        # Loại bỏ các endpoint trùng lặp
        result = list(set(api_endpoints))
        print(f"Tìm thấy {len(result)} API endpoint.")
        return result
        
    except Exception as e:
        print(f"Lỗi khi phân tích JavaScript: {str(e)}")
        return []

@tool("Discover Endpoints")
def discover_endpoints(url=None, max_pages=20, max_depth=3, passive_only=False, fuzz_params=True, js_analysis_depth=2):
    """
    Dò tìm tất cả các endpoint trên một trang web sử dụng kỹ thuật tương tự Burp Suite.
    
    Args:
        url (str, optional): URL trang web cần dò tìm. Nếu không cung cấp, sẽ sử dụng giá trị mặc định.
        max_pages (int, optional): Số trang tối đa cần quét. Mặc định là 20.
        max_depth (int, optional): Độ sâu tối đa khi dò tìm. Mặc định là 3.
        passive_only (bool, optional): Chỉ sử dụng chế độ quét thụ động. Mặc định là False.
        fuzz_params (bool, optional): Thử thay đổi tham số URL để tìm thêm endpoints. Mặc định là True.
        js_analysis_depth (int, optional): Độ sâu phân tích JavaScript. Mặc định là 2.
        
    Returns:
        str: Chuỗi JSON chứa các endpoint
    """
    # Kiểm tra URL từ nhiều nguồn
    if url is None or url.strip() == "":
        # Thử lấy URL từ biến môi trường
        env_url = os.environ.get("TARGET_URL")
        if env_url and env_url.strip() != "":
            url = env_url
            print(f"Sử dụng URL từ biến môi trường: {url}")
        else:
            url = "https://google.com"
            print(f"Không tìm thấy URL. Sử dụng URL mặc định: {url}")
    else:
        # Đảm bảo URL bắt đầu bằng http hoặc https
        if not url.startswith(('http://', 'https://')):
            url = "https://" + url
        print(f"Bắt đầu dò tìm endpoint trên: {url}")
    
    scan_mode = "Passive" if passive_only else "Active"
    print(f"Chế độ: {scan_mode}")
    
    # Sử dụng WebSiteCrawler mới
    crawler = WebSiteCrawler(
        url, 
        max_pages=max_pages, 
        max_depth=max_depth,
        passive_only=passive_only,
        fuzz_params=fuzz_params,
        js_analysis_depth=js_analysis_depth
    )
    
    results = crawler.crawl()
    
    # Định dạng kết quả
    endpoints = results["urls"]
    forms = results["forms"]
    api_endpoints = results["api_endpoints"]
    
    # Thêm thông tin từ phân tích JavaScript
    num_js_files = len(getattr(crawler, 'js_processed', set()))
    
    # Tạo báo cáo đầy đủ
    report = {
        "crawled_urls": endpoints,
        "forms": forms,
        "api_endpoints": api_endpoints,
        "total_endpoints": len(endpoints),
        "total_forms": len(forms),
        "total_api_endpoints": len(api_endpoints),
        "scan_mode": scan_mode,
        "javascript_files_analyzed": num_js_files
    }
    
    return json.dumps(report, ensure_ascii=False) 