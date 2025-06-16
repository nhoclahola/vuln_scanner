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

# No longer overriding sys.stdout/sys.stderr here

def get_base_url(url):
    """Returns the base URL from a full URL"""
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
        self.passive_only = passive_only  # Passive scanning mode (does not create new requests)
        self.fuzz_params = fuzz_params    # Try changing URL parameters
        self.js_analysis_depth = js_analysis_depth  # JavaScript analysis depth
        
        # Store state
        self.visited = set()
        self.found_urls = []
        self.to_visit = []
        self.forms_found = []
        self.api_endpoints = []
        self.disallowed_paths = []
        self.observed_requests = []  # Store requests seen in passive mode
        self.parameter_patterns = {} # Store URL parameter patterns seen
        self.js_processed = set()    # Processed JavaScript
        
        # Session to store cookies and headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Read robots.txt if needed
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
        """Extracts all URLs from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        urls = []
        
        # Extract from a tags
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(url, href)
            urls.append(full_url)
        
        # Extract from form tags
        for form_tag in soup.find_all('form', action=True):
            action = form_tag.get('action', '')
            if action:
                full_url = urljoin(url, action)
                urls.append(full_url)
        
        # Extract from JavaScript
        script_urls = extract_urls_from_scripts(soup)
        for script_url in script_urls:
            full_url = urljoin(url, script_url)
            urls.append(full_url)
        
        # Extract from CSS background
        for style_tag in soup.find_all(['style', 'link'], rel='stylesheet'):
            if style_tag.string:
                urls.extend([urljoin(url, u) for u in re.findall(r'url\([\'"]?([^\'"*)]+)[\'"]?\)', style_tag.string)])
        
        # Normalize and filter URLs
        normalized_urls = []
        for u in urls:
            normalized = self.normalize_url(u)
            parsed = urlparse(normalized)
            # Only keep URLs from the same domain and not external resources
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
                else:  # GET method
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
        """Analyze JavaScript content to find URLs and API endpoints"""
        urls = []
        
        # Find absolute URLs
        urls.extend(re.findall(r'(https?://[^\\s\'\"`]+)', js_content))
        
        # Find relative paths
        # Common patterns: '/path/to/resource', './path', '../path'
        # More specific patterns: '/api/...', '/v1/...', '/auth/...'
        relative_paths = re.findall(r'[\'\"`](/?(?:[\\w.-]+/)*[\\w.-]+(?:\\?[^\\s\'\"`]*)?)[\'\"`]', js_content)
        for path in relative_paths:
            if not path.startswith(('http://', 'https://', '//')) and any(c in path for c in './'): # Simple check for relative
                full_url = urljoin(base_url, path)
                urls.append(full_url)
            elif path.startswith('/'): # Handles root-relative paths
                 full_url = urljoin(base_url, path)
                 urls.append(full_url)


        # Find API endpoint patterns
        api_patterns = [
            r'[\'\"`](/api(?:/[\\w-]+)*)[\'\"`]',            # /api, /api/users, /api/v1/items
            r'[\'\"`](/v\\d+(?:/[\\w-]+)*)[\'\"`]',            # /v1, /v2/users
            r'[\'\"`](/auth(?:/[\\w-]+)*)[\'\"`]',           # /auth, /auth/login
            r'[\'\"`]([\\w.-]+\\.execute\\(([^)]+)\\))[\'\"`]', # For some specific SDK calls
            r'fetch\\s*\\(\\s*[\'\"`]([^ \'\"`]+)[\'\"`]' # URLs in fetch calls
        ]
        for pattern in api_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                # If regex returns groups, take the relevant one (usually the first or last)
                endpoint = match[0] if isinstance(match, tuple) else match
                if endpoint.startswith('/'):
                    full_url = urljoin(base_url, endpoint)
                    urls.append(full_url)
                    self.api_endpoints.append(full_url)
                elif endpoint.startswith('http'): # Already a full URL
                    urls.append(endpoint)
                    self.api_endpoints.append(endpoint)
                # else: could be a variable or something more complex - harder to resolve statically

        # Look for variable assignments that might define base URLs or API paths
        # Example: const API_BASE = "/api/v1"; let userPath = "/users";
        route_patterns = {}
        var_assignments = re.findall(r'(?:const|let|var)\\s+([\\w$]+)\\s*=\\s*[\'\"`]([^ \'\"`]+)[\'\"`]', js_content)
        for var_name, var_value in var_assignments:
            route_patterns[var_name] = var_value
            if var_value.startswith('/'):
                full_url = urljoin(base_url, var_value)
                urls.append(full_url)
                if any(p in var_value for p in ['/api', '/v', '/auth']):
                     self.api_endpoints.append(full_url)
            elif var_value.startswith('http'):
                urls.append(var_value)
                if any(p in var_value for p in ['/api', '/v', '/auth']):
                     self.api_endpoints.append(var_value)


        base_route = route_patterns.get('API_BASE') or route_patterns.get('apiBaseUrl') or route_patterns.get('baseUrl')
        
        # Find templated routes - e.g., ${baseUrl}/users/${id}
        template_match = re.findall(r'\\${(\\w+)}', js_content)
        if template_match and '`' in js_content: # check for template literals
            # This is a simplified approach; real template string parsing is complex
            # Consider lines with backticks that also contain ${...}
            potential_templates = re.findall(r'`([^`]+)`', js_content)
            for template_str_inner in potential_templates:
                if '${' not in template_str_inner:
                    continue

                resolved_template = template_str_inner
                for var in re.findall(r'\\${(\\w+)}', template_str_inner): # find vars inside this specific template
                    if var in route_patterns:
                        resolved_template = resolved_template.replace(f'${{{var}}}', route_patterns[var])
                
                # Replace remaining template variables with a placeholder
                resolved_template = re.sub(r'\\${[^}]+}', '{param}', resolved_template)
                
                if '/' in resolved_template: # Check if it looks like a path
                    if resolved_template.startswith('/'):
                        full_url = urljoin(base_url, resolved_template)
                        urls.append(full_url)
                    elif resolved_template.startswith('http'):
                        urls.append(resolved_template)
                    # else: could be just a string template not forming a full URL without more context

        # Find fetch or XHR requests with URL/route defined in object
        # Example: fetch(config.apiEndpoints.users)
        # This is highly dependent on code structure and difficult to generalize robustly
        config_obj_pattern = r'fetch\\s*\\(\\s*(\\w+(?:\\.\\w+)*)\\s*\\)' # e.g. fetch(config.users) or fetch(API.users)
        config_matches = re.findall(config_obj_pattern, js_content)
        # Further analysis would require understanding the structure of these config objects,
        # which is beyond simple regex.

        # If baseRoute/apiBase is found, try combining with known path patterns
        common_api_patterns = ['/users', '/auth/login', '/auth/register', '/products', '/items', 
                             '/api/data', '/settings', '/config', '/v1/users', '/v2/items']
        if base_route:
            for pattern in common_api_patterns:
                # Ensure no double slashes if base_route ends with / and pattern starts with /
                if base_route.endswith('/') and pattern.startswith('/'):
                    combined = base_route + pattern[1:]
                elif not base_route.endswith('/') and not pattern.startswith('/'):
                     combined = base_route + '/' + pattern
                else:
                    combined = base_route + pattern
                
                if combined.startswith('/'): # If it became a relative path
                    full_url = urljoin(base_url, combined)
                    urls.append(full_url)
                    self.api_endpoints.append(full_url)
                elif combined.startswith('http'): # If it resolved to a full URL
                    urls.append(combined)
                    self.api_endpoints.append(combined)
        
        # Remove duplicates and filter URLs
        urls = list(set(urls))
        filtered_urls = []
        current_domain_netloc = urlparse(base_url).netloc

        for u in urls:
            try:
                parsed_u = urlparse(u)
                # Only keep URLs from the same domain (or relative) and not static resources
                # and ensure it's a valid scheme if it's an absolute URL
                is_same_domain_or_relative = not parsed_u.netloc or parsed_u.netloc == current_domain_netloc
                is_valid_scheme = not parsed_u.scheme or parsed_u.scheme in ['http', 'https']
                is_not_static_resource = not any(parsed_u.path.lower().endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.otf'])
                
                if is_valid_scheme and is_same_domain_or_relative and is_not_static_resource:
                    normalized_u = self.normalize_url(u) # Normalize before adding
                    if normalized_u not in filtered_urls : # Ensure uniqueness after normalization
                         filtered_urls.append(normalized_u)
                
                # Extract and save API endpoints (might be redundant if already added, but set conversion handles it)
                if any(pattern in parsed_u.path for pattern in ['/api/', '/v1/', '/v2/', '/auth/', '/service/', '/graphql']):
                     normalized_api_u = self.normalize_url(u)
                     if normalized_api_u not in self.api_endpoints:
                        self.api_endpoints.append(normalized_api_u)
            except ValueError:
                print(f"Skipping invalid URL found in JS: {u}") # log invalid URLs
                continue
        
        self.api_endpoints = list(set(self.api_endpoints)) # Deduplicate API endpoints
        return filtered_urls

@tool("Web Crawler")
def web_crawler(url=None, max_pages=20, max_depth=3, passive_only=False, fuzz_params=True):
    """
    Crawls a website to discover endpoints, similar to Burp Suite's techniques.
    
    Args:
        url (str, optional): The URL of the website to scan. If not provided, it will use target_url or url from inputs.
        max_pages (int, optional): Maximum number of pages to scan. Defaults to 20.
        max_depth (int, optional): Maximum depth for crawling. Defaults to 3.
        passive_only (bool, optional): If True, only performs a passive scan. Defaults to False.
        fuzz_params (bool, optional): If True, tries to change parameters in URLs to find more endpoints. Defaults to True.
        
    Returns:
        list: A list of URLs, forms, and API endpoints.
    """
    try:
        # Check URL from multiple sources
        if url is None or url.strip() == "":
            # Try to get URL from environment variable
            env_url = os.environ.get("TARGET_URL")
            if env_url and env_url.strip() != "":
                url = env_url
                print(f"Using URL from environment variable: {url}")
            else:
                # Fallback to a default URL if nothing is provided
                url = "https://example.com" # Changed from google.com to a more generic example
                print(f"URL not found. Using default URL: {url}")
        else:
            # Ensure URL starts with http or https
            if not url.startswith(('http://', 'https://')):
                url = "https://" + url # Prepend https if no scheme
            print(f"Starting endpoint discovery on: {url}")
        
        scan_mode = "Passive" if passive_only else "Active"
        print(f"Mode: {scan_mode}, Max Pages: {max_pages}, Max Depth: {max_depth}") # Added more info
        
        # Use new crawler
        crawler = WebSiteCrawler(
            url, 
            max_pages=max_pages, 
            max_depth=max_depth,
            passive_only=passive_only,
            fuzz_params=fuzz_params
            # js_analysis_depth is part of WebSiteCrawler's __init__ but not a direct param here
            # It will use its default or could be exposed if needed.
        )
        
        results = crawler.crawl() # crawl() now returns a dictionary
        
        # The 'urls' key contains the list of discovered page URLs.
        # The 'forms' key contains form information.
        # The 'api_endpoints' key contains discovered API endpoints.
        # For this tool's contract (returning a list), we might concatenate or choose one.
        # Returning all discovered URLs (pages + API) for now.
        # Consider if the expected output should be a dict for more structure.
        
        all_discovered_urls = list(set(results.get("urls", []) + results.get("api_endpoints", [])))
        print(f"Web Crawler discovered {len(all_discovered_urls)} unique URLs/API endpoints.")
        
        # To match the previous simpler return type "list: Danh sách các URL, form và API endpoints"
        # we can return a dictionary that includes all these, or just a list of URLs.
        # For now, returning a dictionary to be more informative, which is a change from the docstring's "list".
        # This might require updating the task that uses this tool if it expects a flat list.
        # Or, stick to the docstring: return all_discovered_urls
        
        return {
            "discovered_urls": results.get("urls", []),
            "forms_found": results.get("forms", []),
            "api_endpoints_found": results.get("api_endpoints", [])
        }
        
    except Exception as e:
        # Adding more detailed error logging
        import traceback
        print(f"Error during crawling of {url}: {str(e)}\\n{traceback.format_exc()}")
        return {"discovered_urls": [], "forms_found": [], "api_endpoints_found": [], "error": str(e)}

def extract_urls_from_scripts(soup):
    """Extract URLs from script tags using regex, including relative and absolute paths."""
    urls = []
    base_url_tag = soup.find('base', href=True)
    # page_base_url is not used here, but could be useful if we want to resolve relative paths
    # based on a <base> tag specifically for this soup object.
    # page_base_url = base_url_tag['href'] if base_url_tag else None

    for script in soup.find_all('script'):
        content = ""
        if script.string:
            content += script.string
        # It's generally not a good idea to fetch external JS live during this phase
        # if script.get('src'):
        #     try:
        #         src_url = urljoin(page_base_url or '', script['src']) # Needs a base if src is relative
        #         # Add fetching logic if truly needed, but be cautious
        #     except Exception:
        #         pass # ignore errors fetching external script for this basic extraction

        # Regex for various URL patterns found in JS
        # Absolute URLs
        urls.extend(re.findall(r'https?://[^\\s\'\"`()]+', content))
        # Relative URLs (e.g., "/path/to/file", "./file.js", "../api/data")
        # This regex looks for strings starting with /, ./, or ../ inside quotes
        urls.extend(re.findall(r'[\'\"`](?:\\./|\\.\\./|/)[^\\s\'\"`]+[\'\"`]', content))
        # API-like paths
        urls.extend(re.findall(r'[\'\"`](?:api|v\\d+)/[^\\s\'\"`]+[\'\"`]', content))

    # Clean and normalize (simple cleaning here)
    cleaned_urls = []
    for url in urls:
        cleaned_url = url.strip('\'\"`') # Remove surrounding quotes/backticks
        # Further normalization (like urljoin with a base) would happen elsewhere
        # if these are to be used for actual requests.
        cleaned_urls.append(cleaned_url)
        
    return list(set(cleaned_urls))


@tool("JavaScript Analyzer")
def javascript_analyzer(url=None, js_code_content=None):
    """
    Analyzes JavaScript code (from a URL or direct string) to find API endpoints and other interesting URLs.
    
    Args:
        url (str, optional): The URL of the HTML page containing JavaScript or a direct URL to a .js file.
        js_code_content (str, optional): Direct JavaScript code string to analyze.
                                         If provided, 'url' might be used as a base for resolving relative paths.
        
    Returns:
        list: A list of discovered API endpoints and potentially other interesting URLs.
    """
    if not url and not js_code_content:
        print("JavaScript Analyzer: URL or JS code content must be provided.")
        return {"error": "URL or JS code content must be provided", "api_endpoints": [], "other_urls": []}

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    })
    
    all_js_content = ""
    base_analysis_url = url # For joining relative paths

    try:
        if js_code_content:
            all_js_content = js_code_content
            print(f"Analyzing provided JavaScript code content.")
        elif url:
            # Ensure URL starts with http or https
            if not url.startswith(('http://', 'https://')):
                url = "https://" + url
            print(f"Analyzing JavaScript on or from: {url}")

            response = session.get(url, timeout=20)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            content_type = response.headers.get('Content-Type', '').lower()

            if 'javascript' in content_type or url.endswith('.js'):
                all_js_content = response.text
            elif 'html' in content_type:
                base_analysis_url = response.url # Use the final URL after redirects as base
                soup = BeautifulSoup(response.text, 'html.parser')
                for script_tag in soup.find_all('script'):
                    if script_tag.string:
                        all_js_content += script_tag.string + "\\n"
                    elif script_tag.get('src'):
                        script_src = urljoin(base_analysis_url, script_tag['src'])
                        try:
                            print(f"Fetching linked script: {script_src}")
                            script_res = session.get(script_src, timeout=10)
                            script_res.raise_for_status()
                            all_js_content += script_res.text + "\\n"
                        except requests.exceptions.RequestException as e_script:
                            print(f"Failed to fetch script {script_src}: {e_script}")
            else:
                print(f"Unsupported content type '{content_type}' at {url} for JS analysis.")
                return {"error": f"Unsupported content type '{content_type}'", "api_endpoints": [], "other_urls": []}
        
        if not all_js_content:
            print("No JavaScript content found to analyze.")
            return {"api_endpoints": [], "other_urls": []}

        # Instantiate a minimal crawler to use its JS analysis logic
        # This feels a bit off, ideally analyze_javascript should be standalone or part of the crawler
        # For now, creating a dummy WebSiteCrawler instance to call its method.
        # This is not ideal as it brings in unrelated crawler setup.
        # Consider refactoring WebSiteCrawler.analyze_javascript to be a static method or a standalone function.
        
        # Using a simplified, direct regex approach here instead of instantiating WebSiteCrawler
        # to make this tool more self-contained for JS analysis.
        
        discovered_urls = []
        api_endpoints = []

        # Regex for various URL patterns found in JS
        # Absolute URLs
        discovered_urls.extend(re.findall(r'https?://[^\\s\'\"`()]+', all_js_content))
        
        # Relative URLs (e.g., "/path/to/file", "./file.js", "../api/data")
        # This regex looks for strings starting with /, ./, or ../ inside quotes or backticks
        relative_pattern = r'[\'\"`](?:\\./|\\.\\./|/)[^\\s\'\"`]+[\'\"`]'
        for match in re.findall(relative_pattern, all_js_content):
            path = match.strip('\'\"`')
            if base_analysis_url: # Needs a base to resolve relative paths
                 discovered_urls.append(urljoin(base_analysis_url, path))
            else: # If no base URL, can only keep if it's somehow absolute-like or context implies
                 discovered_urls.append(path)


        # More specific API-like paths (often relative)
        api_like_patterns = [
            r'[\'\"`](?:/api|/v\\d+|/auth|/service|/graphql)(?:/[^\\s\'\"`?#]+)*[^\\s\'\"`]*[\'\"`]',
            r'(?:apiBaseUrl|API_BASE|baseUrl)\\s*[+`]?\\s*[\'\"`]([^ \'\"`]+)[\'\"`]' # base + path
        ]
        for pattern in api_like_patterns:
             for match in re.findall(pattern, all_js_content):
                endpoint_path = match[0] if isinstance(match, tuple) else match
                endpoint_path = endpoint_path.strip('\'\"`')
                if endpoint_path.startswith('http'):
                    api_endpoints.append(endpoint_path)
                elif base_analysis_url:
                    api_endpoints.append(urljoin(base_analysis_url, endpoint_path))
                else:
                    api_endpoints.append(endpoint_path) # Store as is if no base for joining

        # Clean and normalize
        # Normalization and deduplication
        def normalize_and_deduplicate(url_list, base_for_resolve=None):
            processed = set()
            normalized_list = []
            for u_str in url_list:
                try:
                    # Attempt to join if it's a relative path and base_for_resolve is available
                    if not urlparse(u_str).scheme and base_for_resolve:
                        u_str = urljoin(base_for_resolve, u_str)
                    
                    parsed_u = urlparse(u_str)
                    # Basic filter: must have a scheme and netloc if it's not clearly relative
                    if parsed_u.scheme and parsed_u.netloc:
                        # Remove fragment and standardize
                        u_norm = parsed_u._replace(fragment='', params='', query='').geturl().rstrip('/')
                        if u_norm not in processed:
                            processed.add(u_norm)
                            normalized_list.append(u_norm)
                    elif not parsed_u.scheme and not parsed_u.netloc and parsed_u.path: # Likely relative
                         # For now, keep relative paths if we couldn't resolve them, caller might handle
                         if u_str not in processed: # Store as is, expecting further processing
                            processed.add(u_str)
                            normalized_list.append(u_str)
                except ValueError: # Invalid URL
                    pass 
            return normalized_list

        api_endpoints = normalize_and_deduplicate(api_endpoints, base_analysis_url)
        discovered_urls = normalize_and_deduplicate(list(set(discovered_urls) - set(api_endpoints)), base_analysis_url) # remove API endpoints from general URLs

        print(f"JavaScript Analyzer found {len(api_endpoints)} API endpoints and {len(discovered_urls)} other URLs.")
        return {"api_endpoints": api_endpoints, "other_urls": discovered_urls}

    except requests.exceptions.RequestException as e_req:
        print(f"JavaScript Analyzer: Request error for {url}: {e_req}")
        return {"error": f"Request error: {e_req}", "api_endpoints": [], "other_urls": []}
    except Exception as e:
        import traceback
        print(f"JavaScript Analyzer: Error analyzing {url or 'provided code'}: {e}\\n{traceback.format_exc()}")
        return {"error": f"General error: {e}", "api_endpoints": [], "other_urls": []}

@tool("Discover Endpoints")
def discover_endpoints(url=None, max_pages=20, max_depth=3, passive_only=False, fuzz_params=True, js_analysis_depth=2):
    """
    Discovers all endpoints on a website using techniques similar to Burp Suite.
    This tool combines web crawling and JavaScript analysis to find URLs, forms, and API endpoints.

    Args:
        url (str, optional): The URL of the website to crawl. If not provided, TARGET_URL env var or a default will be used.
        max_pages (int, optional): Maximum number of pages to scan. Defaults to 20.
        max_depth (int, optional): Maximum depth for crawling. Defaults to 3.
        passive_only (bool, optional): Only use passive scanning mode. Defaults to False.
        fuzz_params (bool, optional): Try changing URL parameters to find more endpoints. Defaults to True.
        js_analysis_depth (int, optional): Depth for JavaScript analysis (controls recursive JS discovery if crawler supports it). Defaults to 2.
        
    Returns:
        dict: A dictionary containing lists of discovered URLs, forms, and API endpoints, or an error message.
              Example: {"urls": [...], "forms": [...], "api_endpoints": [...], "error": "message if any"}
    """
    # Check URL from multiple sources
    if url is None or url.strip() == "":
        # Try to get URL from environment variable
        env_url = os.environ.get("TARGET_URL")
        if env_url and env_url.strip() != "":
            url = env_url
            print(f"Discover Endpoints: Using URL from environment variable: {url}")
        else:
            url = "https://example.com" # Default if no URL is provided
            print(f"Discover Endpoints: URL not found. Using default URL: {url}")
    else:
        if not url.startswith(('http://', 'https://')):
            url = "https://" + url
        print(f"Discover Endpoints: Starting discovery on: {url}")

    try:
        print(f"Discover Endpoints: Mode={'Passive' if passive_only else 'Active'}, Max Pages: {max_pages}, Max Depth: {max_depth}, JS Depth: {js_analysis_depth}")

        crawler = WebSiteCrawler(
            start_url=url,
            max_pages=max_pages,
            max_depth=max_depth,
            passive_only=passive_only,
            fuzz_params=fuzz_params,
            js_analysis_depth=js_analysis_depth 
        )
        
        # crawl() returns a dictionary like:
        # {
        #     "urls": list_of_page_urls,
        #     "forms": list_of_form_details,
        #     "api_endpoints": list_of_api_urls,
        #     "js_files": list_of_js_files_found (example, if added)
        # }
        crawl_results = crawler.crawl()
        
        # The WebSiteCrawler's crawl method itself now handles JavaScript analysis
        # and populates self.api_endpoints and self.found_urls internally.
        # The js_analysis_depth parameter is used by the crawler.

        # Log the number of items found
        num_urls = len(crawl_results.get("urls", []))
        num_forms = len(crawl_results.get("forms", []))
        num_apis = len(crawl_results.get("api_endpoints", []))
        print(f"Discover Endpoints: Found {num_urls} page URLs, {num_forms} forms, and {num_apis} API endpoints.")

        return {
            "urls": crawl_results.get("urls", []),
            "forms": crawl_results.get("forms", []),
            "api_endpoints": crawl_results.get("api_endpoints", []),
            "error": None # Explicitly set error to None on success
        }

    except Exception as e:
        import traceback
        error_message = f"Error during endpoint discovery for {url}: {str(e)}"
        print(f"{error_message}\\n{traceback.format_exc()}")
        return {
            "urls": [],
            "forms": [],
            "api_endpoints": [],
            "error": error_message
        }

# Example usage (for testing purposes)
if __name__ == '__main__':
    # Test Web Crawler tool
    # test_url_crawler = "https://example.com" # Replace with a real test site if needed (be responsible)
    # print(f"\\n--- Testing Web Crawler on {test_url_crawler} ---")
    # crawler_output = web_crawler(url=test_url_crawler, max_pages=5, max_depth=2)
    # print("Web Crawler Output:")
    # print(json.dumps(crawler_output, indent=2))

    # Test JavaScript Analyzer tool
    # test_url_js = "https://www.google.com" # A site likely to have complex JS
    # print(f"\\n--- Testing JavaScript Analyzer on {test_url_js} ---")
    # js_analyzer_output = javascript_analyzer(url=test_url_js)
    # print("JavaScript Analyzer Output:")
    # print(json.dumps(js_analyzer_output, indent=2))
    
    # Example with direct JS code:
    # sample_js_code = \"\"\"
    # const API_BASE = "/api/v1";
    # fetch(API_BASE + "/users");
    # fetch('https://example.com/api/v2/items');
    # const anotherUrl = "./data/config.json";
    # console.log(anotherUrl);
    # \"\"\"
    # print(f"\\n--- Testing JavaScript Analyzer with direct code ---")
    # js_analyzer_direct_output = javascript_analyzer(js_code_content=sample_js_code, url="https://base.example.com") # url for base
    # print("JavaScript Analyzer (Direct Code) Output:")
    # print(json.dumps(js_analyzer_direct_output, indent=2))


    # Test Discover Endpoints tool
    test_url_discover = "https://jpshop.netlify.app" # Replace with a real test site
    # Ensure this site is safe and permissible to scan.
    print(f"\\n--- Testing Discover Endpoints on {test_url_discover} ---")
    discover_output = discover_endpoints(url=test_url_discover, max_pages=10, max_depth=2)
    print("Discover Endpoints Output:")
    print(json.dumps(discover_output, indent=2)) 