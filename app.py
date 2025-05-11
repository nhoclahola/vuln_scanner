import sys
import io
import os
import json
import datetime
import argparse
import tempfile
import hashlib
import inspect
import traceback
import threading
import time
import re

# Thêm các thư viện cho Flask
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file, Response

# Thiết lập logging nâng cao
import logging

# Thiết lập logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger('vuln_scanner')

# Create a wrapper to handle Unicode encoding issues
class EncodingWrapper:
    def __init__(self, stream, encoding='utf-8'):
        self.stream = stream
        self.encoding = encoding
        self._wrapped = None
        
    def __getattr__(self, attr):
        if attr in self.__dict__:
            return getattr(self, attr)
        return getattr(self._get_wrapped(), attr)
    
    def _get_wrapped(self):
        if self._wrapped is None:
            self._wrapped = io.TextIOWrapper(
                self.stream.buffer if hasattr(self.stream, 'buffer') else self.stream,
                encoding=self.encoding,
                errors='replace'
            )
        return self._wrapped

# Set up wrapper only when running as Flask app
if not "flask" in sys.argv[0].lower() and not isinstance(sys.stdout, EncodingWrapper):
    sys.stdout = EncodingWrapper(sys.stdout)
    sys.stderr = EncodingWrapper(sys.stderr)

# Add project directories to path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# Safe file opening to handle encoding errors
def safe_open_file(file_path, mode='r', encoding='utf-8'):
    """Open file safely with encoding error handling"""
    try:
        return open(file_path, mode=mode, encoding=encoding)
    except UnicodeDecodeError:
        # Try with Latin-1 encoding if UTF-8 doesn't work
        return open(file_path, mode=mode, encoding='latin-1')

# Thêm các import cần thiết từ main.py
try:
    from crewai import Crew, Process, LLM, Task, Agent
    from crewai.memory import LongTermMemory, ShortTermMemory, EntityMemory
    from dotenv import load_dotenv

    # Sửa đường dẫn import
    from agents.crawler_agent import create_crawler_agent, create_endpoint_scanner_agent
    from agents.information_gatherer import create_information_gatherer_agent
    from agents.security_analyst import create_security_analyst_agent

    from tasks.crawling_tasks import (
        website_crawling_task,
        api_endpoint_discovery_task,
        dynamic_content_analysis_task,
        endpoint_categorization_task
    )

    from tasks.scanning_tasks import (
        xss_scanning_task,
        sql_injection_scanning_task,
        open_redirect_scanning_task,
        csrf_scanning_task,
        path_traversal_scanning_task,
        vulnerability_summary_task
    )

    from tools.web_tools import (
        http_header_fetcher,
        ssl_tls_analyzer,
        cms_detector,
        port_scanner,
        security_headers_analyzer
    )

    from tools.crawler_tools import (
        web_crawler,
        javascript_analyzer
    )

    from tools.vuln_tools import (
        xss_scanner,
        sqli_scanner,
        open_redirect_scanner,
        csrf_scanner,
        path_traversal_scanner,
        scan_xss,
        scan_sqli,
        scan_open_redirect,
        scan_csrf,
        scan_path_traversal
    )

    from tools.security_tools import (
        analyze_vulnerability_severity,
        owasp_risk_score
    )
    HAS_REQUIRED_MODULES = True
except ImportError as e:
    logger.warning(f"Some modules could not be imported: {str(e)}")
    logger.warning("Full functionality may not be available. Only basic scanning will work.")
    HAS_REQUIRED_MODULES = False

# Tải biến môi trường
load_dotenv()

# Khởi tạo ứng dụng Flask
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'vuln_scanner_secret_key')
app.config['SCAN_RESULTS_DIR'] = os.environ.get('SCAN_RESULTS_DIR', 'results')

# Đảm bảo thư mục kết quả tồn tại
if not os.path.exists(app.config['SCAN_RESULTS_DIR']):
    os.makedirs(app.config['SCAN_RESULTS_DIR'])

# Đảm bảo thư mục templates tồn tại
if not os.path.exists(os.path.join(current_dir, 'templates')):
    os.makedirs(os.path.join(current_dir, 'templates'))

# Đảm bảo thư mục static tồn tại
if not os.path.exists(os.path.join(current_dir, 'static')):
    os.makedirs(os.path.join(current_dir, 'static'))

# Hàm tiện ích từ main.py
def save_report_to_file(report, target_url, filename="scan_report.json"):
    """Save scan report to file"""
    try:
        # Normalize URL for use in filename
        safe_url = target_url.replace("://", "_").replace(".", "_").replace("/", "_")
        json_filename = f"report_{safe_url}_{filename}"
        
        # Save original JSON report
        with open(os.path.join(app.config['SCAN_RESULTS_DIR'], json_filename), 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        
        # Save formatted text report
        txt_filename = json_filename.replace('.json', '.txt')
        
        # Check if the report is already well-formatted
        if isinstance(report, dict) and "report" in report and isinstance(report["report"], str) and "# Comprehensive Vulnerability Assessment Report" in report["report"]:
            formatted_report = report["report"]
        else:
            formatted_report = format_vulnerability_report(report)
            
        with open(os.path.join(app.config['SCAN_RESULTS_DIR'], txt_filename), 'w', encoding='utf-8') as f:
            f.write(formatted_report)
        
        return json_filename, txt_filename
    except Exception as e:
        return f"Error saving report: {str(e)}", None

def format_vulnerability_report(report_content):
    """
    Format vulnerability assessment report in a structured and readable way
    
    Args:
        report_content: Original report content
        
    Returns:
        str: Formatted report
    """
    # If the report is already well-formatted, just return it as is
    if isinstance(report_content, str) and "# Comprehensive Vulnerability Assessment Report" in report_content:
        return report_content
    
    # If report is inside a dict under "report" key and is well-formatted
    if isinstance(report_content, dict) and "report" in report_content and isinstance(report_content["report"], str) and "# Comprehensive Vulnerability Assessment Report" in report_content["report"]:
        return report_content["report"]
        
    try:
        # If report is a JSON string, convert to dict
        if isinstance(report_content, str):
            try:
                report_dict = json.loads(report_content)
                if isinstance(report_dict, dict):
                    report_content = report_dict
            except:
                # Not a valid JSON, use as-is
                pass
        
        # Extract relevant information for formatting
        summary = ""
        vulnerabilities = []
        recommendations = []
        
        # Extract from string content
        if isinstance(report_content, str):
            summary = report_content
        # Extract from dict content
        elif isinstance(report_content, dict):
            # Try to extract data from key patterns
            for key, value in report_content.items():
                key_lower = key.lower() if isinstance(key, str) else ""
                
                if "summary" in key_lower or "overview" in key_lower:
                    summary = value
                elif "vulnerabil" in key_lower and isinstance(value, (list, dict)):
                    if isinstance(value, list):
                        vulnerabilities.extend(value)
                    else:
                        for vuln_name, vuln_details in value.items():
                            if isinstance(vuln_details, dict):
                                vuln_details["name"] = vuln_name
                                vulnerabilities.append(vuln_details)
                            else:
                                vulnerabilities.append({
                                    "name": vuln_name,
                                    "details": vuln_details
                                })
                elif "recommend" in key_lower and isinstance(value, (list, str)):
                    if isinstance(value, list):
                        recommendations.extend(value)
                    else:
                        recommendations.append(value)
        
        # Format the report in Markdown
        formatted_report = "# Comprehensive Vulnerability Assessment Report\n\n"
        formatted_report += "## Executive Summary\n\n"
        
        if summary:
            formatted_report += summary + "\n\n"
        else:
            formatted_report += "A security assessment was conducted on the target website to identify potential vulnerabilities and security weaknesses.\n\n"
        
        # Add vulnerabilities section
        formatted_report += "## Identified Vulnerabilities\n\n"
        
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities):
                if isinstance(vuln, dict):
                    formatted_report += f"### {i+1}. {vuln.get('name', 'Unknown Vulnerability')}\n\n"
                    
                    # Add severity if available
                    severity = vuln.get('severity', vuln.get('risk', None))
                    if severity:
                        formatted_report += f"**Severity**: {severity}\n\n"
                    
                    # Add details
                    details = vuln.get('details', vuln.get('description', None))
                    if details:
                        formatted_report += f"**Description**: {details}\n\n"
                    
                    # Add affected locations
                    locations = vuln.get('locations', vuln.get('affected_urls', vuln.get('endpoints', [])))
                    if locations:
                        formatted_report += "**Affected Locations**:\n"
                        if isinstance(locations, list):
                            for loc in locations:
                                formatted_report += f"- {loc}\n"
                        else:
                            formatted_report += f"- {locations}\n"
                        formatted_report += "\n"
                    
                    # Add payload examples
                    payloads = vuln.get('payloads', vuln.get('examples', []))
                    if payloads:
                        formatted_report += "**Example Payloads**:\n"
                        if isinstance(payloads, list):
                            for payload in payloads:
                                formatted_report += f"- `{payload}`\n"
                        else:
                            formatted_report += f"- `{payloads}`\n"
                        formatted_report += "\n"
                else:
                    formatted_report += f"### {i+1}. Vulnerability\n\n"
                    formatted_report += f"{vuln}\n\n"
        else:
            formatted_report += "No vulnerabilities were identified during this assessment.\n\n"
        
        # Add recommendations section
        formatted_report += "## Recommendations\n\n"
        
        if recommendations:
            for i, rec in enumerate(recommendations):
                formatted_report += f"{i+1}. {rec}\n"
        else:
            formatted_report += "1. Regularly update software and dependencies to patch known vulnerabilities.\n"
            formatted_report += "2. Implement proper input validation and output encoding to prevent injection attacks.\n"
            formatted_report += "3. Use Content Security Policy (CSP) to mitigate cross-site scripting attacks.\n"
            formatted_report += "4. Implement proper authentication and authorization mechanisms.\n"
            formatted_report += "5. Conduct regular security assessments to identify new vulnerabilities.\n"
        
        # Add footer
        formatted_report += "\n## Assessment Information\n\n"
        formatted_report += f"Report generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        formatted_report += "Generated by Vulnerability Scanner\n"
        
        return formatted_report
    except Exception as e:
        logger.error(f"Error formatting report: {str(e)}")
        # Return original content if formatting fails
        if isinstance(report_content, str):
            return report_content
        elif isinstance(report_content, dict):
            return json.dumps(report_content, indent=4)
        else:
            return str(report_content) 

def scan_website(scan_id, target_url=None, use_deepseek=True, scan_type="basic", selected_vulnerabilities=None):
    """
    Scan target website and return vulnerability assessment results - Modified from main.py for Flask
    
    Args:
        scan_id (str): Unique ID for this scan
        target_url (str): Target website URL
        use_deepseek (bool): Whether to use DeepSeek LLM
        scan_type (str): Scan type - "basic" or "full"
        selected_vulnerabilities (list): List of vulnerabilities to scan for, if None will scan all based on scan_type
        
    Returns:
        dict: Scan results for storing in database
    """
    scan_logger = logging.getLogger(f"scan_{scan_id}")
    scan_logger.setLevel(logging.INFO)
    
    # Keep track of scan progress
    result_file = os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json")
    
    def update_scan_status(progress, status_message, log_message, agent=None):
        """Update scan status in the database"""
        try:
            with open(result_file, 'r') as f:
                scan_data = json.load(f)
            
            # Update status
            scan_data['progress'] = progress
            
            # Add log
            if "logs" not in scan_data:
                scan_data["logs"] = []
            
            scan_data["logs"].append({
                "time": datetime.datetime.now().strftime('%H:%M:%S'),
                "message": log_message
            })
            
            # Update agent status
            if agent:
                if "agent_status" not in scan_data:
                    scan_data["agent_status"] = {}
                scan_data["agent_status"][agent] = status_message
            
            # Write back to file
            with open(result_file, 'w') as f:
                json.dump(scan_data, f, indent=4)
            
            # Log to console
            scan_logger.info(log_message)
            
        except Exception as e:
            scan_logger.error(f"Error updating scan status: {str(e)}")
    
    if not target_url or target_url.strip() == "":
        error_message = "Error: URL not provided. Please enter a URL to scan."
        update_scan_status(0, "Error", error_message)
        return {"error": error_message}
    
    # Normalize URL if needed
    if not target_url.startswith(('http://', 'https://')):
        target_url = "https://" + target_url
    
    update_scan_status(5, "Starting scan", f"Target URL: {target_url}")
    
    # Initialize LLM
    try:
        if use_deepseek:
            # Set environment variables for DeepSeek
            deepseek_api_key = os.getenv("DEEPSEEK_API_KEY")
            deepseek_api_base = os.getenv("DEEPSEEK_API_BASE")
            
            if not deepseek_api_key or not deepseek_api_base:
                update_scan_status(5, "Configuration", "Missing DeepSeek API key or API base. Switching to OpenAI.")
                use_deepseek = False
            else:
                # Set global environment variables for litellm to use
                os.environ["OPENAI_API_KEY"] = deepseek_api_key
                os.environ["OPENAI_API_BASE"] = deepseek_api_base
                
                # Use LLM integrated in CrewAI with optimized context window settings
                llm = LLM(
                    model="deepseek-chat",  # Model name is required parameter
                    provider="openai",  # Use OpenAI API
                    api_key=deepseek_api_key,
                    api_base=deepseek_api_base,
                    temperature=0.7,
                    context_window=128000,  # Explicitly set DeepSeek's full context window 
                    max_tokens=4096  # Response token limit
                )
                update_scan_status(10, "Configuration", "Using DeepSeek API with 128K context window")
        
        if not use_deepseek:
            # Use OpenAI
            openai_api_key = os.getenv("OPENAI_API_KEY")
            
            if not openai_api_key:
                error_message = "Missing OpenAI API key. Please check your .env file"
                update_scan_status(5, "Error", error_message)
                return {"error": error_message}
            
            # Set global environment variable
            os.environ["OPENAI_API_KEY"] = openai_api_key
            
            # Use LLM integrated in CrewAI with OpenAI
            llm = LLM(
                model="gpt-3.5-turbo",
                provider="openai",
                api_key=openai_api_key,
                temperature=0.7,
                context_window=16000,  # GPT-3.5 has 16K context window
                max_tokens=4096
            )
            update_scan_status(10, "Configuration", "Using OpenAI API with 16K context window")
    except Exception as e:
        error_message = f"Error initializing LLM: {str(e)}"
        update_scan_status(5, "Error", error_message)
        return {"error": error_message}
    
    try:
        # Set global environment variables to ensure all tools can use the target URL
        os.environ["TARGET_URL"] = target_url
        
        # Initialize tools for each agent type
        crawler_tools = [web_crawler, javascript_analyzer]
        scanner_tools = []
        
        # Configure scanner tools based on selected vulnerabilities
        if selected_vulnerabilities:
            if "xss" in selected_vulnerabilities:
                scanner_tools.append(scan_xss)
            if "sqli" in selected_vulnerabilities:
                scanner_tools.append(scan_sqli)
            if "open_redirect" in selected_vulnerabilities:
                scanner_tools.append(scan_open_redirect)
            if "csrf" in selected_vulnerabilities:
                scanner_tools.append(scan_csrf)
            if "path_traversal" in selected_vulnerabilities:
                scanner_tools.append(scan_path_traversal)
        else:
            # Default tools based on scan type
            scanner_tools = [scan_xss, scan_sqli]
            if scan_type == "full":
                scanner_tools.extend([scan_open_redirect, scan_csrf, scan_path_traversal])
        
        info_gatherer_tools = [http_header_fetcher, ssl_tls_analyzer, cms_detector, port_scanner, security_headers_analyzer]
        security_analyst_tools = [analyze_vulnerability_severity, owasp_risk_score]
        
        # Initialize agents with memory_config
        update_scan_status(15, "Initializing agents", "Creating specialized agents for scanning", "setup")
        
        crawler_agent = create_crawler_agent(
            tools=crawler_tools, 
            llm=llm,
            memory=False  # Disable memory at agent level
        )
        
        scanner_agent = create_endpoint_scanner_agent(
            tools=scanner_tools, 
            llm=llm,
            memory=False  # Disable memory at agent level
        )
        
        info_gatherer_agent = create_information_gatherer_agent(
            tools=info_gatherer_tools, 
            llm=llm,
            memory=False  # Disable memory at agent level
        )
        
        security_analyst_agent = create_security_analyst_agent(
            tools=security_analyst_tools, 
            llm=llm,
            memory=False  # Disable memory at agent level
        )
        
        # Define information gathering tasks
        info_gathering_tasks = [
            Task(
                description=f"Analyze HTTP headers for security configuration on {target_url}. Use http_header_fetcher tool to retrieve and analyze HTTP response headers. Look for missing security headers and server information disclosure.",
                expected_output="A detailed analysis of HTTP headers with security recommendations",
                agent=info_gatherer_agent
            ),
            Task(
                description=f"Analyze SSL/TLS configuration on {target_url}. Use ssl_tls_analyzer tool to check for outdated protocols, weak ciphers, and certificate issues.",
                expected_output="A report on SSL/TLS security status with identified weaknesses",
                agent=info_gatherer_agent
            ),
            Task(
                description=f"Detect CMS and technologies used by {target_url}. Use cms_detector tool to identify content management systems, frameworks, and server technologies.",
                expected_output="A list of detected technologies and potential version information",
                agent=info_gatherer_agent
            )
        ]
        
        # Thêm hàm tạo task wrapper để tương thích với main.py
        def create_task_with_backup(task_name, description, expected_output, agent, context_aware=True, async_execution=False, target_url=None):
            """Create a task with automatic backup of results"""
            agent_name = getattr(agent, 'role', str(agent.__class__.__name__)) if agent else "setup"
            update_scan_status(20, f"Creating task: {task_name}", f"Setting up {task_name} task", agent_name)
            
            # Create the task first
            task = Task(
                description=description,
                expected_output=expected_output,
                agent=agent,
                context_aware=context_aware,
                async_execution=async_execution
            )
            
            return task
        
        # Display information about scan type
        if scan_type == "basic":
            update_scan_status(25, "Configuring basic scan", "Setting up basic scan (common vulnerabilities)", "setup")
            tasks = [
                create_task_with_backup(
                    "website_crawling",
                    website_crawling_task(crawler_agent).description,
                    website_crawling_task(crawler_agent).expected_output,
                    crawler_agent,
                    target_url=target_url
                ),
                # Add basic information gathering tasks
                create_task_with_backup(
                    "http_headers_analysis",
                    info_gathering_tasks[0].description,
                    info_gathering_tasks[0].expected_output,
                    info_gatherer_agent,
                    target_url=target_url
                )
            ]
            
            # Add vulnerability scanning tasks based on selected vulnerabilities
            if selected_vulnerabilities:
                if "xss" in selected_vulnerabilities:
                    tasks.append(create_task_with_backup(
                        "xss_scanning",
                        xss_scanning_task(scanner_agent).description,
                        xss_scanning_task(scanner_agent).expected_output,
                        scanner_agent,
                        target_url=target_url
                    ))
                if "sqli" in selected_vulnerabilities:
                    tasks.append(create_task_with_backup(
                        "sql_injection_scanning",
                        sql_injection_scanning_task(scanner_agent).description,
                        sql_injection_scanning_task(scanner_agent).expected_output,
                        scanner_agent,
                        target_url=target_url
                    ))
                if "open_redirect" in selected_vulnerabilities:
                    tasks.append(create_task_with_backup(
                        "open_redirect_scanning",
                        open_redirect_scanning_task(scanner_agent).description,
                        open_redirect_scanning_task(scanner_agent).expected_output,
                        scanner_agent,
                        target_url=target_url
                    ))
                if "csrf" in selected_vulnerabilities:
                    tasks.append(create_task_with_backup(
                        "csrf_scanning",
                        csrf_scanning_task(scanner_agent).description,
                        csrf_scanning_task(scanner_agent).expected_output,
                        scanner_agent,
                        target_url=target_url
                    ))
                if "path_traversal" in selected_vulnerabilities:
                    tasks.append(create_task_with_backup(
                        "path_traversal_scanning",
                        path_traversal_scanning_task(scanner_agent).description,
                        path_traversal_scanning_task(scanner_agent).expected_output,
                        scanner_agent,
                        target_url=target_url
                    ))
            else:
                # Default tasks for basic scan
                tasks.extend([
                    create_task_with_backup(
                        "xss_scanning",
                        xss_scanning_task(scanner_agent).description,
                        xss_scanning_task(scanner_agent).expected_output,
                        scanner_agent,
                        target_url=target_url
                    ),
                    create_task_with_backup(
                        "sql_injection_scanning",
                        sql_injection_scanning_task(scanner_agent).description,
                        sql_injection_scanning_task(scanner_agent).expected_output,
                        scanner_agent,
                        target_url=target_url
                    )
                ])
            
            # Add summary task
            tasks.append(create_task_with_backup(
                "vulnerability_summary",
                "Create a comprehensive summary of all vulnerabilities discovered on the target website. Consolidate findings from all previous scanning tasks and information gathering. Your summary should include ALL details from the crawling phase, headers analysis, XSS scanning, and SQL injection scanning results.",
                "A comprehensive vulnerability summary report with executive summary, complete list of vulnerabilities by severity, and detailed recommendations. The report must include all endpoints found, all vulnerabilities discovered with their exact locations, and specific remediation steps.",
                security_analyst_agent,
                async_execution=False, # Ensure sequential execution to maintain context
                context_aware=True, # Ensure this task receives context from previous tasks
                target_url=target_url
            ))
        else:  # full scan
            update_scan_status(25, "Configuring full scan", "Setting up full scan (all vulnerabilities)", "setup")
            tasks = [
                create_task_with_backup("website_crawling", 
                    website_crawling_task(crawler_agent).description,
                    website_crawling_task(crawler_agent).expected_output,
                    crawler_agent, target_url=target_url),
                create_task_with_backup("api_endpoint_discovery", 
                    api_endpoint_discovery_task(crawler_agent).description,
                    api_endpoint_discovery_task(crawler_agent).expected_output,
                    crawler_agent, target_url=target_url),
                create_task_with_backup("dynamic_content_analysis", 
                    dynamic_content_analysis_task(crawler_agent).description,
                    dynamic_content_analysis_task(crawler_agent).expected_output,
                    crawler_agent, target_url=target_url),
                create_task_with_backup("endpoint_categorization", 
                    endpoint_categorization_task(crawler_agent).description,
                    endpoint_categorization_task(crawler_agent).expected_output,
                    crawler_agent, target_url=target_url),
                # Add all information gathering tasks
                create_task_with_backup("http_headers_analysis", 
                    info_gathering_tasks[0].description, 
                    info_gathering_tasks[0].expected_output,
                    info_gatherer_agent, target_url=target_url),
                create_task_with_backup("ssl_tls_analysis", 
                    info_gathering_tasks[1].description, 
                    info_gathering_tasks[1].expected_output,
                    info_gatherer_agent, target_url=target_url),
                create_task_with_backup("cms_detection", 
                    info_gathering_tasks[2].description, 
                    info_gathering_tasks[2].expected_output,
                    info_gatherer_agent, target_url=target_url),
                create_task_with_backup("port_scanning", 
                    "Scan open ports on " + target_url + ". Use port_scanner tool to identify open ports and services.",
                    "A list of open ports and associated services",
                    info_gatherer_agent, target_url=target_url),
                create_task_with_backup("security_headers_analysis", 
                    "Analyze security headers on " + target_url + ". Use security_headers_analyzer tool to check for presence and configuration of security headers.",
                    "A detailed analysis of security headers with recommendations",
                    info_gatherer_agent, target_url=target_url),
            ]
            
            # Add vulnerability scanning tasks based on selected vulnerabilities or defaults
            if "xss" in selected_vulnerabilities if selected_vulnerabilities else True:
                tasks.append(create_task_with_backup("xss_scanning", 
                    xss_scanning_task(scanner_agent).description,
                    xss_scanning_task(scanner_agent).expected_output,
                    scanner_agent, target_url=target_url))
            
            if "sqli" in selected_vulnerabilities if selected_vulnerabilities else True:
                tasks.append(create_task_with_backup("sql_injection_scanning", 
                    sql_injection_scanning_task(scanner_agent).description,
                    sql_injection_scanning_task(scanner_agent).expected_output,
                    scanner_agent, target_url=target_url))
            
            if "open_redirect" in selected_vulnerabilities if selected_vulnerabilities else True:
                tasks.append(create_task_with_backup("open_redirect_scanning", 
                    open_redirect_scanning_task(scanner_agent).description,
                    open_redirect_scanning_task(scanner_agent).expected_output,
                    scanner_agent, target_url=target_url))
            
            if "csrf" in selected_vulnerabilities if selected_vulnerabilities else True:
                tasks.append(create_task_with_backup("csrf_scanning", 
                    csrf_scanning_task(scanner_agent).description,
                    csrf_scanning_task(scanner_agent).expected_output,
                    scanner_agent, target_url=target_url))
            
            if "path_traversal" in selected_vulnerabilities if selected_vulnerabilities else True:
                tasks.append(create_task_with_backup("path_traversal_scanning", 
                    path_traversal_scanning_task(scanner_agent).description,
                    path_traversal_scanning_task(scanner_agent).expected_output,
                    scanner_agent, target_url=target_url))
            
            # Add summary task
            tasks.append(create_task_with_backup("vulnerability_summary",
                "Create a comprehensive summary of all vulnerabilities discovered on the target website. Consolidate findings from all previous scanning tasks and information gathering. Prioritize issues by severity and provide detailed remediation steps. Your summary should include ALL details from the crawling phase, all API endpoints discovered, dynamic content analysis, header analysis, SSL/TLS configuration, technologies detected, port scanning, all vulnerability scanning results (XSS, SQL Injection, Open Redirect, CSRF, Path Traversal).",
                "A comprehensive vulnerability summary report with executive summary, complete list of vulnerabilities by severity, risk rating, critical issues, and strategic recommendations. The report must include all endpoints found, all vulnerabilities discovered with their exact locations, impact assessment, and specific remediation steps for each issue.",
                security_analyst_agent,
                async_execution=False, # Ensure sequential execution to maintain context
                context_aware=True, # Ensure this task receives context from previous tasks
                target_url=target_url
            ))
            
        # Display scanning tools to be used
        tools_message = "\nScanning tools to be used:\n"
        tools_message += "- Web Crawler - Discover endpoints\n"
        tools_message += "- JavaScript Analyzer - Analyze JavaScript code\n"
        tools_message += "- HTTP Header Fetcher - Collect HTTP headers\n"
        
        if "xss" in selected_vulnerabilities if selected_vulnerabilities else True:
            tools_message += "- XSS Scanner - Scan for XSS vulnerabilities\n"
        if "sqli" in selected_vulnerabilities if selected_vulnerabilities else True:
            tools_message += "- SQL Injection Scanner - Scan for SQL Injection vulnerabilities\n"
        
        if scan_type == "full" or selected_vulnerabilities and any(v in selected_vulnerabilities for v in ["open_redirect", "csrf", "path_traversal"]):
            if "open_redirect" in selected_vulnerabilities if selected_vulnerabilities else True:
                tools_message += "- Open Redirect Scanner - Scan for Open Redirect vulnerabilities\n"
            if "csrf" in selected_vulnerabilities if selected_vulnerabilities else True:
                tools_message += "- CSRF Scanner - Scan for CSRF vulnerabilities\n"
            if "path_traversal" in selected_vulnerabilities if selected_vulnerabilities else True:
                tools_message += "- Path Traversal Scanner - Scan for Path Traversal vulnerabilities\n"
            tools_message += "- SSL/TLS Analyzer - Analyze SSL/TLS configuration\n"
            tools_message += "- CMS Detector - Detect content management systems\n"
            tools_message += "- Port Scanner - Scan for open ports\n"
            tools_message += "- Security Headers Analyzer - Analyze security headers\n"
        
        update_scan_status(30, "Configuring tools", tools_message, "setup")
        
        # Create Crew with optimized memory settings for DeepSeek's large context window
        update_scan_status(35, "Creating AI crew", "Forming the AI agent team for vulnerability scanning", "setup")
        
        vulnerability_scanner_crew = Crew(
            agents=[crawler_agent, scanner_agent, info_gatherer_agent, security_analyst_agent],
            tasks=tasks,
            process=Process.sequential,
            verbose=True,
            memory=False,  # Disable built-in memory system to avoid embedding errors
            context_strategy="full_context" if use_deepseek else "recursive_summarize",  # Use full context for DeepSeek
            max_step_tokens=100000 if use_deepseek else 25000,  # 100K tokens for DeepSeek, 25K for others
            cache=True  # Ensure cache is enabled to save intermediate results
        )
        
        # Before running the crew, log configuration details
        if use_deepseek:
            update_scan_status(40, "Optimization", "Using DeepSeek with 100K max step tokens and full context strategy", "setup")
        else:
            update_scan_status(40, "Optimization", "Using OpenAI with 25K max step tokens and recursive summarize strategy", "setup")
        
        # Update status to running
        update_scan_status(45, "Starting scan", "Beginning vulnerability assessment...", "setup")
        
        # Add exception handling when running crew
        try:
            # Prepare input data
            initial_endpoints = json.dumps(["Discovering..."])
            initial_forms = json.dumps(["Discovering..."])
            
            # Pass URL directly to inputs with multiple keys to ensure it's used
            update_scan_status(50, "Scanning in progress", "AI crew has started scanning the target", "crawler_agent")
            
            results = vulnerability_scanner_crew.kickoff(
                inputs={
                    "target_url": target_url,
                    "url": target_url,
                    "scan_url": target_url,
                    "website_url": target_url,
                    "base_url": target_url,
                    "domain": target_url,
                    "endpoints": initial_endpoints,
                    "forms": initial_forms
                }
            )
            
            # Process results - in this version of CrewAI, we just get the final result
            # The result might be a string or have a raw attribute
            if isinstance(results, str):
                result_content = results
            elif hasattr(results, 'raw'):
                result_content = results.raw
            else:
                # Try to convert to string if all else fails
                result_content = str(results)
            
            update_scan_status(90, "Processing results", "Finalizing scan results and generating report", "security_analyst_agent")
            
            # Apply consistent formatting if needed
            # If the result doesn't already have the comprehensive report format
            if not (isinstance(result_content, str) and "# Comprehensive Vulnerability Assessment Report" in result_content):
                # Try to parse the result as JSON if it's a string
                if isinstance(result_content, str):
                    try:
                        json_content = json.loads(result_content)
                        if isinstance(json_content, dict):
                            result_content = json_content
                    except:
                        pass
                
                # Apply standard formatting
                result_content = format_vulnerability_report(result_content)
            
            # Save report to file
            report_data = {
                "target_url": target_url,
                "scan_time": datetime.datetime.now().isoformat(),
                "scan_type": scan_type,
                "report": result_content
            }
            
            update_scan_status(95, "Saving report", "Saving vulnerability report to file", "security_analyst_agent")
            
            json_filename, txt_filename = save_report_to_file(
                report_data,
                target_url,
                f"{scan_id}_vulnerability_report.json"
            )
            
            update_scan_status(100, "Scan completed", f"Scan completed successfully. Report saved to {json_filename}", "security_analyst_agent")
            
            # Return results for web display
            return {
                "status": "completed",
                "target_url": target_url,
                "report": result_content,
                "json_report": json_filename,
                "txt_report": txt_filename
            }
        except Exception as e:
            error_message = f"Error running crew: {str(e)}"
            update_scan_status(95, "Error", error_message)
            
            return {
                "status": "error",
                "error": error_message
            }
    except Exception as e:
        error_message = f"Unidentified error: {str(e)}"
        update_scan_status(95, "Error", error_message)
        return {
            "status": "error",
            "error": error_message
        } 

# Define Flask routes
@app.route('/')
def index():
    """Home page with scan form."""
    return render_template('index.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    """Start a vulnerability scan."""
    url = request.form.get('url', '')
    if not url:
        flash('URL is required.', 'error')
        return redirect(url_for('index'))
    
    # Create a unique scan ID
    scan_id = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    
    # Get scan type
    scan_type = request.form.get('scan_type', 'basic')
    
    # Get selected vulnerabilities
    vulnerabilities = []
    for vuln in ['xss', 'sqli', 'open_redirect', 'path_traversal', 'csrf']:
        if vuln in request.form:
            vulnerabilities.append(vuln)
    
    if not vulnerabilities:
        flash('Please select at least one vulnerability to scan.', 'error')
        return redirect(url_for('index'))
    
    # Check LLM preference
    use_deepseek = False
    if "use_deepseek" in request.form:
        use_deepseek = True
    elif "use_openai" in request.form:
        use_deepseek = False
    else:
        # Use DeepSeek if the API key is available, otherwise use OpenAI
        deepseek_api_key = os.getenv("DEEPSEEK_API_KEY")
        if deepseek_api_key:
            use_deepseek = True
    
    # Save initial scan details
    scan_data = {
        'id': scan_id,
        'url': url,
        'start_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'initializing',
        'scan_type': scan_type,
        'vulnerabilities': vulnerabilities,
        'use_deepseek': use_deepseek,
        'progress': 0,
        'logs': []
    }
    
    with open(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json"), 'w') as f:
        json.dump(scan_data, f, indent=4)
    
    # Start scan in background thread
    thread = threading.Thread(target=run_background_scan, args=(scan_id, url, vulnerabilities, use_deepseek, scan_type))
    thread.daemon = True
    thread.start()
    
    return redirect(url_for('scan_status', scan_id=scan_id))

def run_background_scan(scan_id, url, vulnerabilities, use_deepseek, scan_type):
    """Run scan in background thread."""
    try:
        # Update scan status to running
        with open(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json"), 'r') as f:
            scan_data = json.load(f)
        
        scan_data['status'] = 'running'
        
        with open(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json"), 'w') as f:
            json.dump(scan_data, f, indent=4)
        
        # Run the scan
        result = scan_website(scan_id, url, use_deepseek, scan_type, vulnerabilities)
        
        # Update scan data with results
        with open(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json"), 'r') as f:
            scan_data = json.load(f)
        
        scan_data['status'] = result.get('status', 'completed' if 'error' not in result else 'error')
        scan_data['progress'] = 100
        scan_data['end_time'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if 'error' in result:
            scan_data['error'] = result['error']
        else:
            scan_data['report'] = result.get('report', '')
            scan_data['json_report'] = result.get('json_report', '')
            scan_data['txt_report'] = result.get('txt_report', '')
        
        with open(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json"), 'w') as f:
            json.dump(scan_data, f, indent=4)
            
    except Exception as e:
        # Update scan with error
        with open(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json"), 'r') as f:
            scan_data = json.load(f)
        
        scan_data['status'] = 'error'
        scan_data['error'] = str(e)
        scan_data['end_time'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        with open(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json"), 'w') as f:
            json.dump(scan_data, f, indent=4)
        
        logger.error(f"Error during scan {scan_id}: {str(e)}")
        logger.error(traceback.format_exc())

@app.route('/status/<scan_id>')
def scan_status(scan_id):
    """Show status of a scan."""
    scan_id = str(scan_id)
    if not os.path.exists(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json")):
        flash('Scan not found.', 'error')
        return redirect(url_for('index'))
    
    with open(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json"), 'r') as f:
        data = json.load(f)
    
    # Thêm kết quả quét cho trang status
    results = {}
    # Với mỗi loại lỗ hổng đã chọn, tạo dữ liệu kết quả tạm thời
    for vuln_type in data.get("vulnerabilities", []):
        results[vuln_type] = {
            "status": "Completed" if data.get("status") == "completed" else "Scanning",
            "vulnerable": False,  # Giá trị mặc định
            "payloads": []
        }
    
    # Nếu quét đã hoàn thành và có báo cáo, phân tích báo cáo để tìm thông tin về lỗ hổng
    if data.get("status") == "completed" and "report" in data:
        # Giá trị mặc định
        overall_risk = "Low"
        
        # Xử lý báo cáo để cập nhật kết quả
        report = data.get("report", "")
        
        # Kiểm tra XSS
        if "xss" in results and ("XSS" in report or "Cross-Site Scripting" in report):
            results["xss"]["vulnerable"] = True
            results["xss"]["payloads"] = ["<script>alert('XSS')</script>"]
            overall_risk = "High"
        
        # Kiểm tra SQL Injection
        if "sqli" in results and ("SQL Injection" in report or "SQLi" in report):
            results["sqli"]["vulnerable"] = True
            results["sqli"]["payloads"] = ["' OR 1=1 --"]
            overall_risk = "High"
        
        # Kiểm tra Open Redirect
        if "open_redirect" in results and "Open Redirect" in report:
            results["open_redirect"]["vulnerable"] = True
            results["open_redirect"]["payloads"] = ["http://evil.com"]
            overall_risk = "Medium"
        
        # Kiểm tra Path Traversal
        if "path_traversal" in results and "Path Traversal" in report:
            results["path_traversal"]["vulnerable"] = True
            results["path_traversal"]["payloads"] = ["../../../etc/passwd"]
            overall_risk = "High"
        
        # Kiểm tra CSRF
        if "csrf" in results and "CSRF" in report:
            results["csrf"]["vulnerable"] = True
            results["csrf"]["payloads"] = ["<form action='transfer.php'>"]
            overall_risk = "Medium"
    else:
        # Nếu quét chưa hoàn thành, không có thông tin về mức độ rủi ro
        overall_risk = None
    
    return render_template(
        'status.html',
        scan_id=scan_id,
        url=data.get("url"),
        start_time=data.get("start_time"),
        end_time=data.get("end_time", ""),
        status=data.get("status"),
        vulnerabilities=data.get("vulnerabilities", []),
        scan_type=data.get("scan_type", "basic"),
        use_deepseek=data.get("use_deepseek", False),
        error=data.get("error", ""),
        progress=data.get("progress", 0),
        logs=data.get("logs", []),
        agent_status=data.get("agent_status", {}),
        results=results,  # Thêm biến results vào context
        overall_risk=overall_risk  # Thêm mức độ rủi ro tổng thể
    )

@app.route('/api/scan_status/<scan_id>')
def api_scan_status(scan_id):
    """API for getting scan status updates."""
    scan_id = str(scan_id)
    if not os.path.exists(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json")):
        return jsonify({'error': 'Scan not found'}), 404
    
    with open(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json"), 'r') as f:
        data = json.load(f)
    
    # Return status data
    return jsonify({
        'status': data.get('status'),
        'progress': data.get('progress', 0),
        'error': data.get('error', ''),
        'agent_status': data.get('agent_status', {}),
        'logs': data.get('logs', [])[-10:] if 'logs' in data else [],  # Only return last 10 logs
        'end_time': data.get('end_time', '')
    })

@app.route('/report/<scan_id>')
def view_report(scan_id):
    """View detailed report of a scan."""
    scan_id = str(scan_id)
    if not os.path.exists(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json")):
        flash('Scan not found.', 'error')
        return redirect(url_for('index'))
    
    with open(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json"), 'r') as f:
        data = json.load(f)
    
    if data.get('status') != 'completed':
        flash('Scan is not completed yet.', 'warning')
        return redirect(url_for('scan_status', scan_id=scan_id))
    
    # Get the raw report content from the Security Analyst
    report_content = data.get('report', '')
    
    # Extract Security Analyst's final answer if it exists
    final_answer = ""
    if "# Agent: Security Analyst" in report_content and "## Final Answer:" in report_content:
        try:
            parts = report_content.split("## Final Answer:")
            if len(parts) > 1:
                final_answer = parts[1].strip()
        except Exception as e:
            logger.error(f"Error extracting Security Analyst final answer: {str(e)}")
    
    # If we couldn't extract the final answer, use the full report
    if not final_answer:
        final_answer = report_content
    
    # Generate results dict for consistency with the template
    vulnerabilities = data.get('vulnerabilities', [])
    results = {}
    for vuln in vulnerabilities:
        vuln_found = False
        if vuln == 'xss' and ('XSS' in final_answer or 'Cross-Site Scripting' in final_answer):
            vuln_found = True
        elif vuln == 'sqli' and ('SQL Injection' in final_answer or 'SQLi' in final_answer):
            vuln_found = True
        elif vuln == 'open_redirect' and 'Open Redirect' in final_answer:
            vuln_found = True
        elif vuln == 'path_traversal' and 'Path Traversal' in final_answer:
            vuln_found = True
        elif vuln == 'csrf' and 'CSRF' in final_answer:
            vuln_found = True
            
        results[vuln] = {
            'vulnerable': vuln_found,
            'payloads': [],
            'details': []
        }
    
    # Determine overall risk level
    overall_risk = "None"
    if "Critical Risk" in final_answer or "Critical vulnerability" in final_answer:
        overall_risk = "Critical"
    elif "High Risk" in final_answer or "High vulnerability" in final_answer:
        overall_risk = "High"
    elif "Medium Risk" in final_answer or "Medium vulnerability" in final_answer:
        overall_risk = "Medium"
    elif "Low Risk" in final_answer or "Low vulnerability" in final_answer:
        overall_risk = "Low"
    
    return render_template(
        'report.html',
        scan_id=scan_id,
        url=data.get("url"),
        start_time=data.get("start_time"),
        end_time=data.get("end_time", ""),
        scan_type=data.get("scan_type", "basic"),
        vulnerabilities=data.get("vulnerabilities", []),
        raw_report=final_answer,  # Use the extracted final answer
        html_report="",  # Don't convert to HTML, display raw markdown
        results=results,
        overall_risk=overall_risk,
        use_markdown=True  # Flag to use markdown rendering in the template
    )

@app.route('/history')
def scan_history():
    """Show history of scans."""
    scans = []
    if os.path.exists(app.config['SCAN_RESULTS_DIR']):
        for filename in os.listdir(app.config['SCAN_RESULTS_DIR']):
            if filename.endswith('.json'):
                try:
                    with open(os.path.join(app.config['SCAN_RESULTS_DIR'], filename), 'r') as f:
                        data = json.load(f)
                    
                    if 'id' in data:  # Only include scan result files
                        scan_data = {
                            'id': data.get('id'),
                            'url': data.get('url'),
                            'start_time': data.get('start_time'),
                            'end_time': data.get('end_time', ""),
                            'status': data.get('status'),
                            'scan_type': data.get('scan_type', 'basic'),
                            'vulnerabilities': data.get('vulnerabilities', [])
                        }
                        scans.append(scan_data)
                except:
                    # Skip files that can't be parsed
                    continue
    
    # Sort by start_time, most recent first
    scans.sort(key=lambda x: x.get('start_time', ''), reverse=True)
    
    return render_template('history.html', scans=scans)

@app.route('/delete_scan/<scan_id>', methods=['POST'])
def delete_scan(scan_id):
    """Delete a scan result."""
    scan_id = str(scan_id)
    if os.path.exists(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json")):
        os.remove(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json"))
        flash('Scan result deleted successfully.', 'success')
    else:
        flash('Scan result not found.', 'error')
    
    return redirect(url_for('scan_history'))

@app.route('/download_report/<scan_id>/<format>')
def download_report(scan_id, format):
    """Download scan report as JSON or TXT."""
    scan_id = str(scan_id)
    if not os.path.exists(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json")):
        flash('Scan result not found.', 'error')
        return redirect(url_for('scan_history'))
    
    with open(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json"), 'r') as f:
        data = json.load(f)
    
    if format == 'json':
        # Create a simplified JSON report
        report_data = {
            'scan_id': scan_id,
            'url': data.get('url'),
            'start_time': data.get('start_time'),
            'end_time': data.get('end_time', ''),
            'scan_type': data.get('scan_type', 'basic'),
            'vulnerabilities_scanned': data.get('vulnerabilities', []),
            'report': data.get('report', ''),
            'report_generated': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Return as JSON download
        response = jsonify(report_data)
        response.headers['Content-Disposition'] = f'attachment; filename=vulnerability_report_{scan_id}.json'
        return response
    
    elif format == 'txt':
        # Get report text
        report_text = data.get('report', '')
        if not isinstance(report_text, str):
            report_text = json.dumps(report_text, indent=4)
        
        # Return as TXT download
        response = Response(report_text, mimetype='text/plain')
        response.headers['Content-Disposition'] = f'attachment; filename=vulnerability_report_{scan_id}.txt'
        return response
    
    else:
        flash('Invalid format specified.', 'error')
        return redirect(url_for('view_report', scan_id=scan_id))

@app.route('/about')
def about():
    """About page with information about the tool."""
    return render_template('about.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for starting a scan programmatically."""
    # Check for JSON data
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    # Get URL
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Create a unique scan ID
    scan_id = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    
    # Get scan type
    scan_type = data.get('scan_type', 'basic')
    if scan_type not in ['basic', 'full']:
        return jsonify({'error': 'Invalid scan type. Must be "basic" or "full"'}), 400
    
    # Get selected vulnerabilities
    vulnerabilities = data.get('vulnerabilities', [])
    if not vulnerabilities:
        # Default vulnerabilities based on scan type
        vulnerabilities = ['xss', 'sqli']
        if scan_type == 'full':
            vulnerabilities.extend(['open_redirect', 'path_traversal', 'csrf'])
    
    # Validate vulnerabilities
    valid_vulns = ['xss', 'sqli', 'open_redirect', 'path_traversal', 'csrf']
    for vuln in vulnerabilities:
        if vuln not in valid_vulns:
            return jsonify({'error': f'Invalid vulnerability type: {vuln}'}), 400
    
    # Check LLM preference
    use_deepseek = data.get('use_deepseek', False)
    
    # Get API key if provided
    api_key = data.get('api_key')
    if api_key:
        if use_deepseek:
            os.environ['DEEPSEEK_API_KEY'] = api_key
        else:
            os.environ['OPENAI_API_KEY'] = api_key
    
    # Save initial scan details
    scan_data = {
        'id': scan_id,
        'url': url,
        'start_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'initializing',
        'scan_type': scan_type,
        'vulnerabilities': vulnerabilities,
        'use_deepseek': use_deepseek,
        'progress': 0,
        'logs': []
    }
    
    with open(os.path.join(app.config['SCAN_RESULTS_DIR'], f"{scan_id}.json"), 'w') as f:
        json.dump(scan_data, f, indent=4)
    
    # Start scan in background thread
    thread = threading.Thread(target=run_background_scan, args=(scan_id, url, vulnerabilities, use_deepseek, scan_type))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'initializing',
        'message': 'Scan started successfully',
        'status_url': url_for('api_scan_status', scan_id=scan_id, _external=True)
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 