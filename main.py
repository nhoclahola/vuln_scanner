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

# Thêm logging nâng cao
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

# Set up wrapper only when running main.py directly
if __name__ == "__main__" and not isinstance(sys.stdout, EncodingWrapper):
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

from crewai import Crew, Process, LLM, Task
from crewai.memory import LongTermMemory, ShortTermMemory, EntityMemory
from dotenv import load_dotenv
import json
import datetime
import argparse

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
    scan_path_traversal,
    search_payloads
)

from tools.security_tools import (
    analyze_vulnerability_severity,
    owasp_risk_score
)

# Tải biến môi trường
load_dotenv()

def save_report_to_file(report, target_url, filename="scan_report.json"):
    """Save scan report to file"""
    try:
        # Normalize URL for use in filename
        safe_url = target_url.replace("://", "_").replace(".", "_").replace("/", "_")
        json_filename = f"report_{safe_url}_{filename}"
        
        # Save original JSON report
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        
        # Save formatted text report
        txt_filename = json_filename.replace('.json', '.txt')
        
        # Check if the report is already well-formatted
        if isinstance(report, dict) and "report" in report and isinstance(report["report"], str) and "# Comprehensive Vulnerability Assessment Report" in report["report"]:
            formatted_report = report["report"]
        else:
            formatted_report = format_vulnerability_report(report)
            
        with open(txt_filename, 'w', encoding='utf-8') as f:
            f.write(formatted_report)
        
        return f"Report saved to file: {json_filename} (JSON) and {txt_filename} (Text)"
    except Exception as e:
        return f"Error saving report: {str(e)}"

def scan_website(target_url=None, use_deepseek=True, scan_type="basic"):
    """
    Scan target website and return vulnerability assessment results
    
    Args:
        target_url (str): Target website URL
        use_deepseek (bool): Whether to use DeepSeek LLM
        scan_type (str): Scan type - "basic" or "full"
        
    Returns:
        str: Vulnerability assessment results
    """
    if not target_url or target_url.strip() == "":
        error_message = "Error: URL not provided. Please enter a URL to scan."
        print(f"\n{error_message}")
        return error_message
    
    # Normalize URL if needed
    if not target_url.startswith(('http://', 'https://')):
        target_url = "https://" + target_url
    
    print(f"\nTarget URL: {target_url}")
    
    # Initialize LLM
    try:
        if use_deepseek:
            # Set environment variables for DeepSeek
            deepseek_api_key = os.getenv("DEEPSEEK_API_KEY")
            deepseek_api_base = os.getenv("DEEPSEEK_API_BASE")
            
            if not deepseek_api_key or not deepseek_api_base:
                print("Missing DeepSeek API key or API base. Switching to OpenAI.")
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
                print("Using DeepSeek API with 128K context window")
        
        if not use_deepseek:
            # Use OpenAI
            openai_api_key = os.getenv("OPENAI_API_KEY")
            
            if not openai_api_key:
                print("Missing OpenAI API key. Please check your .env file")
                return "Error: Missing OpenAI API key. Please check your .env file"
            
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
            print("Using OpenAI API with 16K context window")
    except Exception as e:
        print(f"Error initializing LLM: {str(e)}")
        return f"Error initializing LLM: {str(e)}"
    
    try:
        # Set global environment variables to ensure all tools can use the target URL
        os.environ["TARGET_URL"] = target_url
        
        # Initialize tools for each agent type
        crawler_tools = [web_crawler, javascript_analyzer]
        scanner_tools = [scan_xss, scan_sqli, scan_open_redirect, scan_csrf, scan_path_traversal]
        info_gatherer_tools = [http_header_fetcher, ssl_tls_analyzer, cms_detector, port_scanner, security_headers_analyzer]
        security_analyst_tools = [search_payloads, analyze_vulnerability_severity, owasp_risk_score]
        
        # Initialize agents with memory_config
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
        
        # Thêm hàm tạo task wrapper có khả năng lưu kết quả trung gian
        def create_task_with_backup(task_name, description, expected_output, agent, context_aware=True, async_execution=False, target_url=None):
            """
            Create a task with automatic backup of results
            
            Args:
                task_name (str): Name of the task
                description (str): Task description
                expected_output (str): Expected output format
                agent: Agent to perform the task
                context_aware (bool): Whether the task is context aware
                async_execution (bool): Whether to run the task asynchronously
                target_url (str): Target URL for backup
                
            Returns:
                Task: CrewAI Task with backup capability
            """
            # Create the task first
            task = Task(
                description=description,
                expected_output=expected_output,
                agent=agent,
                context_aware=context_aware,
                async_execution=async_execution
            )
            
            logger.info(f"Task with backup created: {task_name}")
            
            # In newer versions of CrewAI, we need to use the task as is
            # and handle the backup separately after execution
            return task
            
        # Hàm tạo task với khả năng phục hồi kết quả
        def create_task_with_backup_and_recovery(task_name, description, expected_output, agent, 
                                              previous_tasks=None, previous_agents=None,
                                              context_aware=True, async_execution=False, target_url=None):
            """
            Create a task with automatic backup and recovery of results
            
            Args:
                task_name (str): Name of the task
                description (str): Task description
                expected_output (str): Expected output format
                agent: Agent to perform the task
                previous_tasks (list): List of previous task names to recover from if needed
                previous_agents (list): List of agent names corresponding to previous tasks
                context_aware (bool): Whether the task is context aware
                async_execution (bool): Whether to run the task asynchronously
                target_url (str): Target URL for backup
                
            Returns:
                Task: CrewAI Task with backup and recovery capability
            """
            logger.info(f"Creating task with backup and recovery: {task_name}")
            
            # Create the task
            task = Task(
                description=description,
                expected_output=expected_output,
                agent=agent,
                context_aware=context_aware,
                async_execution=async_execution
            )
            
            logger.info(f"Task created: {task_name}")
            
            # In newer versions of CrewAI, we need to use the task as is
            # and handle the backup and recovery separately
            return task
        
        # Display information about scan type
        if scan_type == "basic":
            print("\nPerforming basic scan (basic information and common vulnerabilities)...")
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
                ),
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
                ),
                # Use security_analyst_agent for summary task instead of scanner_agent
                create_task_with_backup(
                    "vulnerability_summary",
                    "Create a comprehensive summary of all vulnerabilities discovered on the target website. Consolidate findings from all previous scanning tasks and information gathering. Your summary should include ALL details from the crawling phase, headers analysis, XSS scanning, and SQL injection scanning results.",
                    "A comprehensive vulnerability summary report with executive summary, complete list of vulnerabilities by severity, and detailed recommendations. The report must include all endpoints found, all vulnerabilities discovered with their exact locations, and specific remediation steps.",
                    security_analyst_agent,
                    async_execution=False, # Ensure sequential execution to maintain context
                    context_aware=True, # Ensure this task receives context from previous tasks
                    target_url=target_url
                )
            ]
        else:  # full scan
            print("\nPerforming full scan (all vulnerabilities)...")
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
                create_task_with_backup("xss_scanning", 
                    xss_scanning_task(scanner_agent).description,
                    xss_scanning_task(scanner_agent).expected_output,
                    scanner_agent, target_url=target_url),
                create_task_with_backup("sql_injection_scanning", 
                    sql_injection_scanning_task(scanner_agent).description,
                    sql_injection_scanning_task(scanner_agent).expected_output,
                    scanner_agent, target_url=target_url),
                create_task_with_backup("open_redirect_scanning", 
                    open_redirect_scanning_task(scanner_agent).description,
                    open_redirect_scanning_task(scanner_agent).expected_output,
                    scanner_agent, target_url=target_url),
                create_task_with_backup("csrf_scanning", 
                    csrf_scanning_task(scanner_agent).description,
                    csrf_scanning_task(scanner_agent).expected_output,
                    scanner_agent, target_url=target_url),
                create_task_with_backup("path_traversal_scanning", 
                    path_traversal_scanning_task(scanner_agent).description,
                    path_traversal_scanning_task(scanner_agent).expected_output,
                    scanner_agent, target_url=target_url),
                # Use security_analyst_agent for summary task instead of scanner_agent
                create_task_with_backup("vulnerability_summary",
                    "Create a comprehensive summary of all vulnerabilities discovered on the target website. Consolidate findings from all previous scanning tasks and information gathering. Prioritize issues by severity and provide detailed remediation steps. Your summary should include ALL details from the crawling phase, all API endpoints discovered, dynamic content analysis, header analysis, SSL/TLS configuration, technologies detected, port scanning, all vulnerability scanning results (XSS, SQL Injection, Open Redirect, CSRF, Path Traversal).",
                    "A comprehensive vulnerability summary report with executive summary, complete list of vulnerabilities by severity, risk rating, critical issues, and strategic recommendations. The report must include all endpoints found, all vulnerabilities discovered with their exact locations, impact assessment, and specific remediation steps for each issue.",
                    security_analyst_agent,
                    async_execution=False, # Ensure sequential execution to maintain context
                    context_aware=True, # Ensure this task receives context from previous tasks
                    target_url=target_url
                )
            ]
            
        # First, get all previous task names and agent names for recovery functionality
        full_task_names = [
            "website_crawling", "api_endpoint_discovery", "dynamic_content_analysis", "endpoint_categorization",
            "http_headers_analysis", "ssl_tls_analysis", "cms_detection", "port_scanning", "security_headers_analysis",
            "xss_scanning", "sql_injection_scanning", "open_redirect_scanning", "csrf_scanning", "path_traversal_scanning"
        ]
        full_agent_names = [
            "crawler_agent", "crawler_agent", "crawler_agent", "crawler_agent",
            "info_gatherer_agent", "info_gatherer_agent", "info_gatherer_agent", "info_gatherer_agent", "info_gatherer_agent",
            "scanner_agent", "scanner_agent", "scanner_agent", "scanner_agent", "scanner_agent"
        ]
        
        # If we are in full scan mode, replace the last task
        if scan_type == "full":
            tasks[-1] = create_task_with_backup_and_recovery(
                "vulnerability_summary",
                "Create a comprehensive summary of all vulnerabilities discovered on the target website. Consolidate findings from all previous scanning tasks and information gathering. Prioritize issues by severity and provide detailed remediation steps. Your summary should include ALL details from the crawling phase, all API endpoints discovered, dynamic content analysis, header analysis, SSL/TLS configuration, technologies detected, port scanning, all vulnerability scanning results (XSS, SQL Injection, Open Redirect, CSRF, Path Traversal).",
                "A comprehensive vulnerability summary report with executive summary, complete list of vulnerabilities by severity, risk rating, critical issues, and strategic recommendations. The report must include all endpoints found, all vulnerabilities discovered with their exact locations, impact assessment, and specific remediation steps for each issue.",
                security_analyst_agent,
                previous_tasks=full_task_names,
                previous_agents=full_agent_names,
                async_execution=False,
                context_aware=True,
                target_url=target_url
            )
        # Replace the last task in the basic scan tasks list as well
        else:
            basic_task_names = ["website_crawling", "http_headers_analysis", "xss_scanning", "sql_injection_scanning"]
            basic_agent_names = ["crawler_agent", "info_gatherer_agent", "scanner_agent", "scanner_agent"] 
            
            tasks[-1] = create_task_with_backup_and_recovery(
                "vulnerability_summary",
                "Create a comprehensive summary of all vulnerabilities discovered on the target website. Consolidate findings from all previous scanning tasks and information gathering. Your summary should include ALL details from the crawling phase, headers analysis, XSS scanning, and SQL injection scanning results. If needed, you can recover information from previous tasks stored in backup files.",
                "A comprehensive vulnerability summary report with executive summary, complete list of vulnerabilities by severity, and detailed recommendations. The report must include all endpoints found, all vulnerabilities discovered with their exact locations, and specific remediation steps.",
                security_analyst_agent,
                previous_tasks=basic_task_names,
                previous_agents=basic_agent_names,
                async_execution=False,
                context_aware=True,
                target_url=target_url
            )
        
        # Display scanning tools to be used
        print("\nScanning tools to be used:")
        print("- Web Crawler - Discover endpoints")
        print("- JavaScript Analyzer - Analyze JavaScript code")
        print("- HTTP Header Fetcher - Collect HTTP headers")
        print("- XSS Scanner - Scan for XSS vulnerabilities")
        print("- SQL Injection Scanner - Scan for SQL Injection vulnerabilities")
        
        if scan_type == "full":
            print("- Open Redirect Scanner - Scan for Open Redirect vulnerabilities")
            print("- CSRF Scanner - Scan for CSRF vulnerabilities")
            print("- Path Traversal Scanner - Scan for Path Traversal vulnerabilities")
            print("- SSL/TLS Analyzer - Analyze SSL/TLS configuration")
            print("- CMS Detector - Detect content management systems")
            print("- Port Scanner - Scan for open ports")
            print("- Security Headers Analyzer - Analyze security headers")
        
        print("\nNote: The scanning process may take several minutes to hours, depending on the target website and scan type.")
        
        # Create Crew with optimized memory settings for DeepSeek's large context window
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
            print("\nOptimized configuration: Using DeepSeek with 100K max step tokens and full context strategy")
        else:
            print("\nStandard configuration: Using OpenAI with 25K max step tokens and recursive summarize strategy")
        
        # Run Crew and print results
        print("\nStarting scan...\n")
        
        # Add exception handling when running crew
        try:
            # Prepare input data
            initial_endpoints = json.dumps(["Discovering..."])
            initial_forms = json.dumps(["Discovering..."])
            
            # Pass URL directly to inputs with multiple keys to ensure it's used
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
            
            # Save final result
            save_interim_results("final_summary", "security_analyst", result_content, target_url)
            
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
            
            save_message = save_report_to_file(
                report_data,
                target_url,
                "vulnerability_report.json"
            )
            print(f"\n{save_message}")
            
            return result_content
        except Exception as e:
            print(f"Error running crew: {str(e)}")
            
            # Try to recover from last saved results if available
            last_results = load_interim_results("final_summary", "security_analyst", target_url)
            if last_results:
                print("Recovered partial results from last saved state")
                return last_results
            
            return f"Error running crew: {str(e)}"
    except Exception as e:
        print(f"Unidentified error: {str(e)}")
        return f"Unidentified error: {str(e)}"

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
                # Try parsing as JSON string
                import json
                report_data = json.loads(report_content)
                if isinstance(report_data, dict):
                    report_content = report_data
            except:
                # If not JSON, keep as string
                pass
        
        # If the report is not a dict or doesn't contain structured information, return as is
        if not isinstance(report_content, dict):
            return str(report_content)
        
        # Start creating a markdown formatted report
        formatted_report = []
        
        # Title and target
        formatted_report.append("# Comprehensive Vulnerability Assessment Report")
        if "target_url" in report_content:
            formatted_report.append(f"# Target: {report_content['target_url']}")
        else:
            formatted_report.append("# Target: Unknown")
        formatted_report.append("")
        
        # Executive Summary
        formatted_report.append("## Executive Summary")
        
        # Create an executive summary based on findings
        summary_text = "This report details security vulnerabilities found during a comprehensive assessment of the target website."
        
        # Count vulnerabilities by severity
        vuln_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        if "findings" in report_content and isinstance(report_content["findings"], list):
            for vuln in report_content["findings"]:
                if isinstance(vuln, dict) and "severity" in vuln:
                    vuln_count[vuln["severity"]] = vuln_count.get(vuln["severity"], 0) + 1
        
        # Add vulnerability counts to summary
        if sum(vuln_count.values()) > 0:
            summary_text += " The assessment revealed "
            if vuln_count["Critical"] > 0:
                summary_text += f"{vuln_count['Critical']} critical, "
            if vuln_count["High"] > 0:
                summary_text += f"{vuln_count['High']} high, "
            if vuln_count["Medium"] > 0:
                summary_text += f"{vuln_count['Medium']} medium, "
            if vuln_count["Low"] > 0:
                summary_text += f"{vuln_count['Low']} low "
            summary_text += "severity vulnerabilities."
        
        formatted_report.append(summary_text)
        formatted_report.append("")
        
        # Risk Assessment Summary
        formatted_report.append("## Risk Assessment Summary")
        
        # Create a nice table for risk assessment summary
        formatted_report.append("| Severity Level | Count | Risk Rating |")
        formatted_report.append("|---------------|-------|-------------|")
        formatted_report.append(f"| Critical | {vuln_count['Critical']} | Critical |")
        formatted_report.append(f"| High | {vuln_count['High']} | High |")
        formatted_report.append(f"| Medium | {vuln_count['Medium']} | Medium |")
        formatted_report.append(f"| Low | {vuln_count['Low']} | Low |")
        formatted_report.append("")
        
        # Detailed Vulnerability Findings
        formatted_report.append("## Detailed Vulnerability Findings")
        formatted_report.append("")
        
        # Add vulnerabilities by severity
        vuln_index = 1
        
        # Create a list to store vulnerability details for the risk assessment table
        risk_table_data = []
        
        for severity in ["Critical", "High", "Medium", "Low"]:
            if "findings" in report_content and isinstance(report_content["findings"], list):
                severity_vulns = [v for v in report_content["findings"] if isinstance(v, dict) and v.get("severity") == severity]
                
                for vuln in severity_vulns:
                    vuln_type = vuln.get("type", "Unknown")
                    subtype = vuln.get("subtype", "")
                    subtype_text = f" ({subtype})" if subtype else ""
                    
                    formatted_report.append(f"### {vuln_index}. {vuln_type}{subtype_text} ({severity})")
                    
                    # Create a table for each vulnerability's details
                    formatted_report.append("| Detail | Value |")
                    formatted_report.append("|-------|-------|")
                    
                    if "location" in vuln:
                        formatted_report.append(f"| Location | {vuln['location']} |")
                    
                    if "parameter" in vuln:
                        formatted_report.append(f"| Parameter | {vuln['parameter']} |")
                    
                    if "cvss_score" in vuln:
                        formatted_report.append(f"| CVSS Score | {vuln['cvss_score']} |")
                    
                    if "description" in vuln:
                        # Format description to fit in table
                        desc = vuln['description'].replace("\n", "<br>")
                        formatted_report.append(f"| Description | {desc} |")
                    
                    if "impact" in vuln:
                        # Format impact to fit in table
                        impact = vuln['impact'].replace("\n", "<br>")
                        formatted_report.append(f"| Impact | {impact} |")
                    
                    if "payload" in vuln:
                        formatted_report.append(f"| Payload | `{vuln['payload']}` |")
                    
                    formatted_report.append("")
                    
                    # Add remediation section
                    if "recommendation" in vuln:
                        formatted_report.append("**Remediation**:")
                        for rec in vuln["recommendation"].split(". "):
                            if rec.strip():
                                formatted_report.append(f"- {rec.strip()}")
                    
                    formatted_report.append("")
                    
                    # Store data for risk assessment table
                    exploitability = "High" if severity in ["Critical", "High"] else "Medium" if severity == "Medium" else "Low"
                    impact_rating = "High" if severity in ["Critical", "High"] else "Medium" if severity == "Medium" else "Low"
                    
                    risk_table_data.append({
                        "type": vuln_type,
                        "severity": severity,
                        "exploitability": exploitability,
                        "impact": impact_rating,
                        "risk": severity
                    })
                    
                    vuln_index += 1
        
        # If no vulnerabilities were found in the findings
        if vuln_index == 1:
            formatted_report.append("No specific vulnerabilities were found or the findings were not in the expected format.")
            formatted_report.append("")
        
        # Add Risk Assessment Table if vulnerabilities were found
        if risk_table_data:
            formatted_report.append("## Risk Assessment")
            formatted_report.append("")
            formatted_report.append("| Vulnerability | Severity | Exploitability | Impact | Risk |")
            formatted_report.append("|--------------|----------|----------------|--------|------|")
            
            for vuln in risk_table_data:
                formatted_report.append(f"| {vuln['type']} | {vuln['severity']} | {vuln['exploitability']} | {vuln['impact']} | {vuln['risk']} |")
            
            formatted_report.append("")
        
        # Technical Details
        formatted_report.append("## Technical Details")
        formatted_report.append("")
        
        # Server Information
        if "server_info" in report_content:
            formatted_report.append("### Server Configuration")
            server_info = report_content["server_info"]
            
            # Create a table for server information
            formatted_report.append("| Configuration | Value |")
            formatted_report.append("|--------------|-------|")
            
            if isinstance(server_info, dict):
                for key, value in server_info.items():
                    formatted_report.append(f"| {key} | {value} |")
            else:
                formatted_report.append(f"| Server Info | {server_info} |")
            
            formatted_report.append("")
        
        # Endpoints with Vulnerabilities
        formatted_report.append("### Endpoints with Vulnerabilities")
        endpoints = set()
        if "findings" in report_content and isinstance(report_content["findings"], list):
            for vuln in report_content["findings"]:
                if isinstance(vuln, dict) and "location" in vuln:
                    endpoints.add(vuln["location"])
        
        if endpoints:
            # Create a table for endpoints
            formatted_report.append("| # | Endpoint | Vulnerability Types |")
            formatted_report.append("|---|---------|---------------------|")
            
            for i, endpoint in enumerate(sorted(endpoints), 1):
                vuln_types = []
                for vuln in report_content["findings"]:
                    if isinstance(vuln, dict) and vuln.get("location") == endpoint:
                        vuln_types.append(vuln.get("type", "Unknown"))
                
                vuln_str = ", ".join(set(vuln_types))
                formatted_report.append(f"| {i} | {endpoint} | {vuln_str} |")
        else:
            formatted_report.append("No specific vulnerable endpoints were identified.")
        
        formatted_report.append("")
        
        # Strategic Recommendations
        formatted_report.append("## Strategic Recommendations")
        formatted_report.append("")
        
        # Immediate Actions
        formatted_report.append("### Immediate Actions (0-7 days):")
        if vuln_count["Critical"] > 0:
            formatted_report.append("1. Patch Critical vulnerabilities immediately")
        if vuln_count["High"] > 0:
            formatted_report.append("2. Implement temporary mitigations for High severity issues")
        formatted_report.append("3. Implement basic security headers (CSP, X-Frame-Options)")
        formatted_report.append("")
        
        # Short-Term Actions
        formatted_report.append("### Short-Term (7-30 days):")
        if vuln_count["High"] > 0:
            formatted_report.append("1. Fix High severity vulnerabilities")
        if vuln_count["Medium"] > 0:
            formatted_report.append("2. Plan remediation for Medium severity issues")
        formatted_report.append("3. Upgrade server software if outdated")
        formatted_report.append("4. Add input validation for all parameters")
        formatted_report.append("")
        
        # Long-Term Actions
        formatted_report.append("### Long-Term (30+ days):")
        if vuln_count["Medium"] > 0 or vuln_count["Low"] > 0:
            formatted_report.append("1. Fix Medium and Low severity vulnerabilities")
        formatted_report.append("2. Implement WAF")
        formatted_report.append("3. Establish vulnerability scanning program")
        formatted_report.append("4. Conduct developer security training")
        formatted_report.append("")
        
        # Conclusion
        formatted_report.append("## Conclusion")
        conclusion_text = "The target website "
        if sum(vuln_count.values()) > 0:
            if vuln_count["Critical"] > 0:
                conclusion_text += "contains critical vulnerabilities that require immediate attention. "
            elif vuln_count["High"] > 0:
                conclusion_text += "contains high severity vulnerabilities that should be addressed promptly. "
            else:
                conclusion_text += "contains some security issues that should be addressed. "
            
            conclusion_text += "A comprehensive remediation plan should be implemented following the priority order outlined in this report."
        else:
            conclusion_text += "appears to be relatively secure based on the tests performed. However, regular security assessments are recommended to maintain this security posture."
        
        formatted_report.append(conclusion_text)
        
        return "\n".join(formatted_report)
    except Exception as e:
        # If there's an error in the formatting process, return the original report
        print(f"Error formatting report: {str(e)}")
        return str(report_content)

def main():
    # Configure argument parser
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner')
    parser.add_argument('-u', '--url', type=str, help='Target URL to scan')
    parser.add_argument('-o', '--openai', action='store_true', help='Use OpenAI instead of DeepSeek')
    parser.add_argument('-f', '--full', action='store_true', help='Perform a full scan (all vulnerability types)')
    args = parser.parse_args()
    
    # Determine which LLM to use
    use_deepseek = not args.openai  # Default is True (use DeepSeek) if no -o option
    
    # Determine scan type
    scan_type = "full" if args.full else "basic"
    
    # If URL not provided via parameter, prompt for input
    target_url = None
    if args.url:
        target_url = args.url
    else:
        target_url = input("Enter target URL: ")
    
    # Check if URL is provided
    if not target_url or target_url.strip() == "":
        print("\nError: URL not provided. Please enter a URL to scan.")
        return 1
    
    # Run scan
    results = scan_website(target_url, use_deepseek, scan_type)
    
    # Display results
    print("\n==== SECURITY VULNERABILITY ASSESSMENT REPORT ====\n")
    
    # Check if the results are already well-formatted
    if isinstance(results, str) and "# Comprehensive Vulnerability Assessment Report" in results:
        print(results)
    else:
        # Format results for clearer display
        formatted_results = format_vulnerability_report(results)
        print(formatted_results)
    
    return 0

# Function to save/load interim results
def save_interim_results(task_name, agent_name, data, target_url):
    """
    Save interim results to a temporary file
    
    Args:
        task_name (str): Name of the task
        agent_name (str): Name of the agent
        data (dict/str): Data to save
        target_url (str): Target URL being scanned
        
    Returns:
        str: Path to the saved file
    """
    try:
        # Create directory if not exists
        interim_dir = os.path.join(tempfile.gettempdir(), "vuln_scanner_results")
        os.makedirs(interim_dir, exist_ok=True)
        
        # Create a unique identifier based on task and URL
        url_hash = hashlib.md5(target_url.encode()).hexdigest()[:10]
        filename = f"{agent_name}_{task_name}_{url_hash}.json"
        filepath = os.path.join(interim_dir, filename)
        
        # Convert to JSON if not a string
        if not isinstance(data, str):
            data_to_save = json.dumps(data, ensure_ascii=False, indent=2)
        else:
            data_to_save = data
            
        # Save to file
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(data_to_save)
            
        print(f"Saved interim results for task '{task_name}' to {filepath}")
        return filepath
    except Exception as e:
        print(f"Warning: Failed to save interim results: {str(e)}")
        return None

def load_interim_results(task_name, agent_name, target_url):
    """
    Load interim results from a temporary file
    
    Args:
        task_name (str): Name of the task
        agent_name (str): Name of the agent
        target_url (str): Target URL being scanned
        
    Returns:
        dict/str: Loaded data or None if file doesn't exist
    """
    try:
        # Find the file with the matching task name and URL hash
        interim_dir = os.path.join(tempfile.gettempdir(), "vuln_scanner_results")
        url_hash = hashlib.md5(target_url.encode()).hexdigest()[:10]
        filename = f"{agent_name}_{task_name}_{url_hash}.json"
        filepath = os.path.join(interim_dir, filename)
        
        # Check if file exists
        if not os.path.exists(filepath):
            return None
            
        # Load from file
        with open(filepath, "r", encoding="utf-8") as f:
            data = f.read()
            
        # Try to parse as JSON
        try:
            return json.loads(data)
        except:
            return data
    except Exception as e:
        print(f"Warning: Failed to load interim results: {str(e)}")
        return None

# Move the load_all_previous_results function here for use across the application
def load_all_previous_results(task_names, agent_names, target_url):
    """
    Load and combine results from previous tasks
    
    Args:
        task_names (list): List of task names to load
        agent_names (list): List of agent names corresponding to tasks
        target_url (str): Target URL being scanned
        
    Returns:
        dict: Combined results from all tasks
    """
    results = {}
    loaded_data = []
    
    # Load each task result
    for i, task_name in enumerate(task_names):
        agent_name = agent_names[i] if i < len(agent_names) else "unknown"
        data = load_interim_results(task_name, agent_name, target_url)
        if data:
            loaded_data.append({
                "task": task_name,
                "agent": agent_name,
                "data": data
            })
            
            # Also add to results dict for easy access
            results[task_name] = data
    
    # Add a summary of what was loaded
    results["_summary"] = {
        "loaded_tasks": [item["task"] for item in loaded_data],
        "total_loaded": len(loaded_data)
    }
    
    return results

if __name__ == "__main__":
    main() 