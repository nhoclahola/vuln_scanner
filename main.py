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
import sqlite3

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

# SQLite Database setup
DB_NAME = "vuln_scanner_history.db"

def init_db():
    """Khởi tạo cơ sở dữ liệu SQLite và bảng scans nếu chưa tồn tại."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            scan_type TEXT,
            scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT, 
            report_json_path TEXT,
            report_md_path TEXT 
        )
    """)
    conn.commit()
    conn.close()
    logger.info(f"Database {DB_NAME} initialized.")

def log_scan_start(target_url, scan_type):
    """Ghi lại thông tin khi một lượt quét bắt đầu và trả về ID của bản ghi."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (target_url, scan_type, status)
        VALUES (?, ?, ?)
    """, (target_url, scan_type, "Running"))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    logger.info(f"Scan started for {target_url} (Type: {scan_type}). DB ID: {scan_id}")
    return scan_id

def log_scan_end(scan_id, status, report_json_path=None, report_md_path=None):
    """Cập nhật thông tin khi một lượt quét kết thúc."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE scans
        SET status = ?, report_json_path = ?, report_md_path = ?
        WHERE id = ?
    """, (status, report_json_path, report_md_path, scan_id))
    conn.commit()
    conn.close()
    logger.info(f"Scan ID {scan_id} updated. Status: {status}, JSON Report: {report_json_path}, MD Report: {report_md_path}")

# Safe file opening to handle encoding errors
def safe_open_file(file_path, mode='r', encoding='utf-8'):
    """Open file safely with encoding error handling"""
    try:
        return open(file_path, mode=mode, encoding=encoding)
    except UnicodeDecodeError:
        # Try with Latin-1 encoding if UTF-8 doesn't work
        return open(file_path, mode=mode, encoding='latin-1')

from crewai import Crew, Process, LLM, Task, Agent
from crewai.memory import LongTermMemory, ShortTermMemory, EntityMemory
from dotenv import load_dotenv
import json
import datetime
import argparse

# Sửa đường dẫn import
from agents.crawler_agent import create_crawler_agent, create_endpoint_scanner_agent
from agents.information_gatherer import create_information_gatherer_agent
from agents.security_analyst import create_security_analyst_agent
from agents.report_formatter_agent import create_json_report_formatter_agent

from tasks.crawling_tasks import (
    website_crawling_task,
    api_endpoint_discovery_task,
    dynamic_content_analysis_task,
    endpoint_categorization_task
)

from tasks.report_formatting_tasks import create_json_report_formatting_task

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

# Tải biến môi trường
load_dotenv()

def scan_website(target_url=None, use_deepseek=True, scan_type="basic", current_scan_id=None):
    """
    Scan target website and return vulnerability assessment results
    
    Args:
        target_url (str): Target website URL
        use_deepseek (bool): Whether to use DeepSeek LLM
        scan_type (str): Scan type - "basic" or "full"
        current_scan_id (int): The ID of the current scan in the database
        
    Returns:
        str: Vulnerability assessment results (status message)
        str: Path to the main JSON report file
        str: Path to the Markdown report file
    """
    if not target_url or target_url.strip() == "":
        error_message = "Error: URL not provided. Please enter a URL to scan."
        logger.error(error_message)
        # Trả về 3 giá trị, các đường dẫn file là None
        return error_message, None, None
    
    # Normalize URL if needed
    if not target_url.startswith(('http://', 'https://')):
        target_url = "https://" + target_url
    
    logger.info(f"Target URL: {target_url}")
    
    # Initialize LLM
    try:
        if use_deepseek:
            # Set environment variables for DeepSeek
            deepseek_api_key = os.getenv("DEEPSEEK_API_KEY")
            deepseek_api_base = os.getenv("DEEPSEEK_API_BASE")
            
            if not deepseek_api_key or not deepseek_api_base:
                logger.warning("Missing DeepSeek API key or API base. Switching to OpenAI.")
                use_deepseek = False
            else:
                # Set global environment variables for litellm to use
                os.environ["OPENAI_API_KEY"] = deepseek_api_key
                os.environ["OPENAI_API_BASE"] = deepseek_api_base
                
                llm = LLM(
                    model="deepseek-chat",
                    provider="openai",
                    api_key=deepseek_api_key,
                    api_base=deepseek_api_base,
                    temperature=0.7,
                    context_window=128000,
                    max_tokens=4096
                )
                logger.info("Using DeepSeek API with 128K context window")
        
        if not use_deepseek:
            openai_api_key = os.getenv("OPENAI_API_KEY")
            if not openai_api_key:
                err_msg = "Error: Missing OpenAI API key. Please check your .env file"
                logger.error(err_msg)
                return err_msg, None, None
            
            os.environ["OPENAI_API_KEY"] = openai_api_key
            llm = LLM(
                model="gpt-3.5-turbo",
                provider="openai",
                api_key=openai_api_key,
                temperature=0.7,
                context_window=16000,
                max_tokens=4096
            )
            logger.info("Using OpenAI API with 16K context window")
    except Exception as e:
        err_msg = f"Error initializing LLM: {str(e)}"
        logger.error(err_msg, exc_info=True)
        return err_msg, None, None
    
    try:
        os.environ["TARGET_URL"] = target_url
        
        crawler_tools = [web_crawler, javascript_analyzer]
        scanner_tools = [scan_xss, scan_sqli, scan_open_redirect, scan_csrf, scan_path_traversal]
        info_gatherer_tools = [http_header_fetcher, ssl_tls_analyzer, cms_detector, port_scanner, security_headers_analyzer]
        security_analyst_tools = [analyze_vulnerability_severity, owasp_risk_score]
        
        crawler_agent = create_crawler_agent(tools=crawler_tools, llm=llm, memory=False)
        scanner_agent = create_endpoint_scanner_agent(tools=scanner_tools, llm=llm, memory=False)
        info_gatherer_agent = create_information_gatherer_agent(tools=info_gatherer_tools, llm=llm, memory=False)
        security_analyst_agent = create_security_analyst_agent(tools=security_analyst_tools, llm=llm, memory=False)
        
        info_gathering_tasks_defs = [
            ("Analyze HTTP headers for security configuration on {target_url}. Use http_header_fetcher tool to retrieve and analyze HTTP response headers. Look for missing security headers and server information disclosure.",
             "A detailed analysis of HTTP headers with security recommendations"),
            ("Analyze SSL/TLS configuration on {target_url}. Use ssl_tls_analyzer tool to check for outdated protocols, weak ciphers, and certificate issues.",
             "A report on SSL/TLS security status with identified weaknesses"),
            ("Detect CMS and technologies used by {target_url}. Use cms_detector tool to identify content management systems, frameworks, and server technologies.",
             "A list of detected technologies and potential version information")
        ]

        tasks = []
        if scan_type == "basic":
            logger.info("Performing basic scan (basic information and common vulnerabilities)...")
            tasks = [
                Task(description=website_crawling_task(crawler_agent).description.format(target_url=target_url), expected_output=website_crawling_task(crawler_agent).expected_output, agent=crawler_agent),
                Task(description=info_gathering_tasks_defs[0][0].format(target_url=target_url), expected_output=info_gathering_tasks_defs[0][1], agent=info_gatherer_agent),
                Task(description=xss_scanning_task(scanner_agent).description.format(target_url=target_url), expected_output=xss_scanning_task(scanner_agent).expected_output, agent=scanner_agent, context_aware=True),
                Task(description=sql_injection_scanning_task(scanner_agent).description.format(target_url=target_url), expected_output=sql_injection_scanning_task(scanner_agent).expected_output, agent=scanner_agent, context_aware=True),
                Task(description=f"Create a comprehensive summary of all vulnerabilities discovered on {target_url}. Consolidate findings from all previous tasks.", 
                     expected_output="A comprehensive vulnerability summary report including all findings and recommendations.", 
                     agent=security_analyst_agent, context_aware=True, async_execution=False)
            ]
        else: # full scan
            logger.info("Performing full scan (all vulnerabilities)...")
            tasks = [
                Task(description=website_crawling_task(crawler_agent).description.format(target_url=target_url), expected_output=website_crawling_task(crawler_agent).expected_output, agent=crawler_agent),
                Task(description=api_endpoint_discovery_task(crawler_agent).description.format(target_url=target_url), expected_output=api_endpoint_discovery_task(crawler_agent).expected_output, agent=crawler_agent, context_aware=True),
                Task(description=dynamic_content_analysis_task(crawler_agent).description.format(target_url=target_url), expected_output=dynamic_content_analysis_task(crawler_agent).expected_output, agent=crawler_agent, context_aware=True),
                Task(description=endpoint_categorization_task(crawler_agent).description.format(target_url=target_url), expected_output=endpoint_categorization_task(crawler_agent).expected_output, agent=crawler_agent, context_aware=True),
                Task(description=info_gathering_tasks_defs[0][0].format(target_url=target_url), expected_output=info_gathering_tasks_defs[0][1], agent=info_gatherer_agent, context_aware=True),
                Task(description=info_gathering_tasks_defs[1][0].format(target_url=target_url), expected_output=info_gathering_tasks_defs[1][1], agent=info_gatherer_agent, context_aware=True),
                Task(description=info_gathering_tasks_defs[2][0].format(target_url=target_url), expected_output=info_gathering_tasks_defs[2][1], agent=info_gatherer_agent, context_aware=True),
                Task(description=f"Scan open ports on {target_url}. Use port_scanner tool.", expected_output="List of open ports and services.", agent=info_gatherer_agent, context_aware=True),
                Task(description=f"Analyze security headers on {target_url}. Use security_headers_analyzer tool.", expected_output="Detailed analysis of security headers.", agent=info_gatherer_agent, context_aware=True),
                Task(description=xss_scanning_task(scanner_agent).description.format(target_url=target_url), expected_output=xss_scanning_task(scanner_agent).expected_output, agent=scanner_agent, context_aware=True),
                Task(description=sql_injection_scanning_task(scanner_agent).description.format(target_url=target_url), expected_output=sql_injection_scanning_task(scanner_agent).expected_output, agent=scanner_agent, context_aware=True),
                Task(description=open_redirect_scanning_task(scanner_agent).description.format(target_url=target_url), expected_output=open_redirect_scanning_task(scanner_agent).expected_output, agent=scanner_agent, context_aware=True),
                Task(description=csrf_scanning_task(scanner_agent).description.format(target_url=target_url), expected_output=csrf_scanning_task(scanner_agent).expected_output, agent=scanner_agent, context_aware=True),
                Task(description=path_traversal_scanning_task(scanner_agent).description.format(target_url=target_url), expected_output=path_traversal_scanning_task(scanner_agent).expected_output, agent=scanner_agent, context_aware=True),
                Task(description=f"Create a comprehensive summary of ALL vulnerabilities discovered on {target_url}. Consolidate findings from ALL previous tasks.", 
                     expected_output="A comprehensive vulnerability summary report including all findings, risk ratings, and strategic recommendations.", 
                     agent=security_analyst_agent, context_aware=True, async_execution=False)
            ]
        
        logger.info("\nNote: The scanning process may take several minutes to hours, depending on the target website and scan type.")
        
        vulnerability_scanner_crew = Crew(
            agents=[crawler_agent, scanner_agent, info_gatherer_agent, security_analyst_agent],
            tasks=tasks,
            process=Process.sequential,
            verbose=True,
            memory=False,
            # context_strategy and max_step_tokens can be added if needed based on full file content
        )
        
        logger.info("\nStarting vulnerability scan crew...")
        
        # Simplified inputs for kickoff
        crew_inputs = {'target_url': target_url}
        analyst_raw_output = vulnerability_scanner_crew.kickoff(inputs=crew_inputs)
        
        analyst_report_content = ""
        if isinstance(analyst_raw_output, str):
            analyst_report_content = analyst_raw_output
        elif hasattr(analyst_raw_output, 'raw_output') and analyst_raw_output.raw_output: # Check TaskOutput
             analyst_report_content = analyst_raw_output.raw_output
        elif hasattr(analyst_raw_output, 'result') and analyst_raw_output.result:
             analyst_report_content = analyst_raw_output.result
        elif hasattr(analyst_raw_output, 'raw') and analyst_raw_output.raw: # Older CrewAI versions
            analyst_report_content = analyst_raw_output.raw
        elif isinstance(analyst_raw_output, dict) and 'final_output' in analyst_raw_output: # Crew output dict
            analyst_report_content = analyst_raw_output['final_output']
        else:
            analyst_report_content = str(analyst_raw_output) # Fallback

        logger.info("Vulnerability scan crew finished. Preparing reports.")
        save_interim_results("final_analyst_summary", "security_analyst", analyst_report_content, target_url)

        # --- Create and run JSON Formatting Crew ---
        logger.info("Starting JSON report formatting...")
        json_formatter_agent = create_json_report_formatter_agent(llm=llm)
        
        # Ensure analyst_report_content is a string for the formatting task description
        analyst_report_content_str_for_task = analyst_report_content
        if not isinstance(analyst_report_content_str_for_task, str):
            try:
                analyst_report_content_str_for_task = json.dumps(analyst_report_content_str_for_task, indent=2)
            except TypeError: # Handle non-serializable objects if any by converting to string
                 analyst_report_content_str_for_task = str(analyst_report_content_str_for_task)


        json_formatting_task_instance = create_json_report_formatting_task(
            agent=json_formatter_agent,
            original_report_content=analyst_report_content_str_for_task
        )

        json_formatting_crew = Crew(
            agents=[json_formatter_agent],
            tasks=[json_formatting_task_instance],
            verbose=True, # Set to False if too noisy for this step
            memory=False
        )
        
        formatter_crew_output = json_formatting_crew.kickoff()
        
        final_json_str = ""
        if isinstance(formatter_crew_output, str):
            final_json_str = formatter_crew_output
        elif hasattr(formatter_crew_output, 'raw_output') and formatter_crew_output.raw_output:
             final_json_str = formatter_crew_output.raw_output
        elif hasattr(formatter_crew_output, 'result') and formatter_crew_output.result:
             final_json_str = formatter_crew_output.result
        elif hasattr(formatter_crew_output, 'raw') and formatter_crew_output.raw: # Older CrewAI versions
            final_json_str = formatter_crew_output.raw
        elif isinstance(formatter_crew_output, dict) and 'final_output' in formatter_crew_output:
            final_json_str = formatter_crew_output['final_output']
        else:
            final_json_str = str(formatter_crew_output) # Fallback

        logger.info("JSON report formatting finished.")

        # --- Save Reports ---
        reports_dir = "scan_reports"
        os.makedirs(reports_dir, exist_ok=True)
        
        # Helper for filename sanitation, now includes a timestamp
        def get_safe_filename_prefix_with_timestamp(url_str):
            # Sanitize URL part
            name = url_str.replace("http://", "").replace("https://", "") # Remove protocol
            name = name.replace("/", "_") # Replace slashes
            name = "".join(c if c.isalnum() or c in ['.', '_', '-'] else '_' for c in name) # Keep dots, underscores, hyphens
            name = name.strip('_.') # Clean leading/trailing unwanted chars
            if not name: # Handle empty name after sanitization (e.g. if URL was just "http://")
                name = "default_target"
            
            # Add timestamp
            timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            return f"{name}_{timestamp_str}"

        safe_filename_base = get_safe_filename_prefix_with_timestamp(target_url)

        # 1. Save the main JSON report (from JSON Formatter Agent)
        main_json_report_path = None
        try:
            final_json_dict = json.loads(final_json_str) # The formatter agent should output a valid JSON string
            main_json_report_filename = f"report_{safe_filename_base}_vulnerability.json"
            main_json_report_path = os.path.join(reports_dir, main_json_report_filename)
            with open(main_json_report_path, 'w', encoding='utf-8') as f:
                json.dump(final_json_dict, f, indent=4, ensure_ascii=False)
            logger.info(f"Main JSON report saved to: {main_json_report_path}")
        except json.JSONDecodeError:
            logger.error(f"JSON Report Formatter Agent did not return a valid JSON string. Raw output: {final_json_str[:500]}...") # Log snippet
            # Save the raw invalid output for debugging
            main_json_report_filename = f"report_{safe_filename_base}_vulnerability_INVALID.json"
            main_json_report_path = os.path.join(reports_dir, main_json_report_filename)
            with open(main_json_report_path, 'w', encoding='utf-8') as f:
                f.write(final_json_str)
            logger.info(f"Saved raw (invalid) JSON output to: {main_json_report_path}")
            # final_json_dict remains None or an error dict if needed later

        # 2. Save the Markdown report (from Security Analyst Agent's output)
        md_report_filename = f"report_{safe_filename_base}_vulnerability.md"
        md_report_path = os.path.join(reports_dir, md_report_filename)
        
        # The analyst_report_content is the direct output from the security analyst.
        # If it's not already in good markdown, format_vulnerability_report should make it so.
        # The format_vulnerability_report function might need adjustment if its output isn't Markdown.
        # For now, we assume analyst_report_content is either Markdown or format_vulnerability_report handles it.
        
        markdown_content_to_save = analyst_report_content
        # Optional: Pass through format_vulnerability_report if analyst_report_content is not guaranteed to be good markdown.
        # Example: if not str(analyst_report_content).strip().startswith("#"): # Simple check for string content
        #    markdown_content_to_save = format_vulnerability_report(analyst_report_content)

        with open(md_report_path, 'w', encoding='utf-8') as f:
            f.write(str(markdown_content_to_save)) # Ensure it's a string
        logger.info(f"Markdown report saved to: {md_report_path}")
        
        status_message = f"Scan completed. Main JSON: {main_json_report_path}, Markdown: {md_report_path}"
        
        log_scan_end(current_scan_id, "Completed", 
                     report_json_path=main_json_report_path, 
                     report_md_path=md_report_path)
        
        return status_message, main_json_report_path, md_report_path

    except Exception as e:
        error_message = f"Error during scan for {target_url}: {str(e)}"
        logger.error(error_message, exc_info=True)
        # Log error to database
        if current_scan_id:
            log_scan_end(current_scan_id, "Error") # Only pass scan_id and status on error
        return error_message, None, None

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
    
    # Khởi tạo DB
    init_db()
    
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
    
    # Bắt đầu ghi log quét
    scan_id = log_scan_start(target_url, scan_type)
    
    # Run scan
    results, json_report_path, txt_report_path = scan_website(target_url, use_deepseek, scan_type, current_scan_id=scan_id)
    
    # Cập nhật log quét khi hoàn thành hoặc lỗi
    # Việc cập nhật web_json_report_path đã được xử lý bên trong scan_website nếu thành công
    # Ở đây chúng ta chỉ cần cập nhật status chính nếu chưa có web_json_report_path
    if not json_report_path:
        scan_status = "Completed"
        if isinstance(results, str) and ("Error:" in results or "Unidentified error:" in results) or not json_report_path:
            scan_status = "Error"
        log_scan_end(scan_id, scan_status, json_report_path, None) # web_json_path là None nếu không được tạo

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
    # Đảm bảo init_db được gọi nếu script chạy trực tiếp và main() không được gọi từ nơi khác
    if not os.path.exists(DB_NAME):
        init_db()
    main() 