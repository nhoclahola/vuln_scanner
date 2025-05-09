from crewai import Task
from agents import InformationGathererAgent, SecurityAnalystAgent
from tools.web_tools import (
    http_header_fetcher,
    ssl_tls_analyzer,
    cms_detector,
    port_scanner,
    security_headers_analyzer
)

def reconnaissance_task(information_gatherer_agent):
    """
    Tạo nhiệm vụ thăm dò HTTP headers từ URL mục tiêu.
    
    Args:
        information_gatherer_agent: Agent thực hiện nhiệm vụ thăm dò.
        
    Returns:
        Task: Đối tượng Task đã định nghĩa.
    """
    return Task(
        description='Perform initial reconnaissance on the target URL: {target_url}. Focus on retrieving HTTP headers to understand server information and basic security configurations.',
        expected_output='A report summarizing the HTTP headers found for the target URL, including server type, security headers, and other relevant information.',
        agent=information_gatherer_agent,
        tools=[http_header_fetcher]
    )

def ssl_tls_analysis_task(information_gatherer_agent):
    """
    Tạo nhiệm vụ phân tích cấu hình SSL/TLS của trang web mục tiêu.
    
    Args:
        information_gatherer_agent: Agent thực hiện nhiệm vụ phân tích.
        
    Returns:
        Task: Đối tượng Task đã định nghĩa.
    """
    return Task(
        description='Analyze the SSL/TLS configuration of the target URL: {target_url}. Focus on certificate validity, supported protocols, and cipher suites.',
        expected_output='A detailed report on the SSL/TLS configuration including certificate information, protocol versions, cipher suites, and potential vulnerabilities.',
        agent=information_gatherer_agent,
        tools=[ssl_tls_analyzer]
    )

def cms_detection_task(information_gatherer_agent):
    """
    Tạo nhiệm vụ phát hiện CMS của trang web mục tiêu.
    
    Args:
        information_gatherer_agent: Agent thực hiện nhiệm vụ phát hiện.
        
    Returns:
        Task: Đối tượng Task đã định nghĩa.
    """
    return Task(
        description='Detect the Content Management System (CMS) used by the target URL: {target_url}. Focus on identifying CMS type and version.',
        expected_output='A report detailing the detected CMS, version information, and potential vulnerabilities associated with the detected CMS.',
        agent=information_gatherer_agent,
        tools=[cms_detector]
    )

def port_scanning_task(information_gatherer_agent):
    """
    Tạo nhiệm vụ quét cổng của máy chủ mục tiêu.
    
    Args:
        information_gatherer_agent: Agent thực hiện nhiệm vụ quét.
        
    Returns:
        Task: Đối tượng Task đã định nghĩa.
    """
    return Task(
        description='Scan for open ports on the target URL: {target_url}. Focus on common web ports (80, 443, 8080, 8443) and other services (21, 22, 3306).',
        expected_output='A report of open ports detected on the target host, including port numbers and potential services running on those ports.',
        agent=information_gatherer_agent,
        tools=[port_scanner]
    )

def security_headers_analysis_task(information_gatherer_agent):
    """
    Tạo nhiệm vụ phân tích các header bảo mật của trang web mục tiêu.
    
    Args:
        information_gatherer_agent: Agent thực hiện nhiệm vụ phân tích.
        
    Returns:
        Task: Đối tượng Task đã định nghĩa.
    """
    return Task(
        description='Analyze the security headers implemented on the target URL: {target_url}. Focus on identifying missing or misconfigured security headers.',
        expected_output='A detailed report on the security headers, including missing headers, recommendations for improvement, and overall assessment.',
        agent=information_gatherer_agent,
        tools=[security_headers_analyzer]
    )

def vulnerability_assessment_task(security_analyst_agent):
    """
    Tạo nhiệm vụ đánh giá lỗ hổng dựa trên kết quả thu thập.
    
    Args:
        security_analyst_agent: Agent thực hiện nhiệm vụ đánh giá.
        
    Returns:
        Task: Đối tượng Task đã định nghĩa.
    """
    return Task(
        description='''
        Analyze the gathered reconnaissance data for the target URL: {target_url} and identify potential security vulnerabilities.
        The reconnaissance data includes:
        1. HTTP Headers: {http_headers}
        2. SSL/TLS Configuration: {ssl_tls_data}
        3. CMS Information: {cms_data}
        4. Open Ports: {port_scan_data}
        5. Security Headers Analysis: {security_headers_data}
        
        Identify potential vulnerabilities, misconfigurations, and security risks based on this data.
        ''',
        expected_output='''
        A comprehensive vulnerability assessment report containing:
        1. Executive Summary of findings
        2. Detailed list of vulnerabilities found
        3. Risk rating for each vulnerability (Critical, High, Medium, Low)
        4. Technical explanation of each vulnerability
        5. Recommendations for remediation
        6. Overall security posture assessment
        ''',
        agent=security_analyst_agent,
        context_task_names=[
            "reconnaissance_task",
            "ssl_tls_analysis_task", 
            "cms_detection_task",
            "port_scanning_task",
            "security_headers_analysis_task"
        ]
    ) 