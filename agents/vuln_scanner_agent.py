import sys
import io
from crewai import Agent
from langchain_community.llms import DeepSeek
from langchain_openai.chat_models import ChatOpenAI
from langchain_core.agents import AgentFinish

# Không ghi đè sys.stdout/sys.stderr ở đây nữa

from tools.web_tools import request_url
from tools.vuln_tools import scan_xss, scan_sqli, scan_open_redirect, scan_path_traversal, scan_csrf

def scan_vulnerabilities(url, endpoints):
    """
    Quét lỗ hổng bảo mật trên các endpoint.
    
    Args:
        url (str): URL gốc của trang web
        endpoints (list): Danh sách các endpoint cần quét
        
    Returns:
        dict: Kết quả phân tích lỗ hổng
    """
    results = {
        "scanned_endpoints": len(endpoints),
        "vulnerabilities_found": 0,
        "details": []
    }
    
    # Đây là hàm giả để thử nghiệm, cần được triển khai thực tế
    
    return results

def create_vuln_scanner_agent(tools, llm=None):
    """
    Tạo một Agent chuyên dùng để quét lỗ hổng trên website.
    
    Args:
        tools (list): Danh sách các công cụ mà agent sẽ sử dụng
        llm (LLM, optional): Mô hình ngôn ngữ lớn để sử dụng
        
    Returns:
        Agent: Đối tượng Agent đã được định nghĩa
    """
    return Agent(
        role='Vulnerability Scanner',
        goal='Identify and analyze security vulnerabilities in the target website',
        backstory='''
        You are a highly skilled security researcher specializing in web application security.
        With years of experience in penetration testing and vulnerability assessment, you can
        identify security flaws that others might miss. You understand attack vectors
        and exploitation techniques, allowing you to find vulnerabilities effectively.
        Your reports are thorough and actionable, providing clear steps for remediation.
        ''',
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=False
    ) 