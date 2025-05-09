import sys
import io
from crewai import Agent

# Không ghi đè sys.stdout/sys.stderr ở đây nữa

def create_crawler_agent(tools, llm=None, memory=False):
    """
    Tạo một Agent chuyên dùng để dò tìm và quét endpoint trên website.
    
    Args:
        tools (list): Danh sách các công cụ mà agent sẽ sử dụng
        llm (LLM, optional): Mô hình ngôn ngữ lớn để sử dụng
        memory (bool, optional): Bật/tắt tính năng memory cho agent
        
    Returns:
        Agent: Đối tượng Agent đã được định nghĩa
    """
    return Agent(
        role='Web Crawler Specialist',
        goal='Discover all endpoints, APIs, forms, and interactive elements on the target website',
        backstory='''
        You are an expert web crawler with extensive experience in endpoint 
        discovery and reconnaissance. Your expertise lies in discovering all 
        accessible pages, APIs, and entry points in web applications. You understand 
        web architecture deeply and can identify patterns in URLs and website structure.
        You have a knack for identifying hidden endpoints that might be vulnerable.
        ''',
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=False,
        memory=memory
    )

def create_endpoint_scanner_agent(tools, llm=None, memory=False):
    """
    Tạo một Agent chuyên dùng để quét lỗ hổng trên các endpoint đã phát hiện.
    
    Args:
        tools (list): Danh sách các công cụ mà agent sẽ sử dụng
        llm (LLM, optional): Mô hình ngôn ngữ lớn để sử dụng
        memory (bool, optional): Bật/tắt tính năng memory cho agent
        
    Returns:
        Agent: Đối tượng Agent đã được định nghĩa
    """
    return Agent(
        role='Endpoint Vulnerability Scanner',
        goal='Scan all discovered endpoints for security vulnerabilities',
        backstory='''
        You are a specialized security professional focusing on endpoint vulnerability assessment.
        With your deep knowledge of web security, you can analyze endpoints, parameters, and
        detect potential vulnerabilities like XSS, SQL Injection, CSRF, and more.
        You are methodical and thorough, ensuring no endpoint is left unchecked.
        After finding vulnerabilities, you provide clear explanations of the risks
        and suggest remediation steps.
        ''',
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=False,
        memory=memory
    ) 