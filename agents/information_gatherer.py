import sys
import io
import json
from crewai import Agent

# No longer overriding sys.stdout/sys.stderr here

from tools.web_tools import http_header_fetcher, ssl_tls_analyzer, cms_detector, port_scanner, security_headers_analyzer

def create_information_gatherer_agent(tools, llm=None, memory=False):
    """
    Creates an Agent specialized in gathering basic information about the target website.
    
    Args:
        tools (list): List of tools the agent will use.
        llm (LLM, optional): The large language model to be used.
        memory (bool, optional): Enable/disable memory for the agent.
        
    Returns:
        Agent: The defined Agent object.
    """
    return Agent(
        role='Information Gathering Specialist',
        goal='Collect comprehensive technical information about the target website',
        backstory='''
        You are an experienced information gathering specialist with expertise in 
        reconnaissance and technical analysis of web applications. Your skills include 
        analyzing HTTP headers, checking SSL/TLS configurations, identifying technologies 
        and frameworks, and scanning for open ports.
        
        You can extract valuable technical details that provide context for security 
        assessments and help identify potential security weaknesses. Your thoroughness 
        is renowned, as you never miss important technical details.
        ''',
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=False,
        memory=memory
    )

def gather_information(url):
    """
    Gathers basic information about a website.
    
    Args:
        url (str): The URL of the website to gather information from.
        
    Returns:
        dict: Information about the website.
    """
    results = {
        "target_url": url,
        "headers": {},
        "ssl_tls": {},
        "cms": {},
        "open_ports": [],
        "security_headers": {}
    }
    
    # Thu thập thông tin HTTP header
    try:
        headers_info = http_header_fetcher(url)
        if headers_info:
            results["headers"] = json.loads(headers_info)
    except Exception as e:
        results["headers"] = {"error": str(e)}
    
    # Phân tích cấu hình SSL/TLS
    try:
        ssl_info = ssl_tls_analyzer(url)
        if ssl_info:
            results["ssl_tls"] = json.loads(ssl_info)
    except Exception as e:
        results["ssl_tls"] = {"error": str(e)}
    
    # Phát hiện CMS
    try:
        cms_info = cms_detector(url)
        if cms_info:
            results["cms"] = json.loads(cms_info)
    except Exception as e:
        results["cms"] = {"error": str(e)}
    
    # Quét cổng
    try:
        port_info = port_scanner(url)
        if port_info:
            results["open_ports"] = json.loads(port_info).get("open_ports", [])
    except Exception as e:
        results["open_ports"] = {"error": str(e)}
    
    # Phân tích security headers
    try:
        security_headers_info = security_headers_analyzer(url)
        if security_headers_info:
            results["security_headers"] = json.loads(security_headers_info)
    except Exception as e:
        results["security_headers"] = {"error": str(e)}
    
    return results 