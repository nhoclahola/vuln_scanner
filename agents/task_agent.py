import sys
import io
from crewai import Agent

# Không ghi đè sys.stdout/sys.stderr ở đây nữa

from tools.web_tools import request_url
from agents.endpoint_scanner_agent import scan_endpoints
from agents.vuln_scanner_agent import scan_vulnerabilities

def create_task_orchestrator_agent(tools, llm=None):
    """
    Tạo một Agent chuyên dùng để điều phối các task quét lỗ hổng.
    
    Args:
        tools (list): Danh sách các công cụ mà agent sẽ sử dụng
        llm (LLM, optional): Mô hình ngôn ngữ lớn để sử dụng
        
    Returns:
        Agent: Đối tượng Agent đã được định nghĩa
    """
    return Agent(
        role='Task Orchestrator',
        goal='Coordinate and manage the vulnerability scanning workflow',
        backstory='''
        You are a master coordinator of security assessment operations, with exceptional
        skills in managing complex security testing workflows. Your expertise lies in
        breaking down security assessments into manageable tasks, prioritizing them
        based on risk and complexity, and ensuring comprehensive coverage of the target.
        You excel at integrating results from different security specialists into
        cohesive, actionable intelligence.
        ''',
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=True
    ) 