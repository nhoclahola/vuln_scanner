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

# Hàm create_endpoint_scanner_agent đã được di chuyển sang file agents/endpoint_scanner_agent.py 