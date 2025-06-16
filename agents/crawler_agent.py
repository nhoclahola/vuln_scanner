import sys
import io
from crewai import Agent

# No longer overriding sys.stdout/sys.stderr here

def create_crawler_agent(tools, llm=None, memory=False):
    """
    Creates an Agent specialized in discovering and scanning endpoints on a website.
    
    Args:
        tools (list): List of tools the agent will use.
        llm (LLM, optional): The large language model to be used.
        memory (bool, optional): Enable/disable memory for the agent.
        
    Returns:
        Agent: The defined Agent object.
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