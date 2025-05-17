from crewai import Agent

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