from crewai import Agent

def create_endpoint_scanner_agent(tools, llm=None, memory=False):
    """
    Creates an Agent specialized in scanning discovered endpoints for vulnerabilities.
    
    Args:
        tools (list): List of tools the agent will use.
        llm (LLM, optional): The large language model to be used.
        memory (bool, optional): Enable/disable memory for the agent.
        
    Returns:
        Agent: The defined Agent object.
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