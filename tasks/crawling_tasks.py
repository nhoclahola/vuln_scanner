import sys
import io
from crewai import Task

# Don't override sys.stdout/sys.stderr here anymore

def website_crawling_task(agent, target_url, max_depth=2, max_pages=100):
    """
    Create a task to crawl and discover all endpoints on the target website
    
    Args:
        agent: Agent that will perform this task
        target_url (str): The target URL to crawl.
        max_depth (int): Maximum crawl depth.
        max_pages (int): Maximum number of pages to crawl.
        
    Returns:
        Task: Task to scan website endpoints
    """
    # Description can now use the parameters directly for clarity if needed
    # but the actual parameters are passed via 'inputs' for the tool.
    task_description = f"""
    Crawl and discover all available endpoints, forms, and interaction points on the target website: {target_url}.
    Limit crawl to a maximum depth of {max_depth} and a maximum of {max_pages} pages.
    
    1. Use the web_crawler tool to perform a comprehensive crawl of the target website, respecting the specified depth and page limits.
    2. Identify ALL available URLs, endpoints, forms, and interactive elements within these limits.
    3. Use the javascript_analyzer tool to analyze JavaScript files for additional endpoints if found within crawled pages.
    4. Organize discovered endpoints by type (static pages, API endpoints, forms, etc.)
    5. Note any parameters or input fields found in forms or API endpoints.
    6. Identify any authentication mechanisms or protected areas encountered.
    7. Document all findings in a structured format.
    
    Your output MUST include a comprehensive list of ALL endpoints discovered within the given constraints.
    """
    
    return Task(
        description=task_description,
        expected_output="""
        A detailed and structured report of all discovered endpoints within the crawl limits, including:
        1. Full URLs of all pages and endpoints with their HTTP methods
        2. List of forms found with their action URLs and input fields
        3. API endpoints with their parameters
        4. JavaScript-based endpoints or AJAX calls
        5. Authentication points and protected areas
        6. Any input parameters or query strings found
        
        The report should be well-organized and include the complete URL path for each endpoint.
        """,
        agent=agent,
        inputs={
            'target_url': target_url, 
            'max_depth': max_depth, 
            'max_pages': max_pages
        },
        async_execution=False,
        context_aware=True
    )

def api_endpoint_discovery_task(agent, target_url=None):
    # Thêm target_url để có thể format description nếu cần, hoặc truyền qua inputs
    # Hiện tại description của task này trong main.py đã được format với target_url
    # Nếu tool của task này cần target_url, nó cũng nên được thêm vào inputs
    description_formatted = """
        Discover and analyze API endpoints on the target website {target_url}.
        
        1. Use the web_crawler tool to identify potential API endpoints.
        2. Look for patterns like /api/, /v1/, /rest/, etc. in URLs.
        3. Analyze JavaScript files using javascript_analyzer to find API calls.
        4. Identify the HTTP methods (GET, POST, PUT, DELETE) supported by each endpoint.
        5. Document any parameters or data structures used by these APIs.
        6. Test sample requests where possible to understand API behavior.
        7. Organize findings by API category/functionality.
        
        Your output MUST include a comprehensive list of ALL API endpoints with their expected parameters.
        """.format(target_url=target_url if target_url else "[TARGET URL NOT SPECIFIED IN TASK DEF]")
    return Task(
        description=description_formatted,
        expected_output="""
        A detailed analysis of API endpoints, including:
        1. Complete list of all API endpoints with their full URLs
        2. HTTP methods supported by each endpoint
        3. Required and optional parameters for each endpoint
        4. Data formats (JSON, XML, etc.) accepted and returned
        5. Authentication requirements (if any)
        6. Examples of request/response patterns
        7. Potential security implications of each endpoint
        
        The report should be structured for easy reference during security testing.
        """,
        agent=agent,
        inputs={'target_url': target_url} if target_url else {},
        async_execution=False,
        context_aware=True
    )

def dynamic_content_analysis_task(agent, target_url=None):
    description_formatted = """
        Analyze dynamic content and client-side functionality on the target website {target_url}.
        
        1. Use the javascript_analyzer tool to identify JavaScript frameworks in use.
        2. Analyze how content is dynamically loaded or modified.
        3. Identify AJAX calls and their endpoints.
        4. Document client-side form validation mechanisms.
        5. Look for client-side templating or rendering libraries.
        6. Identify event handlers that might process user input.
        7. Note any client-side storage usage (localStorage, sessionStorage, cookies).
        
        Your output MUST include a comprehensive analysis of all dynamic content mechanisms.
        """.format(target_url=target_url if target_url else "[TARGET URL NOT SPECIFIED IN TASK DEF]")
    return Task(
        description=description_formatted,
        expected_output="""
        A detailed report on dynamic content and client-side functionality:
        1. JavaScript frameworks and libraries in use (with versions if possible)
        2. Dynamic content loading mechanisms
        3. AJAX call patterns and endpoints
        4. Client-side validation techniques
        5. Event handlers processing user input
        6. Client-side storage usage
        7. Security implications of the dynamic content mechanisms
        
        The report should highlight particularly relevant elements for security testing.
        """,
        agent=agent,
        inputs={'target_url': target_url} if target_url else {},
        async_execution=False,
        context_aware=True
    )

def endpoint_categorization_task(agent, target_url=None):
    description_formatted = """
        Categorize all discovered endpoints by functionality, risk level, and testing priority.
        
        1. Review all endpoints discovered in previous tasks.
        2. Categorize each endpoint by functionality (authentication, data submission, admin, etc.)
        3. Assign a potential risk level to each endpoint (High, Medium, Low)
        4. Prioritize endpoints for security testing based on:
           a. Presence of user input parameters
           b. Access to sensitive functionality or data
           c. Authentication requirements
           d. Potential attack surface
        5. Identify endpoints that should receive special attention during testing
        
        Your output MUST include a comprehensive categorization of ALL endpoints with risk assessment.
        """.format(target_url=target_url if target_url else "[TARGET URL NOT SPECIFIED IN TASK DEF]")
    return Task(
        description=description_formatted,
        expected_output="""
        A structured categorization of all endpoints:
        1. Grouping by functionality (user management, data entry, reporting, etc.)
        2. Risk assessment for each endpoint (High, Medium, Low)
        3. Testing priority ranking
        4. Rationale for risk and priority assignments
        5. Special notes for endpoints requiring detailed testing
        6. Potential attack vectors for each high-risk endpoint
        
        The report should provide a clear testing roadmap for the vulnerability scanning phase.
        """,
        agent=agent,
        inputs={'target_url': target_url} if target_url else {},
        async_execution=False,
        context_aware=True
    ) 