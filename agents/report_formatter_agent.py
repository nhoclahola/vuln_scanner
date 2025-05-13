from crewai import Agent, LLM # LLM có thể cần nếu bạn muốn type hint rõ ràng

def create_json_report_formatter_agent(llm: LLM): # Thêm type hint cho llm
    """Tạo agent để định dạng báo cáo thành JSON cho web."""
    return Agent(
        role='JSON Report Formatter',
        goal='''Transform the detailed vulnerability scan report into a structured, concise JSON format suitable for web frontend display.
The JSON should be easy to parse and render on a web page.
Prioritize clarity and essential information for a dashboard view.
Include a summary section and a list of vulnerabilities with key details.''',
        backstory='''You are an expert in data structuring and API design.
You are tasked with taking a comprehensive, potentially verbose security report
and distilling it into a clean JSON format that web developers can easily use
to build informative and user-friendly dashboards.''',
        verbose=True,
        llm=llm,
        allow_delegation=False,
        memory=False # Không cần memory cho task đơn giản này
    )