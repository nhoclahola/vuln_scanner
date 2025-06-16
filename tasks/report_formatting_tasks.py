from crewai import Task, Agent # Agent có thể cần nếu bạn muốn type hint rõ ràng

def create_json_report_formatting_task(agent: Agent, original_report_content: str): # Thêm type hint
    """Creates a task to format the report into JSON."""
    return Task(
        description=f'''Analyze the following vulnerability scan report and convert it into a structured JSON format.
The JSON output MUST be a single, valid JSON object. Do NOT include any explanatory text before or after the JSON block.
The JSON structure should include:
1.  `summary`: An object containing:
    *   `target_url`: The scanned URL.
    *   `scan_type`: Type of scan (e.g., "basic", "full").
    *   `scan_timestamp`: ISO format timestamp of the scan.
    *   `total_vulnerabilities`: Total number of vulnerabilities found.
    *   `critical_count`: Number of critical vulnerabilities.
    *   `high_count`: Number of high vulnerabilities.
    *   `medium_count`: Number of medium vulnerabilities.
    *   `low_count`: Number of low vulnerabilities.
    *   `overall_risk_level`: A qualitative assessment (e.g., "Critical", "High", "Medium", "Low", "Informational", "None").
2.  `vulnerabilities`: An array of objects, where each object represents a vulnerability and includes:
    *   `id`: A unique identifier (e.g., "VULN-001").
    *   `name`: Name/type of the vulnerability (e.g., "Cross-Site Scripting (XSS)", "SQL Injection").
    *   `severity`: Severity level (e.g., "Critical", "High", "Medium", "Low").
    *   `location`: The URL or component where the vulnerability was found.
    *   `description`: A brief description of the vulnerability.
    *   `remediation`: A brief recommendation for fixing it.
    *   `cvss_score` (optional): CVSS score if available.
    *   `parameter` (optional): Affected parameter if applicable.

Original Report Content to transform:
---
{original_report_content}
---

Ensure the output is ONLY the JSON object.
''',
        expected_output='''A single, valid JSON object string representing the structured vulnerability report.
Example:
{
  "summary": {
    "target_url": "https://example.com",
    "scan_type": "full",
    "scan_timestamp": "2024-07-29T10:00:00Z",
    "total_vulnerabilities": 5,
    "critical_count": 1,
    "high_count": 2,
    "medium_count": 1,
    "low_count": 1,
    "overall_risk_level": "High"
  },
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "name": "SQL Injection",
      "severity": "Critical",
      "location": "https://example.com/login",
      "description": "User input not properly sanitized, allowing SQL injection.",
      "remediation": "Use parameterized queries or ORM.",
      "cvss_score": 9.8,
      "parameter": "username"
    }
    // ... other vulnerabilities
  ]
}
''',
        agent=agent,
        async_execution=False
    )