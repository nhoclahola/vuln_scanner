import sys
import io
from crewai import Agent

# No longer overriding sys.stdout/sys.stderr here

def create_security_analyst_agent(tools, llm=None, memory=False):
    """
    Creates an Agent specialized in security analysis and vulnerability assessment.
    
    Args:
        tools (list): List of tools the agent will use.
        llm (LLM, optional): The large language model to be used.
        memory (bool, optional): Enable/disable memory for the agent.
        
    Returns:
        Agent: The defined Agent object.
    """
    return Agent(
        role='Security Analyst',
        goal='Analyze security vulnerabilities and provide comprehensive risk assessments',
        backstory='''
        You are a senior security analyst with extensive experience in web application security.
        Your expertise lies in analyzing vulnerability scan results, correlating findings with 
        known CVEs and security databases, and providing accurate risk assessments.
        
        You excel at:
        1. Determining the severity and exploitability of security vulnerabilities
        2. Correlating findings with the latest CVE information and security advisories
        3. Crafting detailed remediation plans with prioritized action items
        4. Explaining technical security concepts to both technical and non-technical stakeholders
        5. Analyzing attack vectors and providing contextual threat intelligence
        
        Your analytical thinking and security expertise allow you to provide comprehensive 
        security insights that help organizations improve their security posture.
        ''',
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=False,
        memory=memory
    )

def analyze_vulnerabilities(scan_results, target_url, additional_context=None):
    """
    Analyzes vulnerability scan results and provides a detailed assessment.
    
    Args:
        scan_results (dict): Vulnerability scan results.
        target_url (str): The scanned URL.
        additional_context (dict, optional): Additional context.
        
    Returns:
        dict: Security analysis report.
    """
    # Analysis example - in a real implementation, this would be done by the agent
    vulnerabilities = []
    
    # Process each vulnerability type
    if 'xss_results' in scan_results:
        for xss_finding in scan_results['xss_results']:
            vulnerabilities.append({
                "type": "XSS",
                "severity": "High",
                "details": xss_finding,
                "recommendation": "Implement proper output encoding and Content-Security-Policy"
            })
    
    if 'sqli_results' in scan_results:
        for sqli_finding in scan_results['sqli_results']:
            vulnerabilities.append({
                "type": "SQL Injection",
                "severity": "Critical",
                "details": sqli_finding,
                "recommendation": "Use parameterized queries and prepared statements"
            })
    
    # Tổng hợp kết quả
    report = {
        "target_url": target_url,
        "vulnerabilities_summary": {
            "total": len(vulnerabilities),
            "high_severity": sum(1 for v in vulnerabilities if v["severity"] == "High" or v["severity"] == "Critical"),
            "medium_severity": sum(1 for v in vulnerabilities if v["severity"] == "Medium"),
            "low_severity": sum(1 for v in vulnerabilities if v["severity"] == "Low")
        },
        "findings": vulnerabilities,
        "security_posture": "Poor" if len(vulnerabilities) > 3 else "Fair" if len(vulnerabilities) > 0 else "Good",
        "recommendations": [
            "Implement a vulnerability management program",
            "Conduct regular security assessments",
            "Train developers on secure coding practices"
        ]
    }
    
    return report

def enrich_vulnerability_data(vulnerability_type, vulnerability_details):
    """
    Enriches vulnerability data with additional information like CVE, CVSS score, etc.
    
    Args:
        vulnerability_type (str): Type of vulnerability (XSS, SQLI, etc.).
        vulnerability_details (str): Details about the vulnerability.
        
    Returns:
        dict: Enriched vulnerability information.
    """
    # In a real implementation, this function would call tools to search for related CVEs
    # and analyze severity.
    
    enriched_data = {
        "type": vulnerability_type,
        "details": vulnerability_details,
        "cve_references": [],
        "cvss_score": 0.0,
        "severity": "Unknown",
        "remediation_steps": []
    }
    
    # Mô phỏng các bước làm giàu dữ liệu
    if vulnerability_type.lower() == "xss":
        enriched_data["cve_references"] = ["CVE-2021-12345", "CVE-2020-54321"]
        enriched_data["cvss_score"] = 6.5
        enriched_data["severity"] = "Medium"
        enriched_data["remediation_steps"] = [
            "Implement proper output encoding",
            "Set Content-Security-Policy headers",
            "Validate and sanitize all user inputs"
        ]
    
    elif vulnerability_type.lower() == "sql injection":
        enriched_data["cve_references"] = ["CVE-2021-67890", "CVE-2019-98765"]
        enriched_data["cvss_score"] = 8.5
        enriched_data["severity"] = "High"
        enriched_data["remediation_steps"] = [
            "Use parameterized queries or prepared statements",
            "Implement least privilege database accounts",
            "Apply input validation and sanitization"
        ]
    
    return enriched_data

def generate_security_report(scan_results, target_url, detailed=False):
    """
    Generates an overall security report from scan results.
    
    Args:
        scan_results (dict): Vulnerability scan results.
        target_url (str): The scanned URL.
        detailed (bool): Whether to generate a detailed report.
        
    Returns:
        dict: Security report.
    """
    # Analyze results
    analysis = analyze_vulnerabilities(scan_results, target_url)
    
    # Create basic report
    report = {
        "target_url": target_url,
        "scan_date": scan_results.get("scan_date", "Unknown"),
        "summary": {
            "total_vulnerabilities": len(analysis["findings"]),
            "security_posture": analysis["security_posture"],
            "risk_level": "High" if analysis["security_posture"] == "Poor" else "Medium" if analysis["security_posture"] == "Fair" else "Low"
        },
        "key_findings": [v["type"] + ": " + v["details"] for v in analysis["findings"][:3]],
        "recommendations": analysis["recommendations"]
    }
    
    # Thêm chi tiết nếu cần
    if detailed:
        report["detailed_findings"] = []
        
        for finding in analysis["findings"]:
            enriched_finding = enrich_vulnerability_data(finding["type"], finding["details"])
            report["detailed_findings"].append(enriched_finding)
        
        # Thêm phần hướng dẫn
        report["educational_resources"] = {
            "XSS": "https://owasp.org/www-community/attacks/xss/",
            "SQL Injection": "https://owasp.org/www-community/attacks/SQL_Injection",
            "CSRF": "https://owasp.org/www-community/attacks/csrf",
            "OWASP Top 10": "https://owasp.org/www-project-top-ten/"
        }
    
    return report 