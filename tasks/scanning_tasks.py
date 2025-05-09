import sys
import io
from crewai import Task

# Don't override sys.stdout/sys.stderr here anymore

def xss_scanning_task(agent):
    """
    Create a task to scan for XSS vulnerabilities
    
    Args:
        agent: Agent that will perform this task
        
    Returns:
        Task: Task to scan for XSS vulnerabilities
    """
    return Task(
        description="""
        Scan for Cross-Site Scripting (XSS) vulnerabilities on the target website.
        
        1. Use the scan_xss tool to test all discovered endpoints.
        2. Check all input fields, URL parameters, and form fields.
        3. Test for reflected, stored, and DOM-based XSS vulnerabilities.
        4. Identify unsanitized user inputs that could allow script injection.
        5. Verify if Content-Security-Policy is properly implemented.
        6. Create proof of concept payloads for each vulnerable endpoint.
        7. Document all findings with clear evidence and reproduction steps.
        
        Your output MUST include ALL discovered XSS vulnerabilities with evidence.
        """,
        expected_output="""
        {
            "type": "XSS Vulnerabilities Report",
            "findings": [
                {
                    "type": "XSS",
                    "subtype": "[Reflected/Stored/DOM]",
                    "severity": "[Critical/High/Medium/Low]",
                    "location": "[URL/Endpoint with parameter]",
                    "parameter": "[Vulnerable parameter name]",
                    "description": "[Detailed description of the vulnerability]",
                    "payload": "[Working proof of concept payload]",
                    "evidence": "[Description of observed behavior]",
                    "impact": "[Potential impact of exploitation]",
                    "cvss_score": "[Base CVSS score]",
                    "recommendation": "[Specific remediation steps]"
                }
            ],
            "summary": {
                "total_endpoints_tested": "[Number]",
                "vulnerable_endpoints": "[Number]",
                "critical_vulnerabilities": "[Number]",
                "high_vulnerabilities": "[Number]",
                "medium_vulnerabilities": "[Number]",
                "low_vulnerabilities": "[Number]"
            },
            "recommendations": [
                "[Specific remediation recommendations]"
            ]
        }
        """,
        agent=agent,
        async_execution=False,
        context_aware=True
    )

def sql_injection_scanning_task(agent):
    """
    Create a task to scan for SQL Injection vulnerabilities
    
    Args:
        agent: Agent that will perform this task
        
    Returns:
        Task: Task to scan for SQL Injection vulnerabilities
    """
    return Task(
        description="""
        Scan for SQL Injection vulnerabilities on the target website.
        
        1. Use the scan_sqli tool to test all discovered endpoints.
        2. Focus on form inputs, URL parameters, and API endpoints.
        3. Test for error-based, blind, time-based, and UNION-based SQL injections.
        4. Check for database error messages that may leak information.
        5. Test numeric parameters and string parameters differently.
        6. Create proof of concept payloads for each vulnerable endpoint.
        7. Document all findings with clear evidence and reproduction steps.
        
        Your output MUST include ALL discovered SQL Injection vulnerabilities with evidence.
        """,
        expected_output="""
        {
            "type": "SQL Injection Vulnerabilities Report",
            "findings": [
                {
                    "type": "SQL Injection",
                    "subtype": "[Error-based/Blind/Time-based/UNION-based]",
                    "severity": "[Critical/High/Medium/Low]",
                    "location": "[URL/Endpoint with parameter]",
                    "parameter": "[Vulnerable parameter name]",
                    "description": "[Detailed description of the vulnerability]",
                    "payload": "[Working proof of concept payload]",
                    "evidence": "[Description of observed behavior]",
                    "impact": "[Potential impact of exploitation]",
                    "cvss_score": "[Base CVSS score]",
                    "recommendation": "[Specific remediation steps]"
                }
            ],
            "summary": {
                "total_endpoints_tested": "[Number]",
                "vulnerable_endpoints": "[Number]",
                "critical_vulnerabilities": "[Number]",
                "high_vulnerabilities": "[Number]",
                "medium_vulnerabilities": "[Number]",
                "low_vulnerabilities": "[Number]"
            },
            "recommendations": [
                "[Specific remediation recommendations]"
            ]
        }
        """,
        agent=agent,
        async_execution=False,
        context_aware=True
    )

def open_redirect_scanning_task(agent):
    """
    Create a task to scan for Open Redirect vulnerabilities
    
    Args:
        agent: Agent that will perform this task
        
    Returns:
        Task: Task to scan for Open Redirect vulnerabilities
    """
    return Task(
        description="""
        Scan for Open Redirect vulnerabilities on the target website.
        
        1. Use the scan_open_redirect tool to test all discovered endpoints.
        2. Focus on redirect parameters, URL parameters, and login forms.
        3. Test for unvalidated redirects to external domains.
        4. Check how the application handles URL parameters like 'redirect', 'url', 'next', etc.
        5. Test URL encoding and different protocol handlers.
        6. Create proof of concept payloads for each vulnerable endpoint.
        7. Document all findings with clear evidence and reproduction steps.
        
        Your output MUST include ALL discovered Open Redirect vulnerabilities with evidence.
        """,
        expected_output="""
        {
            "type": "Open Redirect Vulnerabilities Report",
            "findings": [
                {
                    "type": "Open Redirect",
                    "severity": "[High/Medium/Low]",
                    "location": "[URL/Endpoint with parameter]",
                    "parameter": "[Vulnerable parameter name]",
                    "description": "[Detailed description of the vulnerability]",
                    "payload": "[Working proof of concept payload]",
                    "evidence": "[Description of observed behavior]",
                    "impact": "[Potential impact of exploitation]",
                    "cvss_score": "[Base CVSS score]",
                    "recommendation": "[Specific remediation steps]"
                }
            ],
            "summary": {
                "total_endpoints_tested": "[Number]",
                "vulnerable_endpoints": "[Number]",
                "high_vulnerabilities": "[Number]",
                "medium_vulnerabilities": "[Number]",
                "low_vulnerabilities": "[Number]"
            },
            "recommendations": [
                "[Specific remediation recommendations]"
            ]
        }
        """,
        agent=agent,
        async_execution=False,
        context_aware=True
    )

def csrf_scanning_task(agent):
    """
    Create a task to scan for CSRF vulnerabilities
    
    Args:
        agent: Agent that will perform this task
        
    Returns:
        Task: Task to scan for CSRF vulnerabilities
    """
    return Task(
        description="""
        Scan for Cross-Site Request Forgery (CSRF) vulnerabilities on the target website.
        
        1. Use the scan_csrf tool to test all discovered forms and state-changing endpoints.
        2. Check for missing or improperly implemented CSRF tokens.
        3. Test forms that perform sensitive actions like password changes, settings updates, etc.
        4. Verify if SameSite cookie attribute is properly set.
        5. Check if proper referrer validation is in place.
        6. Create proof of concept test cases for vulnerable forms.
        7. Document all findings with clear evidence and reproduction steps.
        
        Your output MUST include ALL discovered CSRF vulnerabilities with proof of concept.
        """,
        expected_output="""
        {
            "type": "CSRF Vulnerabilities Report",
            "findings": [
                {
                    "type": "CSRF",
                    "severity": "[Critical/High/Medium/Low]",
                    "location": "[URL/Endpoint with form]",
                    "form_action": "[Action performed by the form]",
                    "method": "[HTTP method: POST/GET]",
                    "description": "[Detailed description of the vulnerability]",
                    "missing_protection": "[What CSRF protection is missing]",
                    "proof_of_concept": "[Working proof of concept code]",
                    "impact": "[Potential impact of exploitation]",
                    "cvss_score": "[Base CVSS score]",
                    "recommendation": "[Specific remediation steps]"
                }
            ],
            "summary": {
                "total_forms_tested": "[Number]",
                "vulnerable_forms": "[Number]",
                "critical_vulnerabilities": "[Number]",
                "high_vulnerabilities": "[Number]",
                "medium_vulnerabilities": "[Number]",
                "low_vulnerabilities": "[Number]"
            },
            "recommendations": [
                "[Specific remediation recommendations]"
            ]
        }
        """,
        agent=agent,
        async_execution=False,
        context_aware=True
    )

def path_traversal_scanning_task(agent):
    """
    Create a task to scan for Path Traversal vulnerabilities
    
    Args:
        agent: Agent that will perform this task
        
    Returns:
        Task: Task to scan for Path Traversal vulnerabilities
    """
    return Task(
        description="""
        Scan for Path Traversal vulnerabilities on the target website.
        
        1. Use the scan_path_traversal tool to test all endpoints.
        2. Focus on parameters containing 'file', 'path', 'document', 'page', etc.
        3. Test endpoints that serve or reference files.
        4. Check functionality that loads templates or includes.
        5. Examine image or document display functionality.
        6. Try different directory traversal payloads with various encodings.
        7. Attempt to access sensitive files like /etc/passwd or system files.
        
        Your output MUST include ALL discovered Path Traversal vulnerabilities with proof.
        """,
        expected_output="""
        {
            "type": "Path Traversal Vulnerabilities Report",
            "findings": [
                {
                    "type": "Path Traversal",
                    "severity": "[Critical/High/Medium/Low]",
                    "location": "[URL/Endpoint with parameter]",
                    "parameter": "[Vulnerable parameter name]",
                    "description": "[Detailed description of the vulnerability]",
                    "payload": "[Working proof of concept payload]",
                    "files_accessed": "[Files that were successfully accessed]",
                    "evidence": "[Description of observed behavior]",
                    "impact": "[Potential impact of exploitation]",
                    "cvss_score": "[Base CVSS score]",
                    "recommendation": "[Specific remediation steps]"
                }
            ],
            "summary": {
                "total_endpoints_tested": "[Number]",
                "vulnerable_endpoints": "[Number]",
                "critical_vulnerabilities": "[Number]",
                "high_vulnerabilities": "[Number]",
                "medium_vulnerabilities": "[Number]",
                "low_vulnerabilities": "[Number]"
            },
            "recommendations": [
                "[Specific remediation recommendations]"
            ]
        }
        """,
        agent=agent,
        async_execution=False,
        context_aware=True
    )

def vulnerability_summary_task(agent):
    """
    Create a task to summarize all discovered vulnerabilities and provide risk assessment
    
    Args:
        agent: Agent that will perform this task
        
    Returns:
        Task: Task to summarize vulnerabilities
    """
    return Task(
        description="""
        Create a comprehensive summary of all vulnerabilities discovered on the target website.
        
        1. Consolidate findings from all previous scanning tasks.
        2. Categorize all vulnerabilities by type (XSS, SQLi, CSRF, etc.).
        3. Assign severity ratings to each vulnerability (Critical, High, Medium, Low) based on CVSS 3.1 scoring system.
        4. Prioritize vulnerabilities based on impact, exploitability, and remediation effort.
        5. Identify common patterns or root causes across multiple vulnerabilities.
        6. Assess the overall security posture of the application.
        7. Research and reference CWE (Common Weakness Enumeration) IDs for each type of vulnerability.
        8. Evaluate the risk using a standardized methodology like OWASP Risk Rating.
        9. Provide detailed CVSS vector strings for critical vulnerabilities.
        10. Include references to security best practices for remediation.
        11. Suggest both short-term and long-term mitigation strategies.
        
        Your output MUST include a complete analysis of ALL discovered vulnerabilities with CVSS scores, CWE references, 
        and references to industry-standard security resources.
        """,
        expected_output="""
        {
            "type": "Vulnerability Summary Report",
            "summary": {
                "security_posture": "[Poor/Fair/Good/Excellent]",
                "risk_level": "[Critical/High/Medium/Low]",
                "total_vulnerabilities": "[Number]",
                "critical_vulnerabilities": "[Number]",
                "high_vulnerabilities": "[Number]",
                "medium_vulnerabilities": "[Number]",
                "low_vulnerabilities": "[Number]"
            },
            "findings": [
                {
                    "type": "[Vulnerability Type]",
                    "severity": "[Critical/High/Medium/Low]",
                    "location": "[URL/Endpoint]",
                    "description": "[Brief description]",
                    "impact": "[Business impact]",
                    "cvss_score": "[CVSS Score]",
                    "cvss_vector": "[CVSS:3.1/AV:N/AC:L/PR:N/UI:R...]",
                    "cwe_id": "[CWE-XX]",
                    "cwe_name": "[Common Weakness Name]",
                    "recommendation": "[Brief remediation]"
                }
            ],
            "key_issues": [
                "[Top critical issues requiring immediate attention]"
            ],
            "root_causes": [
                "[Common patterns or root causes identified]"
            ],
            "endpoints": [
                "[List of all discovered endpoints]"
            ],
            "recommendations": [
                "[Strategic security recommendations]"
            ],
            "cvss_details": {
                "scoring_system": "CVSS v3.1",
                "calculator_url": "https://www.first.org/cvss/calculator/3.1",
                "severity_explanation": {
                    "Critical": "9.0-10.0: Vulnerabilities that can be exploited remotely, easily, and without authentication",
                    "High": "7.0-8.9: Vulnerabilities that can be exploited with some constraints",
                    "Medium": "4.0-6.9: Vulnerabilities that are harder to exploit or have limited impact",
                    "Low": "0.1-3.9: Vulnerabilities with minimal impact or very difficult to exploit"
                }
            },
            "cwe_details": [
                {
                    "id": "79",
                    "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                    "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
                    "reference": "https://cwe.mitre.org/data/definitions/79.html"
                },
                {
                    "id": "89",
                    "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                    "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
                    "reference": "https://cwe.mitre.org/data/definitions/89.html"
                }
            ],
            "risk_assessment": {
                "business_impact": "[Description of impact on business operations]",
                "data_sensitivity": "[Level of sensitivity of affected data]",
                "attack_vector": "[How the vulnerability can be exploited]",
                "remediation_complexity": "[Complexity level for fixing the issues]",
                "threat_agents": "[Types of attackers who might exploit these vulnerabilities]"
            },
            "reference_resources": [
                {
                    "name": "OWASP Top 10",
                    "url": "https://owasp.org/www-project-top-ten/"
                },
                {
                    "name": "SANS CWE Top 25",
                    "url": "https://www.sans.org/top25-software-errors/"
                },
                {
                    "name": "NIST Security Controls",
                    "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
                }
            ]
        }
        """,
        agent=agent,
        async_execution=False,
        context_aware=True
    ) 