import sys
import io
from crewai import Agent

# Không ghi đè sys.stdout/sys.stderr ở đây nữa

def create_security_analyst_agent(tools, llm=None, memory=False):
    """
    Tạo một Agent chuyên phân tích bảo mật và đánh giá các lỗ hổng.
    
    Args:
        tools (list): Danh sách các công cụ mà agent sẽ sử dụng
        llm (LLM, optional): Mô hình ngôn ngữ lớn để sử dụng
        memory (bool, optional): Bật/tắt tính năng memory cho agent
        
    Returns:
        Agent: Đối tượng Agent đã được định nghĩa
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
    Phân tích kết quả quét lỗ hổng và đưa ra đánh giá chi tiết
    
    Args:
        scan_results (dict): Kết quả quét lỗ hổng
        target_url (str): URL đã quét
        additional_context (dict, optional): Thông tin bổ sung
        
    Returns:
        dict: Báo cáo phân tích an ninh
    """
    # Mẫu phân tích - trong triển khai thực tế sẽ được thực hiện bởi agent
    vulnerabilities = []
    
    # Xử lý mỗi loại lỗ hổng
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
    Làm giàu dữ liệu lỗ hổng với thông tin bổ sung như CVE, điểm CVSS, v.v.
    
    Args:
        vulnerability_type (str): Loại lỗ hổng (XSS, SQLI, etc.)
        vulnerability_details (str): Chi tiết về lỗ hổng
        
    Returns:
        dict: Thông tin lỗ hổng đã được làm giàu
    """
    # Trong triển khai thực tế, hàm này sẽ gọi các công cụ để tìm kiếm CVE liên quan
    # và phân tích mức độ nghiêm trọng
    
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
    Tạo báo cáo an ninh tổng thể từ kết quả quét
    
    Args:
        scan_results (dict): Kết quả quét lỗ hổng
        target_url (str): URL đã quét
        detailed (bool): Tạo báo cáo chi tiết hay không
        
    Returns:
        dict: Báo cáo an ninh
    """
    # Phân tích kết quả
    analysis = analyze_vulnerabilities(scan_results, target_url)
    
    # Tạo báo cáo cơ bản
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