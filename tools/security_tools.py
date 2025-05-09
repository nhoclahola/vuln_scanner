import requests
import json
import re
from bs4 import BeautifulSoup
from crewai.tools import tool

@tool("Vulnerability Severity Analyzer")
def analyze_vulnerability_severity(vuln_type: str, vuln_details: str, has_fix: bool = False) -> str:
    """
    Phân tích và đánh giá mức độ nghiêm trọng của lỗ hổng bảo mật, bao gồm tham chiếu đến CVSS và tài liệu bổ sung.
    
    Args:
        vuln_type (str): Loại lỗ hổng (xss, sqli, open_redirect, path_traversal, csrf)
        vuln_details (str): Chi tiết về lỗ hổng được phát hiện
        has_fix (bool): Có biện pháp khắc phục hay không
        
    Returns:
        str: Đánh giá mức độ nghiêm trọng và phân tích dạng JSON
    """
    try:
        vuln_type = vuln_type.lower()
        
        # Bảng tiêu chí đánh giá cho từng loại lỗ hổng
        vuln_criteria = {
            "xss": {
                "impact": {
                    "high": ["stored", "persistent", "authentication", "admin", "cookie", "session", "javascript execution", "data theft"],
                    "medium": ["reflected", "self-xss", "dom", "temporary", "alert("],
                    "low": ["csp bypass", "filtered", "minimal impact", "constrained"]
                },
                "base_score": 6.5,  # Medium
                "description": "Cross-Site Scripting (XSS) cho phép kẻ tấn công chèn mã JavaScript vào trang web, có thể dẫn đến đánh cắp session, cookie hoặc phising.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "owasp_reference": "https://owasp.org/www-community/attacks/xss/",
                "references": [
                    {"title": "OWASP XSS Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
                    {"title": "PortSwigger XSS Cheat Sheet", "url": "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"}
                ]
            },
            "sqli": {
                "impact": {
                    "high": ["blind", "union", "admin", "root", "shell", "rce", "out-of-band", "data breach", "database dump"],
                    "medium": ["error-based", "boolean", "time-based", "information disclosure"],
                    "low": ["filtered", "limited access", "constrained"]
                },
                "base_score": 8.0,  # High
                "description": "SQL Injection cho phép kẻ tấn công thực thi các câu truy vấn SQL tùy ý, có thể dẫn đến rò rỉ dữ liệu hoặc kiểm soát cơ sở dữ liệu.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "owasp_reference": "https://owasp.org/www-community/attacks/SQL_Injection",
                "references": [
                    {"title": "OWASP SQL Injection Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
                    {"title": "PortSwigger SQL Injection", "url": "https://portswigger.net/web-security/sql-injection"}
                ]
            },
            "open_redirect": {
                "impact": {
                    "high": ["phishing", "authentication", "oauth", "login", "banking", "payment"],
                    "medium": ["redirect chain", "social engineering"],
                    "low": ["internal", "constrained", "limited impact"]
                },
                "base_score": 5.0,  # Medium
                "description": "Open Redirect cho phép kẻ tấn công chuyển hướng người dùng đến một trang web độc hại, thường được sử dụng trong các chiến dịch phishing.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                "owasp_reference": "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                "references": [
                    {"title": "OWASP Unvalidated Redirects and Forwards Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"},
                    {"title": "CWE-601: URL Redirection to Untrusted Site", "url": "https://cwe.mitre.org/data/definitions/601.html"}
                ]
            },
            "path_traversal": {
                "impact": {
                    "high": ["etc/passwd", "config", "source code", "credentials", "sensitive", "arbitrary file read"],
                    "medium": ["log files", "limited access", "metadata"],
                    "low": ["non-sensitive", "constrained"]
                },
                "base_score": 7.0,  # High
                "description": "Path Traversal cho phép kẻ tấn công truy cập các tệp bên ngoài thư mục web root, có thể dẫn đến lộ mã nguồn hoặc tệp cấu hình nhạy cảm.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "owasp_reference": "https://owasp.org/www-community/attacks/Path_Traversal",
                "references": [
                    {"title": "OWASP Path Traversal Prevention", "url": "https://owasp.org/www-community/attacks/Path_Traversal"},
                    {"title": "CWE-22: Improper Limitation of a Pathname", "url": "https://cwe.mitre.org/data/definitions/22.html"}
                ]
            },
            "csrf": {
                "impact": {
                    "high": ["admin", "account takeover", "password change", "payment", "critical function"],
                    "medium": ["user settings", "data modification", "non-critical function"],
                    "low": ["preference change", "minimal impact", "limited function"]
                },
                "base_score": 5.5,  # Medium
                "description": "Cross-Site Request Forgery (CSRF) cho phép kẻ tấn công thực hiện hành động không mong muốn thay mặt người dùng đã xác thực.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                "owasp_reference": "https://owasp.org/www-community/attacks/csrf",
                "references": [
                    {"title": "OWASP CSRF Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"},
                    {"title": "CWE-352: Cross-Site Request Forgery", "url": "https://cwe.mitre.org/data/definitions/352.html"}
                ]
            }
        }
        
        # Nếu không tìm thấy loại lỗ hổng trong danh sách
        if vuln_type not in vuln_criteria:
            result = {
                "vulnerability_type": vuln_type,
                "severity": "Unknown",
                "cvss_score": 0.0,
                "confidence": "Low",
                "description": "Loại lỗ hổng không được nhận diện trong hệ thống đánh giá.",
                "recommendation": "Cần đánh giá thủ công bởi chuyên gia bảo mật.",
                "cvss_resources": {
                    "calculator": "https://www.first.org/cvss/calculator/3.1",
                    "documentation": "https://www.first.org/cvss/v3.1/specification-document"
                },
                "general_references": [
                    {"title": "OWASP Top 10", "url": "https://owasp.org/www-project-top-ten/"},
                    {"title": "MITRE CWE Top 25", "url": "https://cwe.mitre.org/top25/archive/2021/2021_cwe_top25.html"}
                ]
            }
            return json.dumps(result, ensure_ascii=False)
        
        # Phân tích mức độ dựa trên chi tiết lỗ hổng
        vuln_details_lower = vuln_details.lower()
        impact_score = 0
        evidence = []
        
        # Đánh giá tác động cao
        for keyword in vuln_criteria[vuln_type]["impact"]["high"]:
            if keyword in vuln_details_lower:
                impact_score += 3
                evidence.append(f"High impact: '{keyword}'")
                
        # Đánh giá tác động trung bình
        for keyword in vuln_criteria[vuln_type]["impact"]["medium"]:
            if keyword in vuln_details_lower:
                impact_score += 2
                evidence.append(f"Medium impact: '{keyword}'")
                
        # Đánh giá tác động thấp
        for keyword in vuln_criteria[vuln_type]["impact"]["low"]:
            if keyword in vuln_details_lower:
                impact_score += 1
                evidence.append(f"Low impact: '{keyword}'")
        
        # Tính điểm CVSS và mức độ nghiêm trọng
        base_score = vuln_criteria[vuln_type]["base_score"]
        
        # Hiệu chỉnh điểm dựa trên mức độ tác động
        if impact_score >= 6:
            cvss_score = min(base_score + 2.0, 10.0)
            severity = "Critical" if cvss_score >= 9.0 else "High"
            confidence = "High"
        elif impact_score >= 3:
            cvss_score = base_score
            severity = "High" if cvss_score >= 7.0 else "Medium"
            confidence = "Medium"
        elif impact_score >= 1:
            cvss_score = max(base_score - 1.0, 1.0)
            severity = "Medium" if cvss_score >= 4.0 else "Low"
            confidence = "Medium"
        else:
            cvss_score = max(base_score - 2.0, 1.0)
            severity = "Low"
            confidence = "Low"
        
        # Hiệu chỉnh nếu đã có biện pháp khắc phục
        if has_fix:
            cvss_score = max(cvss_score - 1.0, 1.0)
            if severity == "Critical":
                severity = "High"
            elif severity == "High":
                severity = "Medium"
            elif severity == "Medium":
                severity = "Low"
        
        # Tạo khuyến nghị dựa trên mức độ nghiêm trọng
        recommendations = {
            "Critical": "Cần khắc phục ngay lập tức. Ưu tiên cao nhất, có thể cần tạm thời tắt tính năng cho đến khi được vá.",
            "High": "Cần khắc phục trong thời gian sớm nhất. Ưu tiên cao trong chu kỳ phát triển hiện tại.",
            "Medium": "Cần lên kế hoạch khắc phục. Ưu tiên trung bình trong chu kỳ phát triển tiếp theo.",
            "Low": "Nên khắc phục khi có cơ hội. Ưu tiên thấp."
        }
        
        # Bổ sung thông tin về Common Weakness Enumeration (CWE)
        cwe_mapping = {
            "xss": {"id": "CWE-79", "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"},
            "sqli": {"id": "CWE-89", "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"},
            "open_redirect": {"id": "CWE-601", "name": "URL Redirection to Untrusted Site ('Open Redirect')"},
            "path_traversal": {"id": "CWE-22", "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"},
            "csrf": {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)"}
        }
        
        # Thông tin về CVSS
        cvss_info = {
            "base_score": round(cvss_score, 1),
            "severity": severity,
            "vector": vuln_criteria[vuln_type]["cvss_vector"],
            "calculator_url": "https://www.first.org/cvss/calculator/3.1",
            "explanation": {
                "Critical": "9.0-10.0: Lỗ hổng có thể bị khai thác từ xa, dễ dàng và gây ảnh hưởng nghiêm trọng.",
                "High": "7.0-8.9: Lỗ hổng có thể bị khai thác và gây ảnh hưởng đáng kể đến bảo mật.",
                "Medium": "4.0-6.9: Lỗ hổng có thể bị khai thác trong một số điều kiện và gây ảnh hưởng vừa phải.",
                "Low": "0.1-3.9: Lỗ hổng khó bị khai thác hoặc có ảnh hưởng hạn chế."
            }.get(severity, "Không xác định")
        }
        
        # Kết quả đánh giá
        result = {
            "vulnerability_type": vuln_type,
            "severity": severity,
            "cvss_score": round(cvss_score, 1),
            "confidence": confidence,
            "description": vuln_criteria[vuln_type]["description"],
            "analysis_evidence": evidence,
            "cwe": cwe_mapping.get(vuln_type, {"id": "Unknown", "name": "Unknown"}),
            "recommendation": recommendations[severity],
            "has_fix": has_fix,
            "cvss_details": cvss_info,
            "references": vuln_criteria[vuln_type]["references"],
            "owasp_reference": vuln_criteria[vuln_type]["owasp_reference"]
        }
        
        # Thêm hướng dẫn khắc phục cụ thể
        fix_guidance = {
            "xss": "Use proper encoding and escaping for HTML output. Implement Content-Security-Policy (CSP).",
            "sqli": "Use Prepared Statements/Parameterized Queries. Avoid building dynamic SQL with string concatenation.",
            "open_redirect": "Use a whitelist for allowed redirect URLs. Avoid using user input directly in redirects.",
            "path_traversal": "Use allowlists for filenames and directories. Avoid using user input directly in file paths.",
            "csrf": "Implement CSRF tokens. Use SameSite cookies. Verify Origin/Referer headers."
        }
        result["mitigation_guidance"] = fix_guidance.get(vuln_type, "Requires manual assessment by a security expert.")
        
        return json.dumps(result, ensure_ascii=False)
    except Exception as e:
        return json.dumps({
            "error": f"Error analyzing vulnerability severity: {str(e)}",
            "cvss_resources": {
                "calculator": "https://www.first.org/cvss/calculator/3.1",
                "documentation": "https://www.first.org/cvss/v3.1/specification-document"
            },
            "general_references": [
                {"title": "OWASP Top 10", "url": "https://owasp.org/www-project-top-ten/"},
                {"title": "MITRE CWE Top 25", "url": "https://cwe.mitre.org/top25/archive/2021/2021_cwe_top25.html"}
            ]
        })

@tool("OWASP Risk Scorer")
def owasp_risk_score(threat_agent_factors: dict, vulnerability_factors: dict) -> str:
    """
    Tính toán điểm rủi ro theo phương pháp OWASP Risk Rating Methodology.
    
    Args:
        threat_agent_factors (dict): Các yếu tố về tác nhân đe dọa (skill_level, motive, opportunity, size)
        vulnerability_factors (dict): Các yếu tố về lỗ hổng (ease_of_discovery, ease_of_exploit, awareness, intrusion_detection)
        
    Returns:
        str: Kết quả đánh giá rủi ro dạng JSON
    """
    try:
        # Xác định các yếu tố mặc định nếu không được cung cấp
        default_threat_factors = {
            "skill_level": 5,  # 0=No technical skills, 5=Network/programming skills, 9=Security penetration skills
            "motive": 5,       # 0=Low/no reward, 5=Possible reward, 9=High reward
            "opportunity": 5,  # 0=Full access/expensive resources required, 5=Special access/resources required, 9=No access/resources required
            "size": 5          # 0=Developers/system administrators, 5=Authenticated users, 9=Anonymous Internet users
        }
        
        default_vuln_factors = {
            "ease_of_discovery": 5,      # 0=Practically impossible, 5=Easy, 9=Automated tools available
            "ease_of_exploit": 5,        # 0=Theoretical, 5=Easy, 9=Automated tools available
            "awareness": 5,              # 0=Unknown, 5=Hidden, 9=Obvious
            "intrusion_detection": 5     # 0=Active detection in application, 5=Logged and reviewed, 9=Not logged
        }
        
        # Sử dụng giá trị mặc định nếu không có
        for key in default_threat_factors:
            if key not in threat_agent_factors:
                threat_agent_factors[key] = default_threat_factors[key]
                
        for key in default_vuln_factors:
            if key not in vulnerability_factors:
                vulnerability_factors[key] = default_vuln_factors[key]
        
        # Tính điểm
        threat_agent_score = sum(threat_agent_factors.values()) / len(threat_agent_factors)
        vulnerability_score = sum(vulnerability_factors.values()) / len(vulnerability_factors)
        
        # Tính điểm xác suất
        likelihood_score = (threat_agent_score + vulnerability_score) / 2
        
        # Đánh giá mức độ xác suất
        likelihood_levels = ["Low", "Medium", "High"]
        likelihood_index = min(int(likelihood_score / 3), 2)
        likelihood = likelihood_levels[likelihood_index]
        
        # Phân loại điểm rủi ro
        risk_levels = {
            "Low": "Rủi ro thấp - có thể được chấp nhận, theo dõi định kỳ",
            "Medium": "Rủi ro trung bình - cần lập kế hoạch khắc phục",
            "High": "Rủi ro cao - cần khắc phục sớm",
            "Critical": "Rủi ro nghiêm trọng - cần khắc phục ngay lập tức"
        }
        
        # Kết quả
        result = {
            "threat_agent_score": round(threat_agent_score, 1),
            "vulnerability_score": round(vulnerability_score, 1),
            "likelihood_score": round(likelihood_score, 1),
            "likelihood_level": likelihood,
            "detailed_factors": {
                "threat_agent_factors": threat_agent_factors,
                "vulnerability_factors": vulnerability_factors
            },
            "owasp_risk_methodology": "https://owasp.org/www-community/OWASP_Risk_Rating_Methodology",
            "explanation": risk_levels[likelihood],
            "references": [
                {"title": "OWASP Risk Rating Methodology", "url": "https://owasp.org/www-community/OWASP_Risk_Rating_Methodology"},
                {"title": "OWASP Risk Assessment Framework", "url": "https://owasp.org/www-project-risk-assessment-framework/"}
            ]
        }
        
        # Thêm đề xuất hành động
        if likelihood == "Low":
            result["recommended_action"] = "Theo dõi trong chu kỳ bảo trì thông thường."
        elif likelihood == "Medium":
            result["recommended_action"] = "Lên kế hoạch khắc phục trong chu kỳ phát triển tiếp theo."
        else:  # High
            result["recommended_action"] = "Ưu tiên khắc phục ngay trong sprint hiện tại."
        
        return json.dumps(result, ensure_ascii=False)
    except Exception as e:
        return json.dumps({
            "error": f"Lỗi khi tính toán điểm rủi ro OWASP: {str(e)}",
            "references": [
                {"title": "OWASP Risk Rating Methodology", "url": "https://owasp.org/www-community/OWASP_Risk_Rating_Methodology"}
            ]
        }) 