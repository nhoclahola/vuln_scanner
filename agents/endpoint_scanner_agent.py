import sys
import io
from crewai import Agent

# Không ghi đè sys.stdout/sys.stderr ở đây nữa

from tools.web_tools import request_url
from tools.crawler_tools import extract_endpoints_from_url, discover_endpoints

def scan_endpoints(url, endpoints):
    """
    Quét lỗ hổng trên các endpoint đã phát hiện.
    
    Args:
        url (str): URL gốc của trang web
        endpoints (list): Danh sách các endpoint cần quét
        
    Returns:
        dict: Kết quả quét lỗ hổng
    """
    results = {
        "scanned_endpoints": len(endpoints),
        "vulnerabilities": []
    }
    
    for endpoint in endpoints:
        # Logic quét lỗ hổng cho từng endpoint
        pass
        
    return results 