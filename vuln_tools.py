import sys
import os
import re
import json
import logging
import requests
import urllib.parse
from bs4 import BeautifulSoup
import time
import random
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
from requests.exceptions import RequestException, Timeout, ConnectionError

# Add the project root to path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('vuln_tools')

# Thêm hàm trợ giúp để hiển thị và theo dõi thông tin về nguồn gốc payload
def format_payload_sources_for_display(payload_sources):
    """
    Format payload sources information for display in UI
    
    Args:
        payload_sources (dict): Dictionary containing payload sources information
        
    Returns:
        str: Formatted string with payload sources information
    """
    if not payload_sources:
        return "No external payloads were used"
        
    formatted_output = []
    formatted_output.append("=== Payload Sources Information ===")
    
    for source_name, source_info in payload_sources.items():
        if source_name == "default":
            continue
            
        count = source_info.get("count", 0)
        references = source_info.get("references", [])
        
        formatted_output.append(f"Source: {source_name.upper()}")
        formatted_output.append(f"  Payloads: {count}")
        
        if references:
            formatted_output.append("  References:")
            for ref in references:
                if isinstance(ref, dict) and "title" in ref and "url" in ref:
                    formatted_output.append(f"    - {ref['title']}: {ref['url']}")
        
        formatted_output.append("")
    
    return "\n".join(formatted_output)

def get_color_for_payload_source(source_name):
    """
    Get color code for different payload sources for UI display
    
    Args:
        source_name (str): Name of the payload source
        
    Returns:
        str: ANSI color code for the payload source
    """
    source_colors = {
        "github": "\033[92m",  # Green
        "hacktricks": "\033[94m",  # Blue
        "portswigger": "\033[95m",  # Magenta
        "owasp": "\033[96m",  # Cyan
        "default": "\033[93m",  # Yellow
    }
    
    reset_color = "\033[0m"
    return f"{source_colors.get(source_name.lower(), source_colors['default'])}{source_name}{reset_color}"

# Các hàm hiện tại
def search_payloads(vulnerability_type, source=None, max_payloads=50, verbose=False):
    """
    Search for payloads for the specified vulnerability type from various sources
    
    Args:
        vulnerability_type (str): Type of vulnerability (xss, sqli, etc.)
        source (str, optional): Specific source to fetch from (github, hacktricks, etc.)
        max_payloads (int, optional): Maximum number of payloads to fetch
        verbose (bool, optional): Whether to print verbose output
        
    Returns:
        dict: Dictionary containing payloads from various sources
    """
    # Tiếp tục với hàm hiện tại 