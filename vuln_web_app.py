import os
import sys
import json
import threading
import time
import queue
import logging
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, Response, stream_with_context
import re
from werkzeug.utils import safe_join

# Thiết lập logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("web_app.log", encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('vuln_scanner_web')

# Import từ main.py
try:
    from main import scan_website, format_vulnerability_report, init_db, log_scan_start, log_scan_end, DB_NAME, \
                     APP_SETTINGS, SETTINGS_FILE_PATH, load_app_settings as main_load_app_settings, \
                     PLACEHOLDER_DEEPSEEK_API_KEY, \
                     PLACEHOLDER_DEEPSEEK_API_BASE, \
                     PLACEHOLDER_OPENAI_API_KEY, \
                     PLACEHOLDER_OPENAI_API_BASE
except ImportError as e:
    logger.error(f"Could not import necessary components from main.py: {e}. Web app functionality will be limited.")
    APP_SETTINGS = {}
    SETTINGS_FILE_PATH = "settings.json (Lỗi import từ main.py)"
    DB_NAME = "vuln_scanner_history.db (Lỗi import từ main.py)"
    PLACEHOLDER_DEEPSEEK_API_KEY = "NOT_CONFIGURED_IMPORT_ERROR"
    PLACEHOLDER_DEEPSEEK_API_BASE = "NOT_CONFIGURED_IMPORT_ERROR"
    PLACEHOLDER_OPENAI_API_KEY = "NOT_CONFIGURED_IMPORT_ERROR"
    PLACEHOLDER_OPENAI_API_BASE = "NOT_CONFIGURED_IMPORT_ERROR"
    main_load_app_settings = lambda: {} # Mock function
    def scan_website(*args, **kwargs):
        logger.error("scan_website not available due to import error from main.py")
        return "Error: Scan function not available.", None, None

app = Flask(__name__, 
            static_folder='web/static',
            template_folder='web/templates')

# Define a single source of truth for the scan reports directory
# Default to 'scan_reports' if not set via environment or other config mechanism later
app.config.setdefault('SCAN_REPORTS_DIR', 'scan_reports')

# Ensure the directory exists (optional, but good practice)
try:
    os.makedirs(app.config['SCAN_REPORTS_DIR'], exist_ok=True)
except OSError as e:
    logger.error(f"Could not create SCAN_REPORTS_DIR '{app.config['SCAN_REPORTS_DIR']}': {e}")

# Queue và biến toàn cục để lưu output stream
output_queue = queue.Queue()
current_scans = {}
# scan_history = [] # Sẽ được tải từ DB

# Hàm tương tác với SQLite database
def get_scan_history_from_db():
    """Lấy lịch sử quét từ database SQLite"""
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row 
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, target_url, scan_type, scan_timestamp, status, 
                   report_json_path, report_md_path, end_time
            FROM scans
            ORDER BY scan_timestamp DESC
        """)
        rows = cursor.fetchall()
        conn.close()
        
        history = []
        for row in rows:
            item = dict(row)
            if item.get('scan_timestamp'):
                try:
                    dt = datetime.strptime(item['scan_timestamp'], "%Y-%m-%d %H:%M:%S")
                    item['timestamp'] = int(dt.timestamp())
                except (ValueError, TypeError):
                    item['timestamp'] = item['scan_timestamp'] # Giữ nguyên nếu không parse được
            else:
                item['timestamp'] = int(time.time())
            
            if item.get('scan_timestamp') and item.get('end_time'):
                try:
                    start_time = datetime.strptime(item['scan_timestamp'], "%Y-%m-%d %H:%M:%S")
                    end_time = datetime.strptime(item['end_time'], "%Y-%m-%d %H:%M:%S")
                    scan_duration = (end_time - start_time).total_seconds()
                    item['duration'] = round(scan_duration, 2)
                except Exception as e:
                    logger.error(f"Error calculating scan duration for history item {item.get('id')}: {str(e)}")
                    item['duration'] = 0 # Or 'N/A' or None
            else:
                item['duration'] = 0 # Or 'N/A' or None
            
            # Ensure report paths are basenames and stripped
            if item.get('report_json_path'):
                item['report_json_path'] = os.path.basename(item['report_json_path']).strip()
            if item.get('report_md_path'):
                item['report_md_path'] = os.path.basename(item['report_md_path']).strip()

            if item.get('report_json_path') and item['report_json_path'] != '' and os.path.exists(safe_join(app.config['SCAN_REPORTS_DIR'], item['report_json_path'])):
                try:
                    with open(safe_join(app.config['SCAN_REPORTS_DIR'], item['report_json_path']), 'r', encoding='utf-8') as f:
                        report_data = json.load(f)
                        if 'summary' in report_data and 'total_vulnerabilities' in report_data['summary']:
                            item['vulnerabilities'] = report_data['summary']['total_vulnerabilities']
                        elif 'vulnerabilities' in report_data and isinstance(report_data['vulnerabilities'], list):
                            item['vulnerabilities'] = len(report_data['vulnerabilities'])
                        else:
                            item['vulnerabilities'] = 0 
                except Exception as e:
                    logger.error(f"Error reading report file {item['report_json_path']} for history item {item.get('id')}: {str(e)}")
                    item['vulnerabilities'] = 0
            else:
                item['vulnerabilities'] = 0
            history.append(item)
        return history
    except Exception as e:
        logger.error(f"Error fetching scan history from DB: {str(e)}")
        return []

def get_scan_details_from_db(scan_id):
    """Lấy chi tiết của một lần quét từ database SQLite"""
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, target_url, scan_type, scan_timestamp, status, 
                   report_json_path, report_md_path, end_time
            FROM scans
            WHERE id = ?
        """, (scan_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            scan_details = dict(row)
            
            # Ensure report paths are basenames and stripped before returning
            if scan_details.get('report_json_path'):
                scan_details['report_json_path'] = os.path.basename(scan_details['report_json_path']).strip()
            if scan_details.get('report_md_path'):
                scan_details['report_md_path'] = os.path.basename(scan_details['report_md_path']).strip()

            if scan_details.get('scan_timestamp') and scan_details.get('end_time'):
                try:
                    start_time = datetime.strptime(scan_details['scan_timestamp'], "%Y-%m-%d %H:%M:%S")
                    end_time = datetime.strptime(scan_details['end_time'], "%Y-%m-%d %H:%M:%S")
                    scan_duration = (end_time - start_time).total_seconds()
                    scan_details['duration'] = round(scan_duration, 2)
                except Exception as e:
                    logger.error(f"Error calculating scan duration for scan ID {scan_id}: {str(e)}")
                    scan_details['duration'] = 0
            else:
                scan_details['duration'] = 0
            return scan_details
        return None
    except Exception as e:
        logger.error(f"Error fetching scan details for scan ID {scan_id} from DB: {str(e)}")
        return None

def get_overall_vulnerability_stats():
    """Tổng hợp số liệu thống kê phân phối lỗ hổng từ tất cả các báo cáo JSON đã hoàn thành."""
    overall_stats = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0, # Trong trường hợp không có severity hoặc summary
        "total_reports_processed": 0,
        "total_reports_failed_processing": 0
    }
    
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # Chỉ lấy các báo cáo từ các bản quét đã hoàn thành (status = "Completed")
    cursor.execute("SELECT report_json_path FROM scans WHERE status = ? AND report_json_path IS NOT NULL", ("Completed",))
    rows = cursor.fetchall()
    conn.close()

    for row in rows:
        report_path = row['report_json_path']
        if report_path and os.path.exists(report_path):
            try:
                with open(report_path, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)
                
                if isinstance(report_data, dict) and 'summary' in report_data and isinstance(report_data['summary'], dict):
                    summary = report_data['summary']
                    overall_stats["critical"] += summary.get('critical_count', 0)
                    overall_stats["high"] += summary.get('high_count', 0)
                    overall_stats["medium"] += summary.get('medium_count', 0)
                    overall_stats["low"] += summary.get('low_count', 0)
                    # Nếu có các mức severity khác trong summary, bạn có thể thêm vào đây
                else:
                    # Fallback: Nếu không có summary, thử đếm từ list vulnerabilities
                    # Điều này làm cho hàm phức tạp hơn, nhưng an toàn hơn nếu summary không phải lúc nào cũng có
                    # Dựa trên xác nhận của bạn, chúng ta giả định summary luôn có, nên phần này có thể bỏ qua hoặc giữ lại như một fallback
                    if isinstance(report_data, dict) and 'vulnerabilities' in report_data and isinstance(report_data['vulnerabilities'], list):
                        for vuln in report_data['vulnerabilities']:
                            if isinstance(vuln, dict):
                                severity = vuln.get('severity', 'unknown').lower()
                                if severity in overall_stats:
                                    overall_stats[severity] += 1
                                else:
                                    overall_stats["unknown"] += 1 # Đếm các severity không xác định
                    else:
                         overall_stats["unknown"] += 1 # Đếm file không có summary hoặc list vulnerabilities

                overall_stats["total_reports_processed"] += 1
            except json.JSONDecodeError:
                logger.error(f"Error decoding JSON from report file: {report_path}")
                overall_stats["total_reports_failed_processing"] += 1
            except Exception as e:
                logger.error(f"Error processing report file {report_path}: {e}")
                overall_stats["total_reports_failed_processing"] += 1
        else:
            logger.warning(f"Report path {report_path} not found or is null for a completed scan.")
            overall_stats["total_reports_failed_processing"] += 1
            
    return overall_stats

def get_top_vulnerability_types_stats(top_n=5):
    """Thống kê N loại lỗ hổng phổ biến nhất từ tất cả các báo cáo JSON đã hoàn thành."""
    vulnerability_counts = {}
    
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT report_json_path FROM scans WHERE status = ? AND report_json_path IS NOT NULL", ("Completed",))
    rows = cursor.fetchall()
    conn.close()

    for row in rows:
        report_path = row['report_json_path']
        if report_path and os.path.exists(report_path):
            try:
                with open(report_path, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)
                
                if isinstance(report_data, dict) and 'vulnerabilities' in report_data and isinstance(report_data['vulnerabilities'], list):
                    for vuln in report_data['vulnerabilities']:
                        if isinstance(vuln, dict) and 'name' in vuln:
                            vuln_name = vuln['name']
                            vulnerability_counts[vuln_name] = vulnerability_counts.get(vuln_name, 0) + 1
            except Exception as e:
                logger.error(f"Error processing report file {report_path} for top vulnerability types: {e}")
                # Không dừng lại nếu một file lỗi, tiếp tục xử lý các file khác

    # Sắp xếp các lỗ hổng theo số lần xuất hiện giảm dần
    sorted_vulnerabilities = sorted(vulnerability_counts.items(), key=lambda item: item[1], reverse=True)
    
    # Chuyển đổi thành list các dict cho dễ sử dụng ở frontend
    top_vulnerabilities_list = [{
        "name": name, 
        "count": count
    } for name, count in sorted_vulnerabilities[:top_n]]
    
    return top_vulnerabilities_list

class ThreadedScan:
    def __init__(self, scan_id, target_url, use_deepseek, scan_type):
        self.scan_id = scan_id
        self.target_url = target_url
        self.use_deepseek = use_deepseek # Sẽ được truyền từ /api/scan
        self.scan_type = scan_type
        self.status = "pending"
        self.result = None
        self.output_capture = []
        self.start_time = datetime.now()
        self.end_time = None
        self.progress = 0
        self.report_file = None
        self.db_scan_id = None 
        
    def run(self):
        self.status = "running"
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        try:
            sys.stdout = OutputCapture(self)
            sys.stderr = OutputCapture(self)
            
            # log_scan_start được import từ main
            self.db_scan_id = log_scan_start(self.target_url, self.scan_type) 
            
            logger.info(f"ThreadedScan: Starting scan for {self.target_url} with db_scan_id: {self.db_scan_id}, use_deepseek: {self.use_deepseek}, scan_type: {self.scan_type}")
            
            # scan_website được import từ main
            status_message, json_report_path, md_report_path = scan_website(
                target_url=self.target_url, 
                use_deepseek=self.use_deepseek, 
                scan_type=self.scan_type,
                current_scan_id=self.db_scan_id
            )
            
            self.result = status_message
            self.status = "completed"
            self.progress = 100
            self.end_time = datetime.now()
            
            self.report_file = {
                "json": json_report_path,
                "markdown": md_report_path
            }
            
            # log_scan_end được import từ main
            if self.db_scan_id:
                 # log_scan_end trong main.py đã tự động cập nhật end_time
                 # Nó mong muốn status, report_json_path, report_md_path, scan_id
                 # status_message ở đây là thông báo chung, status trong DB nên là "Completed"
                log_scan_end(self.db_scan_id, "Completed", json_report_path, md_report_path)
            
        except Exception as e:
            self.status = "failed"
            self.result = f"Error during scan: {str(e)}"
            self.end_time = datetime.now()
            logger.error(f"Scan error in ThreadedScan for {self.target_url}: {str(e)}", exc_info=True)
            if self.db_scan_id:
                # log_scan_end trong main.py cũng xử lý trường hợp Error
                log_scan_end(self.db_scan_id, "Error") # Chỉ truyền status "Error"
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            if self.scan_id in current_scans: # Dọn dẹp current_scans khi luồng kết thúc
                 # current_scans[self.scan_id] is the ThreadedScan object itself
                 # We might want to keep it for a while for status checks, or remove it if status is final
                 # For now, let's assume it stays until explicitly cleared or overwritten by a new scan with same ID (if IDs are reused)
                 pass


class OutputCapture(object):
    def __init__(self, scan):
        self.scan = scan
        self.buffer = "" # Not currently used

    def write(self, text):
        if not isinstance(text, str):
            text = str(text) # Đảm bảo text luôn là string

        # Lưu trữ output gốc (có thể chứa emoji) cho client
        if self.scan:
            self.scan.output_capture.append(text)
            
            # Logic cập nhật progress dựa trên keywords
            current_progress = self.scan.progress
            new_progress = current_progress
            
            if "Target URL:" in text and current_progress < 5:
                new_progress = 5
            elif "Web Crawler" in text and current_progress < 10:
                new_progress = 10
            elif "Crawling " in text and current_progress < 15:
                new_progress = 15
            elif "Analyzing HTTP headers" in text and current_progress < 25:
                new_progress = 25
            elif "Discovering endpoints" in text and current_progress < 40:
                new_progress = 40
            elif "Analyzing JavaScript" in text and current_progress < 50:
                new_progress = 50
            elif "Scanning for XSS" in text and current_progress < 60:
                new_progress = 60
            elif "Scanning for SQL" in text and current_progress < 70:
                new_progress = 70
            elif "Scanning for" in text and "vulnerabilities" in text and current_progress < 75:
                new_progress = 75
            elif ("Creating comprehensive summary" in text or "Create a comprehensive summary" in text) and current_progress < 80:
                new_progress = 80
            elif "formatting" in text.lower() and "report" in text.lower() and current_progress < 85:
                new_progress = 85
            elif ("Generating report" in text or "Creating report" in text) and current_progress < 90:
                new_progress = 90
            elif "Agent:" in text and current_progress < 95:
                potential_progress = current_progress + 2 
                new_progress = min(potential_progress, 95)

            if new_progress > current_progress:
                self.scan.progress = new_progress
                # Làm sạch text fragment trước khi ghi log server để tránh UnicodeEncodeError
                safe_fragment = text.strip()[:60].encode('ascii', 'replace').decode('ascii')
                logger.info(f"Scan {self.scan.scan_id} progress updated to {self.scan.progress}% based on output. Fragment: \"{safe_fragment}...\"")
        
        # Làm sạch text cho debug log của server
        safe_debug_text = text.strip().encode('ascii', 'replace').decode('ascii')
        logger.debug(f"Captured for scan {self.scan.scan_id if self.scan else 'N/A'}: {safe_debug_text}")

    def flush(self):
        pass

    def isatty(self):
        return False

# Routes
@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    history = get_scan_history_from_db()
    active_scans_with_details = []
    for scan_id, scan_obj in current_scans.items():
        if scan_obj.status in ["pending", "running"]:
            active_scans_with_details.append({
                "id": scan_obj.scan_id,
                "db_id": scan_obj.db_scan_id,
                "target_url": scan_obj.target_url,
                "scan_type": scan_obj.scan_type,
                "status": scan_obj.status,
                "progress": scan_obj.progress,
                "start_time": scan_obj.start_time.strftime("%Y-%m-%d %H:%M:%S") if scan_obj.start_time else "N/A"
            })
    
    vulnerability_distribution = get_overall_vulnerability_stats()
    top_vulnerabilities = get_top_vulnerability_types_stats(top_n=7) # Lấy top 7 cho đa dạng hơn
            
    return render_template('dashboard.html', 
                           title="Dashboard", 
                           scan_history=history[:10],
                           active_scans=active_scans_with_details,
                           vulnerability_distribution=vulnerability_distribution,
                           top_vulnerabilities=top_vulnerabilities)


@app.route('/scan')
def scan_page():
    return render_template('scan.html', title="Start New Scan")

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    target_url = data.get('target_url')
    scan_type = data.get('scan_type', 'basic') # 'basic' or 'full'
    # Lấy lựa chọn LLM từ form, mặc định là deepseek nếu không có
    llm_choice = data.get('llm_provider', 'deepseek') 
    use_deepseek_flag = True if llm_choice == 'deepseek' else False

    if not target_url:
        return jsonify({"error": "Target URL is required"}), 400

    # Tạo một ID duy nhất cho lần quét này (ví dụ: dựa trên timestamp)
    # scan_id = str(int(time.time())) # ID này cho web app, db_scan_id là từ DB
    scan_id = f"webscan_{int(time.time() * 1000)}"


    # Kiểm tra API keys trước khi bắt đầu luồng (nếu có thể)
    # Logic này đã có trong scan_website, nhưng một check sơ bộ ở đây có thể hữu ích
    # Tuy nhiên, để tránh lặp code, ta có thể dựa vào check trong scan_website
    # và scan_website sẽ trả về lỗi nếu key không hợp lệ.

    scan_thread_obj = ThreadedScan(scan_id, target_url, use_deepseek_flag, scan_type)
    current_scans[scan_id] = scan_thread_obj
    
    thread = threading.Thread(target=scan_thread_obj.run)
    thread.daemon = True # Để luồng tự thoát khi app chính thoát
    thread.start()
    
    logger.info(f"Scan initiated for {target_url} with web_scan_id: {scan_id}, use_deepseek: {use_deepseek_flag}, scan_type: {scan_type}")
    return jsonify({"message": "Scan started", "scan_id": scan_id, "status_url": url_for('scan_status', scan_id=scan_id)})

@app.route('/api/scan/<scan_id>')
def scan_status(scan_id):
    scan = current_scans.get(scan_id)
    if not scan:
        # Nếu không có trong current_scans, thử tìm trong DB (có thể là scan đã hoàn thành từ phiên trước)
        # Đây là một cải tiến, hiện tại current_scans chỉ chứa các scan của phiên này.
        # Để đơn giản, nếu không có trong current_scans, coi như không tìm thấy cho API status này.
        return jsonify({"error": "Scan not found or already completed and cleared from active list"}), 404
    
    return jsonify({
        "scan_id": scan.scan_id,
        "db_scan_id": scan.db_scan_id,
        "target_url": scan.target_url,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "progress": scan.progress, # Giả sử có thuộc tính progress trong ThreadedScan
        "result": scan.result, # Kết quả cuối cùng (thông báo hoặc lỗi)
        "start_time": scan.start_time.isoformat() if scan.start_time else None,
        "end_time": scan.end_time.isoformat() if scan.end_time else None,
        "report_file": scan.report_file
    })

@app.route('/api/scan/<scan_id>/output')
def scan_output(scan_id):
    scan = current_scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return Response("".join(scan.output_capture), mimetype='text/plain')


@app.route('/api/scan/<scan_id>/result')
def scan_result(scan_id):
    # This route might be redundant if /api/scan/<scan_id> already returns the final result.
    # However, it could be used specifically to fetch only the result field when the scan is completed/failed.
    scan = current_scans.get(scan_id)
    if not scan:
        db_scan_details = get_scan_details_from_db(scan_id) # Thử tìm ID này trong DB (nếu scan_id là db_id)
        if db_scan_details:
             # Cần điều chỉnh để trả về report nếu có, hoặc một thông báo từ db_scan_details
            report_path = db_scan_details.get('report_json_path') or db_scan_details.get('report_md_path')
            if report_path and os.path.exists(report_path):
                try:
                    with open(report_path, 'r', encoding='utf-8') as f:
                        # Nếu là JSON, parse và trả về, nếu MD, trả về text
                        if report_path.endswith(".json"):
                            return jsonify(json.load(f))
                        else:
                            return Response(f.read(), mimetype='text/markdown')
                except Exception as e:
                    return jsonify({"error": f"Error reading report file: {str(e)}"}), 500
            return jsonify({"status": db_scan_details.get('status', 'Completed (from DB)'), "target_url": db_scan_details.get('target_url'), "message": "Scan details retrieved from database."})
        return jsonify({"error": "Scan not found in active list or database with this ID"}), 404

    if scan.status not in ["completed", "failed"]:
        return jsonify({"status": scan.status, "message": "Scan is still running."})

    # Nếu scan đã hoàn thành hoặc thất bại từ current_scans
    if scan.report_file and scan.report_file.get("json") and os.path.exists(scan.report_file["json"]):
        try:
            with open(scan.report_file["json"], 'r', encoding='utf-8') as f:
                return jsonify(json.load(f))
        except Exception as e:
            logger.error(f"Error reading JSON report {scan.report_file['json']} for scan {scan_id}: {e}")
            return jsonify({"status": scan.status, "result_message": scan.result, "error": "Could not load JSON report."})
    elif scan.report_file and scan.report_file.get("markdown") and os.path.exists(scan.report_file["markdown"]):
        try:
            with open(scan.report_file["markdown"], 'r', encoding='utf-8') as f:
                # Trả về Markdown dưới dạng text/plain hoặc text/markdown
                return Response(f.read(), mimetype='text/markdown')
        except Exception as e:
            logger.error(f"Error reading Markdown report {scan.report_file['markdown']} for scan {scan_id}: {e}")
            return jsonify({"status": scan.status, "result_message": scan.result, "error": "Could not load Markdown report."})
    
    return jsonify({"status": scan.status, "result_message": scan.result, "message": "Scan finished, but no report file found or accessible."})


@app.route('/history')
def history_page():
    return render_template('history.html', title="Scan History")

@app.route('/api/history')
def get_scan_history_api(): # Đổi tên API route để tránh trùng với hàm helper
    history = get_scan_history_from_db()
    return jsonify(history)

# ... (giữ nguyên /api/reports, /api/report/<filename>, /api/history/<int:scan_id> DELETE, /api/report/<path:filename> DELETE, /report/<path:filename>)
# ... (Nếu /api/reports và các hàm liên quan đến file report cần điều chỉnh encoding, hãy xem xét dùng safe_open_file từ main.py)

@app.route('/api/reports')
def list_reports():
    """Trả về danh sách các file báo cáo đã được tạo."""
    reports_dir = app.config['SCAN_REPORTS_DIR']
    try:
        if not os.path.isdir(reports_dir):
            logger.warning(f"Reports directory not found: {reports_dir}")
            return jsonify({"error": "Reports directory not found"}), 404
        
        report_files = []
        for f_name in os.listdir(reports_dir):
            if os.path.isfile(os.path.join(reports_dir, f_name)) and \
               (f_name.endswith('_vulnerability.json') or f_name.endswith('_vulnerability.md')):
                try:
                    # Lấy thông tin cơ bản từ tên file nếu có thể
                    # report_testphp.vulnweb.com_20240726_103000_vulnerability.json
                    parts = f_name.replace('_vulnerability.json', '').replace('_vulnerability.md', '').split('_')
                    target = parts[0].replace('report_','') if len(parts) > 0 else f_name
                    date_str = parts[1] if len(parts) > 1 else None
                    time_str = parts[2] if len(parts) > 2 else None
                    timestamp_display = "Unknown"
                    if date_str and time_str:
                        try:
                            dt_obj = datetime.strptime(f"{date_str}{time_str}", "%Y%m%d%H%M%S")
                            timestamp_display = dt_obj.strftime("%Y-%m-%d %H:%M:%S")
                        except ValueError:
                            timestamp_display = f"{date_str} {time_str}" # Fallback
                    
                    report_files.append({
                        "filename": f_name, # Chỉ tên file
                        "path": f_name, # Legacy, giữ lại để client cũ không bị lỗi ngay, nhưng client mới nên dùng filename
                        "type": "json" if f_name.endswith(".json") else "markdown",
                        "size": os.path.getsize(os.path.join(reports_dir, f_name)),
                        "modified_time": os.path.getmtime(os.path.join(reports_dir, f_name)),
                        "target_guessed": target,
                        "timestamp_display_guessed": timestamp_display
                    })
                except Exception as e:
                    logger.error(f"Error processing report file {f_name} in list_reports: {e}")
                    # Add with minimal info if parsing fails
                    report_files.append({
                        "filename": f_name,
                        "path": f_name,
                        "type": "json" if f_name.endswith(".json") else "markdown",
                        "error": "Could not parse metadata from filename"
                    })

        # Sắp xếp theo thời gian sửa đổi, mới nhất lên đầu
        report_files.sort(key=lambda x: x.get('modified_time', 0), reverse=True)
        return jsonify(report_files)
    except Exception as e:
        logger.error(f"Error listing reports: {e}")
        return jsonify({"error": "Failed to list reports"}), 500

@app.route('/api/report/<path:filename>')
def get_report(filename):
    """Trả về nội dung của một file báo cáo cụ thể."""
    configured_reports_dir_name = app.config['SCAN_REPORTS_DIR']
    reports_dir_abs_path = os.path.abspath(configured_reports_dir_name)
    logger.info(f"API /api/report: app.config['SCAN_REPORTS_DIR'] = '{configured_reports_dir_name}', Absolute path = '{reports_dir_abs_path}'")

    # filename ở đây client nên gửi basename, nhưng chúng ta vẫn xử lý basename và strip để an toàn
    actual_filename_basename = os.path.basename(filename).strip()
    
    # Kiểm tra nếu sau khi strip, basename trở thành rỗng (ví dụ filename chỉ là dấu cách)
    if not actual_filename_basename:
        logger.warning(f"API /api/report: Received filename '{filename}' resulted in empty basename after strip.")
        return jsonify({"error": "Invalid report filename (empty after strip)"}), 400

    requested_path = safe_join(reports_dir_abs_path, actual_filename_basename)

    logger.info(f"API /api/report: Requested filename='{filename}', basename='{actual_filename_basename}', final path='{requested_path}'")

    if not os.path.abspath(requested_path).startswith(os.path.abspath(reports_dir_abs_path)):
        logger.warning(f"Path traversal attempt denied for /api/report: {filename}")
        return jsonify({"error": "Access denied - invalid path"}), 403

    if not os.path.exists(requested_path):
        logger.warning(f"Report file not found for /api/report: {requested_path}")
        return jsonify({"error": "Report file not found"}), 404
    
    try:
        with open(requested_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if actual_filename_basename.endswith('.json'):
            try:
                # Validate JSON before sending to ensure it's well-formed
                json_data = json.loads(content)
                return jsonify(json_data) # Send as JSON response
            except json.JSONDecodeError as je:
                logger.error(f"JSONDecodeError for {actual_filename_basename}: {je}")
                return jsonify({"error": "Report file is not valid JSON", "details": str(je)}), 500
        elif actual_filename_basename.endswith('.md'):
            # For Markdown, send as plain text, client will render
            return Response(content, mimetype='text/markdown; charset=utf-8')
        else:
            # For other types, treat as plain text
            return Response(content, mimetype='text/plain; charset=utf-8')
            
    except Exception as e:
        logger.error(f"Error reading report file {requested_path}: {e}", exc_info=True)
        return jsonify({"error": f"Could not read report file: {str(e)}"}), 500


@app.route('/api/history/<int:scan_id>', methods=['DELETE'])
def delete_scan_history(scan_id):
    try:
        # Trước khi xóa khỏi DB, lấy thông tin report file để xóa
        scan_details = get_scan_details_from_db(scan_id)
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        
        if cursor.rowcount > 0:
            logger.info(f"Scan history with ID {scan_id} deleted from database.")
            # Xóa các file report liên quan
            if scan_details:
                json_report = scan_details.get('report_json_path')
                md_report = scan_details.get('report_md_path')
                if json_report and os.path.exists(json_report):
                    try:
                        os.remove(json_report)
                        logger.info(f"Deleted JSON report file: {json_report}")
                    except Exception as e:
                        logger.error(f"Error deleting JSON report file {json_report}: {e}")
                if md_report and os.path.exists(md_report):
                    try:
                        os.remove(md_report)
                        logger.info(f"Deleted Markdown report file: {md_report}")
                    except Exception as e:
                        logger.error(f"Error deleting Markdown report file {md_report}: {e}")
            conn.close()
            return jsonify({"message": f"Scan history ID {scan_id} and associated reports deleted."}), 200
        else:
            conn.close()
            return jsonify({"error": f"Scan history with ID {scan_id} not found."}), 404
    except Exception as e:
        logger.error(f"Error deleting scan history ID {scan_id}: {e}")
        return jsonify({"error": "Failed to delete scan history", "details": str(e)}), 500


@app.route('/api/report/<path:filename>', methods=['DELETE'])
def delete_report(filename):
    reports_dir = os.path.abspath("scan_reports")
    requested_path = os.path.abspath(os.path.join(reports_dir, filename))

    if not requested_path.startswith(reports_dir):
        return jsonify({"error": "Access denied"}), 403

    if not os.path.exists(requested_path) or not os.path.isfile(requested_path):
        return jsonify({"error": "Report not found"}), 404
    
    try:
        os.remove(requested_path)
        logger.info(f"Report file {filename} deleted successfully.")
        
        # Thử cập nhật DB nếu có bản ghi nào trỏ đến file này (phần này phức tạp hơn)
        # Tìm trong DB các bản ghi có report_json_path hoặc report_md_path là filename và cập nhật thành NULL
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("UPDATE scans SET report_json_path = NULL WHERE report_json_path = ?", (requested_path,))
        cursor.execute("UPDATE scans SET report_md_path = NULL WHERE report_md_path = ?", (requested_path,))
        conn.commit()
        conn.close()
        logger.info(f"Database updated for deleted report: {filename}")
        
        return jsonify({"message": f"Report {filename} deleted."}), 200
    except Exception as e:
        logger.error(f"Error deleting report file {filename}: {e}")
        return jsonify({"error": "Failed to delete report file", "details": str(e)}), 500


@app.route('/report/<path:filename_from_url>')
def view_report(filename_from_url):
    app.logger.info(f"Accessing /report/ route for path: {filename_from_url}")
    filename_from_url = filename_from_url.strip()
    if not filename_from_url:
        app.logger.error("Filename from URL is empty after stripping when trying to render report page.")
        return render_template("404.html", error_message=f"Invalid report path: filename is empty."), 400

    # report.html sẽ tự lấy filename từ window.location.pathname thông qua JS.
    app.logger.info(f"Rendering template: 'report.html' for URL path '{filename_from_url}'")
    
    return render_template('report.html')


def check_db_status_internal():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM scans LIMIT 1")
        conn.close()
        return {"status_message": "Hoạt động", "ok": True, "details": "Kết nối cơ sở dữ liệu thành công."}
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return {"status_message": "Lỗi kết nối", "ok": False, "details": str(e)}

@app.route('/settings')
def settings_page():
    current_configs = {
        "deepseek_api_key": APP_SETTINGS.get("DEEPSEEK_API_KEY", PLACEHOLDER_DEEPSEEK_API_KEY),
        "deepseek_api_base": APP_SETTINGS.get("DEEPSEEK_API_BASE", PLACEHOLDER_DEEPSEEK_API_BASE),
        "openai_api_key": APP_SETTINGS.get("OPENAI_API_KEY", PLACEHOLDER_OPENAI_API_KEY),
        "openai_api_base": APP_SETTINGS.get("OPENAI_API_BASE", PLACEHOLDER_OPENAI_API_BASE),
    }
    
    system_health_info = {}
    settings_file_exists = os.path.exists(SETTINGS_FILE_PATH)
    system_health_info["settings_file"] = {
        "label": f"Tệp cấu hình ({SETTINGS_FILE_PATH})",
        "status_message": "Tìm thấy" if settings_file_exists else "Không tìm thấy (sẽ được tạo nếu lưu cài đặt)",
        "ok": settings_file_exists,
        "details": SETTINGS_FILE_PATH
    }
    db_info = check_db_status_internal()
    system_health_info["database"] = {
        "label": "Cơ sở dữ liệu (SQLite)",
        "status_message": db_info["status_message"],
        "ok": db_info["ok"],
        "details": db_info.get("details", "")
    }
            
    return render_template('settings.html', 
                           title="Settings & Status", 
                           current_llm_configs=current_configs,
                           system_health_status_dict=system_health_info,
                           settings_file_path_on_server_for_display=SETTINGS_FILE_PATH,
                           PLACEHOLDER_DEEPSEEK_API_KEY=PLACEHOLDER_DEEPSEEK_API_KEY,
                           PLACEHOLDER_DEEPSEEK_API_BASE=PLACEHOLDER_DEEPSEEK_API_BASE,
                           PLACEHOLDER_OPENAI_API_KEY=PLACEHOLDER_OPENAI_API_KEY,
                           PLACEHOLDER_OPENAI_API_BASE=PLACEHOLDER_OPENAI_API_BASE
                           )

@app.route('/api/settings/llm', methods=['POST'])
def save_llm_settings():
    global APP_SETTINGS 
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON payload"}), 400

        new_ds_key = data.get('deepseek_api_key', '').strip()
        new_ds_base = data.get('deepseek_api_base', '').strip()
        new_openai_key = data.get('openai_api_key', '').strip()
        new_openai_base = data.get('openai_api_base', '').strip()

        try:
            with open(SETTINGS_FILE_PATH, 'r', encoding='utf-8') as f:
                current_file_settings = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            current_file_settings = {}
        
        current_file_settings["DEEPSEEK_API_KEY"] = new_ds_key if new_ds_key else PLACEHOLDER_DEEPSEEK_API_KEY
        current_file_settings["DEEPSEEK_API_BASE"] = new_ds_base if new_ds_base else PLACEHOLDER_DEEPSEEK_API_BASE
        current_file_settings["OPENAI_API_KEY"] = new_openai_key if new_openai_key else PLACEHOLDER_OPENAI_API_KEY
        current_file_settings["OPENAI_API_BASE"] = new_openai_base if new_openai_base else PLACEHOLDER_OPENAI_API_BASE

        with open(SETTINGS_FILE_PATH, 'w', encoding='utf-8') as f:
            json.dump(current_file_settings, f, indent=4, ensure_ascii=False)
        
        logger.info(f"LLM settings saved to {SETTINGS_FILE_PATH}")

        reloaded_settings = main_load_app_settings()
        if isinstance(APP_SETTINGS, dict) and isinstance(reloaded_settings, dict):
            APP_SETTINGS.clear()
            APP_SETTINGS.update(reloaded_settings)
            if 'main' in sys.modules:
                main_module_app_settings = getattr(sys.modules['main'], 'APP_SETTINGS', None)
                if main_module_app_settings is not None and main_module_app_settings is not APP_SETTINGS:
                    main_module_app_settings.clear()
                    main_module_app_settings.update(reloaded_settings)
                    logger.info("main.APP_SETTINGS (module global) also reloaded.")
            logger.info("In-memory APP_SETTINGS (used by web_app) has been updated.")
        else:
            logger.warning("Could not reliably update in-memory APP_SETTINGS. A restart might be needed.")

        return jsonify({"message": "LLM settings saved successfully. Applied to current session."}), 200

    except Exception as e:
        logger.error(f"Error saving LLM settings: {e}", exc_info=True)
        return jsonify({"error": f"Failed to save LLM settings: {str(e)}"}), 500

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', title="Page Not Found"), 404

@app.route('/api/db/scan/<int:db_id>')
def get_scan_by_db_id(db_id):
    scan = get_scan_details_from_db(db_id)
    if scan:
        return jsonify(scan)
    return jsonify({"error": "Scan not found"}), 404

if __name__ == '__main__':
    # Khởi tạo DB nếu chưa có khi web app chạy trực tiếp
    # init_db() # init_db đã được gọi trong main.py, và main.py được import
    # Nếu main.py không được import thành công, init_db() ở đây có thể cần thiết
    # Tuy nhiên, APP_SETTINGS và các hằng số khác cũng sẽ thiếu.
    # Tốt nhất là đảm bảo main.py được import đúng cách.
    
    # Kiểm tra xem init_db có nên được gọi từ đây không, hay chỉ dựa vào main.py
    # Nếu chạy vuln_web_app.py độc lập, init_db() trong main.py không được chạy trừ khi import.
    # Nếu main.py được import, init_db() đã chạy.
    # Để an toàn, nếu DB_NAME không phải là placeholder lỗi:
    if "Lỗi import" not in DB_NAME and not os.path.exists(DB_NAME):
        logger.info(f"Database {DB_NAME} not found. Attempting to initialize from web_app.")
        try:
            # Cần đảm bảo init_db từ main.py có thể được gọi hoặc định nghĩa lại ở đây
            # Vì init_db trong main.py có logger riêng, nó sẽ thông báo.
            from main import init_db as main_init_db # Thử import lại chỉ init_db
            main_init_db()
        except ImportError:
             logger.error("Could not import init_db from main.py to initialize database from web_app.")
        except Exception as e_init:
            logger.error(f"Error initializing DB from web_app: {e_init}")


    app.run(debug=True, host='0.0.0.0', port=5000) #
