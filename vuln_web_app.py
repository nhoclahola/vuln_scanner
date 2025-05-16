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

# Thiết lập logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("web_app.log"),
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
                    item['duration'] = 0
            else:
                item['duration'] = 0
            
            if item.get('report_json_path') and os.path.exists(item['report_json_path']):
                try:
                    with open(item['report_json_path'], 'r', encoding='utf-8') as f:
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
        self.buffer = ""

    def write(self, text):
        # Đẩy output vào queue để stream tới client nếu cần
        output_queue.put(text)
        # Lưu lại output cho scan cụ thể này
        if self.scan:
            self.scan.output_capture.append(text)
        # Ghi vào log file của web app
        # sys.__stdout__.write(text) # Tránh vòng lặp vô hạn nếu logger cũng ghi ra stdout
        logger.debug(f"Captured output: {text.strip()}") # Ghi vào log dưới dạng debug

    def flush(self):
        # sys.__stdout__.flush()
        pass # Flask xử lý flush

    def isatty(self): # Cần cho một số thư viện
        return False

# Routes
@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    # Lấy lịch sử quét và các lần quét đang chạy để hiển thị
    history = get_scan_history_from_db() 
    
    # Lấy trạng thái thực tế của các lần quét đang chạy từ current_scans
    # (current_scans chứa các đối tượng ThreadedScan)
    active_scans_with_details = []
    for scan_id, scan_obj in current_scans.items():
        if scan_obj.status in ["pending", "running"]: # Chỉ những cái thực sự đang chạy hoặc chờ
            active_scans_with_details.append({
                "id": scan_obj.scan_id,
                "db_id": scan_obj.db_scan_id,
                "target_url": scan_obj.target_url,
                "scan_type": scan_obj.scan_type,
                "status": scan_obj.status,
                "progress": scan_obj.progress,
                "start_time": scan_obj.start_time.strftime("%Y-%m-%d %H:%M:%S") if scan_obj.start_time else "N/A"
            })
            
    return render_template('dashboard.html', 
                           title="Dashboard", 
                           scan_history=history[:10], # Chỉ hiển thị 10 mục gần nhất trên dashboard
                           active_scans=active_scans_with_details)


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
    reports_dir = "scan_reports"
    if not os.path.exists(reports_dir):
        return jsonify([])
    
    report_files = []
    for filename in os.listdir(reports_dir):
        if filename.startswith("report_") and (filename.endswith(".json") or filename.endswith(".md")):
            file_path = os.path.join(reports_dir, filename)
            try:
                stat = os.stat(file_path)
                # Trích xuất thông tin từ tên file nếu có thể (ví dụ: target, timestamp)
                # report_example_pentest_corp_20231026_103045_vulnerability.json
                parts = filename.replace("report_", "").replace("_vulnerability.json", "").replace("_vulnerability.md", "").split("_")
                target_guess = "N/A"
                timestamp_str = "N/A"
                if len(parts) > 1: # Giả sử ít nhất có target và timestamp
                    timestamp_str = parts[-2] + "_" + parts[-1] if len(parts) >=2 else parts[-1]
                    target_guess = "_".join(parts[:-2]) if len(parts) > 2 else parts[0]

                report_files.append({
                    "filename": filename,
                    "path": file_path,
                    "size": stat.st_size,
                    "modified_time": datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    "type": "JSON" if filename.endswith(".json") else "Markdown",
                    "target_guess": target_guess,
                    "timestamp_str": timestamp_str
                })
            except Exception as e:
                logger.error(f"Error processing report file {filename}: {e}")
                report_files.append({
                    "filename": filename,
                    "error": str(e)
                })
    
    # Sắp xếp theo thời gian sửa đổi, mới nhất lên đầu
    report_files.sort(key=lambda x: x.get("modified_time", ""), reverse=True)
    return jsonify(report_files)

@app.route('/api/report/<path:filename>')
def get_report(filename):
    # filename ở đây bao gồm cả thư mục con nếu có, nhưng hiện tại là không
    # Chúng ta cần đảm bảo filename an toàn, không cho phép path traversal
    reports_dir = os.path.abspath("scan_reports")
    requested_path = os.path.abspath(os.path.join(reports_dir, filename))

    if not requested_path.startswith(reports_dir):
        return jsonify({"error": "Access denied"}), 403 # Path traversal attempt

    if not os.path.exists(requested_path) or not os.path.isfile(requested_path):
        return jsonify({"error": "Report not found"}), 404

    try:
        # Sử dụng safe_open_file nếu cần xử lý encoding phức tạp
        with open(requested_path, 'r', encoding='utf-8') as f: # Mặc định utf-8 cho report
            content = f.read()
        
        if filename.endswith(".json"):
            return jsonify(json.loads(content)) # Parse lại JSON để đảm bảo nó valid
        elif filename.endswith(".md"):
            return Response(content, mimetype='text/markdown') # Hoặc text/plain
        else:
            return Response(content, mimetype='text/plain')
            
    except json.JSONDecodeError as e:
        logger.error(f"JSONDecodeError for report {filename}: {e}")
        return jsonify({"error": "Report is not valid JSON", "details": str(e)}), 500
    except Exception as e:
        logger.error(f"Error reading report {filename}: {e}")
        return jsonify({"error": "Could not read report file", "details": str(e)}), 500


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


@app.route('/report/<path:filename>')
def view_report(filename):
    # Đây là trang HTML để hiển thị report, không phải API trả về JSON/Markdown thô
    # Nó sẽ gọi /api/report/<filename> để lấy nội dung
    # Cần kiểm tra loại file để render template phù hợp
    file_type = "json" if filename.endswith(".json") else "markdown" if filename.endswith(".md") else "unknown"
    return render_template('view_report.html', 
                           title=f"View Report: {filename}", 
                           report_filename=filename,
                           report_api_url=url_for('get_report', filename=filename),
                           file_type=file_type)


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

# @app.route('/api/db/scan/<int:db_id>') # Route này có vẻ không cần thiết nữa nếu dashboard dùng scan_history
# def get_scan_by_db_id(db_id):
#     scan = get_scan_details_from_db(db_id)
#     if scan:
#         return jsonify(scan)
#     return jsonify({"error": "Scan not found"}), 404

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
