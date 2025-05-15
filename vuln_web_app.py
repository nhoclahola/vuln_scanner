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

# Import hàm scan_website từ main.py
from main import scan_website, format_vulnerability_report, init_db, log_scan_start, log_scan_end, DB_NAME

app = Flask(__name__, 
            static_folder='web/static',
            template_folder='web/templates')

# Queue và biến toàn cục để lưu output stream
output_queue = queue.Queue()
current_scans = {}
scan_history = []

# Hàm tương tác với SQLite database
def get_scan_history_from_db():
    """Lấy lịch sử quét từ database SQLite"""
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row  # Để kết quả trả về dạng dict
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, target_url, scan_type, scan_timestamp, status, 
                   report_json_path, report_md_path, end_time
            FROM scans
            ORDER BY scan_timestamp DESC
        """)
        rows = cursor.fetchall()
        conn.close()
        
        # Chuyển đổi rows thành list of dict
        history = []
        for row in rows:
            item = dict(row)
            
            # Xử lý timestamp để đảm bảo client có thể hiển thị đúng
            if item['scan_timestamp']:
                # Nếu là chuỗi định dạng ngày tháng, chuyển thành timestamp số để client dễ xử lý
                if isinstance(item['scan_timestamp'], str):
                    try:
                        dt = datetime.strptime(item['scan_timestamp'], "%Y-%m-%d %H:%M:%S")
                        item['timestamp'] = int(dt.timestamp())
                    except (ValueError, TypeError):
                        # Nếu không phải định dạng chuẩn, giữ nguyên
                        item['timestamp'] = item['scan_timestamp']
                else:
                    # Nếu đã là số, gán trực tiếp
                    item['timestamp'] = item['scan_timestamp']
            else:
                # Nếu không có timestamp, dùng thời gian hiện tại
                item['timestamp'] = int(time.time())
            
            # Tính thời gian quét từ scan_timestamp và end_time
            if item['scan_timestamp'] and item['end_time']:
                try:
                    # Chuyển đổi chuỗi thành đối tượng datetime
                    start_time = datetime.strptime(item['scan_timestamp'], "%Y-%m-%d %H:%M:%S")
                    end_time = datetime.strptime(item['end_time'], "%Y-%m-%d %H:%M:%S")
                    
                    # Tính thời gian quét (giây)
                    scan_duration = (end_time - start_time).total_seconds()
                    item['duration'] = round(scan_duration, 2)
                except Exception as e:
                    logger.error(f"Error calculating scan duration: {str(e)}")
                    item['duration'] = 0
            else:
                item['duration'] = 0
            
            # Thêm thông tin về số lượng lỗ hổng từ file report nếu có
            if item['report_json_path'] and os.path.exists(item['report_json_path']):
                try:
                    with open(item['report_json_path'], 'r', encoding='utf-8') as f:
                        report_data = json.load(f)
                        # Lấy số lượng lỗ hổng từ summary nếu có
                        if 'summary' in report_data and 'total_vulnerabilities' in report_data['summary']:
                            item['vulnerabilities'] = report_data['summary']['total_vulnerabilities']
                        elif 'vulnerabilities' in report_data and isinstance(report_data['vulnerabilities'], list):
                            item['vulnerabilities'] = len(report_data['vulnerabilities'])
                except Exception as e:
                    logger.error(f"Error reading report file {item['report_json_path']}: {str(e)}")
            
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
            
            # Tính thời gian quét từ scan_timestamp và end_time
            if scan_details['scan_timestamp'] and scan_details['end_time']:
                try:
                    # Chuyển đổi chuỗi thành đối tượng datetime
                    start_time = datetime.strptime(scan_details['scan_timestamp'], "%Y-%m-%d %H:%M:%S")
                    end_time = datetime.strptime(scan_details['end_time'], "%Y-%m-%d %H:%M:%S")
                    
                    # Tính thời gian quét (giây)
                    scan_duration = (end_time - start_time).total_seconds()
                    scan_details['duration'] = round(scan_duration, 2)
                except Exception as e:
                    logger.error(f"Error calculating scan duration: {str(e)}")
                    scan_details['duration'] = 0
            else:
                scan_details['duration'] = 0
                
            return scan_details
        return None
    except Exception as e:
        logger.error(f"Error fetching scan details from DB: {str(e)}")
        return None

class ThreadedScan:
    def __init__(self, scan_id, target_url, use_deepseek, scan_type):
        self.scan_id = scan_id
        self.target_url = target_url
        self.use_deepseek = use_deepseek
        self.scan_type = scan_type
        self.status = "pending"
        self.result = None
        self.output_capture = []
        self.start_time = datetime.now()
        self.end_time = None
        self.progress = 0
        self.report_file = None
        self.db_scan_id = None  # Lưu ID của bản ghi trong database
        
    def run(self):
        self.status = "running"
        try:
            # Redirect stdout to capture output
            original_stdout = sys.stdout
            original_stderr = sys.stderr
            sys.stdout = OutputCapture(self)
            sys.stderr = OutputCapture(self)
            
            # Ghi lại thông tin quét vào database
            self.db_scan_id = log_scan_start(self.target_url, self.scan_type)
            
            # Run the scan
            logger.info(f"Starting scan for {self.target_url}")
            status_message, json_report_path, md_report_path = scan_website(
                self.target_url, 
                self.use_deepseek, 
                self.scan_type,
                current_scan_id=self.db_scan_id
            )
            
            self.result = status_message
            self.status = "completed"
            
            # Lưu đường dẫn đến báo cáo
            self.report_file = {
                "json": json_report_path,
                "markdown": md_report_path
            }
                
            # Calculate duration
            duration = (self.end_time or datetime.now()) - self.start_time
            duration_seconds = duration.total_seconds()
            
            # Thêm vào scan_history (cho khả năng tương thích ngược)
            scan_record = {
                "id": self.scan_id,
                "db_id": self.db_scan_id,
                "target_url": self.target_url,
                "scan_type": self.scan_type,
                "timestamp": int(time.mktime(self.start_time.timetuple())),
                "duration": round(duration_seconds, 2),
                "status": "completed",
                "report_json_path": json_report_path,
                "report_md_path": md_report_path
            }
            scan_history.append(scan_record)
            
            # Save scan history to file (cho khả năng tương thích ngược)
            try:
                with open('scan_history.json', 'w') as f:
                    json.dump(scan_history, f, indent=2)
            except Exception as e:
                logger.error(f"Error saving scan history: {str(e)}")
            
            # Ghi log kết thúc quét và lưu báo cáo vào database
            if self.db_scan_id:
                log_scan_end(self.db_scan_id, json_report_path, md_report_path)
            
            self.progress = 100  # Set progress to 100% when complete
            self.end_time = datetime.now()
        except Exception as e:
            self.status = "failed"
            self.result = f"Error: {str(e)}"
            logger.error(f"Scan error: {str(e)}", exc_info=True)
            if self.db_scan_id:
                # Update DB record to indicate failure
                try:
                    conn = sqlite3.connect(DB_NAME)
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE scans 
                        SET status = ?, end_time = ?
                        WHERE id = ?
                    """, ("failed", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.db_scan_id))
                    conn.commit()
                    conn.close()
                except Exception as db_error:
                    logger.error(f"Failed to update scan status in DB: {str(db_error)}")
        finally:
            # Restore stdout
            sys.stdout = original_stdout
            sys.stderr = original_stderr

class OutputCapture(object):
    def __init__(self, scan):
        self.scan = scan
    
    def write(self, text):
        if text.strip():  # Ignore empty lines
            self.scan.output_capture.append(text)
            output_queue.put({"scan_id": self.scan.scan_id, "text": text})
            # Update progress based on certain keywords
            if "Target URL:" in text:
                self.scan.progress = 5
            elif "Web Crawler" in text:
                self.scan.progress = 10
            elif "Crawling " in text:
                # Don't regress progress if already higher
                if self.scan.progress < 15:
                    self.scan.progress = 15
            elif "Analyzing HTTP headers" in text:
                self.scan.progress = 25
            elif "Discovering endpoints" in text:
                self.scan.progress = 40
            elif "Analyzing JavaScript" in text:
                self.scan.progress = 50
            elif "Scanning for XSS" in text:
                self.scan.progress = 60
            elif "Scanning for SQL" in text:
                self.scan.progress = 70
            elif "Scanning for" in text and "vulnerabilities" in text:
                # For other vulnerability types
                if self.scan.progress < 75:
                    self.scan.progress = 75
            elif "Creating comprehensive summary" in text or "Create a comprehensive summary" in text:
                self.scan.progress = 80
            elif "formatting" in text.lower() and "report" in text.lower():
                self.scan.progress = 85
            elif "Generating report" in text or "Creating report" in text:
                self.scan.progress = 90
            elif "Report saved" in text:
                self.scan.progress = 100
            # Fallback progress increments based on CrewAI markers
            elif "Agent:" in text and self.scan.progress < 90:
                # Small progress increment for any agent activity
                self.scan.progress += 2
                # Cap at 95 for agent activity (saving 100 for completion)
                if self.scan.progress > 95:
                    self.scan.progress = 95
        return len(text)
    
    def flush(self):
        pass

# Đường dẫn trang chủ và dashboard
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# Đường dẫn cho trang quét
@app.route('/scan')
def scan_page():
    return render_template('scan.html')

# API để bắt đầu quét
@app.route('/api/scan', methods=['POST'])
def start_scan():
    target_url = request.form.get('url')
    use_openai = request.form.get('llm_provider') == 'openai'
    scan_type = request.form.get('scan_type', 'basic')
    
    if not target_url:
        return jsonify({"error": "URL is required"}), 400
    
    # Generate a unique scan ID
    scan_id = f"{int(time.time())}"
    
    # Create threaded scan
    scan = ThreadedScan(
        scan_id=scan_id,
        target_url=target_url,
        use_deepseek=not use_openai,
        scan_type=scan_type
    )
    
    # Add to current scans
    current_scans[scan_id] = scan
    
    # Start scanning in a new thread
    thread = threading.Thread(target=scan.run)
    thread.daemon = True
    thread.start()
    
    return jsonify({"scan_id": scan_id})

# API để kiểm tra trạng thái quét
@app.route('/api/scan/<scan_id>')
def scan_status(scan_id):
    if scan_id in current_scans:
        scan = current_scans[scan_id]
        
        # Calculate elapsed time
        elapsed = (scan.end_time if scan.end_time else datetime.now()) - scan.start_time
        elapsed_str = str(elapsed).split('.')[0]  # Remove microseconds
        
        # Nếu có db_scan_id, lấy thêm thông tin từ database
        db_scan_details = None
        if hasattr(scan, 'db_scan_id') and scan.db_scan_id:
            db_scan_details = get_scan_details_from_db(scan.db_scan_id)
        
        report_json = None
        report_md = None
        
        # Ưu tiên lấy từ scan object trước
        if scan.report_file and isinstance(scan.report_file, dict):
            report_json = scan.report_file.get('json')
            report_md = scan.report_file.get('markdown')
        elif scan.report_file and isinstance(scan.report_file, str):
            # Tương thích ngược với code cũ
            report_json = scan.report_file
        
        # Nếu không có từ scan object, thử lấy từ database
        if db_scan_details:
            if not report_json and db_scan_details.get('report_json_path'):
                report_json = db_scan_details.get('report_json_path')
            if not report_md and db_scan_details.get('report_md_path'):
                report_md = db_scan_details.get('report_md_path')
                
            # Nếu scan đã hoàn thành, lấy thời gian quét đã tính toán từ database
            if scan.status == "completed" and db_scan_details.get('duration'):
                elapsed_str = f"{db_scan_details.get('duration')} seconds"
        
        return jsonify({
            "scan_id": scan_id,
            "db_scan_id": scan.db_scan_id if hasattr(scan, 'db_scan_id') else None,
            "status": scan.status,
            "target_url": scan.target_url,
            "progress": scan.progress,
            "elapsed_time": elapsed_str,
            "report_json_path": report_json,
            "report_md_path": report_md
        })
    
    return jsonify({"error": "Scan not found"}), 404

# API để lấy output của quét
@app.route('/api/scan/<scan_id>/output')
def scan_output(scan_id):
    if scan_id in current_scans:
        scan = current_scans[scan_id]
        return jsonify({"output": scan.output_capture})
    
    return jsonify({"error": "Scan not found"}), 404

# API để lấy kết quả quét
@app.route('/api/scan/<scan_id>/result')
def scan_result(scan_id):
    if scan_id in current_scans:
        scan = current_scans[scan_id]
        
        if scan.status == "completed":
            # Lấy thông tin báo cáo
            report_json = None
            report_md = None
            
            # Ưu tiên lấy từ scan object
            if scan.report_file and isinstance(scan.report_file, dict):
                report_json = scan.report_file.get('json')
                report_md = scan.report_file.get('markdown')
            elif scan.report_file and isinstance(scan.report_file, str):
                # Tương thích ngược với code cũ
                report_json = scan.report_file
            
            # Nếu có db_scan_id, kiểm tra thông tin từ database
            if hasattr(scan, 'db_scan_id') and scan.db_scan_id:
                db_scan_details = get_scan_details_from_db(scan.db_scan_id)
                if db_scan_details:
                    if not report_json and db_scan_details.get('report_json_path'):
                        report_json = db_scan_details.get('report_json_path')
                    if not report_md and db_scan_details.get('report_md_path'):
                        report_md = db_scan_details.get('report_md_path')
            
            # Đọc nội dung báo cáo từ file
            formatted_result = None
            if report_json and os.path.exists(report_json):
                try:
                    with open(report_json, 'r', encoding='utf-8') as f:
                        report_content = json.load(f)
                        formatted_result = report_content
                except Exception as e:
                    logger.error(f"Error reading JSON report {report_json}: {str(e)}")
            
            if not formatted_result and report_md and os.path.exists(report_md):
                try:
                    with open(report_md, 'r', encoding='utf-8') as f:
                        report_content = f.read()
                        formatted_result = {
                            "markdown_content": report_content,
                            "type": "markdown"
                        }
                except Exception as e:
                    logger.error(f"Error reading MD report {report_md}: {str(e)}")
            
            # Nếu không đọc được file báo cáo, dùng kết quả từ scan.result
            if not formatted_result:
                if isinstance(scan.result, dict):
                    formatted_result = scan.result
                else:
                    formatted_result = {
                        "text_result": str(scan.result),
                        "type": "text"
                    }
                
            return jsonify({
                "status": "completed", 
                "result": formatted_result,
                "report_json_path": report_json,
                "report_md_path": report_md
            })
        
        return jsonify({"status": scan.status})
    
    return jsonify({"error": "Scan not found"}), 404

# API để stream real-time output
@app.route('/api/stream')
def stream():
    """Stream scan outputs as Server-Sent Events"""
    def event_stream():
        while True:
            try:
                # Get message with a timeout to avoid blocking forever
                message = output_queue.get(timeout=1)
                yield f"data: {json.dumps(message)}\n\n"
            except queue.Empty:
                # Send a keep-alive comment
                yield ": keep-alive\n\n"
            except Exception as e:
                logger.error(f"Error in event stream: {str(e)}")
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return Response(stream_with_context(event_stream()),
                  mimetype="text/event-stream")

# Trang lịch sử quét
@app.route('/history')
def history_page():
    return render_template('history.html')

# API lấy lịch sử quét
@app.route('/api/history')
def get_scan_history():
    """Lấy lịch sử quét từ database"""
    try:
        # Chỉ lấy từ database SQLite
        history = get_scan_history_from_db()
        return jsonify(history)
    except Exception as e:
        logger.error(f"Error getting scan history: {str(e)}")
        return jsonify({"error": str(e)}), 500

# API liệt kê báo cáo
@app.route('/api/reports')
def list_reports():
    """List all available scan reports from database and scan_reports directory"""
    reports = []
    
    # Lấy báo cáo từ database
    db_history = get_scan_history_from_db()
    for item in db_history:
        if item['report_json_path'] or item['report_md_path']:
            json_path = item['report_json_path']
            md_path = item['report_md_path']
            
            # Kiểm tra tệp có tồn tại không
            json_exists = json_path and os.path.exists(json_path)
            md_exists = md_path and os.path.exists(md_path)
            
            if json_exists or md_exists:
                # Lấy thời gian tạo từ timestamp hoặc thời gian sửa đổi tệp
                if isinstance(item['scan_timestamp'], str):
                    created = item['scan_timestamp']
                else:
                    try:
                        created = datetime.fromtimestamp(item['scan_timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        # Nếu timestamp không hợp lệ, lấy thời gian sửa đổi tệp
                        json_time = os.path.getmtime(json_path) if json_exists else 0
                        md_time = os.path.getmtime(md_path) if md_exists else 0
                        timestamp = max(json_time, md_time)
                        created = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                
                reports.append({
                    "db_id": item['id'],
                    "target_url": item['target_url'],
                    "scan_type": item['scan_type'],
                    "created": created,
                    "json_path": json_path if json_exists else None,
                    "md_path": md_path if md_exists else None
                })
    
    # Kiểm tra thư mục scan_reports để tìm báo cáo bổ sung
    if os.path.exists('scan_reports'):
        for filename in os.listdir('scan_reports'):
            filepath = os.path.join('scan_reports', filename)
            
            # Kiểm tra xem báo cáo đã được thêm vào danh sách chưa
            already_added = False
            for report in reports:
                if ((report.get('json_path') == filepath) or 
                    (report.get('md_path') == filepath)):
                    already_added = True
                    break
            
            if not already_added and (filename.endswith('.json') or filename.endswith('.md')):
                # Trích xuất thông tin từ tên tệp
                parts = filename.split('_')
                if len(parts) >= 2:
                    # Định dạng mới: report_domain_timestamp_vulnerability.json
                    target_url = parts[1]
                    
                    # Lấy thời gian tạo từ tệp
                    timestamp = os.path.getmtime(filepath)
                    created = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Thêm vào danh sách báo cáo
                    if filename.endswith('.json'):
                        md_file = filepath.replace('.json', '.md')
                        has_md = os.path.exists(md_file)
                        reports.append({
                            "target_url": target_url,
                            "created": created,
                            "json_path": filepath,
                            "md_path": md_file if has_md else None
                        })
                    elif filename.endswith('.md'):
                        json_file = filepath.replace('.md', '.json')
                        # Chỉ thêm file .md nếu không có file .json tương ứng
                        if not os.path.exists(json_file):
                            reports.append({
                                "target_url": target_url,
                                "created": created,
                                "json_path": None,
                                "md_path": filepath
                            })
    
    # Sort by newest first
    reports.sort(key=lambda x: x["created"], reverse=True)
    return jsonify({"reports": reports})

# API đọc nội dung báo cáo
@app.route('/api/report/<path:filename>')
def get_report(filename):
    """Get a specific report"""
    try:
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # If it's a JSON file, format it
            if filename.endswith('.json'):
                try:
                    data = json.loads(content)
                    return jsonify({"content": data})
                except json.JSONDecodeError as e:
                    logger.error(f"Error decoding JSON: {str(e)}")
                    return jsonify({"content": content, "type": "text", "error": "Invalid JSON format"})
            elif filename.endswith('.md'):
                # Markdown file
                return jsonify({"content": content, "type": "markdown"})
            else:
                # Đây là file text
                return jsonify({"content": {"text_result": content, "type": "text"}})
        else:
            return jsonify({"error": "Report not found"}), 404
    except Exception as e:
        return jsonify({"error": f"Error reading report: {str(e)}"}), 500

# API xóa lịch sử quét
@app.route('/api/history/<int:scan_id>', methods=['DELETE'])
def delete_scan_history(scan_id):
    """Delete a specific scan record from the database and its associated report files"""
    try:
        # First get the scan details to find report files
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT report_json_path, report_md_path
            FROM scans
            WHERE id = ?
        """, (scan_id,))
        scan = cursor.fetchone()
        
        if not scan:
            return jsonify({"success": False, "error": "Scan record not found"}), 404
        
        # Get report paths
        report_json_path = scan['report_json_path']
        report_md_path = scan['report_md_path']
        
        # Delete the scan record from database
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()
        
        # Delete associated report files if they exist
        files_deleted = []
        
        if report_json_path and os.path.exists(report_json_path):
            os.remove(report_json_path)
            files_deleted.append(report_json_path)
            
            # Also try to delete any associated .txt file
            txt_filename = report_json_path.replace('.json', '.txt')
            if os.path.exists(txt_filename):
                os.remove(txt_filename)
                files_deleted.append(txt_filename)
        
        if report_md_path and os.path.exists(report_md_path):
            os.remove(report_md_path)
            files_deleted.append(report_md_path)
        
        logger.info(f"Deleted scan record ID {scan_id} and {len(files_deleted)} associated files")
        
        return jsonify({
            "success": True, 
            "message": f"Scan record and {len(files_deleted)} associated files deleted successfully",
            "files_deleted": files_deleted
        })
    except Exception as e:
        logger.error(f"Error deleting scan record: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": f"Error deleting scan record: {str(e)}"}), 500

# API xóa báo cáo
@app.route('/api/report/<path:filename>', methods=['DELETE'])
def delete_report(filename):
    """Delete a specific report"""
    try:
        if os.path.exists(filename):
            # Delete the JSON file
            os.remove(filename)
            
            # Also remove corresponding text file if it exists
            txt_filename = filename.replace('.json', '.txt')
            if os.path.exists(txt_filename):
                os.remove(txt_filename)
                
            # Check if this report is associated with any scan in the database
            conn = sqlite3.connect(DB_NAME)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id FROM scans 
                WHERE report_json_path = ? OR report_md_path = ?
            """, (filename, filename))
            scan = cursor.fetchone()
            
            if scan:
                # Update the database record to remove the reference to this file
                if filename.endswith('.json'):
                    cursor.execute("UPDATE scans SET report_json_path = NULL WHERE id = ?", (scan['id'],))
                elif filename.endswith('.md'):
                    cursor.execute("UPDATE scans SET report_md_path = NULL WHERE id = ?", (scan['id'],))
                conn.commit()
            
            conn.close()
            
            return jsonify({"success": True, "message": "Report deleted successfully"})
        else:
            return jsonify({"success": False, "error": "Report not found"}), 404
    except Exception as e:
        logger.error(f"Error deleting report: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": f"Error deleting report: {str(e)}"}), 500

# Trang chi tiết báo cáo
@app.route('/report/<path:filename>')
def view_report(filename):
    return render_template('report.html', filename=filename)

# Trang cấu hình
@app.route('/settings')
def settings_page():
    return render_template('settings.html')

# Xử lý 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

def load_scan_history():
    """Không sử dụng file scan_history.json nữa, biến này chỉ có mặt để tránh lỗi khi tham chiếu đến nó"""
    global scan_history
    scan_history = []  # Luôn để mảng rỗng vì không còn dùng file scan_history.json

# API để lấy kết quả quét từ ID trong database
@app.route('/api/db/scan/<int:db_id>')
def get_scan_by_db_id(db_id):
    """Get scan details by database ID"""
    try:
        scan_details = get_scan_details_from_db(db_id)
        
        if scan_details:
            # Format response
            json_path = scan_details.get('report_json_path')
            md_path = scan_details.get('report_md_path')
            
            # Kiểm tra tệp có tồn tại không
            json_exists = json_path and os.path.exists(json_path)
            md_exists = md_path and os.path.exists(md_path)
            
            # Chuyển đổi timestamp thành định dạng dễ đọc
            timestamp_display = scan_details.get('scan_timestamp', '')
            timestamp_unix = 0
            
            if timestamp_display:
                if isinstance(timestamp_display, str):
                    try:
                        # Chuyển từ string sang datetime rồi thành unix timestamp
                        dt = datetime.strptime(timestamp_display, "%Y-%m-%d %H:%M:%S")
                        timestamp_unix = int(dt.timestamp())
                    except (ValueError, TypeError) as e:
                        # Try alternative formats if the standard format fails
                        try:
                            # Try ISO format
                            dt = datetime.fromisoformat(timestamp_display.replace('Z', '+00:00'))
                            timestamp_unix = int(dt.timestamp())
                        except:
                            # If all parsing fails, use current time
                            logger.error(f"Error parsing timestamp string '{timestamp_display}': {e}")
                            timestamp_unix = int(time.time())
                else:
                    # Nếu là số, giả định đó là unix timestamp
                    timestamp_unix = int(timestamp_display)
            
            response = {
                "id": scan_details['id'],
                "target_url": scan_details.get('target_url', 'Unknown'),
                "scan_type": scan_details.get('scan_type', 'basic'),
                "status": scan_details.get('status', 'Unknown'),
                "timestamp": timestamp_unix,
                "timestamp_display": timestamp_display,
                "report_json_path": json_path if json_exists else None,
                "report_md_path": md_path if md_exists else None,
                "duration": scan_details.get('duration', "N/A")  # Lấy thời gian quét từ chi tiết scan
            }
            
            return jsonify(response)
        
        # Không tìm thấy trong cơ sở dữ liệu
        return jsonify({"error": "Scan not found"}), 404
    except Exception as e:
        logger.error(f"Error in get_scan_by_db_id: {str(e)}", exc_info=True)
        return jsonify({"error": f"Error getting scan details: {str(e)}"}), 500

if __name__ == '__main__':
    # Đảm bảo database đã được khởi tạo
    init_db()
    
    # Ensure required directories exist
    os.makedirs('web/static', exist_ok=True)
    os.makedirs('web/templates', exist_ok=True)
    os.makedirs('web/static/css', exist_ok=True)
    os.makedirs('web/static/js', exist_ok=True)
    os.makedirs('web/static/img', exist_ok=True)
    os.makedirs('scan_reports', exist_ok=True)
    
    # Load scan history
    load_scan_history()
    
    # Run the app
    app.run(debug=True, host='0.0.0.0', port=5000) 