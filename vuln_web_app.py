import os
import sys
import json
import threading
import time
import queue
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, Response, stream_with_context

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
from main import scan_website, save_report_to_file, format_vulnerability_report

app = Flask(__name__, 
            static_folder='web/static',
            template_folder='web/templates')

# Queue và biến toàn cục để lưu output stream
output_queue = queue.Queue()
current_scans = {}
scan_history = []

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
        
    def run(self):
        self.status = "running"
        try:
            # Redirect stdout to capture output
            original_stdout = sys.stdout
            original_stderr = sys.stderr
            sys.stdout = OutputCapture(self)
            sys.stderr = OutputCapture(self)
            
            # Run the scan
            logger.info(f"Starting scan for {self.target_url}")
            result = scan_website(self.target_url, self.use_deepseek, self.scan_type)
            self.result = result
            self.status = "completed"
            
            # Count vulnerabilities
            vulnerabilities_count = 0
            if result:
                # Kiểm tra xem result có phải là dict không trước khi sử dụng .items()
                if isinstance(result, dict):
                    # Count all vulnerabilities by category
                    for category, vulns in result.items():
                        if category not in ['metadata', 'summary'] and isinstance(vulns, list):
                            vulnerabilities_count += len(vulns)
                elif isinstance(result, str):
                    # Nếu result là string, có thể là thông báo lỗ hổng hoặc thông báo khác
                    logger.info(f"Scan result is a string: {result}")
                    # Không tính là lỗ hổng
                    vulnerabilities_count = 0
                else:
                    # Kiểu dữ liệu khác
                    logger.info(f"Scan result has unexpected type: {type(result)}")
                    vulnerabilities_count = 0
            
            # Save report to file
            if result:
                logger.info("Saving report to file")
                
                # Nếu result là dict, lưu dưới dạng JSON, nếu không thì lưu dưới dạng text
                if isinstance(result, dict):
                    report_info = save_report_to_file(result, self.target_url, "vulnerability_report.json")
                else:
                    # Lưu kết quả dạng text nếu không phải là dict
                    report_filename = f"report_{self.target_url.replace('://', '_').replace('/', '_').replace(':', '_')}_{int(time.time())}.txt"
                    with open(report_filename, 'w', encoding='utf-8') as f:
                        f.write(str(result))
                    report_info = report_filename
                
                self.report_file = report_info
                
                # Calculate duration
                duration = (self.end_time or datetime.now()) - self.start_time
                duration_seconds = duration.total_seconds()
                
                # Add to scan history with more details
                scan_record = {
                    "id": self.scan_id,
                    "target_url": self.target_url,
                    "scan_type": self.scan_type,
                    "timestamp": int(time.mktime(self.start_time.timetuple())),
                    "duration": round(duration_seconds, 2),
                    "vulnerabilities": vulnerabilities_count,
                    "report_file": report_info,
                    "status": "completed"
                }
                scan_history.append(scan_record)
                
                # Save scan history to file
                try:
                    with open('scan_history.json', 'w') as f:
                        json.dump(scan_history, f, indent=2)
                except Exception as e:
                    logger.error(f"Error saving scan history: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error in scan: {str(e)}")
            self.status = "error"
            self.result = {"error": str(e)}
            
            # Add error entry to scan history
            scan_record = {
                "id": self.scan_id,
                "target_url": self.target_url,
                "scan_type": self.scan_type,
                "timestamp": int(time.mktime(self.start_time.timetuple())),
                "duration": 0,
                "vulnerabilities": 0,
                "status": "error",
                "error": str(e)
            }
            scan_history.append(scan_record)
            
            # Try to save scan history
            try:
                with open('scan_history.json', 'w') as f:
                    json.dump(scan_history, f, indent=2)
            except Exception as ex:
                logger.error(f"Error saving scan history after error: {str(ex)}")
                
        finally:
            # Restore stdout and stderr
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            self.end_time = datetime.now()

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
            elif "Analyzing HTTP headers" in text:
                self.scan.progress = 25
            elif "Discovering endpoints" in text:
                self.scan.progress = 40
            elif "Analyzing JavaScript" in text:
                self.scan.progress = 50
            elif "Scanning for XSS" in text:
                self.scan.progress = 65
            elif "Scanning for SQL" in text:
                self.scan.progress = 75
            elif "Analyzing vulnerabilities" in text:
                self.scan.progress = 85
            elif "Report saved" in text:
                self.scan.progress = 100
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
        
        return jsonify({
            "scan_id": scan_id,
            "status": scan.status,
            "target_url": scan.target_url,
            "progress": scan.progress,
            "elapsed_time": elapsed_str,
            "report_file": scan.report_file
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
            # Format the result if needed
            if isinstance(scan.result, dict):
                formatted_result = format_vulnerability_report(scan.result)
            else:
                # Nếu kết quả không phải là dict, trả về dưới dạng text
                formatted_result = {
                    "text_result": str(scan.result),
                    "type": "text"
                }
                
            return jsonify({
                "status": "completed", 
                "result": formatted_result,
                "report_file": scan.report_file
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
    history_data = []
    
    # Nếu file lịch sử tồn tại, đọc từ đó
    if os.path.exists('scan_history.json'):
        try:
            with open('scan_history.json', 'r') as f:
                history_data = json.load(f)
        except Exception as e:
            logger.error(f"Error loading scan history: {str(e)}")
            # Nếu không đọc được file, dùng biến toàn cục
            history_data = scan_history
    else:
        # Nếu không có file, dùng biến toàn cục
        history_data = scan_history
    
    # Đảm bảo mọi mục đều có các trường cần thiết
    for item in history_data:
        # Đảm bảo các trường cơ bản tồn tại
        if 'target_url' not in item:
            item['target_url'] = 'unknown'
        if 'timestamp' not in item:
            # Sử dụng thời gian hiện tại nếu không có timestamp
            item['timestamp'] = int(time.time())
        if 'scan_type' not in item:
            item['scan_type'] = 'Basic'
        if 'vulnerabilities' not in item:
            item['vulnerabilities'] = 0
    
    # Sắp xếp theo thời gian mới nhất trước
    history_data.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
    
    return jsonify(history_data)

# API liệt kê báo cáo
@app.route('/api/reports')
def list_reports():
    """List all available scan reports"""
    reports = []
    for filename in os.listdir('.'):
        if filename.startswith('report_') and filename.endswith('.json'):
            # Extract target URL from filename
            parts = filename.split('_')
            target_url = parts[1] if len(parts) > 1 else "unknown"
            
            # Get report creation time
            timestamp = os.path.getmtime(filename)
            created = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            reports.append({
                "filename": filename,
                "target_url": target_url,
                "created": created,
                "txt_available": filename.replace('.json', '.txt') in os.listdir('.')
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
            else:
                # Đây là file text
                return jsonify({"content": {"text_result": content, "type": "text"}})
        else:
            return jsonify({"error": "Report not found"}), 404
    except Exception as e:
        return jsonify({"error": f"Error reading report: {str(e)}"}), 500

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
                
            # Update scan history if needed
            global scan_history
            # Filter out entries with this report file
            scan_history = [scan for scan in scan_history if scan.get('report_file') != filename]
            
            # Save updated history
            try:
                with open('scan_history.json', 'w') as f:
                    json.dump(scan_history, f)
            except Exception as e:
                logger.error(f"Error saving scan history after deletion: {str(e)}")
            
            return jsonify({"success": True, "message": "Report deleted successfully"})
        else:
            return jsonify({"success": False, "error": "Report not found"}), 404
    except Exception as e:
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

# Load scan history from file if exists
def load_scan_history():
    global scan_history
    if os.path.exists('scan_history.json'):
        try:
            with open('scan_history.json', 'r') as f:
                scan_history = json.load(f)
        except Exception as e:
            logger.error(f"Error loading scan history: {str(e)}")

if __name__ == '__main__':
    # Ensure required directories exist
    os.makedirs('web/static', exist_ok=True)
    os.makedirs('web/templates', exist_ok=True)
    os.makedirs('web/static/css', exist_ok=True)
    os.makedirs('web/static/js', exist_ok=True)
    os.makedirs('web/static/img', exist_ok=True)
    
    # Load scan history
    load_scan_history()
    
    # Run the app
    app.run(debug=True, host='0.0.0.0', port=5000) 