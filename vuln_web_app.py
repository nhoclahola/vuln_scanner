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
            
            # Save report to file
            if result:
                logger.info("Saving report to file")
                report_info = save_report_to_file(result, self.target_url, "vulnerability_report.json")
                self.report_file = report_info
                
                # Add to scan history
                scan_record = {
                    "id": self.scan_id,
                    "url": self.target_url,
                    "type": self.scan_type,
                    "time": self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "duration": str(self.end_time - self.start_time).split('.')[0] if self.end_time else "N/A",
                    "report_file": report_info
                }
                scan_history.append(scan_record)
                
                # Save scan history to file
                with open('scan_history.json', 'w') as f:
                    json.dump(scan_history, f, default=str)
            
        except Exception as e:
            logger.error(f"Error in scan: {str(e)}")
            self.status = "error"
            self.result = {"error": str(e)}
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
                formatted_result = scan.result
                
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
    # Nếu file lịch sử tồn tại, đọc từ đó
    if os.path.exists('scan_history.json'):
        try:
            with open('scan_history.json', 'r') as f:
                history = json.load(f)
            return jsonify({"history": history})
        except Exception as e:
            logger.error(f"Error loading scan history: {str(e)}")
    
    # Nếu không, trả về danh sách từ biến toàn cục
    return jsonify({"history": scan_history})

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
                except:
                    return jsonify({"content": content})
            else:
                return jsonify({"content": content})
        else:
            return jsonify({"error": "Report not found"}), 404
    except Exception as e:
        return jsonify({"error": f"Error reading report: {str(e)}"}), 500

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