# Cấu trúc thư mục Vulnerability Scanner

```
vuln_scanner/
│
├── agents/
│   ├── __init__.py
│   ├── crawler_agent.py            # Agent cho việc dò tìm endpoint
│   ├── information_gatherer.py     # Agent thu thập thông tin
│   └── security_analyst.py         # Agent phân tích bảo mật
│
├── core/
│   ├── __init__.py
│   ├── config.py                   # Cấu hình hệ thống
│   ├── logger.py                   # Hệ thống ghi nhật ký
│   └── exceptions.py               # Các lớp ngoại lệ tùy chỉnh
│
├── db/
│   ├── __init__.py
│   ├── models.py                   # Mô hình dữ liệu
│   └── storage.py                  # Lưu trữ kết quả quét
│
├── scanners/
│   ├── __init__.py
│   ├── endpoint_scanner.py         # Quét và phát hiện endpoint
│   ├── vuln_scanner.py             # Quét lỗ hổng
│   ├── payloads/                   # Thư mục chứa các payload
│   │   ├── __init__.py
│   │   ├── xss_payloads.py
│   │   ├── sqli_payloads.py
│   │   └── other_payloads.py
│   └── signatures/                 # Chữ ký lỗ hổng
│       ├── __init__.py
│       └── vuln_signatures.py
│
├── tasks/
│   ├── __init__.py
│   ├── reconnaissance_tasks.py
│   ├── crawling_tasks.py
│   ├── scanning_tasks.py
│   └── assessment_tasks.py
│
├── tools/
│   ├── __init__.py
│   ├── web_tools.py                # Công cụ web cơ bản
│   ├── crawler_tools.py            # Công cụ dò tìm endpoint
│   ├── vuln_tools.py               # Công cụ kiểm tra lỗ hổng
│   └── report_tools.py             # Công cụ tạo báo cáo
│
├── utils/
│   ├── __init__.py
│   ├── http_utils.py               # Tiện ích HTTP
│   ├── parser_utils.py             # Tiện ích phân tích HTML/JS
│   └── encoding_utils.py           # Tiện ích mã hóa
│
├── reports/
│   ├── __init__.py
│   ├── report_generator.py         # Tạo báo cáo
│   └── templates/                  # Mẫu báo cáo
│       ├── html_report.py
│       └── json_report.py
│
├── ui/                            # Giao diện người dùng (tùy chọn)
│   ├── __init__.py
│   ├── cli.py                      # Giao diện dòng lệnh
│   └── web_ui.py                   # Giao diện web
│
├── .env                           # Biến môi trường
├── .gitignore                     # Tệp gitignore
├── setup.py                       # Cài đặt gói
├── requirements.txt               # Phụ thuộc
├── main.py                        # Điểm khởi đầu chính
├── README.md                      # Tài liệu
├── install.bat                    # Script cài đặt cho Windows
└── install.sh                     # Script cài đặt cho Linux/Mac
```

## Luồng hoạt động

1. **Input URL**: Người dùng cung cấp URL mục tiêu
2. **Crawling**: Dò tìm tất cả các endpoint trên trang web
3. **Information Gathering**: Thu thập thông tin về máy chủ, công nghệ sử dụng
4. **Vulnerability Scanning**: Kiểm tra các lỗ hổng trên mỗi endpoint
5. **Analysis**: Phân tích kết quả và xác định mức độ rủi ro
6. **Reporting**: Tạo báo cáo chi tiết về các lỗ hổng tìm thấy

## Các loại lỗ hổng được hỗ trợ

1. Cross-Site Scripting (XSS)
2. SQL Injection
3. Command Injection
4. CSRF (Cross-Site Request Forgery)
5. Open Redirect
6. SSRF (Server-Side Request Forgery)
7. File Inclusion / Path Traversal
8. Insecure Deserialization
9. Security Misconfiguration
10. Components with Known Vulnerabilities 