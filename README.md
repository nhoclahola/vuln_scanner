# Vulnerability Scanner (Công cụ quét lỗ hổng bảo mật Web)

Ứng dụng quét lỗ hổng bảo mật web sử dụng CrewAI với hệ thống Multi-Agent - một công cụ quét an ninh web thông minh, hiện đại và linh hoạt cho phép phát hiện và phân tích các lỗ hổng bảo mật trên các trang web.

## Tính năng chính

- **Hệ thống Multi-Agent**: Sử dụng 4 agent chuyên biệt làm việc cùng nhau để phát hiện lỗ hổng
- **Thu thập thông tin**: Dò tìm endpoint, form và tài nguyên của trang web
- **Quét lỗ hổng**: Phát hiện các lỗ hổng phổ biến như XSS, SQL Injection, CSRF, Path Traversal, Open Redirect
- **Phân tích bảo mật**: Thu thập thông tin về cấu hình bảo mật của máy chủ web
- **Đánh giá và báo cáo**: Phân tích mức độ nghiêm trọng, tham chiếu đến CVE, và đề xuất biện pháp khắc phục

### Các lỗ hổng được hỗ trợ

- Cross-Site Scripting (XSS)
- SQL Injection
- Cross-Site Request Forgery (CSRF)
- Path Traversal
- Open Redirect
- Thiếu Security Headers
- Cấu hình SSL/TLS không an toàn

## Tính năng nâng cao (Phiên bản mới)

- **Dynamic Payload Discovery**: Agent có thể tự động tìm kiếm payload từ các nguồn web như PortSwigger, HackTricks, PayloadsAllTheThings
- **CVE References**: Tích hợp với cơ sở dữ liệu CVE (Common Vulnerabilities and Exposures) để cung cấp thông tin về lỗ hổng đã biết
- **CVSS Scoring**: Đánh giá mức độ nghiêm trọng theo tiêu chuẩn CVSS (Common Vulnerability Scoring System)
- **OWASP Risk Rating**: Tính toán điểm rủi ro theo phương pháp OWASP Risk Rating Methodology
- **Enhanced Memory System**: Cải thiện hệ thống memory trong Multi-Agent để tăng cường context giữa các agent
- **Remediation Guidance**: Hướng dẫn khắc phục chi tiết cho mỗi lỗ hổng được phát hiện

## Kiến trúc hệ thống

### Agents

1. **Web Crawler Agent**: Dò tìm và lập bản đồ trang web, phát hiện các endpoint và form
2. **Information Gatherer Agent**: Thu thập thông tin về máy chủ web, header, cấu hình SSL/TLS
3. **Endpoint Scanner Agent**: Quét các endpoint đã phát hiện để tìm lỗ hổng bảo mật
4. **Security Analyst Agent**: Phân tích kết quả, đánh giá mức độ rủi ro và đưa ra khuyến nghị

### Luồng công việc

```
                ┌─────────────────┐
                │   Web Crawler   │
                │      Agent      │
                └────────┬────────┘
                         │
                         ▼
        ┌─────────────────────────────┐
        │    Information Gatherer     │
        │           Agent             │
        └──────────────┬──────────────┘
                       │
                       ▼
        ┌─────────────────────────────┐
        │     Endpoint Scanner        │
        │           Agent             │
        └──────────────┬──────────────┘
                       │
                       ▼
        ┌─────────────────────────────┐
        │     Security Analyst         │
        │           Agent             │
        └─────────────────────────────┘
```

### Công cụ mới

1. **Payload Searcher**: Tự động tìm kiếm payload từ các nguồn web
2. **CVE Searcher**: Tìm kiếm thông tin về CVE để tham chiếu với lỗ hổng phát hiện được
3. **Vulnerability Severity Analyzer**: Phân tích và đánh giá mức độ nghiêm trọng của lỗ hổng
4. **OWASP Risk Scorer**: Tính toán điểm rủi ro theo phương pháp OWASP

## Yêu cầu

- Python 3.9+
- CrewAI
- LangChain
- OpenAI API key hoặc DeepSeek API key
- Requests, BeautifulSoup4, và các thư viện phụ thuộc khác

## Cài đặt

```bash
git clone https://github.com/yourusername/vuln_scanner.git
cd vuln_scanner
pip install -r requirements.txt
```

## Cấu hình

Tạo file `.env` trong thư mục gốc với nội dung sau:

```
OPENAI_API_KEY=your_openai_api_key_here
DEEPSEEK_API_KEY=your_deepseek_api_key_here
DEEPSEEK_API_BASE=your_deepseek_api_base_here
```

## Sử dụng

```bash
# Quét cơ bản với OpenAI
python main.py -u https://example.com -o

# Quét cơ bản với DeepSeek (mặc định)
python main.py -u https://example.com

# Quét đầy đủ
python main.py -u https://example.com -f
```

## Hướng dẫn nâng cao

### Quản lý context trong Multi-Agent

Hệ thống Multi-Agent mới sử dụng cơ chế memory để đảm bảo thông tin không bị mất giữa các agent:

- **Crawler Agent Memory**: Lưu trữ thông tin về các URL và endpoint đã phát hiện
- **Scanner Agent Memory**: Lưu trữ thông tin về các lỗ hổng tiềm năng đã phát hiện
- **Security Analyst Memory**: Lưu trữ kết quả phân tích và tham chiếu đến các CVE

### Tùy chỉnh payload

Để thêm các payload tùy chỉnh, bạn có thể sửa file `tools/vuln_tools.py` và thêm vào các danh sách payload.

### Phân tích an ninh nâng cao

Sử dụng Security Analyst Agent và các công cụ security mới để phân tích sâu về các lỗ hổng. Các tính năng phân tích an ninh nâng cao bao gồm:

- Tìm kiếm CVE liên quan đến lỗ hổng
- Đánh giá mức độ rủi ro theo phương pháp OWASP
- Phân tích chi tiết dựa trên CVSS
- Khuyến nghị khắc phục cụ thể cho từng lỗ hổng

## Đóng góp

Chúng tôi hoan nghênh mọi đóng góp! Hãy tạo Pull Request hoặc mở Issue nếu bạn có ý tưởng cải thiện.

## Giấy phép

MIT License

## Tuyên bố miễn trừ trách nhiệm

Công cụ này chỉ nên được sử dụng để đánh giá bảo mật cho các hệ thống mà bạn được phép kiểm tra. Việc quét không được phép có thể vi phạm pháp luật. 