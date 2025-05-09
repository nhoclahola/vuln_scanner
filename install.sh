#!/bin/bash

echo "=== Web Vulnerability Scanner - Cài đặt ==="

# Kiểm tra Python
if ! command -v python3 &> /dev/null; then
    echo "Không tìm thấy Python. Vui lòng cài đặt Python 3.9 trở lên."
    echo "https://www.python.org/downloads/"
    exit 1
fi

# Tạo môi trường ảo
echo "Đang tạo môi trường ảo..."
python3 -m venv venv
if [ $? -ne 0 ]; then
    echo "Lỗi khi tạo môi trường ảo."
    exit 1
fi

# Kích hoạt môi trường ảo
echo "Đang kích hoạt môi trường ảo..."
source venv/bin/activate
if [ $? -ne 0 ]; then
    echo "Lỗi khi kích hoạt môi trường ảo."
    exit 1
fi

# Cài đặt các gói phụ thuộc
echo "Đang cài đặt các gói phụ thuộc..."
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "Lỗi khi cài đặt các gói phụ thuộc."
    exit 1
fi

echo "==================================="
echo "Cài đặt thành công!"
echo "Để chạy ứng dụng, thực hiện các lệnh sau:"
echo "- Kích hoạt môi trường ảo: source venv/bin/activate"
echo "- Chạy ứng dụng: python main.py"
echo "==================================="

# Thêm quyền thực thi cho script
chmod +x install.sh 