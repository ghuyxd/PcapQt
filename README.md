# PcapQt

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/PyQt5-5.15+-green?style=for-the-badge&logo=qt" alt="PyQt5">
  <img src="https://img.shields.io/badge/Scapy-2.5+-orange?style=for-the-badge" alt="Scapy">
  <img src="https://img.shields.io/badge/Platform-Windows-lightgrey?style=for-the-badge&logo=windows" alt="Windows">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
</p>

**PcapQt** là một ứng dụng phân tích và bắt gói tin mạng (Network Packet Analyzer) hiện đại, xây dựng bằng **Python 3**, **PyQt5** và thư viện **Scapy**. Ứng dụng cung cấp giao diện trực quan tương tự Wireshark nhưng nhẹ hơn, tập trung vào các tính năng cốt lõi và khả năng tùy biến cao.

---

## ✨ Tính năng chính

### 📡 Bắt gói tin (Packet Capture)
- **Real-time Capture**: Bắt gói tin thời gian thực từ các interface mạng (WiFi, Ethernet, Loopback...).
- **High Performance**: Sử dụng cơ chế **packet batching** và xử lý đa luồng (multi-threading) để đảm bảo UI mượt mà ngay cả khi lưu lượng mạng cao.
- **Packet Limiting**: Tùy chọn giới hạn số lượng gói tin lưu trữ (10k, 20k, 50k hoặc tùy chỉnh) để quản lý bộ nhớ hiệu quả.

### 🔍 Phân tích giao thức (Protocol Analysis)
Hỗ trợ phân tích chi tiết các tầng trong mô hình OSI:
- **Layer 2 (Data Link)**: Ethernet II, ARP (Request/Reply), VLAN tags.
- **Layer 3 (Network)**: IPv4 (Header analysis, TTL, Checksum), ICMP.
- **Layer 4 (Transport)**: 
  - **TCP**: Phân tích Flags (SYN, ACK, FIN...), Window Size, Sequence/Ack numbers.
  - **UDP**: Port analysis, Length.
- **Layer 7 (Application)**: 
  - **HTTP**: Tự động nhận diện Method (GET, POST...), URI, Status Code, Host/Server headers.
  - **DNS**: Phân tích Query (Domain name) và Response (Answer RDATA).
  - **TLS/SSL**: Nhận diện phiên bản TLS (1.0 - 1.3), Client Hello (SNI), Server Hello.
  - **Others**: Nhận diện cơ bản cho SSH, FTP, SMTP, DHCP, SMB, MySQL, Redis...

### 🛠 Công cụ & Tiện ích
- **Advanced Filtering**: Lọc gói tin theo cú pháp text đơn giản (ví dụ: `tcp`, `ip.src==192.168.1.5`, `http`, `port==80`).
- **DNS Resolution**: Tự động phân giải tên miền (Hostname) từ địa chỉ IP nguồn/đích.
- **Follow Stream**: Tái tạo và xem nội dung luồng dữ liệu TCP/UDP (nhấn chuột phải vào gói tin).
- **IP Statistics**: Thống kê số lượng request theo từng địa chỉ IP.

---

## 📦 Yêu cầu hệ thống

- **Hệ điều hành**: Windows 10/11 (64-bit).
- **Python**: 3.11+.
- **Npcap**: Để bắt gói tin trên Windows (được cài đặt tự động bởi script).

---

## 🚀 Cài đặt

### Cách 1: Cài đặt tự động (Khuyên dùng)
Dự án cung cấp script tự động tải và cài đặt Python, Npcap và các thư viện cần thiết.

1. Clone repository về máy.
2. Chạy file `install.bat` với quyền **Administrator**.
   - Script sẽ tự động tải Python 3.11 và Npcap nếu chưa có.
   - Tạo môi trường ảo (.venv) và cài đặt thư viện.

### Cách 2: Cài đặt thủ công

1. Cài đặt **Python 3.11+** và **Npcap**.
2. Clone repository:
    ```bash
    git clone https://github.com/ghuyxd/PcapQt.git
    cd PcapQt
    ```
3. Tạo môi trường ảo và cài đặt dependencies:
    ```bash
    python -m venv .venv
    .venv\Scripts\activate
    pip install .
    ```

---

## 🔨 Build File EXE

Để đóng gói ứng dụng thành file `.exe` chạy độc lập:

1. Chạy file `build.bat` trong thư mục gốc.
2. File thực thi sẽ được tạo tại thư mục `dist/PcapQt/PcapQt.exe`.

---

## 🎮 Hướng dẫn sử dụng

### 1. Bắt đầu bắt gói tin
- Mở ứng dụng, một hộp thoại chọn interface sẽ hiện ra. Chọn network adapter bạn muốn theo dõi.
- Nhấn nút **Start** trên toolbar để bắt đầu.
- Gói tin sẽ xuất hiện trên bảng chính. Cột "Info" sẽ hiển thị thông tin tóm tắt thông minh (Protocol, Hostname, Info).

### 2. Lọc gói tin (Filter)
Nhập cú pháp lọc vào thanh Filter bar phía trên:
- **Protocol**: `tcp`, `udp`, `icmp`, `arp`, `dns`, `http`, `tls` ...
- **IP**: `ip.src==192.168.1.1` hoặc `ip.dst==1.1.1.1`
- **Port**: `port==80` hoặc `tcp.port==443`
- **Kết hợp**: Hiện tại hỗ trợ lọc đơn giản.

### 3. Xem chi tiết & Follow Stream
- **Chi tiết**: Nhấn vào một gói tin, bảng chi tiết bên dưới sẽ hiển thị cấu trúc hex/text của từng layer (Ethernet, IP, TCP, ...).
- **Follow Stream**: Chuột phải vào gói tin TCP/UDP -> Chọn **Follow TCP Stream**. Hộp thoại mới sẽ hiện ra nội dung payload của toàn bộ phiên kết nối.

### 4. Thống kê
- Nhấn nút **📊 IP Stats** trên toolbar để xem bảng thống kê các IP đang hoạt động tích cực nhất trong phiên bắt hiện tại.

---

## 📁 Cấu trúc dự án

```
PcapQt/
├── pcapqt/
│   ├── main.py                  # Điểm khởi chạy ứng dụng
│   ├── models/                  # Data Models (TableView, Filter)
│   ├── views/                   # UI Dialogs & Widgets
│   │   ├── main_window.py       # Cửa sổ chính & Xử lý UI logic
│   │   ├── interface_dialog.py  # Chọn interface
│   │   └── stream_dialog.py     # Cửa sổ Follow Stream
│   ├── threads/                 # Background Threads
│   │   └── sniffer_thread.py    # Luồng bắt gói tin (Scapy)
│   └── utils/                   # Tiện ích xử lý
│       ├── packet_parser.py     # Parser chính cho các Layers
│       ├── dns_resolver.py      # Xử lý DNS lookup
│       └── protocol_parsers/    # Parser chi tiết cho App Layer
├── install.bat                  # Script cài đặt tự động
├── build.bat                    # Script đóng gói EXE
└── pyproject.toml               # Cấu hình dự án & Dependencies
```

---

## 📝 License
MIT License.

---

## 🤝 Contact
GitHub: [@ghuyxd](https://github.com/ghuyxd)
