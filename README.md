# PcapQt

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/PyQt5-5.15+-green?style=for-the-badge&logo=qt" alt="PyQt5">
  <img src="https://img.shields.io/badge/Scapy-2.5+-orange?style=for-the-badge" alt="Scapy">
  <img src="https://img.shields.io/badge/Platform-Windows-lightgrey?style=for-the-badge&logo=windows" alt="Windows">
</p>

**PcapQt** là ứng dụng phân tích và bắt gói tin mạng được xây dựng bằng **PyQt5** và **Scapy**. Cung cấp giao diện nhẹ, dễ sử dụng tương tự Wireshark để hiển thị, kiểm tra và phân tích các gói tin được bắt.

---

## ✨ Tính năng chính

### 📡 Bắt gói tin (Packet Capture)
- Bắt gói tin thời gian thực từ các network interface
- Hỗ trợ chọn interface với tên thân thiện (friendly names)
- Packet batching để xử lý lưu lượng cao mà không bị lag

### 🔍 Phân tích gói tin (Packet Analysis)
- **Layer 2 (Data Link)**: Ethernet, ARP, VLAN
- **Layer 3 (Network)**: IPv4, IPv6, ICMP, ICMPv6, IGMP
- **Layer 4 (Transport)**: TCP, UDP
- **Layer 7 (Application)**: HTTP, HTTPS/TLS, DNS, DHCP, FTP, SSH, SMTP, POP3, IMAP, SNMP, NTP, Telnet

### 🎨 Giao diện người dùng
- Bảng packet với màu sắc theo protocol (tương tự Wireshark)
- Panel chi tiết packet theo từng layer OSI
- Hex dump viewer
- Follow TCP/UDP stream
- Packet filtering với syntax linh hoạt

### 📊 Thống kê & Phân tích
- Protocol hierarchy statistics
- Endpoint statistics
- Conversation tracking
- TCP stream analysis
- Expert info (warnings, errors, notes)

### 💾 File Operations
- Mở file PCAP/PCAPNG
- Lưu captured packets
- Export sang CSV/Text

---

## 📦 Yêu cầu hệ thống

### Bắt buộc
- **Windows 10/11** (64-bit)
- **Python 3.11+**
- **Npcap** - [Download tại đây](https://npcap.com/#download)

### Dependencies
```
pyqt5>=5.15
scapy>=2.5
```

---

## 🚀 Cài đặt

### Sử dụng Poetry (khuyến nghị)

```bash
# Clone repository
git clone https://github.com/ghuyxd/PcapQt.git
cd PcapQt

# Cài đặt dependencies
poetry install

# Chạy ứng dụng
poetry run python -m pcapqt
```

### Sử dụng pip

```bash
# Clone repository
git clone https://github.com/ghuyxd/PcapQt.git
cd PcapQt

# Tạo virtual environment
python -m venv .venv
.venv\Scripts\activate

# Cài đặt dependencies
pip install pyqt5 scapy

# Chạy ứng dụng
python -m pcapqt.main
```

---

## 🎮 Sử dụng

### Bắt gói tin
1. Khởi động ứng dụng
2. Chọn network interface từ dialog
3. Nhấn nút **Start** để bắt đầu capture
4. Nhấn **Stop** để dừng

### Filtering
Hỗ trợ các filter syntax:
```
tcp                    # Lọc TCP packets
udp                    # Lọc UDP packets
ip.src==192.168.1.1    # Lọc theo source IP
ip.dst==10.0.0.1       # Lọc theo destination IP
port==80               # Lọc theo port
tcp.port==443          # Lọc TCP port cụ thể
http                   # Lọc HTTP traffic
dns                    # Lọc DNS traffic
ssh                    # Lọc SSH traffic
tcp and port==80       # Kết hợp filters
```

### Follow Stream
- Right-click vào packet TCP/UDP
- Chọn "Follow TCP Stream" hoặc "Follow UDP Stream"

---

## 📁 Cấu trúc dự án

```
PcapQt/
├── pcapqt/
│   ├── main.py                    # Entry point
│   ├── ui_pcapqt.py               # Generated UI code
│   ├── models/                    # Data models
│   │   ├── packet_table_model.py
│   │   ├── packet_detail_model.py
│   │   └── packet_filter_model.py
│   ├── views/                     # UI components
│   │   ├── main_window.py
│   │   ├── interface_dialog.py
│   │   ├── stream_dialog.py
│   │   ├── statistics_dialog.py
│   │   └── ...
│   ├── threads/                   # Background threads
│   │   └── sniffer_thread.py
│   └── utils/                     # Utilities
│       ├── packet_parser.py
│       ├── stream_analyzer.py
│       ├── tcp_analyzer.py
│       ├── checksum_validator.py
│       └── protocol_parsers/      # Protocol-specific parsers
│           ├── application_parsers.py
│           ├── ipv6_parser.py
│           ├── icmpv6_parser.py
│           └── constants.py
├── resources/                     # Icons, images
├── pyproject.toml                 # Poetry config
└── README.md
```

---

## 🔧 Development

### Thiết kế UI với Qt Designer
```bash
# Cài đặt pyqt5-tools
pip install pyqt5-tools

# Mở Qt Designer
pyqt5-tools designer

# Compile .ui sang .py
pyuic5 -x pcapqt.ui -o pcapqt/ui_pcapqt.py
```

---

## 📝 License

MIT License

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📧 Contact

- GitHub: [@ghuyxd](https://github.com/ghuyxd)
