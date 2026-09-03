# 🛡️ CyberGuard SOAR - AI-Powered Security Incident Response Platform

**CyberGuard SOAR** là hệ thống Security Orchestration, Automation, and Response (SOAR) mini hoàn chỉnh, hiện đại, được thiết kế chuyên biệt cho việc nghiên cứu, đào tạo SOC Analyst và triển khai thực tế trong môi trường doanh nghiệp vừa/nhỏ hoặc mạng nội bộ.

Hệ thống kết hợp khả năng **Orchestration & Playbooks** với **AI Reasoning Engine (Tier-3 SOC Copilot)** và cơ chế **Human-in-the-Loop** an toàn, giúp tự động tiếp nhận cảnh báo, làm giàu dữ liệu (Threat Intelligence), đánh giá mức độ nghiêm trọng, ánh xạ kỹ thuật tấn công sang **MITRE ATT&CK Framework**, và đề xuất/thực thi các hành động ngăn chặn (Firewall, Wazuh Agent Quarantine, Cloudflare WAF).

---

## 🌟 Tính Năng Cốt Lõi (Key Features)

1. **Universal Alert Ingestion & Normalizer**:
   - Webhook REST API (`/api/v1/alerts/webhook`) tương thích tự động với **Wazuh**, **Suricata (EVE JSON)**, **Snort**, **Zeek**, EDR và custom JSON payload.
   - Tự động trích xuất các IOCs (`source_ip`, `file_hash`, `domain`, `agent_id`, `rule_id`).

2. **Threat Intelligence & Làm Giàu Dữ Liệu (Enrichment)**:
   - **IP-API & Whois (Tích hợp sẵn & Miễn phí)**: Geolocation (Quốc gia, Thành phố), ASN, ISP, kiểm tra dải IP Private/LAN.
   - **VirusTotal v3 API**: Quét và thống kê kết quả từ 70+ Antivirus engines cho File Hash (MD5/SHA256), Domain, và IP độc hại.
   - Hệ thống Local DB Cache tối ưu tốc độ và giảm thiểu request tới API bên ngoài.

3. **AI Reasoning & MITRE ATT&CK Engine**:
   - Hỗ trợ đa mô hình: **Google Gemini API**, **OpenAI (GPT-4o / GPT-4o-mini)**, **DeepSeek API**, và Custom OpenAI-compatible endpoints (Ollama / vLLM on-premise).
   - Tự động phân tích nguyên nhân gốc rễ (**Root Cause Analysis**) và tạo báo cáo diễn biến sự cố (**Attack Narrative**).
   - Đánh giá điểm tin cậy (**Confidence Score**) và phát hiện cảnh báo giả (**False Positive Score**).
   - Ánh xạ tự động sang ma trận **MITRE ATT&CK Enterprise Matrix** (*T1110 Brute Force, T1486 Ransomware, T1190 Web Exploit, T1059 Command Execution...*).

4. **Visual Node-based Playbook Builder**:
   - Trực quan hóa kịch bản xử lý sự cố dạng đồ thị Node Graph (kéo thả, kết nối các bước Trigger &rarr; Enrich &rarr; AI Triage &rarr; Approval &rarr; Action).
   - Đồng bộ hai chiều thời gian thực giữa **Visual Flow** và mã **YAML Code**.
   - Cung cấp sẵn các mẫu Playbooks chuẩn:
     - *SSH & RDP Brute Force Auto-Defense*
     - *Wazuh Ransomware & Malware Host Isolation*
     - *Cloudflare WAF Automated Web Attack Block*

5. **Human-in-the-Loop & Response Connectors**:
   - Hàng đợi phê duyệt an toàn (Pending Approvals Queue): SOC Analyst xem xét lý do AI đề xuất và bấm **1-Click Approve** hoặc **Reject**.
   - **Windows Defender Firewall Connector**: Chặn IP qua `netsh advfirewall` / PowerShell.
   - **Linux SSH Connector**: Kết nối SSH tới Gateway thực thi `ufw deny` hoặc `iptables -I INPUT -s <IP> -j DROP`.
   - **Cloudflare WAF Connector**: Thêm IP độc hại vào IP Access Rules list.
   - **Wazuh Manager API Connector**: Gửi lệnh Active Response cách ly endpoint bị xâm nhập.

6. **Interactive Attack Simulator**:
   - Bộ giả lập tích hợp sẵn 5 kịch bản tấn công kinh điển (Brute Force, Ransomware vssadmin, Cobalt Strike Beacon, SQL Injection, Nmap Port Scan) giúp kiểm thử và demo toàn bộ quy trình SOAR trong vài giây.

---

## 🏗️ Kiến Trúc Hệ Thống (Architecture)

```
d:\soar\
├── backend/                  # FastAPI Core Backend
│   ├── app/
│   │   ├── api/              # REST API Routers (Alerts, Incidents, Approvals, Playbooks, ThreatIntel, Settings, Stats)
│   │   ├── core/             # Database (SQLAlchemy Async + SQLite), Config
│   │   ├── models/           # DB Models (Alert, Incident, Playbook, PendingApproval, ActionLog, SystemSetting)
│   │   ├── schemas/          # Pydantic Schemas
│   │   ├── services/         # AI Service, Mitre Service, Enrichment Service, Playbook Engine, Response Service
│   │   ├── seed_data/        # Default Playbooks & Mock Data Seed
│   │   └── main.py           # FastAPI App Factory & Static SPA Hosting
│   ├── requirements.txt
│   ├── run.py                # Backend Launcher (uvicorn)
│   └── tests/                # Automated pytest suite
│
├── frontend/                 # Modern Cyber Dark SOC Dashboard (Vite + React + Tailwind)
│   ├── src/
│   │   ├── components/       # Navbar, Sidebar, SeverityBadge, MitreBadge, NodeBuilder
│   │   ├── pages/            # Dashboard, Incidents, Approvals, Playbooks, ThreatIntel, Simulator, Settings
│   │   ├── services/         # Axios API Client
│   │   ├── App.jsx
│   │   ├── index.css
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
```

---

## 🚀 Hướng Dẫn Cài Đặt & Khởi Chạy (Quickstart)

### Cách 1: Khởi chạy 1-Click bằng file `.bat` (Khuyên dùng trên Windows)
- Nhấp đúp chuột vào file [`start_soar.bat`](file:///d:/soar/start_soar.bat) ở thư mục gốc `d:\soar\`.
- Script sẽ tự động khởi động **Backend API (Port 8000)**, **Frontend (Port 5173)** và **tự động mở trình duyệt** đến Dashboard.
- Khi muốn tắt toàn bộ hệ thống, chỉ cần nhấp đúp vào [`stop_soar.bat`](file:///d:/soar/stop_soar.bat).

---

### Cách 2: Khởi chạy thủ công qua Terminal

#### Bước 1: Khởi động Backend (FastAPI)
```powershell
cd d:\soar\backend
python run.py
```
Backend sẽ khởi chạy tại: `http://localhost:8000` (API Docs tại `http://localhost:8000/docs`).

#### Bước 2: Khởi động Frontend (React + Vite)
```powershell
cd d:\soar\frontend
npm run dev
```
Truy cập Dashboard tại: `http://localhost:5173`.

---

## 📡 Hướng Dẫn Tích Hợp Webhook Ingestion

Gửi HTTP POST request với payload JSON tới:
```http
POST http://localhost:8000/api/v1/alerts/webhook
Content-Type: application/json
```

### Ví dụ 1: Payload từ Wazuh Manager Alert
```json
{
  "rule": {
    "id": 5710,
    "level": 10,
    "description": "sshd: Multiple failed login attempts (Brute Force)"
  },
  "data": {
    "srcip": "185.220.101.45",
    "dstip": "192.168.1.10"
  },
  "agent": {
    "id": "001",
    "name": "SRV-LINUX-PROD"
  }
}
```

### Ví dụ 2: Payload từ Suricata IDS (EVE JSON)
```json
{
  "event_type": "alert",
  "alert": {
    "signature": "ET WEB_SERVER Possible SQL Injection in URI",
    "signature_id": 2010999,
    "severity": 1,
    "category": "Web Application Attack"
  },
  "src_ip": "45.154.255.89",
  "dest_ip": "10.0.0.2"
}
```

### Ví dụ 3: Generic Security Alert Payload
```json
{
  "title": "Suspicious PowerShell DownloadString Execution",
  "severity": "high",
  "source": "Custom-EDR",
  "source_ip": "194.26.29.112",
  "hostname": "CEO-LAPTOP",
  "user": "corp\\admin",
  "description": "PowerShell executed with hidden window downloading payload from external IP."
}
```

---

## 🧪 Kiểm Thử Tự Động (Automated Testing)

Chạy bộ kiểm thử backend:
```powershell
cd d:\soar\backend
python -m pytest tests/test_backend.py -v
```

---

## ⚙️ Cấu Hình API Keys & Connectors
1. Truy cập trang **Settings & Connectors** trên Web UI.
2. Chọn **Google Gemini API** (hoặc OpenAI/DeepSeek) và dán API Key của bạn.
3. Điền **VirusTotal API Key** nếu cần tra cứu hash mã độc mở rộng.
4. Cấu hình thông tin kết nối **Wazuh API**, **Windows Firewall**, hoặc **Cloudflare API**.
5. Bấm **Save All Settings**.

---

*Hệ thống được phát triển với tiêu chuẩn SOC Tier-3 hiện đại, linh hoạt mở rộng và an toàn cho vận hành thực tế.*
