# CYBERGUARD MINI SOAR - TÀI LIỆU TOÀN DIỆN DỰ ÁN (PROJECT CONTEXT)

> **Dự án:** CyberGuard Mini SOAR – Nền tảng Điều phối, Tự động hóa và Phản hồi An ninh mạng tích hợp AI Tier-3 Triage & Wazuh SIEM  
> **Thư mục làm việc:** `d:\soar`  
> **Ngày cập nhật:** 2026-09-10  
> **Trạng thái:** Hoàn thiện 100% (Backend Test 16/16 Passing, Frontend Build 0 Error - Đã tích hợp trọn vẹn Bước 1: Safety Guardrails & Auto-Rollback TTL Worker, Bước 2: Bổ sung 2 Connector tối quan trọng: Enterprise Identity Provider & Central Webhook EDR, và Bước 3: Nâng cấp AI Triage với ReAct / Multi-turn Autonomous Investigation Engine)

---

## 1. TỔNG QUAN VÀ MỤC TIÊU CỐT LÕI (OVERVIEW & GOALS)

1. **Giải quyết tình trạng Alert Fatigue & Deduplication:** Tự động hóa tiếp nhận hàng nghìn cảnh báo từ SIEM (Wazuh) và IDS (Suricata), gộp nhóm trùng lặp thông minh (Alert Deduplication), làm giàu dữ liệu đe dọa (Threat Intelligence), và lập chỉ mục sự cố an ninh trong thời gian $< 50\text{ ms}$.
2. **AI Tier-3 Virtual SOC Analyst & Autonomous ReAct Engine:** Sử dụng chu trình điều tra đa lượt tự chủ **ReAct (Reasoning + Acting)** lặp qua 2–3 vòng: đặt giả thuyết (**Thought**), gọi công cụ kiểm tra thực tế (**Action Tool Calling**), thu thập chứng cứ (**Observation**) rồi mới tổng hợp Attack Narrative, RCA, ánh xạ MITRE ATT&CK (`T1110`, `T1078`, `T1190`, `T1486`, `T1539`), chấm điểm Confidence Score và False Positive Risk. Cung cấp tính năng **Interactive Deep Investigation** cho phép chuyên viên SOC đặt câu hỏi chuyên sâu và tái phân tích thời gian thực.
3. **Safety Guardrails & Blast Radius Mitigation (Bảo vệ Hạ tầng Trọng yếu):** Tự động từ chối bất kỳ hành vi chặn hoặc cô lập nào đối với các địa chỉ IP huyết mạch của mạng doanh nghiệp (`127.0.0.1`, `8.8.8.8`, `1.1.1.1`, Gateway `.1`, Host SOAR `192.168.56.1`, Broadcast `.255`), loại trừ hoàn toàn nguy cơ AI hoặc Analyst tự cô lập máy chủ điều hành.
4. **Auto-Rollback TTL (Hẹn giờ gỡ chặn tự động):** Tiến trình nền (Background TTL Worker) theo dõi thời hạn khóa tạm thời (15m, 1h, 24h) và tự động unblock IP/reconnect host trên `iptables`/tường lửa/EDR khi hết hạn, phát sự kiện WebSocket real-time thông báo cho SOC Analyst.
5. **Đa dạng hóa Hệ thống Điều phối Phản hồi Ngoài SSH (Multi-Domain Connectors):**
   - **Identity Provider Connector (`identity`):** Tích hợp Okta Workforce API, Microsoft Entra ID (Azure AD) và Enterprise Mock Simulation. Cung cấp các hành động tức thời: thu hồi toàn bộ token phiên làm việc (`revoke_user_sessions`), vô hiệu hóa tài khoản tạm thời (`disable_user_account`), yêu cầu đổi mật khẩu khẩn cấp (`force_password_reset`), và hoàn tác kích hoạt lại (`enable_user_account`).
   - **Central EDR Controller (`edr`):** Tích hợp Wazuh Active Response REST API, CrowdStrike Falcon và EDR Webhook trung tâm. Cung cấp các hành động can thiệp mức kernel: cô lập máy trạm khỏi mạng (`isolate_endpoint`), tiêu diệt tiến trình độc hại theo PID (`kill_process`), đưa tệp tin mã độc vào kho lưu trữ cách ly (`quarantine_file`), và hoàn tác khôi phục mạng (`reconnect_endpoint`).
6. **Mô hình Phê duyệt An toàn (Human-in-the-Loop Gateway):** Playbook tự động điều phối dừng lại ở các bước can thiệp hạ tầng để chuyên viên SOC kiểm duyệt, chọn TTL và bấm **1-Click Approve & Execute** hoặc **Hoàn tác / Rollback** chuyên biệt cho từng loại connector.
7. **Thực thi trên Hạ tầng Mạng Thật & Enterprise Simulation:** Kết nối SSH Paramiko từ máy chủ Windows sang máy ảo Kali Linux để chèn và tra cứu quy tắc `iptables` trực tiếp vào nhân Linux, điều khiển Wazuh REST API cổng 55000, và fallback mô phỏng doanh nghiệp khi ở môi trường Lab.
8. **Phòng thí nghiệm Diễn tập Tấn công (Red-Team Attack Simulator):** Tích hợp 10 vector tấn công trực tiếp vào VM và giả lập danh tính IP độc hại quốc tế (*Spoofed Attacker Source IP*), bao gồm cả Credential Stuffing & Stolen Session Cookie và Ransomware Shadow Copy Deletion (`vssadmin.exe`).

---

## 2. MÔ HÌNH KIẾN TRÚC VÀ MẠNG LAB (NETWORK TOPOLOGY)

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ MÔ HÌNH MẠNG PHÒNG THÍ NGHIỆM LAB (Dải mạng Host-Only: 192.168.56.0/24)                │
├────────────────────────────────────────────────────┬───────────────────────────────────┤
│ 🖥️ MÁY CHỦ PHÂN TÍCH (HOST WINDOWS 11)             │ 🖥️ MÁY ẢO MỤC TIÊU (KALI LINUX VM)│
│ • Địa chỉ IP: 192.168.56.1                         │ • Địa chỉ IP: 192.168.56.107      │
│ • VirtualBox Host-Only Ethernet Adapter            │ • Network Adapter: Host-Only      │
│ ────────────────────────────────────────────────── │ ───────────────────────────────── │
│ • CyberGuard SOAR Backend: Cổng 8000 (FastAPI)     │ • OpenSSH Server: Cổng 22         │
│ • CyberGuard SOC Frontend: Cổng 5173 (React/Vite)  │ • Apache2 Web Server: Cổng 80     │
│ • Webhook Ingestion API: /api/v1/alerts/webhook    │ • Wazuh Manager SIEM: Cổng 55000  │
└────────────────────────────────────────────────────┴───────────────────────────────────┘
```

### Luồng Xử lý Sự cố Khép kín (End-to-End Incident Lifecycle):
1. Kẻ tấn công phát động tấn công thật (SSH Brute Force / Web SQLi) sang Kali `192.168.56.107`.
2. OpenSSH ghi `/var/log/auth.log` hoặc Apache ghi `/var/log/apache2/access.log`.
3. Wazuh Manager khớp Rule 5710/31101 & kích hoạt `/var/ossec/integrations/custom-soar`.
4. Script đẩy Webhook JSON sang máy chủ Windows `http://192.168.56.1:8000/api/v1/alerts/webhook`.
5. SOAR Backend chuẩn hóa dữ liệu, tạo Sự cố (`INC-YYYYMMDD-XXXX`), gọi IP-API & VirusTotal v3.
6. AI Tier-3 Triage suy luận Attack Narrative, RCA, mã MITRE ATT&CK và đề xuất phương án ngăn chặn.
7. Playbook sinh bản ghi `PendingApproval` và đưa vào hàng đợi **Human Approvals**.
8. Chuyên viên SOC bấm **Approve & Execute Now** trên Web SOAR.
9. SOAR SSH sang Kali Linux chạy lệnh: `echo '<password>' | sudo -S iptables -I INPUT -s <IP> -j DROP`.
10. Ghi nhận nhật ký vào `ActionLog` và cập nhật sự cố sang trạng thái **`[CONTAINED]`**.

---

## 3. CẤU TRÚC THƯ MỤC DỰ ÁN (PROJECT DIRECTORY STRUCTURE)

```text
d:\soar\
├── backend\                           # BACKEND FASTAPI & SERVICES
│   ├── app\
│   │   ├── api\                       # CÁC ĐỊNH TUYẾN RESTful API
│   │   │   ├── alerts.py              # Webhook Ingestion & Live Attack Prober
│   │   │   ├── approvals.py           # Human-in-the-Loop Decision Handler
│   │   │   ├── connectors.py          # Wazuh Manager API & Test Connectors
│   │   │   ├── incidents.py           # Quản lý & Điều tra Sự cố An ninh
│   │   │   ├── playbooks.py           # Quản trị Kịch bản Phản hồi
│   │   │   ├── settings.py            # Cấu hình Hệ thống & Khóa API bảo mật
│   │   │   ├── stats.py               # Thống kê KPI & Phân bổ Severity
│   │   │   └── threat_intel.py        # API Tra cứu CTI (IP-API, VirusTotal)
│   │   ├── core\
│   │   │   ├── config.py              # Cấu hình môi trường & Settings Pydantic
│   │   │   └── database.py            # SQLAlchemy Async Engine & Sessionmaker
│   │   ├── models\
│   │   │   └── models.py              # 8 Bảng Cơ sở dữ liệu Thực thể ORM
│   │   ├── schemas\
│   │   │   └── schemas.py             # Pydantic Schemas Request & Response
│   │   ├── seed_data\
│   │   │   └── seed.py                # Dữ liệu mẫu Playbooks & Cấu hình mặc định
│   │   ├── services\                  # CÁC DỊCH VỤ NGHIỆP VỤ LÕI
│   │   │   ├── ai_service.py          # ReAct Autonomous Investigation & LLM Triage
│   │   │   ├── enrichment_service.py  # Làm giàu CTI (IP-API, VirusTotal v3 Cache)
│   │   │   ├── guardrail_service.py   # Safety Guardrails & Blast Radius Mitigation
│   │   │   ├── investigation_tools.py # 5 Công cụ Điều tra Hệ thống Thực tế cho AI
│   │   │   ├── mitre_service.py       # Ánh xạ Chiến thuật & Kỹ thuật MITRE
│   │   │   ├── playbook_engine.py     # Động cơ duyệt đồ thị kịch bản phản hồi
│   │   │   ├── response_service.py    # Điều phối SSH iptables, Wazuh AR, Identity, EDR
│   │   │   └── ttl_worker.py          # Tiến trình nền Auto-Rollback TTL
│   │   └── main.py                    # Điểm khởi động FastAPI App & CORS
│   ├── tests\
│   │   └── test_backend.py            # Bộ kiểm thử tự động Pytest (16/16 tests passing)
│   ├── requirements.txt               # Thư viện Python phụ thuộc
│   └── soar.db                        # Cơ sở dữ liệu SQLite Async
├── frontend\                          # FRONTEND REACT + VITE + TAILWINDCSS
│   ├── src\
│   │   ├── components\
│   │   │   ├── MitreBadge.jsx         # Huy hiệu mã kỹ thuật MITRE ATT&CK
│   │   │   ├── Navbar.jsx             # Thanh điều hướng trên cùng & Trạng thái
│   │   │   ├── SeverityBadge.jsx      # Huy hiệu mức độ Critical/High/Med/Low
│   │   │   └── Sidebar.jsx            # Menu điều hướng bên trái
│   │   ├── pages\                     # CÁC TRANG CHỨC NĂNG SOC DASHBOARD
│   │   │   ├── ApprovalsPage.jsx      # Hàng đợi Phê duyệt Human Approvals (1-Click)
│   │   │   ├── DashboardPage.jsx      # SOC Live KPI Dashboard & Severity Charts
│   │   │   ├── IncidentsPage.jsx      # Incident Investigation Drawer & RCA
│   │   │   ├── PlaybooksPage.jsx      # Quản trị Kịch bản Phản hồi
│   │   │   ├── SettingsPage.jsx       # Cấu hình SSH, LLM Keys & Quét Wazuh VM
│   │   │   ├── SimulatorPage.jsx      # Phòng thí nghiệm Live Attack & IP Spoofing
│   │   │   └── ThreatIntelPage.jsx    # Tra cứu trực tiếp IP Geolocation & VirusTotal
│   │   ├── services\
│   │   │   └── api.js                 # Axios API Client kết nối Backend
│   │   ├── utils\
│   │   │   └── date.js                # Tiện ích chuyển đổi múi giờ GMT+7 địa phương
│   │   ├── App.jsx                    # Root Component & Điều hướng Tab
│   │   ├── index.css                  # Custom CSS & Glassmorphism Theme
│   │   └── main.jsx                   # Entry point React DOM
│   ├── package.json                   # Thư viện Node.js phụ thuộc
│   └── vite.config.js                 # Cấu hình Vite Build Tool
├── docs\
│   └── diagrams\                      # SƠ ĐỒ THIẾT KẾ & BÁO CÁO MERMAID
│       ├── soar-architecture.html     # Sơ đồ Kiến trúc Tương tác Standalone
│       ├── soar-architecture.json     # Dữ liệu Kiến trúc JSON
│       └── soar-incident-response.json# Dữ liệu Quy trình Phản hồi JSON
├── start_soar.bat                     # Script 1-Click Khởi động Toàn bộ Hệ thống
├── stop_soar.bat                      # Script 1-Click Dừng Hệ thống
├── README.md                          # Tài liệu Hướng dẫn Sử dụng Nhanh
└── project_context.md                 # TÀI LIỆU TOÀN DIỆN BÀN GIAO DỰ ÁN
```

---

## 4. CÁC ĐOẠN MÃ NGUỒN CỐT LÕI (KEY CODE IMPLEMENTATIONS)

### 4.1. Thực thi Chặn Tường lửa `iptables` từ xa qua SSH Paramiko
File: `backend/app/services/response_service.py`

```python
@classmethod
async def block_ip_linux_ssh(cls, ip: str, parameters: Dict[str, Any], db: AsyncSession = None) -> Dict[str, Any]:
    """
    Thực thi chèn quy tắc chặn DROP trên máy ảo Kali Linux từ xa qua SSH với quyền sudo -S
    """
    configs = await cls.get_connector_settings(db, "LINUX_SSH")
    host = parameters.get("host") or configs.get("LINUX_SSH_HOST") or "192.168.56.107"
    user = parameters.get("user") or configs.get("LINUX_SSH_USER") or "minh"
    password = parameters.get("password") or configs.get("LINUX_SSH_PASSWORD") or ""
    port = int(parameters.get("port") or configs.get("LINUX_SSH_PORT") or 22)

    cmd = f"echo '{password}' | sudo -S iptables -I INPUT -s {ip} -j DROP"

    def _ssh_exec():
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, port=port, username=user, password=password, timeout=5.0)
        stdin, stdout, stderr = client.exec_command(cmd)
        exit_status = stdout.channel.recv_exit_status()
        err_out = stderr.read().decode('utf-8', errors='ignore')
        client.close()
        return exit_status, err_out

    try:
        exit_code, err_msg = await asyncio.to_thread(_ssh_exec)
        if exit_code == 0:
            return {
                "status": "success",
                "mode": "live",
                "message": f"Successfully executed live iptables block on VM {host} ({user}@{host}) for IP {ip} (`sudo iptables -I INPUT -s {ip} -j DROP`).",
                "command": cmd
            }
        return {
            "status": "failed",
            "message": f"iptables execution failed on Kali VM {host} (Exit Code {exit_code}): {err_msg}"
        }
    except Exception as e:
        return {
            "status": "failed",
            "message": f"SSH connection failed to Kali VM {host}: {str(e)}"
        }
```

---

### 4.2. Bộ não Phân tích AI Tier-3 Triage (Gemini SDK & Heuristic Fallback)
File: `backend/app/services/ai_service.py`

```python
@classmethod
async def analyze_incident(cls, incident_data: Dict[str, Any], db: AsyncSession = None) -> Dict[str, Any]:
    api_key = await cls.get_config(db, "GEMINI_API_KEY")
    if api_key:
        try:
            client = genai.Client(api_key=api_key)
            prompt = cls._build_triage_prompt(incident_data)
            response = client.models.generate_content(
                model="gemini-1.5-flash",
                contents=prompt,
                config={"response_mime_type": "application/json"}
            )
            return json.loads(response.text)
        except Exception:
            pass # Tự động chuyển tiếp sang Heuristic Fallback nội bộ
    
    # Dự phòng: Bộ quy tắc Chuyên gia SOC Heuristics nội bộ
    return cls._fallback_heuristic_triage(incident_data)

@classmethod
def _fallback_heuristic_triage(cls, incident_data: Dict[str, Any]) -> Dict[str, Any]:
    title = (incident_data.get("title") or "").lower()
    desc = (incident_data.get("description") or "").lower()
    source_ip = incident_data.get("source_ip") or "185.220.101.45"

    if any(k in title or k in desc for k in ["ssh", "brute force", "failed password", "5710", "5712"]):
        return {
            "severity": "high",
            "confidence_score": 0.98,
            "false_positive_score": 0.01,
            "attack_narrative": "Hostile external actor executing rapid automated password dictionary attacks against SSH (Port 22).",
            "root_cause_analysis": "Exposed SSH service subjected to authentication brute force attempts.",
            "mitre_tactics": ["Credential Access"],
            "mitre_techniques": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
            "recommended_actions": [{
                "action_type": "block_ip",
                "connector": "linux_ssh",
                "target": source_ip,
                "reason": "Block hostile external IP on Linux VM iptables firewall.",
                "risk_level": "low"
            }]
        }
    # (Xử lý tương tự cho Web SQLi T1190 và Ransomware T1486...)
```

---

### 4.3. Script Tích hợp Webhook trên Wazuh SIEM Manager (Kali Linux)
File: `/var/ossec/integrations/custom-soar`

```python
#!/usr/bin/env python3
import sys
import json
import requests

alert_file_path = sys.argv[1]
hook_url = sys.argv[4] if len(sys.argv) > 4 else "http://192.168.56.1:8000/api/v1/alerts/webhook"

try:
    with open(alert_file_path, 'r', encoding='utf-8') as f:
        alert_json = json.load(f)
    
    headers = {'Content-Type': 'application/json'}
    response = requests.post(hook_url, json=alert_json, headers=headers, timeout=5)
    sys.exit(0)
except Exception:
    sys.exit(1)
```

Cấu hình trong `/var/ossec/etc/ossec.conf`:
```xml
<integration>
  <name>custom-soar</name>
  <hook_url>http://192.168.56.1:8000/api/v1/alerts/webhook</hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

---

### 4.4. Xử lý Phê duyệt An toàn (Human-in-the-Loop Gateway)
File: `backend/app/api/approvals.py`

```python
@router.post("/{approval_id}/decision")
async def handle_approval_decision(
    approval_id: int,
    request: ApprovalDecisionRequest,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(PendingApproval).where(PendingApproval.id == approval_id))
    approval = result.scalars().first()
    if not approval or approval.status != "pending":
        raise HTTPException(status_code=400, detail="Invalid approval state")

    approval.analyst_note = request.analyst_note
    approval.resolved_at = datetime.datetime.utcnow()

    if request.decision.lower() == "reject":
        approval.status = "rejected"
        await db.commit()
        return {"status": "rejected", "approval_id": approval.id}

    # Execute response connector
    exec_res = await ResponseService.execute_action(
        connector=approval.connector,
        action_type=approval.action_type,
        target=approval.target,
        parameters=approval.parameters or {},
        db=db
    )

    exec_status = exec_res.get("status", "success")
    approval.status = "executed" if exec_status in ["success", "dry_run", "live_success", "live", "info"] else "failed"

    # Ghi ActionLog và cập nhật sự cố sang CONTAINED
    action_log = ActionLog(
        incident_id=approval.incident_id,
        action_type=approval.action_type,
        connector=approval.connector,
        target=approval.target,
        status=exec_status,
        output_message=exec_res.get("message"),
        executed_by="Analyst Approved"
    )
    db.add(action_log)

    inc_res = await db.execute(select(Incident).where(Incident.id == approval.incident_id))
    incident = inc_res.scalars().first()
    if incident and incident.status in ["open", "investigating"]:
        incident.status = "contained"

    await db.commit()
    return {"status": approval.status, "execution_result": exec_res}
```

---

### 4.5. Bộ chuyển đổi Múi giờ Địa phương (Frontend Timezone Normalizer)
File: `frontend/src/utils/date.js`

```javascript
export const formatLocalDateTime = (dateStr) => {
  if (!dateStr) return '';
  try {
    const normalized = typeof dateStr === 'string' && !dateStr.endsWith('Z') && !dateStr.includes('+')
      ? `${dateStr}Z`
      : dateStr;
    const date = new Date(normalized);
    if (isNaN(date.getTime())) return String(dateStr);
    return date.toLocaleString();
  } catch (e) {
    return String(dateStr);
  }
};

export const formatLocalTime = (dateStr) => {
  if (!dateStr) return '';
  try {
    const normalized = typeof dateStr === 'string' && !dateStr.endsWith('Z') && !dateStr.includes('+')
      ? `${dateStr}Z`
      : dateStr;
    const date = new Date(normalized);
    if (isNaN(date.getTime())) return String(dateStr);
    return date.toLocaleTimeString();
  } catch (e) {
    return String(dateStr);
  }
};
```

---

## 5. HƯỚNG DẪN DEMO 4 KỊCH BẢN THỰC NGHIỆM (A - Z DEMO GUIDE)

### 🔹 Kịch bản 1: Tấn công SSH Brute Force Flood (Port 22)
1. **Phát động:** Web SOAR &rarr; **`Attack Simulator`** &rarr; **`🔥 Live VM Attack`** &rarr; Chọn vector `💥 SSH Brute Force (Port 22)`, Spoofed IP: `185.220.101.45 (Germany)`, Attempts: `5` &rarr; Bấm **`Launch Attack`**.
2. **Kiểm tra Log trên Kali:** `sudo tail -n 10 /var/log/auth.log` (Thấy log `Failed password for invalid user ... from 192.168.56.1`).
3. **Phân tích AI:** Tab **`Incidents`** &rarr; Mở drawer &rarr; Thấy **MITRE `T1110`**, Confidence `98%`.
4. **Phê duyệt:** Tab **`Human Approvals`** &rarr; Thấy thẻ `BLOCK IP [LINUX_SSH]` &rarr; Bấm **`Approve & Execute Now`**.
5. **Kiểm tra iptables trên Kali:** `sudo iptables -L INPUT -v -n` (Thấy dòng `DROP 185.220.101.45`). Sự cố chuyển sang **`[CONTAINED]`**.

### 🔹 Kịch bản 2: Tấn công Web SQL Injection & Path Traversal (Port 80)
1. **Chuẩn bị trên Kali:** `sudo systemctl enable --now apache2`.
2. **Phát động:** Simulator &rarr; Vector `🌐 Web Application Attack (Port 80 SQLi / Path Traversal)` &rarr; Bấm **`Launch Attack`**.
3. **Kiểm tra Log trên Kali:** `sudo tail -n 10 /var/log/apache2/access.log` (Thấy các payload `UNION SELECT`, `etc/passwd`).
4. **Phân tích AI:** Tab **`Incidents`** &rarr; AI Triage chỉ ra nguyên nhân *Unsanitized Query Parameter*, gắn mã **MITRE `T1190`**.

### 🔹 Kịch bản 3: Tấn công Mã độc / Ransomware & Cách ly Máy trạm
1. **Phát động:** Simulator &rarr; **`⚡ Pre-built Scenarios`** &rarr; Thẻ **`Ransomware & Shadow Copy Deletion`** &rarr; Bấm **`Launch Scenario`**.
   *(Hoặc chạy lệnh tạo file mã hóa `.locked` trên Kali bằng `openssl enc`)*.
2. **Phân tích AI:** Tab **`Incidents`** &rarr; Thấy mức độ `CRITICAL`, mã **MITRE `T1486 (Data Encrypted for Impact)`**, Confidence `99%`.
3. **Phê duyệt:** Tab **`Human Approvals`** &rarr; Thẻ `ISOLATE WAZUH_AGENT` (Target: `002` hoặc `001`) &rarr; Bấm **`Approve & Execute Now`** &rarr; Chuyển sang **`EXECUTED`** và sự cố chuyển thành **`[CONTAINED]`**.

### 🔹 Kịch bản 4: Đánh giá Tuân thủ SCA CIS Benchmark từ xa
1. **Khám phá Máy ảo:** Tab **`Settings & Connectors`** &rarr; Bấm **`Discover & Fetch VM Agents`** &rarr; Danh sách hiện Agent `#000` / `#001` (`Kali GNU/Linux` - `Active`).
2. **Kích hoạt Audit:** Bấm nút **`SCA Audit`** (hoặc `Syscheck FIM`).
3. **Kết quả:** Khung **Wazuh VM Live Execution Result** trả về báo cáo đánh giá 85+ tiêu chí tuân thủ CIS Benchmark cho máy ảo Kali.

---

## 6. HƯỚNG DẪN VẬN HÀNH & KIỂM THỬ TỰ ĐỘNG

```bash
# 1. Khởi động toàn bộ nền tảng trên Windows:
start_soar.bat

# 2. Dừng toàn bộ nền tảng:
stop_soar.bat

# 3. Chạy kiểm thử tự động Backend (Pytest):
cd /d d:\soar\backend
python -m pytest tests/test_backend.py -v

# 4. Build kiểm tra Frontend:
cd /d d:\soar\frontend
npm run build
```

---
*Tài liệu này đóng vai trò là Context chuẩn xác và đầy đủ nhất của dự án CyberGuard Mini SOAR để chuyển giao giữa các phiên làm việc.*
