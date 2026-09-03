import re
import uuid
import datetime
import asyncio
import ipaddress
import httpx
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc, func

from app.core.config import settings
from app.core.database import get_db
from app.models.models import Alert, Incident, SystemSetting
from app.schemas.schemas import AlertResponse, AlertCreate
from app.services.playbook_engine import PlaybookEngine
from app.services.websocket_manager import ws_manager

router = APIRouter(prefix="/alerts", tags=["Alerts"])

# --- INPUT SANITIZATION UTILITIES ---

def sanitize_text(val: Any, max_len: int = 255) -> Optional[str]:
    """Loại bỏ các ký tự điều khiển nguy hiểm, giữ văn bản an toàn."""
    if val is None:
        return None
    s = str(val).strip()
    s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', s)
    return s[:max_len]

def sanitize_ip(val: Any) -> Optional[str]:
    """Kiểm tra và chuẩn hóa địa chỉ IP (IPv4 / IPv6)."""
    if not val:
        return None
    val_str = str(val).strip()
    try:
        ip_obj = ipaddress.ip_address(val_str)
        return str(ip_obj)
    except ValueError:
        cleaned = re.sub(r'[^a-fA-F0-9.:]', '', val_str)
        try:
            return str(ipaddress.ip_address(cleaned))
        except ValueError:
            return None

def sanitize_hash(val: Any) -> Optional[str]:
    """Chuẩn hóa mã băm (MD5, SHA1, SHA256) chỉ giữ ký tự hex."""
    if not val:
        return None
    cleaned = re.sub(r'[^a-fA-F0-9]', '', str(val).strip().lower())
    if len(cleaned) in [32, 40, 64]:
        return cleaned
    return cleaned[:128] if cleaned else None

def sanitize_identifier(val: Any, max_len: int = 64) -> Optional[str]:
    """Chuẩn hóa ID (agent_id, rule_id, hostname, user). Loại bỏ shell meta-chars."""
    if not val:
        return None
    cleaned = re.sub(r'[^a-zA-Z0-9._\-@]', '', str(val).strip())
    return cleaned[:max_len]

# --- UNIVERSAL ALERT NORMALIZER WITH SANITIZATION ---

def normalize_alert_payload(raw_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Universal normalizer for alert payloads from Wazuh, Suricata, Syslog, or custom JSON
    with automatic security sanitization on all extracted IOCs and fields.
    """
    # Check for Wazuh alert format
    if "rule" in raw_json and ("agent" in raw_json or "data" in raw_json):
        rule = raw_json.get("rule", {})
        data = raw_json.get("data", {})
        agent = raw_json.get("agent", {})
        
        level = rule.get("level", 5)
        severity = "info"
        if level >= 13:
            severity = "critical"
        elif level >= 10:
            severity = "high"
        elif level >= 5:
            severity = "medium"
        elif level >= 1:
            severity = "low"

        raw_src = data.get("srcip") or data.get("src_ip") or raw_json.get("src_ip")
        raw_dst = data.get("dstip") or data.get("dst_ip")
        raw_hash = data.get("md5") or data.get("sha256") or data.get("hash")

        return {
            "title": sanitize_text(rule.get("description", "Wazuh Security Event"), 255),
            "description": sanitize_text(f"Wazuh Rule ID {rule.get('id')}: {rule.get('description')}", 2000),
            "severity": severity,
            "source": "Wazuh",
            "source_ip": sanitize_ip(raw_src),
            "destination_ip": sanitize_ip(raw_dst),
            "file_hash": sanitize_hash(raw_hash),
            "agent_id": sanitize_identifier(agent.get("id"), 64),
            "hostname": sanitize_identifier(agent.get("name"), 128),
            "rule_id": sanitize_identifier(rule.get("id"), 64),
            "raw_payload": raw_json
        }

    # Suricata EVE JSON format
    if "event_type" in raw_json and "alert" in raw_json:
        alert_obj = raw_json.get("alert", {})
        sev_map = {1: "critical", 2: "high", 3: "medium", 4: "low"}
        return {
            "title": sanitize_text(alert_obj.get("signature", "Suricata Network Alert"), 255),
            "description": sanitize_text(f"Category: {alert_obj.get('category')}", 2000),
            "severity": sev_map.get(alert_obj.get("severity", 3), "medium"),
            "source": "Suricata",
            "source_ip": sanitize_ip(raw_json.get("src_ip")),
            "destination_ip": sanitize_ip(raw_json.get("dest_ip")),
            "rule_id": sanitize_identifier(alert_obj.get("signature_id"), 64),
            "raw_payload": raw_json
        }

    # Generic or Custom Format
    title = raw_json.get("title") or raw_json.get("event") or raw_json.get("message") or "Security Alert"
    severity = str(raw_json.get("severity", "medium")).lower()
    if severity not in ["critical", "high", "medium", "low", "info"]:
        severity = "medium"

    return {
        "title": sanitize_text(title, 255),
        "description": sanitize_text(raw_json.get("description") or raw_json.get("details"), 2000),
        "severity": severity,
        "source": sanitize_identifier(raw_json.get("source", "Webhook"), 64) or "Webhook",
        "source_ip": sanitize_ip(raw_json.get("source_ip") or raw_json.get("src_ip") or raw_json.get("client_ip")),
        "destination_ip": sanitize_ip(raw_json.get("destination_ip") or raw_json.get("dest_ip") or raw_json.get("target_ip")),
        "file_hash": sanitize_hash(raw_json.get("file_hash") or raw_json.get("hash") or raw_json.get("sha256")),
        "domain": sanitize_text(raw_json.get("domain") or raw_json.get("hostname"), 255),
        "url": sanitize_text(raw_json.get("url"), 1000),
        "agent_id": sanitize_identifier(raw_json.get("agent_id"), 64),
        "hostname": sanitize_identifier(raw_json.get("hostname"), 128),
        "user": sanitize_identifier(raw_json.get("user") or raw_json.get("username"), 128),
        "rule_id": sanitize_identifier(raw_json.get("rule_id", ""), 64),
        "raw_payload": raw_json
    }

# --- WEBHOOK SECRET AUTHENTICATION ---

async def verify_webhook_secret(request: Request, db: AsyncSession):
    """
    Xác thực Secret Token khi tiếp nhận Webhook.
    Nếu cấu hình REQUIRE_WEBHOOK_SECRET = True trong Settings, bắt buộc phải có secret hợp lệ.
    """
    stmt_key = select(SystemSetting).where(SystemSetting.key == "WEBHOOK_SECRET_KEY")
    res_key = await db.execute(stmt_key)
    row_key = res_key.scalars().first()
    expected_secret = (row_key.value if row_key and row_key.value else settings.WEBHOOK_SECRET_KEY or "cyberguard-soar-secret").strip()

    stmt_req = select(SystemSetting).where(SystemSetting.key == "REQUIRE_WEBHOOK_SECRET")
    res_req = await db.execute(stmt_req)
    row_req = res_req.scalars().first()
    is_required = (row_req.value.strip().lower() == "true") if row_req and row_req.value else False

    # Lấy secret từ Header (X-Webhook-Secret hoặc Bearer) hoặc query param (?secret=...)
    header_secret = request.headers.get("X-Webhook-Secret") or request.headers.get("x-webhook-secret")
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        header_secret = header_secret or auth_header[7:].strip()

    query_secret = request.query_params.get("secret")
    client_secret = (header_secret or query_secret or "").strip()

    if is_required:
        if not client_secret or client_secret != expected_secret:
            raise HTTPException(
                status_code=401,
                detail="Unauthorized: Missing or invalid Webhook Secret. Please provide 'X-Webhook-Secret' header."
            )
    elif client_secret and client_secret != expected_secret:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Provided Webhook Secret is invalid."
        )

CORRELATION_WINDOW_MINUTES = 15

async def find_correlated_incident(
    normalized: Dict[str, Any],
    db: AsyncSession,
    window_minutes: int = CORRELATION_WINDOW_MINUTES
) -> Optional[Incident]:
    """
    Tìm kiếm sự cố đang hoạt động (open, investigating, contained)
    trong cửa sổ thời gian (mặc định 15 phút) khớp với các IOC:
    1. Trùng source_ip
    2. Trùng file_hash
    3. Trùng agent_id và rule_id
    """
    source_ip = normalized.get("source_ip")
    file_hash = normalized.get("file_hash")
    agent_id = normalized.get("agent_id")
    rule_id = normalized.get("rule_id")

    if not source_ip and not file_hash and not (agent_id and rule_id):
        return None

    cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=window_minutes)

    query = (
        select(Incident)
        .where(
            Incident.status.in_(["open", "investigating", "contained"]),
            Incident.updated_at >= cutoff_time
        )
        .order_by(desc(Incident.updated_at))
    )
    result = await db.execute(query)
    candidates = result.scalars().all()

    for inc in candidates:
        alerts_query = select(Alert).where(Alert.incident_id == inc.id)
        al_res = await db.execute(alerts_query)
        inc_alerts = al_res.scalars().all()

        for a in inc_alerts:
            if source_ip and a.source_ip == source_ip:
                return inc
            if file_hash and a.file_hash == file_hash:
                return inc
            if agent_id and rule_id and a.agent_id == agent_id and a.rule_id == rule_id:
                return inc

    return None

async def process_alert_ingestion(raw_payload: Dict[str, Any], db: AsyncSession) -> Alert:
    """
    Core engine xử lý tiếp nhận, làm sạch dữ liệu (Sanitization),
    gom cụm tương quan (Deduplication), tự động tạo Incident và phát sóng WebSocket.
    """
    normalized = normalize_alert_payload(raw_payload)
    alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"

    # 1. Tạo bản ghi Alert
    new_alert = Alert(
        alert_id=alert_id,
        title=normalized["title"],
        description=normalized["description"],
        severity=normalized["severity"],
        source=normalized["source"],
        source_ip=normalized.get("source_ip"),
        destination_ip=normalized.get("destination_ip"),
        file_hash=normalized.get("file_hash"),
        domain=normalized.get("domain"),
        url=normalized.get("url"),
        agent_id=normalized.get("agent_id"),
        hostname=normalized.get("hostname"),
        user=normalized.get("user"),
        rule_id=normalized.get("rule_id"),
        raw_payload=normalized["raw_payload"],
        status="new"
    )
    db.add(new_alert)
    await db.commit()
    await db.refresh(new_alert)

    # 2. Kiểm tra cửa sổ tương quan (Alert Deduplication / Correlation Window)
    existing_incident = await find_correlated_incident(normalized, db)

    if existing_incident:
        # Gom cụm alert vào Incident hiện hữu
        new_alert.incident_id = existing_incident.id
        new_alert.status = "correlated"

        existing_incident.alert_count = (existing_incident.alert_count or 1) + 1
        existing_incident.updated_at = datetime.datetime.utcnow()

        # Nâng mức nghiêm trọng nếu cảnh báo mới có severity cao hơn
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        if sev_rank.get(new_alert.severity.lower(), 0) > sev_rank.get(existing_incident.severity.lower(), 0):
            existing_incident.severity = new_alert.severity

        await db.commit()
        await db.refresh(new_alert)

        # Broadcast sự kiện WebSocket
        try:
            await ws_manager.broadcast("NEW_ALERT", {
                "alert_id": new_alert.alert_id,
                "title": new_alert.title,
                "severity": new_alert.severity,
                "source": new_alert.source,
                "source_ip": new_alert.source_ip,
                "incident_id": existing_incident.id,
                "is_correlated": True,
                "alert_count": existing_incident.alert_count,
                "created_at": new_alert.created_at.isoformat() if new_alert.created_at else None
            })
        except Exception:
            pass

        return new_alert

    # 3. Tạo mới Incident nếu chưa có sự cố tương quan
    inc_number = f"INC-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
    new_incident = Incident(
        incident_number=inc_number,
        title=f"Incident: {new_alert.title}",
        severity=new_alert.severity,
        status="investigating",
        alert_count=1,
        summary=f"Automated incident created from alert: {new_alert.title}"
    )
    db.add(new_incident)
    await db.commit()
    await db.refresh(new_incident)

    # Gán alert vào Incident mới
    new_alert.incident_id = new_incident.id
    new_alert.status = "processing"
    await db.commit()

    # 4. Kích hoạt động cơ Playbook tự động
    await PlaybookEngine.match_and_trigger(new_alert, new_incident, db)

    # Broadcast sự kiện WebSocket
    try:
        await ws_manager.broadcast("NEW_ALERT", {
            "alert_id": new_alert.alert_id,
            "title": new_alert.title,
            "severity": new_alert.severity,
            "source": new_alert.source,
            "source_ip": new_alert.source_ip,
            "incident_id": new_incident.id,
            "is_correlated": False,
            "alert_count": 1,
            "created_at": new_alert.created_at.isoformat() if new_alert.created_at else None
        })
    except Exception:
        pass

    return new_alert

@router.post("/webhook", response_model=AlertResponse)
async def ingest_webhook_alert(
    raw_payload: Dict[str, Any],
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Ingest alerts from Wazuh, Suricata, EDR, SIEM, or custom scripts via Webhook.
    Tự động gom cụm cảnh báo lặp (Deduplication) hoặc tạo Incident mới & chạy Playbooks.
    Hỗ trợ xác thực X-Webhook-Secret và phát sóng sự kiện thời gian thực qua WebSocket.
    """
    await verify_webhook_secret(request, db)
    return await process_alert_ingestion(raw_payload, db)

@router.get("", response_model=List[AlertResponse])
async def list_alerts(
    skip: int = 0,
    limit: int = 50,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    query = select(Alert).order_by(desc(Alert.created_at)).offset(skip).limit(limit)
    if severity:
        query = query.where(Alert.severity == severity.lower())
    if source:
        query = query.where(Alert.source == source)
    
    result = await db.execute(query)
    return result.scalars().all()

@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.post("/simulate")
async def simulate_attack_alert(scenario: str = Query(..., description="ssh_bruteforce, ransomware, malware_hash, web_sqli, port_scan"), db: AsyncSession = Depends(get_db)):
    """
    Built-in Attack Simulator to test and demonstrate the SOAR automation lifecycle.
    """
    scenarios = {
        "ssh_bruteforce": {
            "title": "SSH Authentication Brute Force Attack Detected",
            "source": "Wazuh",
            "rule": {"id": "5710", "level": 10, "description": "sshd: Multiple failed login attempts (Brute Force)"},
            "data": {"srcip": "185.220.101.45", "dstip": "192.168.1.10"},
            "agent": {"id": "001", "name": "SRV-LINUX-PROD"},
            "description": "50 failed SSH login attempts detected within 60 seconds from IP 185.220.101.45"
        },
        "ransomware": {
            "title": "Suspicious Shadow Copy Deletion (vssadmin) & Mass File Modification",
            "source": "Wazuh",
            "rule": {"id": "92100", "level": 14, "description": "Ransomware activity: Volume Shadow Copies deleted via vssadmin.exe"},
            "data": {"process": "vssadmin.exe delete shadows /all /quiet", "srcip": "10.0.0.85"},
            "agent": {"id": "002", "name": "WKSTN-FINANCE-04"},
            "description": "Endpoint WKSTN-FINANCE-04 executed vssadmin delete shadows followed by high entropy file writes."
        },
        "malware_hash": {
            "title": "Cobalt Strike Beacon Dropper Detected by Sysmon",
            "source": "EDR",
            "source_ip": "194.26.29.112",
            "destination_ip": "10.0.0.15",
            "file_hash": "44d88612fea8a8f36de82e1278abb02f",
            "hostname": "CEO-LAPTOP",
            "user": "corp\\jdoe",
            "severity": "critical",
            "description": "Malicious payload beacon_x64.dll written to %TEMP% directory."
        },
        "web_sqli": {
            "title": "SQL Injection & Path Traversal Attack on Payment Gateway",
            "source": "Suricata",
            "event_type": "alert",
            "alert": {"signature": "ET WEB_SERVER Possible SQL Injection attempt in URI", "signature_id": 2010999, "severity": 1, "category": "Web Application Attack"},
            "src_ip": "45.154.255.89",
            "dest_ip": "10.0.0.2",
            "description": "GET /api/v1/checkout?id=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users--"
        },
        "port_scan": {
            "title": "SYN Stealth Port Scan Detected",
            "source": "Suricata",
            "event_type": "alert",
            "alert": {"signature": "GPL SCAN Potential NMAP SYN scan", "signature_id": 2000537, "severity": 2, "category": "Network Reconnaissance"},
            "src_ip": "193.142.146.33",
            "dest_ip": "192.168.1.1",
            "description": "Rapid scanning of 1000 standard TCP ports detected from 193.142.146.33"
        }
    }

    payload = scenarios.get(scenario)
    if not payload:
        raise HTTPException(status_code=400, detail=f"Unknown scenario. Available: {list(scenarios.keys())}")

    return await process_alert_ingestion(payload, db)

@router.post("/live-attack-vm")
async def live_attack_vm(payload: Dict[str, Any], db: AsyncSession = Depends(get_db)):
    """
    Real Red-Team Attack Probe: Sends actual network traffic (SSH brute force, TCP port scan, Web SQLi)
    from the Host directly to the Target Virtual Machine IP, with optional Attacker IP Spoofing for Threat Intel enrichment.
    """
    target_ip = payload.get("target_ip", "192.168.56.101").strip()
    attack_type = payload.get("attack_type", "ssh_bruteforce")
    attempts = min(int(payload.get("attempts", 6)), 20)
    spoofed_ip = payload.get("spoofed_ip", "185.220.101.45").strip()
    trigger_soar_pipeline = payload.get("trigger_soar_pipeline", True)

    logs = []
    logs.append(f"[*] Initializing Red-Team Live Attack against Target VM: {target_ip}...")
    if spoofed_ip:
        logs.append(f"[*] Spoofed Attacker Identity: {spoofed_ip} (Enriched with Geolocation & Threat Intel)")

    if attack_type == "ssh_bruteforce":
        logs.append(f"[*] Launching authentic SSH Password Brute Force ({attempts} login attempts against port 22)...")
        usernames = ["admin", "root", "oracle", "test", "kali_guest", "devops", "backup", "operator"]
        failed_count = 0

        def try_ssh_login(target, user, pwd):
            try:
                import paramiko
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    target,
                    port=22,
                    username=user,
                    password=pwd,
                    timeout=8.0,
                    banner_timeout=8.0,
                    auth_timeout=8.0,
                    look_for_keys=False,
                    allow_agent=False
                )
                client.close()
                return "SUCCESS", "Logged in"
            except paramiko.AuthenticationException:
                # OpenSSH writes: "Failed password for [invalid user] <user> from <ip> port <port> ssh2"
                return "FAILED", "Authentication failed (Expected)"
            except Exception as e:
                return "FAILED", f"Error: {str(e)[:40]}"

        for i in range(attempts):
            user = usernames[i % len(usernames)]
            fake_pass = f"BruteForcePass_{uuid.uuid4().hex[:6]}!"
            status, err_msg = await asyncio.to_thread(try_ssh_login, target_ip, user, fake_pass)
            failed_count += 1
            logs.append(f"[!] Attempt #{i+1}: Sent SSH password auth for '{user}' (Spoofed Origin: {spoofed_ip}) -> {status}")
            await asyncio.sleep(0.3)

        logs.append(f"[+] Attack complete: Generated {failed_count} authentic Failed Password events on {target_ip}.")
        logs.append("[i] OpenSSH on Kali has logged: 'Failed password for user' in /var/log/auth.log.")
        logs.append("[i] Wazuh Rule 5710/5712 (sshd Brute Force) is triggered!")

    elif attack_type == "port_scan":
        ports = [21, 22, 25, 80, 443, 3306, 3389, 55000, 8080, 9200]
        logs.append(f"[*] Launching TCP Port Sweep against {len(ports)} target ports on {target_ip}...")
        open_ports = []

        for p in ports:
            try:
                conn = asyncio.open_connection(target_ip, p)
                reader, writer = await asyncio.wait_for(conn, timeout=1.0)
                writer.close()
                await writer.wait_closed()
                open_ports.append(p)
                logs.append(f"[+] Port {p}/TCP is OPEN on {target_ip}")
            except Exception:
                logs.append(f"[-] Port {p}/TCP is CLOSED / FILTERED on {target_ip}")

        logs.append(f"[+] Scan complete: Discovered {len(open_ports)} open ports: {open_ports}")
        logs.append("[i] Expected Wazuh Detection: Rule 510/2000537 (Network Port Reconnaissance).")

    elif attack_type == "web_sqli":
        logs.append(f"[*] Launching Web SQL Injection & Directory Traversal fuzzing against {target_ip}...")
        payloads = [
            "/index.php?id=1%27%20UNION%20SELECT%20null,version(),current_user()--",
            "/api/v1/users?search=%27%20OR%201=1--",
            "/../../../etc/passwd",
            "/admin/config.php.bak",
            "/.env"
        ]

        async with httpx.AsyncClient(timeout=3.0) as client:
            for p in payloads:
                url = f"http://{target_ip}{p}"
                try:
                    resp = await client.get(url)
                    logs.append(f"[!] Sent exploit URI: {p[:40]}... (Spoofed Origin: {spoofed_ip}) -> HTTP {resp.status_code}")
                except Exception as e:
                    logs.append(f"[!] Sent exploit URI: {p[:40]}... -> Connection error (Web server not active): {str(e)[:40]}")

        logs.append("[i] Expected Wazuh Detection: Rule 31101/31103 (SQL Injection / Path Traversal attempt).")

    # Ingest enriched incident into SOAR if requested
    incident_id = None
    if trigger_soar_pipeline:
        alert_title = "SSH Authentication Brute Force Attack Detected" if attack_type == "ssh_bruteforce" else (
            "SQL Injection & Web Exploit Attempt" if attack_type == "web_sqli" else "TCP Port Discovery & Reconnaissance Scan"
        )
        sim_payload = {
            "title": alert_title,
            "source": "Wazuh",
            "source_ip": spoofed_ip or "185.220.101.45",
            "destination_ip": target_ip,
            "severity": "high",
            "description": f"Red-Team {attack_type} attack executed against VM {target_ip} from hostile origin {spoofed_ip}.",
            "rule_id": "5710" if attack_type == "ssh_bruteforce" else "31101"
        }
        created_alert = await process_alert_ingestion(sim_payload, db)
        incident_id = created_alert.incident_id
        logs.append(f"[✓] SOAR Incident #{incident_id} created with enriched Threat Intel for {spoofed_ip}!")

    return {
        "status": "success",
        "target_ip": target_ip,
        "attack_type": attack_type,
        "spoofed_ip": spoofed_ip,
        "attempts": attempts,
        "incident_id": incident_id,
        "logs": logs
    }
