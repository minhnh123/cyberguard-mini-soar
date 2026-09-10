import React, { useState } from 'react';
import { 
  Zap, 
  CheckCircle2, 
  AlertTriangle
} from 'lucide-react';
import { AlertsAPI } from '../services/api';

export default function SimulatorPage({ onSelectIncident, onGoApprovals }) {
  const [activeTab, setActiveTab] = useState('live_vm'); // 'live_vm' | 'custom'

  // Live Red-Team VM Attack States
  const [targetVmIp, setTargetVmIp] = useState('192.168.56.107');
  const [targetPort, setTargetPort] = useState('');
  const [spoofedAttackerIp, setSpoofedAttackerIp] = useState('185.220.101.45');
  const [selectedVector, setSelectedVector] = useState('ssh_bruteforce');
  const [liveAttempts, setLiveAttempts] = useState(10);
  const [loading, setLoading] = useState(false);
  const [liveAttackLogs, setLiveAttackLogs] = useState(null);

  // Custom JSON Webhook State
  const [customJson, setCustomJson] = useState('{\n  "title": "Custom High-Severity Web Shell Alert",\n  "severity": "high",\n  "source": "Custom-EDR",\n  "source_ip": "194.26.29.112",\n  "hostname": "WEB-SRV-01",\n  "description": "Suspicious PHP webshell execution detected in /var/www/uploads/"\n}');
  const [customResult, setCustomResult] = useState(null);

  const HOSTILE_IP_PRESETS = [
    { ip: '185.220.101.45', label: '🇩🇪 185.220.101.45 (Tor Exit Node - Germany)' },
    { ip: '45.154.255.89', label: '🇳🇱 45.154.255.89 (Hostile Scanner - Netherlands)' },
    { ip: '194.26.29.112', label: '🇷🇺 194.26.29.112 (Cobalt Strike C2 - Russia)' },
    { ip: '193.142.146.33', label: '🇧🇬 193.142.146.33 (Mirai Botnet Cluster - Bulgaria)' },
    { ip: '89.248.165.74', label: '🇸🇨 89.248.165.74 (Bulletproof Hosting - Seychelles)' },
    { ip: '103.20.5.1', label: '🇻🇳 103.20.5.1 (Malicious Web Exploit Origin - Vietnam)' }
  ];

  const ATTACK_VECTORS = [
    {
      id: 'ssh_bruteforce',
      name: 'SSH Brute Force Auth Flood',
      protocol: 'TCP / Port 22',
      defaultPort: 22,
      mitre: 'T1110.001 (Password Guessing)',
      severity: 'HIGH',
      badge: 'Kernel Auth Failures',
      icon: Terminal,
      color: 'rose',
      description: 'Gửi liên tục các gói tin xác thực SSH với từ điển tài khoản (admin, root, kali_guest, devops...) ghi log thất bại thực tế vào /var/log/auth.log trên máy ảo.'
    },
    {
      id: 'web_rce_cmd_injection',
      name: 'Web RCE & Webshell Injection Exploit',
      protocol: 'HTTP / Port 80, 8080',
      defaultPort: 80,
      mitre: 'T1059.004 (Unix Shell Command Injection)',
      severity: 'CRITICAL',
      badge: 'Critical Exploit Payload',
      icon: Zap,
      color: 'rose',
      description: 'Bắn chuỗi khai thác Remote Code Execution (id;whoami;cat /etc/passwd), Shellshock CVE-2014-6271 và Log4Shell JNDI injection (${jndi:ldap://...}).'
    },
    {
      id: 'web_sqli',
      name: 'Web SQL Injection & Path Traversal',
      protocol: 'HTTP / Port 80, 8080',
      defaultPort: 80,
      mitre: 'T1190 (Exploit Public-Facing App)',
      severity: 'HIGH',
      badge: 'SQLi & LFI Payloads',
      icon: ShieldAlert,
      color: 'amber',
      description: 'Fuzzing các chuỗi SQLi UNION SELECT, OR 1=1 và Directory Traversal (../../../../etc/passwd, .env, wp-config) kèm header X-Forwarded-For giả lập.'
    },
    {
      id: 'port_scan',
      name: 'TCP SYN & Service Discovery Port Sweep',
      protocol: 'TCP Full-Range (16 Ports)',
      defaultPort: null,
      mitre: 'T1046 (Network Service Discovery)',
      severity: 'MEDIUM',
      badge: 'Reconnaissance Sweep',
      icon: Radio,
      color: 'cyan',
      description: 'Quét thăm dò 16 cổng dịch vụ phổ biến (SSH 22, Web 80/443, SMB 445, MySQL 3306, RDP 3389, Wazuh 55000, Elastic 9200) để lập bản đồ mạng mục tiêu.'
    },
    {
      id: 'http_slowloris_dos',
      name: 'HTTP Slowloris & Request Exhaustion DoS',
      protocol: 'HTTP Sockets / Port 80',
      defaultPort: 80,
      mitre: 'T1498.001 (Direct Network Flood)',
      severity: 'HIGH',
      badge: 'Denial of Service',
      icon: Flame,
      color: 'orange',
      description: 'Mở đồng thời nhiều kết nối HTTP socket dở dang và gửi header chậm từng phần nhằm làm cạn kiệt tài nguyên xử lý của web server trên máy ảo.'
    },
    {
      id: 'ftp_telnet_credential_stuffing',
      name: 'FTP / Telnet Credential Stuffing',
      protocol: 'FTP / Telnet (Port 21/23)',
      defaultPort: 21,
      mitre: 'T1110.004 (Credential Stuffing)',
      severity: 'HIGH',
      badge: 'Service Auth Flood',
      icon: Lock,
      color: 'yellow',
      description: 'Kết nối socket trực tiếp tới cổng dịch vụ FTP/Telnet trên máy ảo, thử xác thực anonymous, root:toor, admin:admin123 để kích hoạt quy tắc Wazuh 11100.'
    },
    {
      id: 'smb_null_session',
      name: 'SMB / RPC Null Session & Share Probe',
      protocol: 'SMB / NetBIOS (Port 445/139)',
      defaultPort: 445,
      mitre: 'T1078.001 (Default Accounts)',
      severity: 'HIGH',
      badge: 'Lateral Movement Probe',
      icon: Server,
      color: 'indigo',
      description: 'Gửi gói tin thương lượng SMB Negotiate Protocol Packet để kiểm tra Samba share và cố gắng kết nối phiên làm việc ẩn danh (Null Session).'
    },
    {
      id: 'udp_dns_amplification',
      name: 'UDP Reflection & DNS Amplification Probe',
      protocol: 'UDP Datagrams (Port 53/123)',
      defaultPort: 53,
      mitre: 'T1498.002 (Reflection Amplification)',
      severity: 'MEDIUM',
      badge: 'UDP Flood Traffic',
      icon: Globe,
      color: 'teal',
      description: 'Bắn các gói tin UDP phân giải DNS ANY và NTP monlist để kiểm tra lưu lượng UDP xâm nhập và kích hoạt phát hiện Suricata IDS Rule 514.'
    },
    {
      id: 'identity_compromise',
      name: 'Credential Stuffing & Stolen Session Cookie',
      protocol: 'OAuth 2.0 / IdP SAML Token Replay',
      defaultPort: 443,
      mitre: 'T1078 (Valid Accounts) / T1539 (Steal Session Cookie)',
      severity: 'HIGH',
      badge: 'Identity Takeover',
      color: 'purple',
      description: 'Giả lập truy cập trái phép bằng Session Cookie bị đánh cắp của alex.morgan@cyberguard.corp từ IP Tor Exit Node. Kích hoạt Identity SOAR Revocation Playbook.'
    },
    {
      id: 'ransomware_execution',
      name: 'Ransomware Shadow Copy Deletion (vssadmin)',
      protocol: 'Endpoint Process Tree / EDR Hook',
      defaultPort: null,
      mitre: 'T1486 (Data Encrypted) / T1489 (Service Stop)',
      severity: 'CRITICAL',
      badge: 'EDR Process Containment',
      color: 'rose',
      description: 'Kích hoạt tiến trình thực thi ransomware nguy hiểm (vssadmin.exe delete shadows /all /quiet) trên máy trạm tài chính (PID: 4821) để kích hoạt EDR Endpoint Quarantine.'
    }
  ];

  const handleLaunchLiveVmAttack = async () => {
    try {
      setLoading(true);
      setLiveAttackLogs(null);
      const res = await AlertsAPI.launchLiveAttack({
        target_ip: targetVmIp,
        target_port: targetPort ? parseInt(targetPort) : undefined,
        spoofed_ip: spoofedAttackerIp,
        attack_type: selectedVector,
        attempts: liveAttempts,
        trigger_soar_pipeline: true
      });
      setLiveAttackLogs(res);
    } catch (err) {
      alert(`Khởi chạy tấn công thất bại: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleSendCustom = async () => {
    try {
      setLoading(true);
      setCustomResult(null);
      const parsed = JSON.parse(customJson);
      const res = await AlertsAPI.ingestWebhook(parsed);
      setCustomResult(res);
    } catch (err) {
      alert(`Lỗi Webhook Alert: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const selectedVectorObj = ATTACK_VECTORS.find(v => v.id === selectedVector) || ATTACK_VECTORS[0];

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Top Header */}
      <div className="p-5 rounded-xl bg-gradient-to-r from-rose-950/40 via-slate-900 to-indigo-950/40 border border-rose-500/30 flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex h-2 w-2 rounded-full bg-rose-500 animate-ping"></span>
            <span className="text-[10px] uppercase font-mono font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
              Live Red-Team Lab
            </span>
          </div>
          <h2 className="text-base font-bold text-rose-200 mt-1">
            Live VM Attack Launcher & Threat Intel Simulator
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Phát sinh các gói tin tấn công mạng thật (SSH, Web RCE, SQLi, DoS, Port Scan, FTP, SMB, UDP) sang máy ảo Kali với Spoofed Threat Actor IP để kích hoạt chuỗi SOAR Playbook.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex rounded-lg bg-slate-900 p-1 border border-slate-800 text-xs shrink-0">
          <button
            onClick={() => setActiveTab('live_vm')}
            className={`px-4 py-1.5 rounded-md font-medium transition ${
              activeTab === 'live_vm'
                ? 'bg-rose-600 text-white font-bold shadow-lg shadow-rose-600/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>Live VM Attack</span>
          </button>

          <button
            onClick={() => setActiveTab('custom')}
            className={`px-3 py-1.5 rounded-md font-medium transition ${
              activeTab === 'custom'
                ? 'bg-cyan-500 text-slate-950 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>Custom JSON Webhook</span>
          </button>
        </div>
      </div>

      {/* TAB 1: LIVE RED-TEAM VM ATTACK LAUNCHER */}
      {activeTab === 'live_vm' && (
        <div className="space-y-6">
          {/* Attack Configuration Controls Panel */}
          <div className="glass-panel p-5 rounded-xl border border-slate-800 bg-slate-950/70 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <h3 className="text-xs font-bold text-slate-200 uppercase font-mono tracking-wider">
                1. Cấu hình Mục tiêu & Danh tính Kẻ tấn công
              </h3>
              <span className="text-[11px] text-slate-400 font-mono">
                Đích đến: <strong className="text-cyan-400">{targetVmIp}:{targetPort || selectedVectorObj.defaultPort || 'ALL'}</strong>
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
              {/* Target VM IP */}
              <div>
                <label className="text-slate-300 font-semibold mb-1 block">Target Virtual Machine IP</label>
                <input
                  type="text"
                  value={targetVmIp}
                  onChange={(e) => setTargetVmIp(e.target.value)}
                  placeholder="192.168.56.107"
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 font-mono text-cyan-300 focus:outline-none focus:border-rose-500"
                />
                <span className="text-[10px] text-slate-500 mt-1 block">Địa chỉ IP máy ảo Kali Linux của bạn</span>
              </div>

              {/* Target Custom Port */}
              <div>
                <label className="text-slate-300 font-semibold mb-1 block">Target Port (Tuỳ chọn)</label>
                <input
                  type="text"
                  value={targetPort}
                  onChange={(e) => setTargetPort(e.target.value)}
                  placeholder={`Mặc định: ${selectedVectorObj.defaultPort || 'Tự động'}`}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 font-mono text-slate-200 focus:outline-none focus:border-rose-500"
                />
                <span className="text-[10px] text-slate-500 mt-1 block">Để trống nếu dùng cổng mặc định</span>
              </div>

              {/* Spoofed Attacker IP */}
              <div>
                <label className="text-slate-300 font-semibold mb-1 block">
                  Spoofed Attacker Source IP
                </label>
                <select
                  value={spoofedAttackerIp}
                  onChange={(e) => setSpoofedAttackerIp(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 font-mono text-amber-300 focus:outline-none focus:border-rose-500"
                >
                  {HOSTILE_IP_PRESETS.map((item) => (
                    <option key={item.ip} value={item.ip}>
                      {item.label}
                    </option>
                  ))}
                </select>
                <span className="text-[10px] text-slate-400 mt-1 block leading-tight">
                  💡 <strong className="text-cyan-400">Đổi IP khác</strong> để tạo Sự cố mới riêng biệt, hoặc <strong className="text-amber-400">giữ nguyên IP</strong> để kiểm tra Deduplication (gom cụm 15m).
                </span>
              </div>

              {/* Attempts Slider */}
              <div>
                <label className="text-slate-300 font-semibold mb-1 block flex items-center justify-between">
                  <span>Cường độ / Số gói tin:</span>
                  <strong className="text-rose-400 font-mono">{liveAttempts} lần</strong>
                </label>
                <input
                  type="range"
                  min="3"
                  max="25"
                  value={liveAttempts}
                  onChange={(e) => setLiveAttempts(parseInt(e.target.value))}
                  className="w-full mt-2 accent-rose-500 cursor-pointer"
                />
                <span className="text-[10px] text-slate-500 mt-1 block">Số lần gửi gói tin probe / authentication</span>
              </div>
            </div>
          </div>

          {/* Attack Vectors Grid (8 Methods) */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-slate-200 uppercase font-mono tracking-wider">
                2. Chọn Phương thức Tấn công Thực tế ({ATTACK_VECTORS.length} Vectors)
              </h3>
              <span className="text-xs text-slate-400">
                Đang chọn: <strong className="text-rose-400 font-semibold">{selectedVectorObj.name}</strong>
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3.5">
              {ATTACK_VECTORS.map((vec) => {
                const Icon = vec.icon;
                const isSelected = selectedVector === vec.id;

                return (
                  <div
                    key={vec.id}
                    onClick={() => {
                      setSelectedVector(vec.id);
                      if (vec.defaultPort) {
                        setTargetPort('');
                      }
                    }}
                    className={`cursor-pointer rounded-xl p-4 border transition flex flex-col justify-between space-y-3 relative ${
                      isSelected
                        ? 'border-rose-500 bg-rose-950/25 shadow-lg shadow-rose-500/10 ring-1 ring-rose-500/50'
                        : 'border-slate-800 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-900/70'
                    }`}
                  >
                    {/* Header */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase border ${
                          vec.severity === 'CRITICAL'
                            ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                            : vec.severity === 'HIGH'
                            ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                            : 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                        }`}>
                          {vec.severity}
                        </span>
                        <span className="text-[11px] font-mono text-cyan-400">
                          {vec.protocol}
                        </span>
                      </div>

                      <h4 className={`text-xs font-bold leading-snug ${isSelected ? 'text-white' : 'text-slate-200'}`}>
                        {vec.name}
                      </h4>

                      <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-3">
                        {vec.description}
                      </p>
                    </div>

                    {/* Footer tags */}
                    <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono">
                      <span className="text-slate-500 truncate max-w-[150px]">
                        {vec.mitre}
                      </span>
                      {isSelected && (
                        <span className="text-rose-400 font-bold">
                          Active
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Launch Button Action Bar */}
          <div className="p-4 rounded-xl glass-panel border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3 bg-slate-900/60">
            <div className="flex items-center gap-3 text-xs text-slate-300">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse"></span>
              <div>
                Sẵn sàng phát sinh <strong className="text-white">{selectedVectorObj.name}</strong> ({liveAttempts} packets) tới <strong className="text-cyan-400 font-mono">{targetVmIp}:{targetPort || selectedVectorObj.defaultPort || 'ALL'}</strong>
              </div>
            </div>

            <button
              onClick={handleLaunchLiveVmAttack}
              disabled={loading}
              className="w-full sm:w-auto px-7 py-2.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs shadow-lg shadow-rose-600/30 transition disabled:opacity-50"
            >
              <span>{loading ? 'Đang gửi gói tin tấn công thật...' : `Khởi chạy Tấn công (${selectedVectorObj.name})`}</span>
            </button>
          </div>

          {/* Live Attack Output Terminal */}
          {liveAttackLogs && (
            <div className="glass-panel p-5 rounded-xl border border-rose-500/40 bg-slate-950/90 space-y-4 animate-fade-in">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-slate-200 uppercase">
                    Real-Time Attack Terminal Output
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                    Attack Dispatched
                  </span>
                </div>

                {liveAttackLogs.incident_id && (
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => onSelectIncident && onSelectIncident(liveAttackLogs.incident_id)}
                      className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold transition"
                    >
                      <span>Xem Sự Cố #{liveAttackLogs.incident_id}</span>
                    </button>
                    {onGoApprovals && (
                      <button
                        onClick={onGoApprovals}
                        className="px-3 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-xs font-semibold transition"
                      >
                        Tới Hàng Đợi Phê Duyệt
                      </button>
                    )}
                  </div>
                )}
              </div>

              {/* Deduplication or New Incident Status Banner */}
              {liveAttackLogs.incident_id && (
                liveAttackLogs.is_correlated ? (
                  <div className="p-3 rounded-lg bg-cyan-950/60 border border-cyan-500/40 text-cyan-200 text-xs flex items-start gap-2.5">
                    <Zap className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold text-cyan-300 uppercase tracking-wider text-[11px] block">⚡ ĐÃ KÍCH HOẠT CƠ CHẾ DEDUPLICATION (GOM CỤM TỰ ĐỘNG)</span>
                      <p className="mt-0.5 text-slate-300">
                        Cảnh báo này đã được gom vào <strong>Sự cố #{liveAttackLogs.incident_id}</strong> do cùng xuất phát từ IP kẻ tấn công <strong>{liveAttackLogs.spoofed_ip}</strong> trong vòng 15 phút. SOAR chống tràn cảnh báo nên không sinh thẻ sự cố thừa.
                        <span className="text-cyan-400 block mt-1">👉 Mẹo: Để tạo một Sự cố MỚI TINH, hãy đổi "Spoofed Attacker Source IP" sang một IP quốc gia khác ở bảng trên!</span>
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-500/40 text-emerald-200 text-xs flex items-start gap-2.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold text-emerald-300 uppercase tracking-wider text-[11px] block">✓ ĐÃ KHỞI TẠO SỰ CỐ MỚI THÀNH CÔNG</span>
                      <p className="mt-0.5 text-slate-300">
                        Sự cố <strong>#{liveAttackLogs.incident_id}</strong> đã được tạo mới với đầy đủ hồ sơ Threat Intelligence cho IP <strong>{liveAttackLogs.spoofed_ip}</strong> và kích hoạt chuỗi SOAR Playbook.
                      </p>
                    </div>
                  </div>
                )
              )}

              {/* Logs Stream */}
              <div className="bg-black/90 p-4 rounded-xl border border-slate-900 font-mono text-xs text-slate-300 max-h-72 overflow-y-auto space-y-1">
                {liveAttackLogs.logs?.map((line, i) => (
                  <div
                    key={i}
                    className={
                      line.includes('[+]') || line.includes('[✓]')
                        ? 'text-emerald-400 font-semibold'
                        : line.includes('[!]')
                        ? 'text-rose-400'
                        : line.includes('[i]')
                        ? 'text-cyan-300 italic'
                        : 'text-slate-400'
                    }
                  >
                    {line}
                  </div>
                ))}
              </div>

              <div className="text-[11px] text-slate-400 flex items-center justify-between pt-1">
                <span>Trạng thái: <strong className="text-emerald-400">Thành công</strong> | Đã gắn danh tính IP giả lập: <strong className="text-amber-300 font-mono">{liveAttackLogs.spoofed_ip}</strong></span>
                <span>Kiểm tra iptables máy ảo để xem rule chặn tự động kích hoạt</span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: CUSTOM JSON WEBHOOK INGESTION */}
      {activeTab === 'custom' && (
        <div className="glass-panel p-6 rounded-xl border border-slate-800 space-y-5">
          <div>
            <h3 className="font-bold text-sm text-slate-100">
              Custom Webhook Ingestion
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Gửi một cảnh báo JSON thô mô phỏng log từ Wazuh, Suricata, AWS GuardDuty hoặc CrowdStrike để kiểm tra đường ống phân loại.
            </p>
          </div>

          <div className="space-y-2">
            <label className="text-xs font-mono text-slate-400">JSON Payload Content:</label>
            <textarea
              rows={9}
              value={customJson}
              onChange={(e) => setCustomJson(e.target.value)}
              className="w-full p-3.5 rounded-xl bg-black/80 border border-slate-700 font-mono text-xs text-emerald-400 focus:outline-none focus:border-cyan-500 leading-relaxed"
            />
          </div>

          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-500 font-mono">Endpoint: POST /api/v1/alerts/webhook</span>
            <button
              onClick={handleSendCustom}
              disabled={loading}
              className="px-6 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition shadow-lg shadow-cyan-500/20"
            >
              <span>{loading ? 'Đang gửi...' : 'Gửi Cảnh Báo Tuỳ Chỉnh'}</span>
            </button>
          </div>

          {customResult && (
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2 text-xs">
              <div className="flex items-center gap-2 text-emerald-400 font-semibold">
                <CheckCircle2 className="w-4 h-4" />
                <span>Cảnh báo đã được tiếp nhận thành công!</span>
              </div>
              <div className="text-slate-300 font-mono">
                Incident ID: <strong>#{customResult.incident_id}</strong> | Alert ID: <strong>#{customResult.id}</strong> | Status: <strong>{customResult.status}</strong>
              </div>
              {onSelectIncident && (
                <button
                  onClick={() => onSelectIncident(customResult.incident_id)}
                  className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold pt-1 transition"
                >
                  <span>Chuyển tới chi tiết Sự cố #{customResult.incident_id}</span>
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
