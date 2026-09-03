import React, { useState } from 'react';
import { 
  Zap, 
  Radio, 
  Terminal, 
  ShieldAlert, 
  Send, 
  CheckCircle2, 
  FileCode, 
  ExternalLink,
  Flame,
  Lock,
  Server,
  Crosshair,
  Globe
} from 'lucide-react';
import { AlertsAPI } from '../services/api';

export default function SimulatorPage({ onSelectIncident, onGoApprovals }) {
  const [selectedScenario, setSelectedScenario] = useState('ssh_bruteforce');
  const [customJson, setCustomJson] = useState('{\n  "title": "Custom High-Severity Web Shell Alert",\n  "severity": "high",\n  "source": "Custom-EDR",\n  "source_ip": "194.26.29.112",\n  "hostname": "WEB-SRV-01",\n  "description": "Suspicious PHP webshell execution detected in /var/www/uploads/"\n}');
  const [loading, setLoading] = useState(false);
  const [simulationResult, setSimulationResult] = useState(null);
  const [activeTab, setActiveTab] = useState('presets'); // 'presets' | 'live_vm' | 'custom'

  // Live Red-Team VM Attack States with Spoofed Attacker IP
  const [targetVmIp, setTargetVmIp] = useState('192.168.56.107');
  const [spoofedAttackerIp, setSpoofedAttackerIp] = useState('185.220.101.45');
  const [liveAttackType, setLiveAttackType] = useState('ssh_bruteforce');
  const [liveAttempts, setLiveAttempts] = useState(10);
  const [liveAttackLogs, setLiveAttackLogs] = useState(null);

  const HOSTILE_IP_PRESETS = [
    { ip: '185.220.101.45', label: '🇩🇪 185.220.101.45 (Tor Exit Node - Germany)' },
    { ip: '45.154.255.89', label: '🇳🇱 45.154.255.89 (Hostile Scanner - Netherlands)' },
    { ip: '194.26.29.112', label: '🇷🇺 194.26.29.112 (Cobalt Strike C2 - Russia)' },
    { ip: '193.142.146.33', label: '🇧🇬 193.142.146.33 (Botnet Cluster - Bulgaria)' },
    { ip: '89.248.165.74', label: '🇸🇨 89.248.165.74 (Bulletproof Hosting - Seychelles)' }
  ];

  const scenarios = [
    {
      id: 'ssh_bruteforce',
      title: 'SSH Authentication Brute Force Attack',
      source: 'Wazuh Agent 001',
      severity: 'high',
      mitre: 'T1110 (Brute Force)',
      description: '50 rapid failed login attempts from external Tor exit node IP 185.220.101.45. Triggers IP enrichment and Firewall block approval.',
      icon: Terminal,
      color: 'border-orange-500/40 bg-orange-950/10'
    },
    {
      id: 'ransomware',
      title: 'Wazuh Ransomware & Volume Shadow Copy Deletion',
      source: 'Wazuh Endpoint 002',
      severity: 'critical',
      mitre: 'T1486 (Data Encrypted for Impact)',
      description: 'Execution of vssadmin delete shadows /all on finance workstation. Triggers emergency Wazuh Agent host quarantine proposal.',
      icon: Lock,
      color: 'border-rose-500/40 bg-rose-950/10'
    },
    {
      id: 'malware_hash',
      title: 'Cobalt Strike Beacon Dropper Executed',
      source: 'Corporate EDR',
      severity: 'critical',
      mitre: 'T1059 (Command Interpreter) / T1071 (C2)',
      description: 'Known malware hash written to disk by suspicious process. Triggers VirusTotal scan and host isolation.',
      icon: Flame,
      color: 'border-rose-500/40 bg-rose-950/10'
    },
    {
      id: 'web_sqli',
      title: 'Web Application SQL Injection & RCE Exploit',
      source: 'Suricata IDS',
      severity: 'high',
      mitre: 'T1190 (Exploit Public-Facing App)',
      description: 'UNION SELECT SQL injection targeting billing API from external IP 45.154.255.89. Triggers Cloudflare WAF block proposal.',
      icon: ShieldAlert,
      color: 'border-cyan-500/40 bg-cyan-950/10'
    },
    {
      id: 'port_scan',
      title: 'NMAP Reconnaissance & Port Sweep',
      source: 'Suricata Network Monitor',
      severity: 'medium',
      mitre: 'T1046 (Network Service Discovery)',
      description: 'Port sweep of standard service ports from hostile subnet 193.142.146.33.',
      icon: Radio,
      color: 'border-amber-500/40 bg-amber-950/10'
    }
  ];

  const handleRunPreset = async (scenarioId) => {
    try {
      setLoading(true);
      setSimulationResult(null);
      const res = await AlertsAPI.simulate(scenarioId);
      setSimulationResult(res);
    } catch (err) {
      alert(`Simulation error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleSendCustom = async () => {
    try {
      setLoading(true);
      setSimulationResult(null);
      const parsed = JSON.parse(customJson);
      const res = await AlertsAPI.ingestWebhook(parsed);
      setSimulationResult(res);
    } catch (err) {
      alert(`Custom Alert error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleLaunchLiveVmAttack = async () => {
    try {
      setLoading(true);
      setLiveAttackLogs(null);
      const res = await AlertsAPI.launchLiveAttack({
        target_ip: targetVmIp,
        spoofed_ip: spoofedAttackerIp,
        attack_type: liveAttackType,
        attempts: liveAttempts,
        trigger_soar_pipeline: true
      });
      setLiveAttackLogs(res);
    } catch (err) {
      alert(`Failed to launch live attack: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="p-5 rounded-xl bg-gradient-to-r from-cyan-950/40 via-slate-900 to-indigo-950/40 border border-cyan-500/30 flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-cyan-200 flex items-center gap-2">
            <Radio className="w-5 h-5 text-cyan-400" />
            Attack Alert Generator & Red-Team Testing Lab
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Trigger SOAR alert simulations OR launch real socket/HTTP network attacks directly against your Kali VM with Spoofed Attacker Threat Intel.
          </p>
        </div>

        <div className="flex rounded-lg bg-slate-900 p-1 border border-slate-800 text-xs">
          <button
            onClick={() => setActiveTab('presets')}
            className={`px-3 py-1.5 rounded-md font-medium transition ${
              activeTab === 'presets' ? 'bg-cyan-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Pre-built Scenarios
          </button>

          <button
            onClick={() => setActiveTab('live_vm')}
            className={`px-3 py-1.5 rounded-md font-medium transition flex items-center gap-1.5 ${
              activeTab === 'live_vm' ? 'bg-rose-500 text-slate-950 font-bold shadow-lg shadow-rose-500/20' : 'text-rose-400 hover:text-rose-300'
            }`}
          >
            <Crosshair className="w-3.5 h-3.5" />
            <span>🔥 Live VM Attack</span>
          </button>

          <button
            onClick={() => setActiveTab('custom')}
            className={`px-3 py-1.5 rounded-md font-medium transition ${
              activeTab === 'custom' ? 'bg-cyan-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Custom JSON Webhook
          </button>
        </div>
      </div>

      {/* TAB 1: Preset Scenarios Grid */}
      {activeTab === 'presets' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {scenarios.map((sc) => {
            const Icon = sc.icon;
            return (
              <div
                key={sc.id}
                className={`glass-panel p-5 rounded-xl border ${sc.color} flex flex-col justify-between space-y-4 hover:border-cyan-400/60 transition`}
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="p-2 rounded-lg bg-slate-950 border border-slate-800">
                      <Icon className="w-4 h-4 text-cyan-400" />
                    </div>
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {sc.source}
                    </span>
                  </div>

                  <h3 className="font-bold text-sm text-slate-100">{sc.title}</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">{sc.description}</p>
                </div>

                <div className="space-y-3 pt-2 border-t border-slate-800/80">
                  <div className="text-[11px] font-mono text-indigo-300">
                    Target MITRE: <strong>{sc.mitre}</strong>
                  </div>

                  <button
                    onClick={() => handleRunPreset(sc.id)}
                    disabled={loading}
                    className="w-full py-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 font-bold text-xs flex items-center justify-center gap-1.5 transition shadow-sm"
                  >
                    <Zap className="w-3.5 h-3.5" />
                    <span>{loading ? 'Triggering...' : 'Fire Attack Simulation'}</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* TAB 2: LIVE RED TEAM VM ATTACK LAUNCHER */}
      {activeTab === 'live_vm' && (
        <div className="glass-panel p-6 rounded-xl border border-rose-500/40 bg-rose-950/10 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-rose-500/30">
            <div>
              <h3 className="text-sm font-bold text-rose-300 flex items-center gap-2">
                <Crosshair className="w-5 h-5 text-rose-400" />
                Live Red-Team VM Attack Launcher & Threat Intel Simulator
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Gửi gói tin tấn công SSH/Web thật sang máy ảo Kali `192.168.56.107` đồng thời gắn danh tính IP độc hại quốc tế để làm giàu Threat Intel & kích hoạt Playbook!
              </p>
            </div>
            <span className="text-[10px] font-mono font-bold px-2.5 py-1 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 uppercase">
              Live Probe + Spoofed Threat Intel
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
              <span className="text-[10px] text-slate-500 mt-1 block">IP máy ảo Kali của bạn</span>
            </div>

            {/* Spoofed Attacker IP */}
            <div>
              <label className="text-slate-300 font-semibold mb-1 block flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-cyan-400" />
                <span>Spoofed Attacker Source IP (Fake IP)</span>
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
              <span className="text-[10px] text-slate-500 mt-1 block">IP giả lập dùng để tra cứu Geolocation & ASN</span>
            </div>

            {/* Attack Vector */}
            <div>
              <label className="text-slate-300 font-semibold mb-1 block">Attack Vector</label>
              <select
                value={liveAttackType}
                onChange={(e) => setLiveAttackType(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-rose-500"
              >
                <option value="ssh_bruteforce">💥 SSH Brute Force Authentication Flood (Port 22)</option>
                <option value="web_sqli">🌐 Web SQL Injection & Path Traversal Fuzzing (Port 80)</option>
                <option value="port_scan">🔍 TCP Port Discovery & Reconnaissance Scan</option>
              </select>
              <span className="text-[10px] text-slate-500 mt-1 block">Kiểu tấn công sẽ phát sinh trên máy ảo</span>
            </div>

            {/* Attempts Slider */}
            <div>
              <label className="text-slate-300 font-semibold mb-1 block">Number of Attempts: {liveAttempts}</label>
              <input
                type="range"
                min="3"
                max="15"
                value={liveAttempts}
                onChange={(e) => setLiveAttempts(parseInt(e.target.value))}
                className="w-full mt-2 accent-rose-500 cursor-pointer"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Số lần gửi gói tin đăng nhập sai</span>
            </div>
          </div>

          <div className="flex items-center justify-between pt-2">
            <div className="text-[11px] text-slate-400 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>Đích đến: <strong>{targetVmIp}</strong> | Nguồn tấn công giả lập: <strong className="text-amber-300 font-mono">{spoofedAttackerIp}</strong></span>
            </div>

            <button
              onClick={handleLaunchLiveVmAttack}
              disabled={loading}
              className="px-6 py-2.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs flex items-center gap-2 shadow-lg shadow-rose-600/30 transition"
            >
              <Flame className="w-4 h-4" />
              <span>{loading ? 'Attacking VM...' : `Launch Attack (Fake Origin: ${spoofedAttackerIp})`}</span>
            </button>
          </div>

          {/* Live Attack Terminal Log Output */}
          {liveAttackLogs && (
            <div className="p-4 rounded-xl bg-slate-950 border border-rose-500/40 space-y-3 animate-in fade-in">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-rose-300 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-rose-400" />
                  Live Attack Execution Results ({liveAttackLogs.attack_type.toUpperCase()}):
                </span>
                <div className="flex items-center gap-3">
                  {liveAttackLogs.incident_id && (
                    <button
                      onClick={() => onSelectIncident(liveAttackLogs.incident_id)}
                      className="text-[11px] font-bold text-cyan-300 hover:text-cyan-200 flex items-center gap-1"
                    >
                      <span>Investigate Incident #{liveAttackLogs.incident_id} &rarr;</span>
                    </button>
                  )}
                  <span className="font-mono text-[10px] text-slate-400">Target: {liveAttackLogs.target_ip}</span>
                </div>
              </div>

              <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-300 space-y-1 max-h-64 overflow-y-auto">
                {liveAttackLogs.logs?.map((log, idx) => (
                  <div 
                    key={idx} 
                    className={
                      log.startsWith('[+]') 
                        ? 'text-emerald-400' 
                        : log.startsWith('[!]') 
                        ? 'text-amber-300' 
                        : log.startsWith('[✓]')
                        ? 'text-emerald-300 font-bold'
                        : log.startsWith('[i]')
                        ? 'text-cyan-300 font-semibold'
                        : 'text-slate-400'
                    }
                  >
                    {log}
                  </div>
                ))}
              </div>

              <div className="flex items-center justify-end gap-3 pt-1">
                <button
                  onClick={onGoApprovals}
                  className="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 shadow-lg shadow-amber-500/20 transition"
                >
                  <span>Go to Human Approvals (Block {spoofedAttackerIp}) &rarr;</span>
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: Custom JSON Webhook Tester */}
      {activeTab === 'custom' && (
        <div className="glass-panel p-6 rounded-xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              Custom Webhook Payload Tester (POST /api/v1/alerts/webhook)
            </h3>
            <span className="text-xs text-slate-400 font-mono">Format: Wazuh, Suricata, or Generic JSON</span>
          </div>

          <textarea
            rows={8}
            value={customJson}
            onChange={(e) => setCustomJson(e.target.value)}
            className="w-full p-4 rounded-xl bg-slate-900 border border-slate-700 font-mono text-xs text-cyan-300 focus:outline-none focus:border-cyan-500 leading-relaxed"
          />

          <div className="flex justify-end">
            <button
              onClick={handleSendCustom}
              disabled={loading}
              className="px-6 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-2 shadow-lg shadow-cyan-500/20 transition"
            >
              <Send className="w-4 h-4" />
              <span>{loading ? 'Sending...' : 'Send Alert Payload'}</span>
            </button>
          </div>
        </div>
      )}

      {/* Simulation Results Output */}
      {simulationResult && (
        <div className="glass-panel p-6 rounded-xl border border-emerald-500/40 bg-emerald-950/10 space-y-4 animate-in fade-in zoom-in-95">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
              <CheckCircle2 className="w-5 h-5" />
              <span>Simulation Ingested & Playbook Triggered Successfully!</span>
            </div>
            <span className="text-xs font-mono text-slate-400">
              Alert ID: <strong className="text-slate-200">{simulationResult.alert_id}</strong>
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
              <div className="text-slate-400">Incident Associated:</div>
              <div className="font-bold text-cyan-400 mt-0.5">#{simulationResult.incident_id || 'Auto-created'}</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
              <div className="text-slate-400">Severity:</div>
              <div className="font-bold text-orange-400 mt-0.5 uppercase">{simulationResult.severity}</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
              <div className="text-slate-400">Source Entity:</div>
              <div className="font-bold text-slate-200 mt-0.5 truncate">{simulationResult.source_ip || simulationResult.hostname || 'N/A'}</div>
            </div>
          </div>

          <div className="flex items-center justify-end gap-3 pt-2">
            {simulationResult.incident_id && (
              <button
                onClick={() => onSelectIncident(simulationResult.incident_id)}
                className="px-4 py-2 rounded-lg bg-indigo-600/30 hover:bg-indigo-600/40 text-indigo-200 border border-indigo-500/40 text-xs font-semibold flex items-center gap-1.5 transition"
              >
                <span>Investigate Incident #{simulationResult.incident_id}</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            )}

            <button
              onClick={onGoApprovals}
              className="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 shadow-lg shadow-amber-500/20 transition"
            >
              <span>Check Pending Approvals Queue &rarr;</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
