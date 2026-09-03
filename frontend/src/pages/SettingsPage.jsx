import React, { useEffect, useState } from 'react';
import { 
  Settings, 
  Brain, 
  Search, 
  Terminal, 
  Lock, 
  Globe, 
  Save, 
  CheckCircle2, 
  ShieldCheck, 
  Server,
  Zap,
  RefreshCw,
  Play,
  AlertTriangle,
  HardDrive,
  Shield,
  Copy,
  Key
} from 'lucide-react';
import { SettingsAPI, ConnectorsAPI } from '../services/api';

export default function SettingsPage() {
  const [settingsList, setSettingsList] = useState([]);
  const [formData, setFormData] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveStatus, setSaveStatus] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [testingConnector, setTestingConnector] = useState(false);

  // Wazuh VM Agent Scanner States (Tự động load từ localStorage nếu có)
  const [wazuhAgents, setWazuhAgents] = useState(() => {
    try {
      const saved = localStorage.getItem('cyberguard_wazuh_agents');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });
  const [loadingAgents, setLoadingAgents] = useState(false);
  const [wazuhStatusMessage, setWazuhStatusMessage] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [scanningAgentId, setScanningAgentId] = useState(null);

  const loadSettings = async () => {
    try {
      setLoading(true);
      const data = await SettingsAPI.getAll();
      setSettingsList(data);
      const initialForm = {};
      data.forEach(item => {
        initialForm[item.key] = item.value || '';
      });
      setFormData(initialForm);

      // Tự động load agents từ Wazuh VM nếu đã cấu hình
      if (initialForm['WAZUH_API_URL']) {
        handleFetchWazuhAgents();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const [copiedSecret, setCopiedSecret] = useState(false);

  const handleChange = (key, value) => {
    setFormData(prev => ({ ...prev, [key]: value }));
  };

  const generateSecret = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let result = 'cg_soar_';
    for (let i = 0; i < 24; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    handleChange('WEBHOOK_SECRET_KEY', result);
  };

  const copySecret = () => {
    const secret = formData['WEBHOOK_SECRET_KEY'] || 'cyberguard-soar-secret';
    navigator.clipboard.writeText(secret);
    setCopiedSecret(true);
    setTimeout(() => setCopiedSecret(false), 2000);
  };

  const handleSave = async (e) => {
    if (e) e.preventDefault();
    try {
      setSaving(true);
      setSaveStatus('');
      const payload = Object.keys(formData).map(key => {
        const original = settingsList.find(s => s.key === key);
        return {
          key,
          value: formData[key],
          category: original?.category || 'general',
          is_secret: original?.is_secret || false
        };
      });

      await SettingsAPI.save(payload);
      setSaveStatus('Settings saved successfully!');
      setTimeout(() => setSaveStatus(''), 4000);
      await loadSettings();
    } catch (err) {
      alert(`Failed to save settings: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleTestConnector = async (connector) => {
    try {
      setTestingConnector(true);
      setTestResult(null);

      let params = {};
      let target = '127.0.0.1';

      if (connector === 'linux_ssh') {
        target = formData['LINUX_SSH_HOST'] || '192.168.56.107';
        params = {
          host: formData['LINUX_SSH_HOST'] || '192.168.56.107',
          user: formData['LINUX_SSH_USER'] || 'minh',
          password: formData['LINUX_SSH_PASSWORD'] || ''
        };
      } else if (connector === 'cloudflare') {
        params = { token: formData['CLOUDFLARE_API_TOKEN'] || '' };
        target = '185.220.101.45';
      }

      const res = await ConnectorsAPI.test({
        connector,
        action_type: 'test_connection',
        target,
        parameters: params
      });
      setTestResult({ connector, result: res });
    } catch (err) {
      setTestResult({ connector, error: err.message });
    } finally {
      setTestingConnector(false);
    }
  };

  // Fetch VM Agents from Wazuh Manager API
  const handleFetchWazuhAgents = async () => {
    try {
      setLoadingAgents(true);
      setScanResult(null);
      const res = await ConnectorsAPI.getWazuhAgents();
      setWazuhStatusMessage(res.message || '');
      const items = res.data?.affected_items || [];
      setWazuhAgents(items);
      try {
        localStorage.setItem('cyberguard_wazuh_agents', JSON.stringify(items));
      } catch (e) {
        console.error(e);
      }
    } catch (err) {
      setWazuhStatusMessage(`Failed to query Wazuh Manager: ${err.message}`);
    } finally {
      setLoadingAgents(false);
    }
  };

  // Trigger on-demand live scan on VM Agent (Syscheck FIM, SCA, Vulnerability)
  const handleTriggerScan = async (agentId, scanType) => {
    try {
      setScanningAgentId(`${agentId}-${scanType}`);
      setScanResult(null);
      const res = await ConnectorsAPI.triggerWazuhScan(agentId, scanType);
      setScanResult({ agentId, scanType, data: res });
    } catch (err) {
      setScanResult({ agentId, scanType, error: err.message });
    } finally {
      setScanningAgentId(null);
    }
  };

  // Trigger Active Response on VM Agent
  const handleTriggerActiveResponse = async (agentId) => {
    try {
      setScanningAgentId(`${agentId}-ar`);
      setScanResult(null);
      const res = await ConnectorsAPI.triggerWazuhAction(agentId, 'firewall-drop');
      setScanResult({ agentId, scanType: 'Active Response (Firewall Drop)', data: res });
    } catch (err) {
      setScanResult({ agentId, scanType: 'Active Response', error: err.message });
    } finally {
      setScanningAgentId(null);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <Settings className="w-5 h-5 text-cyan-400" />
            AI Providers & Infrastructure Connectors
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Configure LLM API keys (Google Gemini, OpenAI, DeepSeek), VirusTotal, and Response Connectors (Wazuh VM, Firewall, Cloudflare).
          </p>
        </div>

        <button
          onClick={handleSave}
          disabled={saving}
          className="px-6 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-2 shadow-lg shadow-cyan-500/20 transition"
        >
          <Save className="w-4 h-4" />
          <span>{saving ? 'Saving...' : 'Save All Settings'}</span>
        </button>
      </div>

      {saveStatus && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{saveStatus}</span>
        </div>
      )}

      {/* SECTION 1: WAZUH MANAGER VM REST API LIVE SCANNER */}
      <div className="glass-panel p-6 rounded-xl border border-rose-500/40 bg-rose-950/10 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-rose-500/30">
          <div className="flex items-center gap-2 text-sm font-bold text-rose-300">
            <Server className="w-5 h-5 text-rose-400" />
            <span>Wazuh Manager VM REST API & Live Agent Scanner</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleFetchWazuhAgents}
              disabled={loadingAgents}
              className="px-4 py-2 rounded-lg bg-rose-500 hover:bg-rose-400 text-slate-950 font-bold text-xs flex items-center gap-2 shadow-lg shadow-rose-500/20 transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingAgents ? 'animate-spin' : ''}`} />
              <span>{loadingAgents ? 'Querying VM...' : 'Discover & Fetch VM Agents'}</span>
            </button>
          </div>
        </div>

        {/* Wazuh Manager VM Connection Form */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div>
            <label className="text-slate-300 font-semibold mb-1 block">Wazuh Manager VM URL</label>
            <input
              type="text"
              value={formData['WAZUH_API_URL'] || ''}
              onChange={(e) => handleChange('WAZUH_API_URL', e.target.value)}
              placeholder="https://192.168.1.150:55000"
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 font-mono text-cyan-300 focus:outline-none focus:border-rose-500"
            />
            <span className="text-[10px] text-slate-500 mt-1 block">Port 55000 (REST API on Wazuh VM)</span>
          </div>

          <div>
            <label className="text-slate-300 font-semibold mb-1 block">Wazuh API User</label>
            <input
              type="text"
              value={formData['WAZUH_API_USER'] || ''}
              onChange={(e) => handleChange('WAZUH_API_USER', e.target.value)}
              placeholder="wazuh-wui or wazuh"
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 font-mono text-slate-200 focus:outline-none focus:border-rose-500"
            />
          </div>

          <div>
            <label className="text-slate-300 font-semibold mb-1 block">Wazuh API Password</label>
            <input
              type="password"
              value={formData['WAZUH_API_PASSWORD'] || ''}
              onChange={(e) => handleChange('WAZUH_API_PASSWORD', e.target.value)}
              placeholder="••••••••"
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 font-mono text-slate-200 focus:outline-none focus:border-rose-500"
            />
          </div>
        </div>

        {wazuhStatusMessage && (
          <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-xs text-slate-300 font-mono flex items-center justify-between">
            <span>Status: {wazuhStatusMessage}</span>
          </div>
        )}

        {/* Live VM Agents Table & On-Demand Scan Triggers */}
        <div className="space-y-3 pt-2">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Registered Virtual Machine Agents ({wazuhAgents.length})
            </h4>
            <span className="text-[11px] text-slate-400">Click actions below to trigger live scans on your VM</span>
          </div>

          {wazuhAgents.length === 0 ? (
            <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 text-center text-xs text-slate-400 space-y-2">
              <Server className="w-8 h-8 text-slate-600 mx-auto" />
              <div>No VM agents loaded yet. Click <strong>"Discover & Fetch VM Agents"</strong> to query your Wazuh Manager.</div>
            </div>
          ) : (
            <div className="space-y-3">
              {wazuhAgents.map((ag) => (
                <div
                  key={ag.id}
                  className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-cyan-400">Agent ID: #{ag.id}</span>
                      <span className="font-semibold text-sm text-slate-100">{ag.name}</span>
                      <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${
                        ag.status === 'active'
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}>
                        {ag.status}
                      </span>
                    </div>

                    <div className="text-xs text-slate-400 flex items-center gap-4 flex-wrap font-mono">
                      <span>IP: <strong className="text-slate-200">{ag.ip}</strong></span>
                      <span>OS: <strong className="text-slate-200">{ag.os?.name || 'N/A'} {ag.os?.version || ''}</strong></span>
                      <span>Version: <strong className="text-slate-200">{ag.version || 'Wazuh v4'}</strong></span>
                    </div>
                  </div>

                  {/* Scan & Response Action Buttons */}
                  <div className="flex items-center gap-2 flex-wrap">
                    {/* Trigger Syscheck FIM scan */}
                    <button
                      onClick={() => handleTriggerScan(ag.id, 'syscheck')}
                      disabled={scanningAgentId === `${ag.id}-syscheck`}
                      className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-semibold flex items-center gap-1.5 transition"
                      title="Trigger immediate File Integrity & Malware scan"
                    >
                      <HardDrive className="w-3.5 h-3.5" />
                      <span>{scanningAgentId === `${ag.id}-syscheck` ? 'Scanning...' : 'Syscheck (FIM)'}</span>
                    </button>

                    {/* Trigger SCA scan */}
                    <button
                      onClick={() => handleTriggerScan(ag.id, 'sca')}
                      disabled={scanningAgentId === `${ag.id}-sca`}
                      className="px-3 py-1.5 rounded-lg bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/40 text-xs font-semibold flex items-center gap-1.5 transition"
                      title="Trigger Security Configuration Assessment"
                    >
                      <Shield className="w-3.5 h-3.5" />
                      <span>{scanningAgentId === `${ag.id}-sca` ? 'Scanning...' : 'SCA Audit'}</span>
                    </button>

                    {/* Trigger Vulnerability check */}
                    <button
                      onClick={() => handleTriggerScan(ag.id, 'vulnerability')}
                      disabled={scanningAgentId === `${ag.id}-vulnerability`}
                      className="px-3 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-xs font-semibold flex items-center gap-1.5 transition"
                      title="Query CVE Vulnerabilities on VM"
                    >
                      <Search className="w-3.5 h-3.5" />
                      <span>{scanningAgentId === `${ag.id}-vulnerability` ? 'Checking...' : 'Vulnerabilities'}</span>
                    </button>

                    {/* Active Response Test */}
                    <button
                      onClick={() => handleTriggerActiveResponse(ag.id)}
                      disabled={scanningAgentId === `${ag.id}-ar`}
                      className="px-3 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 text-xs font-semibold flex items-center gap-1.5 transition"
                      title="Send test Active Response command to Agent"
                    >
                      <Lock className="w-3.5 h-3.5" />
                      <span>{scanningAgentId === `${ag.id}-ar` ? 'Executing...' : 'Active Response'}</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Scan / Action Results Banner */}
          {scanResult && (
            <div className="p-4 rounded-xl bg-slate-900 border border-cyan-500/40 space-y-2 animate-in fade-in">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-cyan-300 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                  Wazuh VM Live Execution Result (Agent #{scanResult.agentId} - {scanResult.scanType}):
                </span>
                <button
                  onClick={() => setScanResult(null)}
                  className="text-xs text-slate-400 hover:text-slate-200"
                >
                  Dismiss
                </button>
              </div>
              <pre className="p-3 bg-slate-950 rounded border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                {JSON.stringify(scanResult.data || scanResult.error, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>

      {/* SECTION 2: AI REASONING & LLM CONFIGURATION */}
      <div className="glass-panel p-6 rounded-xl border border-slate-800 space-y-4">
        <div className="flex items-center gap-2 text-sm font-bold text-indigo-300 pb-2 border-b border-slate-800">
          <Brain className="w-4 h-4 text-indigo-400" />
          <span>AI Reasoning & LLM Provider Configuration</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div>
            <label className="block text-slate-300 font-semibold mb-1">Active AI Provider</label>
            <select
              value={formData['AI_PROVIDER'] || 'gemini'}
              onChange={(e) => handleChange('AI_PROVIDER', e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="gemini">Google Gemini API (Recommended)</option>
              <option value="openai">OpenAI (GPT-4o / GPT-4o-mini)</option>
              <option value="deepseek">DeepSeek API (DeepSeek-V3 / R1)</option>
              <option value="custom">Custom OpenAI-Compatible (Ollama / Local LLM)</option>
            </select>
            <span className="text-[10px] text-slate-500 mt-1 block">Provider used for automated incident triage & MITRE mapping.</span>
          </div>

          <div>
            <label className="block text-slate-300 font-semibold mb-1">AI Model Name</label>
            <input
              type="text"
              value={formData['AI_MODEL'] || ''}
              onChange={(e) => handleChange('AI_MODEL', e.target.value)}
              placeholder="e.g. gemini-1.5-flash or gpt-4o-mini"
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
            />
            <span className="text-[10px] text-slate-500 mt-1 block">Default: gemini-1.5-flash</span>
          </div>

          <div>
            <label className="block text-slate-300 font-semibold mb-1">Google Gemini API Key</label>
            <input
              type="password"
              value={formData['GEMINI_API_KEY'] || ''}
              onChange={(e) => handleChange('GEMINI_API_KEY', e.target.value)}
              placeholder="AIzaSy..."
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-slate-300 font-semibold mb-1">OpenAI API Key</label>
            <input
              type="password"
              value={formData['OPENAI_API_KEY'] || ''}
              onChange={(e) => handleChange('OPENAI_API_KEY', e.target.value)}
              placeholder="sk-..."
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-slate-300 font-semibold mb-1">DeepSeek API Key</label>
            <input
              type="password"
              value={formData['DEEPSEEK_API_KEY'] || ''}
              onChange={(e) => handleChange('DEEPSEEK_API_KEY', e.target.value)}
              placeholder="sk-..."
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-slate-300 font-semibold mb-1">Custom Base URL (Local LLM / Ollama)</label>
            <input
              type="text"
              value={formData['AI_CUSTOM_BASE_URL'] || ''}
              onChange={(e) => handleChange('AI_CUSTOM_BASE_URL', e.target.value)}
              placeholder="http://localhost:11434/v1"
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>
      </div>

      {/* SECTION 3: THREAT INTEL & OTHER CONNECTORS */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* VirusTotal */}
        <div className="glass-panel p-6 rounded-xl border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 text-sm font-bold text-cyan-300 pb-2 border-b border-slate-800">
            <Search className="w-4 h-4 text-cyan-400" />
            <span>Threat Intelligence</span>
          </div>

          <div className="text-xs space-y-3">
            <div>
              <label className="block text-slate-300 font-semibold mb-1">VirusTotal v3 API Key</label>
              <input
                type="password"
                value={formData['VIRUSTOTAL_API_KEY'] || ''}
                onChange={(e) => handleChange('VIRUSTOTAL_API_KEY', e.target.value)}
                placeholder="64-character VirusTotal API Key"
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-200">IP Geolocation & Whois (IP-API)</div>
                <div className="text-[11px] text-slate-400">Integrated directly (No API Key Required)</div>
              </div>
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                ACTIVE
              </span>
            </div>
          </div>
        </div>

        {/* Windows & Cloudflare Connectors */}
        <div className="glass-panel p-6 rounded-xl border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 text-sm font-bold text-emerald-300 pb-2 border-b border-slate-800">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <span>Firewall & WAF Connectors</span>
          </div>

          <div className="text-xs space-y-3">
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-200">Windows Defender Firewall</div>
                <div className="text-[11px] text-slate-400">`netsh advfirewall` inbound/outbound rules</div>
              </div>
              <button
                type="button"
                onClick={() => handleTestConnector('windows_firewall')}
                disabled={testingConnector}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-[11px]"
              >
                Test
              </button>
            </div>

            {/* Linux SSH VM Connector */}
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-semibold text-slate-200">Linux SSH (Máy ảo Kali / iptables)</div>
                  <div className="text-[11px] text-slate-400">Thực thi lệnh chặn `iptables` trực tiếp trên máy ảo</div>
                </div>
                <button
                  type="button"
                  onClick={() => handleTestConnector('linux_ssh')}
                  disabled={testingConnector}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-rose-300 border border-slate-700 text-[11px]"
                >
                  Test SSH
                </button>
              </div>

              <div className="grid grid-cols-2 gap-2 pt-1">
                <div>
                  <label className="text-[10px] text-slate-400 block mb-0.5">Kali VM IP</label>
                  <input
                    type="text"
                    value={formData['LINUX_SSH_HOST'] || '192.168.56.107'}
                    onChange={(e) => handleChange('LINUX_SSH_HOST', e.target.value)}
                    placeholder="192.168.56.107"
                    className="w-full px-2 py-1 rounded bg-slate-950 border border-slate-700 font-mono text-cyan-300 text-[11px]"
                  />
                </div>
                <div>
                  <label className="text-[10px] text-slate-400 block mb-0.5">SSH Username</label>
                  <input
                    type="text"
                    value={formData['LINUX_SSH_USER'] || 'minh'}
                    onChange={(e) => handleChange('LINUX_SSH_USER', e.target.value)}
                    placeholder="minh or kali"
                    className="w-full px-2 py-1 rounded bg-slate-950 border border-slate-700 font-mono text-slate-200 text-[11px]"
                  />
                </div>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 block mb-0.5">SSH Password (Mật khẩu đăng nhập Kali)</label>
                <input
                  type="password"
                  value={formData['LINUX_SSH_PASSWORD'] || ''}
                  onChange={(e) => handleChange('LINUX_SSH_PASSWORD', e.target.value)}
                  placeholder="Mật khẩu của user minh/kali"
                  className="w-full px-2 py-1 rounded bg-slate-950 border border-slate-700 font-mono text-slate-200 text-[11px]"
                />
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <div className="font-semibold text-slate-200">Cloudflare WAF IP Rules</div>
                <button
                  type="button"
                  onClick={() => handleTestConnector('cloudflare')}
                  disabled={testingConnector}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-orange-300 border border-slate-700 text-[11px]"
                >
                  Test
                </button>
              </div>
              <input
                type="password"
                value={formData['CLOUDFLARE_API_TOKEN'] || ''}
                onChange={(e) => handleChange('CLOUDFLARE_API_TOKEN', e.target.value)}
                placeholder="Cloudflare API Token"
                className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 font-mono text-slate-200 text-[11px]"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Webhook Ingestion Security & Secret Key */}
      <div className="glass-panel p-6 rounded-xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <div className="flex items-center gap-2 text-sm font-bold text-amber-300">
            <Key className="w-4 h-4 text-amber-400" />
            <span>Webhook Ingestion Security & Secret Key</span>
          </div>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
            API Webhook Auth
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                Webhook Secret Token (<code className="text-amber-300 font-mono">X-Webhook-Secret</code>)
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={formData['WEBHOOK_SECRET_KEY'] || 'cyberguard-soar-secret'}
                  onChange={(e) => handleChange('WEBHOOK_SECRET_KEY', e.target.value)}
                  placeholder="cyberguard-soar-secret"
                  className="flex-1 px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 font-mono text-cyan-300 text-xs focus:border-cyan-500 focus:outline-none"
                />
                <button
                  type="button"
                  onClick={generateSecret}
                  className="px-2.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium flex items-center gap-1 transition"
                  title="Generate New Random Secret"
                >
                  <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Generate</span>
                </button>
                <button
                  type="button"
                  onClick={copySecret}
                  className="px-2.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium flex items-center gap-1 transition"
                  title="Copy Secret Token"
                >
                  <Copy className="w-3.5 h-3.5 text-amber-400" />
                  <span>{copiedSecret ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Khóa bí mật chia sẻ dùng để xác thực các hệ thống gửi cảnh báo (Wazuh SIEM, Suricata, Custom scripts).
              </p>
            </div>

            {/* Toggle Enforce Secret */}
            <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
              <div>
                <div className="font-semibold text-xs text-slate-200">Bắt Buộc Xác Thực Webhook Secret</div>
                <div className="text-[11px] text-slate-400">
                  Từ chối HTTP 401 với tất cả các webhook không có header <code className="text-amber-300 font-mono">X-Webhook-Secret</code> hợp lệ.
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData['REQUIRE_WEBHOOK_SECRET'] === 'true'}
                  onChange={(e) => handleChange('REQUIRE_WEBHOOK_SECRET', e.target.checked ? 'true' : 'false')}
                  className="sr-only peer"
                />
                <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-500"></div>
              </label>
            </div>
          </div>

          {/* Code Snippet Preview */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-300 block">
              Mẫu Tích Hợp Header Xác Thực (Wazuh / cURL)
            </label>
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto space-y-2 leading-relaxed">
              <div className="text-slate-500"># Gửi alert qua curl với header bảo mật:</div>
              <div className="text-cyan-300 whitespace-pre">
{`curl -X POST http://localhost:8000/api/v1/alerts/webhook \\
  -H "Content-Type: application/json" \\
  -H "X-Webhook-Secret: ${formData['WEBHOOK_SECRET_KEY'] || 'cyberguard-soar-secret'}" \\
  -d '{"title": "Wazuh Alert", "source_ip": "185.220.101.45"}'`}
              </div>
              <div className="text-slate-500 pt-1"># Cấu hình trong /var/ossec/integrations/custom-soar.py:</div>
              <div className="text-amber-300">
                headers = {'{'}"Content-Type": "application/json", "X-Webhook-Secret": "{formData['WEBHOOK_SECRET_KEY'] || 'cyberguard-soar-secret'}"{'}'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Connector Test Output Banner */}
      {testResult && (
        <div className={`p-4 rounded-xl border space-y-2 animate-in fade-in ${
          testResult.result?.status === 'success'
            ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
            : 'bg-rose-950/30 border-rose-500/40 text-rose-300'
        }`}>
          <div className="flex items-center justify-between text-xs font-bold">
            <span className="flex items-center gap-2">
              {testResult.result?.status === 'success' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-rose-400" />
              )}
              <span>Kết quả kiểm tra bộ điều phối ({testResult.connector.toUpperCase()}):</span>
            </span>
            <button
              onClick={() => setTestResult(null)}
              className="text-xs text-slate-400 hover:text-slate-200"
            >
              Đóng ✕
            </button>
          </div>
          <div className="text-xs font-mono pt-1 text-slate-200">
            {testResult.result?.message || testResult.error}
          </div>
          {testResult.result?.details && (
            <pre className="p-2.5 mt-2 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto">
              {typeof testResult.result.details === 'object' ? JSON.stringify(testResult.result.details, null, 2) : testResult.result.details}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
