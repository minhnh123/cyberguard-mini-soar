import React, { useEffect, useState } from 'react';
import { 
  CheckCircle2, 
  XCircle, 
  Clock, 
  ShieldAlert, 
  Terminal, 
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  Lock,
  Flame,
  Globe,
  RotateCcw,
  Trash2,
  ShieldCheck,
  Eye,
  Check,
  Copy,
  X
} from 'lucide-react';
import { ApprovalsAPI, ConnectorsAPI } from '../services/api';
import { formatLocalTime } from '../utils/date';

export default function ApprovalsPage({ onSelectIncident, lastWsEvent }) {
  const [approvals, setApprovals] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('pending');
  const [actionInProgress, setActionInProgress] = useState(false);
  const [notes, setNotes] = useState({});

  // Rollback state
  const [rollbackInProgressId, setRollbackInProgressId] = useState(null);
  const [showRollbackConfirmId, setShowRollbackConfirmId] = useState(null);
  const [rollbackNotes, setRollbackNotes] = useState({});

  // VM Firewall Rules Inspector Modal State
  const [showRulesModal, setShowRulesModal] = useState(false);
  const [activeRulesConnector, setActiveRulesConnector] = useState('linux_ssh');
  const [rulesLoading, setRulesLoading] = useState(false);
  const [vmRulesData, setVmRulesData] = useState(null);
  const [deletingRuleTarget, setDeletingRuleTarget] = useState(null);
  const [showRawOutput, setShowRawOutput] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);

  const loadApprovals = async () => {
    try {
      setLoading(true);
      const data = await ApprovalsAPI.list({
        status: statusFilter === 'all' ? undefined : statusFilter
      });
      setApprovals(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const loadFirewallRules = async (connector = activeRulesConnector) => {
    try {
      setRulesLoading(true);
      const data = await ConnectorsAPI.getFirewallRules(connector);
      setVmRulesData(data);
    } catch (err) {
      setVmRulesData({
        status: 'error',
        connector,
        message: err.message || 'Không thể tải danh sách rule tường lửa.',
        rules_count: 0,
        rules: [],
        raw_output: ''
      });
    } finally {
      setRulesLoading(false);
    }
  };

  useEffect(() => {
    loadApprovals();
  }, [statusFilter, lastWsEvent]);

  // Handle Approve / Reject decision
  const handleDecision = async (approvalId, decision) => {
    try {
      setActionInProgress(true);
      const note = notes[approvalId] || '';
      await ApprovalsAPI.decision(approvalId, decision, note);
      await loadApprovals();
    } catch (err) {
      alert(`Thao tác thất bại: ${err.message}`);
    } finally {
      setActionInProgress(false);
    }
  };

  // Handle Rollback / Undo executed action
  const handleRollback = async (approvalId) => {
    try {
      setRollbackInProgressId(approvalId);
      const note = rollbackNotes[approvalId] || 'Hoàn tác gỡ chặn bởi SOC Analyst';
      const res = await ApprovalsAPI.rollback(approvalId, note);
      setShowRollbackConfirmId(null);
      await loadApprovals();
      if (showRulesModal) {
        await loadFirewallRules(activeRulesConnector);
      }
    } catch (err) {
      alert(`Hoàn tác thất bại: ${err.response?.data?.detail || err.message}`);
    } finally {
      setRollbackInProgressId(null);
    }
  };

  // Handle Delete Rule directly from VM Firewall Rules modal
  const handleDeleteRule = async (target) => {
    if (!window.confirm(`Bạn có chắc chắn muốn gỡ bỏ rule [${target}] khỏi tường lửa ${activeRulesConnector}?`)) {
      return;
    }
    try {
      setDeletingRuleTarget(target);
      await ConnectorsAPI.deleteFirewallRule(activeRulesConnector, target);
      await loadFirewallRules(activeRulesConnector);
      await loadApprovals();
    } catch (err) {
      alert(`Không thể gỡ rule: ${err.message}`);
    } finally {
      setDeletingRuleTarget(null);
    }
  };

  const copyToClipboard = (text) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const getConnectorIcon = (connector) => {
    switch (connector) {
      case 'windows_firewall': return <Terminal className="w-4 h-4 text-cyan-400" />;
      case 'wazuh': return <Lock className="w-4 h-4 text-rose-400" />;
      case 'cloudflare': return <Globe className="w-4 h-4 text-orange-400" />;
      default: return <Flame className="w-4 h-4 text-amber-400" />;
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Top Header Card */}
      <div className="p-5 rounded-xl bg-gradient-to-r from-amber-950/30 via-slate-900 to-slate-900 border border-amber-500/30 flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-amber-200 flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-amber-400" />
            Human-in-the-Loop Security Approval Queue
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            AI Tier-3 automated proposals requiring human verification before executing firewall blocks or endpoint quarantine.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Button: Inspect VM Firewall Rules */}
          <button
            onClick={() => {
              setShowRulesModal(true);
              loadFirewallRules(activeRulesConnector);
            }}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 hover:text-cyan-200 border border-cyan-500/30 text-xs font-semibold flex items-center gap-1.5 transition shadow-sm hover:border-cyan-400/60"
          >
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Xem Rule Máy Ảo</span>
          </button>

          {/* Status Filter Tabs */}
          <div className="flex rounded-lg bg-slate-900 p-1 border border-slate-800 text-xs">
            <button
              onClick={() => setStatusFilter('pending')}
              className={`px-3 py-1.5 rounded-md font-medium transition ${
                statusFilter === 'pending'
                  ? 'bg-amber-500 text-slate-950 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Pending
            </button>
            <button
              onClick={() => setStatusFilter('executed')}
              className={`px-3 py-1.5 rounded-md font-medium transition ${
                statusFilter === 'executed'
                  ? 'bg-emerald-500 text-slate-950 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Executed
            </button>
            <button
              onClick={() => setStatusFilter('reverted')}
              className={`px-3 py-1.5 rounded-md font-medium transition ${
                statusFilter === 'reverted'
                  ? 'bg-purple-600 text-white font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Reverted
            </button>
            <button
              onClick={() => setStatusFilter('rejected')}
              className={`px-3 py-1.5 rounded-md font-medium transition ${
                statusFilter === 'rejected'
                  ? 'bg-rose-500 text-white font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Rejected
            </button>
            <button
              onClick={() => setStatusFilter('all')}
              className={`px-3 py-1.5 rounded-md font-medium transition ${
                statusFilter === 'all'
                  ? 'bg-slate-700 text-slate-100 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All
            </button>
          </div>

          <button
            onClick={loadApprovals}
            title="Tải lại danh sách"
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Approvals List */}
      <div className="space-y-4">
        {loading ? (
          <div className="glass-panel p-12 rounded-xl text-center text-xs text-slate-500">
            <RefreshCw className="w-6 h-6 text-slate-500 animate-spin mx-auto mb-2" />
            Đang tải hàng đợi phê duyệt...
          </div>
        ) : approvals.length === 0 ? (
          <div className="glass-panel p-12 rounded-xl text-center text-xs text-slate-400 space-y-2">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
            <div className="font-semibold text-slate-200">Không có yêu cầu phê duyệt {statusFilter !== 'all' ? `trạng thái "${statusFilter}"` : ''}.</div>
            <div className="text-slate-500">Tất cả đề xuất ngăn chặn đã được xử lý hoặc giải phóng an toàn.</div>
          </div>
        ) : (
          approvals.map((appr) => (
            <div
              key={appr.id}
              className={`glass-panel p-5 rounded-xl border transition space-y-4 ${
                appr.status === 'pending'
                  ? 'border-amber-500/40 bg-amber-950/10'
                  : appr.status === 'executed'
                  ? 'border-emerald-500/30'
                  : appr.status === 'reverted'
                  ? 'border-purple-500/30 bg-purple-950/5'
                  : 'border-rose-500/30'
              }`}
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
                    {getConnectorIcon(appr.connector)}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold uppercase text-slate-100">
                        {appr.action_type.replace('_', ' ')}
                      </span>
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                        {appr.connector}
                      </span>
                      <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded border ${
                        appr.status === 'pending'
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 animate-pulse'
                          : appr.status === 'executed'
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                          : appr.status === 'reverted'
                          ? 'bg-purple-500/20 text-purple-300 border-purple-500/40'
                          : 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                      }`}>
                        {appr.status}
                      </span>
                    </div>
                    <div className="text-xs text-slate-400 mt-0.5">
                      Target Entity: <strong className="text-slate-200 font-mono">{appr.target}</strong>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3 text-right">
                  <button
                    onClick={() => onSelectIncident(appr.incident_id)}
                    className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
                  >
                    <span>View Incident #{appr.incident_id}</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </button>
                  <span className="text-[10px] text-slate-500 font-mono">
                    {formatLocalTime(appr.created_at)}
                  </span>
                </div>
              </div>

              {/* Rationale & Risk */}
              <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800 text-xs space-y-1.5">
                <div className="flex items-center justify-between text-[11px] text-slate-400 font-semibold">
                  <span>AI Tier-3 Investigation Rationale:</span>
                  <span className="text-amber-400 uppercase">Risk Level: {appr.risk_level}</span>
                </div>
                <p className="text-slate-300 leading-relaxed">{appr.reason}</p>
              </div>

              {/* Action Controls for Pending Approvals */}
              {appr.status === 'pending' && (
                <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2 border-t border-slate-800">
                  <input
                    type="text"
                    placeholder="Analyst confirmation note or reason..."
                    value={notes[appr.id] || ''}
                    onChange={(e) => setNotes({ ...notes, [appr.id]: e.target.value })}
                    className="w-full sm:w-80 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
                  />

                  <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
                    <button
                      onClick={() => handleDecision(appr.id, 'reject')}
                      disabled={actionInProgress}
                      className="px-4 py-2 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 text-xs font-semibold transition"
                    >
                      Reject Action
                    </button>
                    <button
                      onClick={() => handleDecision(appr.id, 'approve')}
                      disabled={actionInProgress}
                      className="px-5 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 text-xs font-bold transition flex items-center gap-1.5 shadow-lg shadow-amber-500/20"
                    >
                      <CheckCircle2 className="w-4 h-4" />
                      <span>Approve & Execute Now</span>
                    </button>
                  </div>
                </div>
              )}

              {/* Rollback / Undo Controls for Executed Approvals */}
              {appr.status === 'executed' && (
                <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 border-t border-slate-800/80">
                  <div className="flex items-center gap-2 text-xs text-slate-400">
                    <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span>Quy tắc đang hiệu lực trên <strong className="text-slate-200 font-mono">{appr.connector}</strong></span>
                  </div>

                  {showRollbackConfirmId === appr.id ? (
                    <div className="flex items-center gap-2 w-full sm:w-auto">
                      <input
                        type="text"
                        placeholder="Lý do hoàn tác / unblock..."
                        value={rollbackNotes[appr.id] || ''}
                        onChange={(e) => setRollbackNotes({ ...rollbackNotes, [appr.id]: e.target.value })}
                        className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-amber-500 w-full sm:w-64"
                      />
                      <button
                        onClick={() => handleRollback(appr.id)}
                        disabled={rollbackInProgressId === appr.id}
                        className="px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 text-xs font-bold transition flex items-center gap-1 shrink-0"
                      >
                        {rollbackInProgressId === appr.id ? (
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <RotateCcw className="w-3.5 h-3.5" />
                        )}
                        <span>Xác nhận Hoàn tác</span>
                      </button>
                      <button
                        onClick={() => setShowRollbackConfirmId(null)}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 text-xs transition"
                      >
                        Hủy
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => {
                        setShowRollbackConfirmId(appr.id);
                        setRollbackNotes({
                          ...rollbackNotes,
                          [appr.id]: `Hoàn tác gỡ chặn IP ${appr.target} trên ${appr.connector}`
                        });
                      }}
                      className="px-3.5 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-semibold flex items-center gap-1.5 transition hover:border-amber-400/60"
                    >
                      <RotateCcw className="w-3.5 h-3.5 text-amber-400" />
                      <span>Hoàn tác / Gỡ chặn IP ({appr.target})</span>
                    </button>
                  )}
                </div>
              )}

              {/* Status Note for Reverted Approvals */}
              {appr.status === 'reverted' && (
                <div className="flex items-center gap-2 pt-2 border-t border-slate-800/80 text-xs text-purple-300">
                  <RotateCcw className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                  <span>Yêu cầu này đã được hoàn tác. Rule chặn trên <strong>{appr.connector}</strong> đã được gỡ bỏ an toàn.</span>
                </div>
              )}

              {appr.analyst_note && (
                <div className="text-[11px] text-slate-400 italic">
                  Analyst note: "{appr.analyst_note}"
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* VM FIREWALL RULES INSPECTOR MODAL */}
      {showRulesModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="glass-panel w-full max-w-4xl max-h-[90vh] rounded-2xl border border-slate-700 shadow-2xl flex flex-col overflow-hidden bg-slate-950/95">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                  <Terminal className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                    <span>VM & Host Active Firewall Rules Inspector</span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 font-mono">
                      Live Kernel
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Tra cứu và quản lý các quy tắc chặn thực tế trên máy ảo Kali Linux (iptables) hoặc Windows Firewall
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowRulesModal(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Controls & Tabs */}
            <div className="p-4 border-b border-slate-800/80 bg-slate-900/30 flex flex-wrap items-center justify-between gap-3">
              <div className="flex rounded-lg bg-slate-900 p-1 border border-slate-800 text-xs">
                <button
                  onClick={() => {
                    setActiveRulesConnector('linux_ssh');
                    loadFirewallRules('linux_ssh');
                  }}
                  className={`px-3.5 py-1.5 rounded-md font-medium transition flex items-center gap-2 ${
                    activeRulesConnector === 'linux_ssh'
                      ? 'bg-cyan-600 text-white font-bold shadow'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <span>🐧 Kali Linux VM (iptables)</span>
                </button>
                <button
                  onClick={() => {
                    setActiveRulesConnector('windows_firewall');
                    loadFirewallRules('windows_firewall');
                  }}
                  className={`px-3.5 py-1.5 rounded-md font-medium transition flex items-center gap-2 ${
                    activeRulesConnector === 'windows_firewall'
                      ? 'bg-cyan-600 text-white font-bold shadow'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <span>🪟 Windows Defender Firewall</span>
                </button>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => loadFirewallRules(activeRulesConnector)}
                  disabled={rulesLoading}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 transition border border-slate-700"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${rulesLoading ? 'animate-spin' : ''}`} />
                  <span>Làm mới</span>
                </button>
              </div>
            </div>

            {/* Modal Content / Table */}
            <div className="p-5 flex-1 overflow-y-auto space-y-4">
              {/* Status Banner */}
              {vmRulesData && (
                <div>
                  {vmRulesData.status === 'offline' || vmRulesData.status === 'error' ? (
                    <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300 flex items-start gap-2.5">
                      <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                      <div>
                        <div className="font-semibold">Mất kết nối tới máy ảo</div>
                        <div className="text-rose-300/80 mt-0.5">{vmRulesData.message}</div>
                      </div>
                    </div>
                  ) : (
                    <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                        <span>
                          {activeRulesConnector === 'linux_ssh'
                            ? `Kết nối SSH thành công tới máy ảo ${vmRulesData.host || '192.168.56.107'} (User: ${vmRulesData.user || 'minh'})`
                            : `Đã kết nối với Windows Defender Firewall trên máy host`}
                        </span>
                      </div>
                      <span className="font-mono font-bold bg-emerald-500/20 px-2 py-0.5 rounded text-[11px]">
                        {vmRulesData.rules_count || 0} active rule(s)
                      </span>
                    </div>
                  )}
                </div>
              )}

              {/* Rules Table */}
              {rulesLoading ? (
                <div className="py-16 text-center text-xs text-slate-500 space-y-2">
                  <RefreshCw className="w-7 h-7 text-cyan-400 animate-spin mx-auto" />
                  <div>Đang truy vấn bảng quy tắc iptables trên máy ảo qua SSH...</div>
                </div>
              ) : vmRulesData && vmRulesData.rules && vmRulesData.rules.length > 0 ? (
                <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/40">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 bg-slate-900/80 text-[11px] font-mono text-slate-400 uppercase">
                        <th className="p-3">#</th>
                        <th className="p-3">Hành động</th>
                        <th className="p-3">Giao thức</th>
                        <th className="p-3">IP Nguồn (Target)</th>
                        <th className="p-3">Đích</th>
                        <th className="p-3 text-right">Thao tác</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono">
                      {vmRulesData.rules.map((rule, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/30 transition">
                          <td className="p-3 text-slate-400">
                            #{rule.line_num || idx + 1}
                          </td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                              (rule.target || rule.action || '').toUpperCase() === 'DROP' || (rule.action || '').toUpperCase() === 'BLOCK'
                                ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                                : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                            }`}>
                              {rule.target || rule.action || 'DROP'}
                            </span>
                          </td>
                          <td className="p-3 text-cyan-300">
                            {rule.protocol || rule.direction || 'all'}
                          </td>
                          <td className="p-3">
                            <strong className="text-slate-100 font-bold">
                              {rule.source || rule.remote_ip || rule.name || '0.0.0.0/0'}
                            </strong>
                          </td>
                          <td className="p-3 text-slate-400">
                            {rule.destination || '0.0.0.0/0'}
                          </td>
                          <td className="p-3 text-right">
                            <button
                              onClick={() => handleDeleteRule(rule.source || rule.line_num || rule.name)}
                              disabled={deletingRuleTarget === (rule.source || rule.line_num || rule.name)}
                              className="px-2.5 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 text-[11px] font-semibold transition inline-flex items-center gap-1"
                              title="Gỡ bỏ rule này ngay lập tức"
                            >
                              {deletingRuleTarget === (rule.source || rule.line_num || rule.name) ? (
                                <RefreshCw className="w-3 h-3 animate-spin" />
                              ) : (
                                <Trash2 className="w-3 h-3" />
                              )}
                              <span>Gỡ bỏ</span>
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-12 text-center text-xs text-slate-400 space-y-2 rounded-xl border border-slate-800 bg-slate-900/20">
                  <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto" />
                  <div className="font-semibold text-slate-200">Không có rule nào đang chặn trên Chain INPUT</div>
                  <div className="text-slate-500">Mọi lưu lượng mạng đến máy ảo đang theo chính sách mặc định (ACCEPT).</div>
                </div>
              )}

              {/* Raw Terminal Output Toggle */}
              {vmRulesData?.raw_output && (
                <div className="pt-2 border-t border-slate-800/80">
                  <div className="flex items-center justify-between mb-2">
                    <button
                      onClick={() => setShowRawOutput(!showRawOutput)}
                      className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1.5 transition font-mono"
                    >
                      <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                      <span>{showRawOutput ? 'Ẩn' : 'Xem'} kết quả Terminal gốc ({activeRulesConnector === 'linux_ssh' ? 'iptables -L INPUT -n' : 'netsh advfirewall'})</span>
                    </button>
                    {showRawOutput && (
                      <button
                        onClick={() => copyToClipboard(vmRulesData.raw_output)}
                        className="text-[11px] text-slate-400 hover:text-slate-200 flex items-center gap-1"
                      >
                        {copiedRaw ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedRaw ? 'Đã sao chép' : 'Sao chép output'}</span>
                      </button>
                    )}
                  </div>

                  {showRawOutput && (
                    <pre className="p-3.5 rounded-xl bg-black/90 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-56 leading-relaxed">
                      {vmRulesData.raw_output}
                    </pre>
                  )}
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between text-xs text-slate-400">
              <div>
                Target Host: <strong className="text-slate-200 font-mono">{activeRulesConnector === 'linux_ssh' ? '192.168.56.107' : 'Local Windows Host'}</strong>
              </div>
              <button
                onClick={() => setShowRulesModal(false)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold transition border border-slate-700"
              >
                Đóng
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
