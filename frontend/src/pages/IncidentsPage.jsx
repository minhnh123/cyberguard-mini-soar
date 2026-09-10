import React, { useEffect, useState } from 'react';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  Brain, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  Terminal, 
  Globe, 
  FileText, 
  RefreshCw,
  ExternalLink,
  ChevronRight,
  ShieldCheck,
  Lock,
  Unlock,
  Layers
} from 'lucide-react';
import { IncidentsAPI, ApprovalsAPI } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import MitreBadge from '../components/MitreBadge';
import { formatLocalDateTime, formatLocalTime } from '../utils/date';

export default function IncidentsPage({ selectedIncidentId, onClearSelectedIncident, lastWsEvent }) {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeIncident, setActiveIncident] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [actionInProgress, setActionInProgress] = useState(false);
  const [analystNote, setAnalystNote] = useState('');
  const [deepQuery, setDeepQuery] = useState('');

  const loadIncidents = async () => {
    try {
      setLoading(true);
      const data = await IncidentsAPI.list({
        status: statusFilter || undefined,
        severity: severityFilter || undefined
      });
      setIncidents(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const loadIncidentDetail = async (id) => {
    try {
      setLoadingDetail(true);
      const data = await IncidentsAPI.get(id);
      setActiveIncident(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingDetail(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, [statusFilter, severityFilter, lastWsEvent]);

  useEffect(() => {
    if (activeIncident?.id && lastWsEvent) {
      loadIncidentDetail(activeIncident.id);
    }
  }, [lastWsEvent]);

  useEffect(() => {
    if (selectedIncidentId) {
      loadIncidentDetail(selectedIncidentId);
    }
  }, [selectedIncidentId]);

  const handleDecision = async (approvalId, decision) => {
    try {
      setActionInProgress(true);
      await ApprovalsAPI.decision(approvalId, decision, analystNote || 'Decision from Incident View');
      setAnalystNote('');
      if (activeIncident) {
        await loadIncidentDetail(activeIncident.id);
      }
      await loadIncidents();
    } catch (err) {
      alert(`Action error: ${err.message}`);
    } finally {
      setActionInProgress(false);
    }
  };

  const handleReanalyze = async (query = null) => {
    if (!activeIncident) return;
    try {
      setLoadingDetail(true);
      const payload = (typeof query === 'string' && query.trim()) ? { analyst_query: query.trim() } : {};
      await IncidentsAPI.reanalyze(activeIncident.id, payload);
      await loadIncidentDetail(activeIncident.id);
      await loadIncidents();
      if (typeof query === 'string') {
        setDeepQuery('');
      }
    } catch (err) {
      alert(`Re-analyze error: ${err.message}`);
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleStatusChange = async (newStatus) => {
    if (!activeIncident) return;
    try {
      await IncidentsAPI.update(activeIncident.id, { status: newStatus });
      setActiveIncident({ ...activeIncident, status: newStatus });
      await loadIncidents();
    } catch (err) {
      console.error(err);
    }
  };

  const handleUnblock = async (target, connector) => {
    if (!activeIncident) return;
    const confirmMsg = `Are you sure you want to unblock / rollback containment rule for ${target} (${connector})?`;
    if (!window.confirm(confirmMsg)) return;

    try {
      setActionInProgress(true);
      const res = await IncidentsAPI.unblock(activeIncident.id, {
        target,
        connector,
        analyst_note: analystNote || 'Rollback from SOC Incident Drawer'
      });
      alert(`Unblock result: ${res.execution_result?.message || 'Success'}`);
      await loadIncidentDetail(activeIncident.id);
      await loadIncidents();
    } catch (err) {
      alert(`Unblock error: ${err.response?.data?.detail || err.message}`);
    } finally {
      setActionInProgress(false);
    }
  };

  const filteredIncidents = incidents.filter(inc => 
    inc.title.toLowerCase().includes(search.toLowerCase()) ||
    inc.incident_number.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Controls Bar */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-4 glass-panel p-4 rounded-xl border border-slate-800">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search incident number, title..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto flex-wrap">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="contained">Contained</option>
            <option value="closed">Closed</option>
          </select>

          <button
            onClick={loadIncidents}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Incidents Table / Cards */}
      <div className="glass-panel rounded-xl border border-slate-800 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="font-semibold text-sm text-slate-100">
            Security Incidents ({filteredIncidents.length})
          </h3>
        </div>

        <div className="divide-y divide-slate-800">
          {loading ? (
            <div className="py-12 text-center text-xs text-slate-500">Loading incidents...</div>
          ) : filteredIncidents.length === 0 ? (
            <div className="py-12 text-center text-xs text-slate-500">No incidents match your criteria.</div>
          ) : (
            filteredIncidents.map((inc) => (
              <div
                key={inc.id}
                onClick={() => loadIncidentDetail(inc.id)}
                className="p-4 hover:bg-slate-900/60 transition cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-4 group"
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="font-mono text-xs text-cyan-400 font-bold">{inc.incident_number}</span>
                    <SeverityBadge severity={inc.severity} />
                    <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded border ${
                      inc.status === 'contained'
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        : inc.status === 'closed'
                        ? 'bg-slate-800 text-slate-400 border-slate-700'
                        : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                    }`}>
                      {inc.status}
                    </span>
                    {inc.pending_approvals_count > 0 && (
                      <span className="text-[10px] px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold animate-pulse">
                        {inc.pending_approvals_count} action pending approval
                      </span>
                    )}
                    {inc.alert_count > 1 && (
                      <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-mono font-semibold flex items-center gap-1">
                        <span>⚡</span>
                        <span>{inc.alert_count} alerts correlated</span>
                      </span>
                    )}
                  </div>

                  <div className="text-sm font-semibold text-slate-200 group-hover:text-cyan-300 transition">
                    {inc.title}
                  </div>

                  <div className="text-xs text-slate-400 line-clamp-1">
                    {inc.summary}
                  </div>

                  {inc.mitre_tactics && inc.mitre_tactics.length > 0 && (
                    <div className="flex items-center gap-1.5 pt-1 flex-wrap">
                      {inc.mitre_tactics.map((tactic, idx) => (
                        <span key={idx} className="text-[10px] px-2 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-500/30 font-mono">
                          {tactic}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="flex md:flex-col items-end justify-between md:justify-center gap-1 shrink-0 text-right">
                  <div className="text-xs text-slate-400 font-mono">
                    Confidence: <strong className="text-cyan-400">{Math.round((inc.confidence_score || 1) * 100)}%</strong>
                  </div>
                  <div className="text-[11px] text-slate-500">
                    {formatLocalDateTime(inc.created_at)}
                  </div>
                  <div className="text-xs text-cyan-400 group-hover:translate-x-1 transition pt-1">
                    <span>Investigate</span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Incident Investigation Detail Modal / Drawer */}
      {activeIncident && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-5xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95">
            {/* Header */}
            <div className="p-5 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm font-bold text-cyan-400">{activeIncident.incident_number}</span>
                  <SeverityBadge severity={activeIncident.severity} />
                  <select
                    value={activeIncident.status}
                    onChange={(e) => handleStatusChange(e.target.value)}
                    className="px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-xs font-mono uppercase text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="open">Open</option>
                    <option value="investigating">Investigating</option>
                    <option value="contained">Contained</option>
                    <option value="closed">Closed</option>
                  </select>
                </div>
                <h2 className="text-base font-bold text-slate-100">{activeIncident.title}</h2>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleReanalyze}
                  disabled={loadingDetail}
                  className="px-3 py-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/40 text-xs font-medium transition"
                >
                  <span>{loadingDetail ? 'Analyzing...' : 'AI Re-Analyze'}</span>
                </button>

                <button
                  onClick={() => {
                    setActiveIncident(null);
                    if (onClearSelectedIncident) onClearSelectedIncident();
                  }}
                  className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition"
                >
                  <XCircle className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Scrollable Body */}
            <div className="p-6 overflow-y-auto space-y-6 flex-1">
              {/* AI Triage Analysis Card */}
              <div className="p-5 rounded-xl bg-gradient-to-br from-indigo-950/40 via-slate-900 to-slate-900 border border-indigo-500/30 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="text-sm font-bold text-indigo-300">
                    Tier-3 SOC AI Reasoning & Triage
                  </div>
                  <div className="flex items-center gap-3 text-xs font-mono">
                    <span className="text-slate-400">
                      Confidence: <strong className="text-cyan-400">{Math.round((activeIncident.confidence_score || 1) * 100)}%</strong>
                    </span>
                    <span className="text-slate-400">
                      False Positive Risk: <strong className="text-emerald-400">{Math.round((activeIncident.false_positive_score || 0) * 100)}%</strong>
                    </span>
                  </div>
                </div>

                <div className="text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-4 rounded-lg border border-indigo-500/20 space-y-2">
                  <div className="font-semibold text-slate-200">Attack Narrative:</div>
                  <p>{activeIncident.summary || activeIncident.ai_analysis?.attack_narrative || 'AI triage complete.'}</p>

                  {activeIncident.ai_analysis?.root_cause_analysis && (
                    <>
                      <div className="font-semibold text-slate-200 pt-2">Root Cause Analysis:</div>
                      <p className="text-slate-400">{activeIncident.ai_analysis.root_cause_analysis}</p>
                    </>
                  )}
                </div>

                {/* MITRE ATT&CK Matrix Badges */}
                <div className="space-y-2">
                  <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    MITRE ATT&CK Framework Mapping:
                  </div>
                  <div className="flex items-center gap-2 flex-wrap">
                    {activeIncident.mitre_techniques && activeIncident.mitre_techniques.length > 0 ? (
                      activeIncident.mitre_techniques.map((tech, idx) => (
                        <MitreBadge
                          key={idx}
                          techniqueId={tech.id}
                          techniqueName={tech.name}
                          tactic={tech.tactic}
                        />
                      ))
                    ) : (
                      <span className="text-xs text-slate-500">No specific MITRE techniques mapped yet</span>
                    )}
                  </div>
                </div>

                {/* ReAct Autonomous Investigation Trace */}
                {activeIncident.ai_analysis?.investigation_trail && activeIncident.ai_analysis.investigation_trail.length > 0 && (
                  <div className="space-y-3 pt-3 border-t border-indigo-500/20">
                    <div className="flex items-center justify-between">
                      <div className="text-xs font-semibold uppercase tracking-wider text-indigo-300">
                        ReAct Autonomous Investigation Trace ({activeIncident.ai_analysis.investigation_trail.length} Rounds)
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-900/50 text-indigo-300 border border-indigo-500/30">
                        Explainable Multi-Hop AI
                      </span>
                    </div>

                    <div className="space-y-3">
                      {activeIncident.ai_analysis.investigation_trail.map((step, idx) => (
                        <div key={idx} className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800 text-xs space-y-2.5">
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-cyan-400 font-bold text-[11px]">
                              ROUND {step.round || (idx + 1)}
                            </span>
                            <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-amber-950/40 text-amber-300 border border-amber-500/30">
                              Tool: {step.action}
                            </span>
                          </div>

                          {/* Thought */}
                          <div className="p-2.5 rounded bg-slate-900/90 border-l-2 border-indigo-400 text-slate-300 leading-relaxed">
                            <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-400 mb-1">
                              Investigative Hypothesis (Thought):
                            </div>
                            <p className="italic text-slate-200">{step.thought}</p>
                          </div>

                          {/* Action Input */}
                          {step.action_input && Object.keys(step.action_input).length > 0 && (
                            <div className="text-[11px] font-mono text-slate-400 bg-slate-900/50 px-2.5 py-1.5 rounded border border-slate-800">
                              <span className="text-slate-500">Parameters:</span> {JSON.stringify(step.action_input)}
                            </div>
                          )}

                          {/* Observation */}
                          <div className="space-y-1">
                            <div className="text-[10px] font-bold uppercase tracking-wider text-emerald-400">
                              Live Observation / Evidence:
                            </div>
                            <pre className="p-2.5 rounded bg-black/60 border border-slate-800/80 text-[11px] font-mono text-emerald-300 overflow-x-auto max-h-40 whitespace-pre-wrap">
                              {typeof step.observation === 'object' 
                                ? JSON.stringify(step.observation, null, 2) 
                                : String(step.observation)}
                            </pre>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Interactive ReAct Deep Inquiry */}
                <div className="p-3.5 rounded-lg bg-slate-950/70 border border-indigo-500/30 space-y-2 pt-3">
                  <div className="text-xs font-semibold text-slate-200">
                    Interactive Deep Investigation
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Chỉ thị hoặc đặt câu hỏi chuyên sâu cho SOC AI (ví dụ: "Kiểm tra tiến trình con của PID 4821 và lịch sử đăng nhập SSH gần nhất").
                  </p>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={deepQuery}
                      onChange={(e) => setDeepQuery(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && deepQuery.trim() && !loadingDetail) {
                          handleReanalyze(deepQuery);
                        }
                      }}
                      placeholder="Nhập câu hỏi điều tra chuyên sâu..."
                      disabled={loadingDetail}
                      className="flex-1 px-3 py-2 text-xs bg-slate-900 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                    />
                    <button
                      onClick={() => handleReanalyze(deepQuery)}
                      disabled={loadingDetail || !deepQuery.trim()}
                      className="px-4 py-2 text-xs font-medium rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-50 disabled:cursor-not-allowed transition"
                    >
                      {loadingDetail ? 'Đang điều tra...' : 'Deep Investigate'}
                    </button>
                  </div>
                </div>
              </div>

              {/* Pending Approvals & Automated Actions Section */}
              <div className="space-y-3">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Containment & Response Actions
                </h3>

                {activeIncident.approvals && activeIncident.approvals.filter(a => a.status === 'pending').length > 0 ? (
                  <div className="space-y-3">
                    {activeIncident.approvals.filter(a => a.status === 'pending').map((appr) => (
                      <div key={appr.id} className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/40 space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono font-bold uppercase px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                              {appr.action_type.replace('_', ' ')}
                            </span>
                            <span className="text-xs font-mono text-slate-300">
                              Target: <strong className="text-amber-200">{appr.target}</strong> ({appr.connector})
                            </span>
                          </div>
                          <span className="text-[11px] font-semibold text-amber-400 uppercase">
                            Risk Level: {appr.risk_level}
                          </span>
                        </div>

                        <p className="text-xs text-slate-300">{appr.reason}</p>

                        <div className="flex items-center justify-between gap-3 pt-1 border-t border-amber-500/20">
                          <input
                            type="text"
                            placeholder="Optional analyst note..."
                            value={analystNote}
                            onChange={(e) => setAnalystNote(e.target.value)}
                            className="text-xs px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 flex-1 focus:outline-none"
                          />
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => handleDecision(appr.id, 'reject')}
                              disabled={actionInProgress}
                              className="px-3 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 text-xs font-semibold transition"
                            >
                              Reject
                            </button>
                            <button
                              onClick={() => handleDecision(appr.id, 'approve')}
                              disabled={actionInProgress}
                              className="px-4 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 text-xs font-bold transition shadow-lg shadow-amber-500/20"
                            >
                              <span>Approve & Execute</span>
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-400 flex items-center justify-between">
                    <span>No pending containment approvals for this incident.</span>
                    <span className="text-emerald-400 font-mono text-[11px]">ALL APPROVED / CLEAN</span>
                  </div>
                )}

                {/* Executed Action History */}
                {activeIncident.actions && activeIncident.actions.length > 0 && (
                  <div className="mt-3 space-y-2">
                    <div className="text-[11px] font-semibold text-slate-400 uppercase">Executed Action Log:</div>
                    {activeIncident.actions.map((act) => {
                      const isBlockAction = ['block_ip', 'isolate_wazuh_agent', 'cloudflare_block'].includes(act.action_type);
                      const isUnblockAction = act.action_type === 'unblock_ip';
                      const hasBeenUnblocked = activeIncident.actions.some(
                        (other) => other.action_type === 'unblock_ip' && other.target === act.target
                      );

                      return (
                        <div key={act.id} className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                          <div className="space-y-1 min-w-0 flex-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              {isUnblockAction ? (
                                <span className="text-cyan-400 font-semibold font-mono">
                                  {act.action_type}
                                </span>
                              ) : (
                                <span className="text-emerald-400 font-semibold font-mono">
                                  {act.action_type}
                                </span>
                              )}
                              <span className="text-slate-300 font-mono font-medium">&rarr; {act.target} ({act.connector})</span>
                              {isBlockAction && hasBeenUnblocked && (
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-mono">
                                  UNBLOCKED / REVERTED
                                </span>
                              )}
                            </div>
                            {act.output_message && <div className="text-[11px] text-slate-400 font-mono truncate">{act.output_message}</div>}
                          </div>

                          <div className="flex items-center gap-3 shrink-0">
                            {isBlockAction && !hasBeenUnblocked && (
                              <button
                                onClick={() => handleUnblock(act.target, act.connector)}
                                disabled={actionInProgress}
                                className="px-2.5 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 text-[11px] font-semibold transition"
                                title="Rollback / Unblock this rule on firewall"
                              >
                                <span>Unblock / Rollback</span>
                              </button>
                            )}
                            <span className="text-[10px] text-slate-500 font-mono">{formatLocalTime(act.created_at)}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Raw Alerts Context */}
              <div className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Correlated Raw Alerts ({activeIncident.alerts?.length || 0})
                </h3>
                {activeIncident.alerts?.map((al) => (
                  <div key={al.id} className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 text-xs space-y-2 font-mono">
                    <div className="flex items-center justify-between">
                      <span className="text-cyan-300 font-bold">{al.title}</span>
                      <span className="text-slate-500">{al.source}</span>
                    </div>
                    {al.source_ip && <div>Source IP: <span className="text-slate-200">{al.source_ip}</span></div>}
                    {al.destination_ip && <div>Dest IP: <span className="text-slate-200">{al.destination_ip}</span></div>}
                    {al.file_hash && <div>File Hash: <span className="text-slate-200">{al.file_hash}</span></div>}
                    {al.agent_id && <div>Wazuh Agent ID: <span className="text-slate-200">{al.agent_id} ({al.hostname})</span></div>}
                    {al.raw_payload && (
                      <details className="mt-2 text-[11px] text-slate-400 cursor-pointer">
                        <summary className="hover:text-cyan-300">View Raw Alert JSON Payload</summary>
                        <pre className="mt-2 p-3 bg-slate-900 rounded border border-slate-800 overflow-x-auto text-[10px] text-slate-300">
                          {JSON.stringify(al.raw_payload, null, 2)}
                        </pre>
                      </details>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
