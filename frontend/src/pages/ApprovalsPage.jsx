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
  Globe
} from 'lucide-react';
import { ApprovalsAPI } from '../services/api';
import { formatLocalTime } from '../utils/date';

export default function ApprovalsPage({ onSelectIncident, lastWsEvent }) {
  const [approvals, setApprovals] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('pending');
  const [actionInProgress, setActionInProgress] = useState(false);
  const [notes, setNotes] = useState({});

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

  useEffect(() => {
    loadApprovals();
  }, [statusFilter, lastWsEvent]);

  const handleDecision = async (approvalId, decision) => {
    try {
      setActionInProgress(true);
      const note = notes[approvalId] || '';
      await ApprovalsAPI.decision(approvalId, decision, note);
      await loadApprovals();
    } catch (err) {
      alert(`Action failed: ${err.message}`);
    } finally {
      setActionInProgress(false);
    }
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

        <div className="flex items-center gap-3">
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
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Approvals List */}
      <div className="space-y-4">
        {loading ? (
          <div className="glass-panel p-12 rounded-xl text-center text-xs text-slate-500">
            Loading approval queue...
          </div>
        ) : approvals.length === 0 ? (
          <div className="glass-panel p-12 rounded-xl text-center text-xs text-slate-400 space-y-2">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
            <div className="font-semibold text-slate-200">No {statusFilter !== 'all' ? statusFilter : ''} approvals found.</div>
            <div className="text-slate-500">All containment proposals are resolved or clean.</div>
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

              {appr.status !== 'pending' && appr.analyst_note && (
                <div className="text-[11px] text-slate-400 italic">
                  Analyst note: "{appr.analyst_note}"
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
