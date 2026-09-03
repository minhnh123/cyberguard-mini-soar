import React, { useEffect, useState } from 'react';
import { 
  ShieldAlert, 
  CheckCircle2, 
  Activity, 
  Clock, 
  ArrowUpRight, 
  Zap, 
  AlertTriangle, 
  Globe, 
  Terminal,
  ExternalLink
} from 'lucide-react';
import { StatsAPI, AlertsAPI, IncidentsAPI } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import MitreBadge from '../components/MitreBadge';
import { formatLocalTime } from '../utils/date';

export default function DashboardPage({ onSelectIncident, onGoApprovals, onOpenSimulator, lastWsEvent }) {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      setLoading(true);
      const [statsData, alertsData] = await Promise.all([
        StatsAPI.getDashboard(),
        AlertsAPI.list({ limit: 10 })
      ]);
      setStats(statsData);
      setAlerts(alertsData);
    } catch (err) {
      console.error("Dashboard load error", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, [lastWsEvent]);

  const kpis = stats?.kpis || {};
  const severityBreakdown = stats?.severity_breakdown || {};
  const recentIncidents = stats?.recent_incidents || [];
  const topSourceIps = stats?.top_source_ips || [];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Quick Launch Banner for Lab/Demonstration */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-cyan-950/40 via-slate-900 to-indigo-950/40 border border-cyan-500/30 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-cyan-500/20 border border-cyan-400/40 flex items-center justify-center shrink-0">
            <Zap className="w-5 h-5 text-cyan-400 animate-pulse" />
          </div>
          <div>
            <h3 className="font-semibold text-sm text-cyan-200">Mini SOAR Ready for Ingestion & Live IR</h3>
            <p className="text-xs text-slate-400">
              Universal Webhook active at <code className="text-cyan-300 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">/api/v1/alerts/webhook</code>. Trigger simulated attacks to observe automated triage.
            </p>
          </div>
        </div>
        <button
          onClick={onOpenSimulator}
          className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs transition flex items-center gap-1.5 shrink-0 shadow-lg shadow-cyan-500/20"
        >
          <Zap className="w-4 h-4" />
          <span>Launch Attack Simulator</span>
        </button>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Alerts */}
        <div className="glass-panel p-5 rounded-xl border border-slate-800 glass-panel-hover">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Alerts Ingested</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-slate-100">{kpis.total_alerts || 0}</div>
          <div className="text-[11px] text-slate-400 mt-2 flex items-center gap-1">
            <span className="text-emerald-400 font-medium">100% Parsed</span> across all connectors
          </div>
        </div>

        {/* Active Incidents */}
        <div className="glass-panel p-5 rounded-xl border border-slate-800 glass-panel-hover">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Active Incidents</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-rose-300">{kpis.open_incidents || 0}</div>
          <div className="text-[11px] text-slate-400 mt-2 flex items-center gap-1">
            <span className="text-cyan-400 font-medium">{kpis.contained_incidents || 0}</span> incidents contained
          </div>
        </div>

        {/* Pending Approvals */}
        <div 
          onClick={onGoApprovals}
          className="glass-panel p-5 rounded-xl border border-amber-500/30 hover:border-amber-500/60 transition cursor-pointer glass-panel-hover"
        >
          <div className="flex items-center justify-between text-amber-400/90 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Pending Approvals</span>
            <CheckCircle2 className="w-4 h-4 text-amber-400 animate-pulse" />
          </div>
          <div className="text-3xl font-bold font-mono text-amber-300">{kpis.pending_approvals || 0}</div>
          <div className="text-[11px] text-amber-400/80 mt-2 flex items-center gap-1">
            <span>Human-in-the-Loop Gateway &rarr;</span>
          </div>
        </div>

        {/* Response Execution */}
        <div className="glass-panel p-5 rounded-xl border border-slate-800 glass-panel-hover">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Automated Actions</span>
            <Terminal className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-3xl font-bold font-mono text-emerald-300">{kpis.executed_actions || 0}</div>
          <div className="text-[11px] text-slate-400 mt-2 flex items-center gap-1">
            <Clock className="w-3.5 h-3.5 text-slate-400" />
            <span>Avg Response: <strong className="text-emerald-400 font-mono">{kpis.mttr_minutes || 1.8} min</strong></span>
          </div>
        </div>
      </div>

      {/* Severity Breakdown Bar */}
      <div className="glass-panel p-5 rounded-xl border border-slate-800">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">Incident Severity Distribution</h3>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-between">
            <div>
              <div className="text-xs text-rose-300 font-medium">Critical</div>
              <div className="text-xl font-bold font-mono text-rose-400">{severityBreakdown.critical || 0}</div>
            </div>
            <span className="w-3 h-3 rounded-full bg-rose-500"></span>
          </div>

          <div className="p-3 rounded-lg bg-orange-500/10 border border-orange-500/30 flex items-center justify-between">
            <div>
              <div className="text-xs text-orange-300 font-medium">High</div>
              <div className="text-xl font-bold font-mono text-orange-400">{severityBreakdown.high || 0}</div>
            </div>
            <span className="w-3 h-3 rounded-full bg-orange-500"></span>
          </div>

          <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-between">
            <div>
              <div className="text-xs text-amber-300 font-medium">Medium</div>
              <div className="text-xl font-bold font-mono text-amber-400">{severityBreakdown.medium || 0}</div>
            </div>
            <span className="w-3 h-3 rounded-full bg-amber-500"></span>
          </div>

          <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-between">
            <div>
              <div className="text-xs text-emerald-300 font-medium">Low / Info</div>
              <div className="text-xl font-bold font-mono text-emerald-400">{(severityBreakdown.low || 0) + (severityBreakdown.info || 0)}</div>
            </div>
            <span className="w-3 h-3 rounded-full bg-emerald-500"></span>
          </div>
        </div>
      </div>

      {/* Main Grid: Active Incidents & Live Alert Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Active Incidents List (2 Columns) */}
        <div className="lg:col-span-2 glass-panel p-5 rounded-xl border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                Active Security Incidents (AI Triaged)
              </h2>
              <p className="text-xs text-slate-400">Correlated incidents with confidence scoring & MITRE tactics</p>
            </div>
          </div>

          <div className="space-y-3 flex-1 overflow-y-auto">
            {recentIncidents.length === 0 ? (
              <div className="text-center py-12 text-slate-500 text-xs">
                No incidents detected yet. Launch a test from the Attack Simulator!
              </div>
            ) : (
              recentIncidents.map((inc) => (
                <div
                  key={inc.id}
                  onClick={() => onSelectIncident(inc.id)}
                  className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 hover:border-cyan-500/40 transition cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 group"
                >
                  <div className="space-y-1.5 flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs text-cyan-400 font-semibold">{inc.incident_number}</span>
                      <SeverityBadge severity={inc.severity} />
                      <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded border ${
                        inc.status === 'contained' 
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' 
                          : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                      }`}>
                        {inc.status}
                      </span>
                    </div>

                    <h4 className="text-sm font-medium text-slate-200 group-hover:text-cyan-300 transition truncate">
                      {inc.title}
                    </h4>

                    {inc.mitre_tactics && inc.mitre_tactics.length > 0 && (
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {inc.mitre_tactics.map((tactic, idx) => (
                          <span key={idx} className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-500/30 font-mono">
                            {tactic}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="flex sm:flex-col items-end justify-between sm:justify-center gap-1 shrink-0 text-right">
                    <div className="text-[11px] text-slate-400 font-mono">
                      AI Confidence: <strong className="text-cyan-400">{Math.round((inc.confidence_score || 1) * 100)}%</strong>
                    </div>
                    <div className="text-[10px] text-slate-500">
                      {formatLocalTime(inc.created_at)}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Column: Live Feed & Top Attacking IPs */}
        <div className="space-y-6">
          {/* Top Hostile Source IPs */}
          <div className="glass-panel p-5 rounded-xl border border-slate-800">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
              <Globe className="w-3.5 h-3.5 text-cyan-400" />
              Top Hostile Source IPs
            </h3>
            <div className="space-y-2">
              {topSourceIps.length === 0 ? (
                <div className="text-slate-500 text-xs text-center py-4">No external attacker IPs logged</div>
              ) : (
                topSourceIps.map((item, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2 rounded bg-slate-900/60 border border-slate-800/80 text-xs">
                    <span className="font-mono text-cyan-300 font-medium">{item.ip}</span>
                    <span className="text-[11px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold">
                      {item.count} alert{item.count > 1 ? 's' : ''}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Live Alerts Stream */}
          <div className="glass-panel p-5 rounded-xl border border-slate-800">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                Live Alert Stream
              </h3>
              <span className="text-[10px] text-slate-500 font-mono">Latest 10</span>
            </div>

            <div className="space-y-2.5 max-h-[300px] overflow-y-auto">
              {alerts.length === 0 ? (
                <div className="text-slate-500 text-xs text-center py-6">Waiting for incoming alerts...</div>
              ) : (
                alerts.map((al) => (
                  <div key={al.id} className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                        {al.source}
                      </span>
                      <SeverityBadge severity={al.severity} />
                    </div>
                    <div className="font-medium text-slate-200 truncate">{al.title}</div>
                    {al.source_ip && (
                      <div className="text-[11px] font-mono text-slate-400">
                        Src: <span className="text-slate-200">{al.source_ip}</span>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
