import React from 'react';
import { ShieldCheck, RefreshCw, Zap, Bell, CheckCircle2 } from 'lucide-react';

export default function Navbar({ activeTab, onRefresh, isRefreshing, pendingApprovalsCount = 0, onOpenSimulator, onGoApprovals, wsConnected = true }) {
  const titles = {
    dashboard: 'Security Operations Center (SOC) Overview',
    incidents: 'Incident Investigation & AI Triage Center',
    approvals: 'Human-in-the-Loop Approval Queue',
    playbooks: 'Visual DAG Playbook Builder & Orchestrator',
    'threat-intel': 'Threat Intelligence IOC Scanner',
    simulator: 'Interactive Attack Alert Generator & Testbed',
    settings: 'AI Providers & Response Connectors Settings'
  };

  return (
    <header className="h-16 border-b border-slate-800 bg-slate-900/60 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-20">
      <div className="flex items-center gap-3">
        <h1 className="text-base font-semibold text-slate-100">
          {titles[activeTab] || 'CyberGuard SOAR'}
        </h1>
        <span className="hidden md:inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
          <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-emerald-400 animate-pulse shadow-sm shadow-emerald-400/50' : 'bg-amber-400'}`}></span>
          {wsConnected ? 'LIVE WEBSOCKET' : 'CONNECTING...'}
        </span>
      </div>

      <div className="flex items-center gap-3">
        {/* Quick Pending Approvals alert button */}
        {pendingApprovalsCount > 0 && (
          <button
            onClick={onGoApprovals}
            className="px-3 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-xs font-semibold shadow-sm transition animate-pulse"
          >
            <span>{pendingApprovalsCount} Action{pendingApprovalsCount > 1 ? 's' : ''} Awaiting Approval</span>
          </button>
        )}

        {/* Quick Simulator button */}
        <button
          onClick={onOpenSimulator}
          className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-medium transition"
        >
          <span>Simulate Attack</span>
        </button>

        {/* Refresh button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
          title="Refresh Data"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
        </button>
      </div>
    </header>
  );
}
