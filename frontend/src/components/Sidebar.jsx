import React from 'react';
import { 
  LayoutDashboard, 
  ShieldAlert, 
  CheckCircle2, 
  Workflow, 
  Search, 
  Radio, 
  Settings, 
  Cpu
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab, pendingApprovalsCount = 0, openIncidentsCount = 0 }) {
  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: LayoutDashboard },
    { 
      id: 'incidents', 
      label: 'Incident Triage', 
      icon: ShieldAlert, 
      badge: openIncidentsCount > 0 ? openIncidentsCount : null,
      badgeColor: 'bg-rose-500/20 text-rose-300 border-rose-500/40' 
    },
    { 
      id: 'approvals', 
      label: 'Human Approvals', 
      icon: CheckCircle2, 
      badge: pendingApprovalsCount > 0 ? pendingApprovalsCount : null,
      badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-500/40 animate-pulse' 
    },
    { id: 'playbooks', label: 'Playbook Builder', icon: Workflow },
    { id: 'threat-intel', label: 'Threat Intel Scanner', icon: Search },
    { id: 'simulator', label: 'Attack Simulator', icon: Radio },
    { id: 'settings', label: 'Settings & Connectors', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-slate-900/90 border-r border-slate-800 flex flex-col shrink-0 h-screen sticky top-0">
      {/* Brand Header */}
      <div className="h-16 flex items-center gap-3 px-5 border-b border-slate-800 bg-slate-950/40">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 border border-cyan-400/40">
          <Cpu className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="font-bold text-sm tracking-wide bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
            CYBERGUARD SOAR
          </div>
          <div className="text-[10px] text-slate-400 font-mono flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            AI-POWERED IR ENGINE
          </div>
        </div>
      </div>

      {/* Nav Menu */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500 font-mono">
          Security Operations
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-950'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className={`text-[11px] font-bold px-2 py-0.5 rounded-full border ${item.badgeColor}`}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer system info */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-950/60">
        <div className="rounded-lg p-2.5 bg-slate-900 border border-slate-800 text-xs">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span>Automation Node</span>
            <span className="text-emerald-400 font-mono text-[11px]">ONLINE</span>
          </div>
          <div className="text-[11px] text-slate-500 font-mono truncate">
            FastAPI + Gemini / LLM Tier 3
          </div>
        </div>
      </div>
    </aside>
  );
}
