import React from 'react';
import { Shield } from 'lucide-react';

export default function MitreBadge({ techniqueId, techniqueName, tactic }) {
  return (
    <div className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-indigo-950/60 border border-indigo-500/30 text-indigo-200 text-xs font-mono">
      <Shield className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
      <span className="font-bold text-indigo-300">{techniqueId}</span>
      {techniqueName && <span className="text-slate-300 truncate max-w-[160px]">{techniqueName}</span>}
      {tactic && <span className="text-[10px] text-indigo-400/80 uppercase px-1 py-0.5 rounded bg-indigo-900/40">({tactic})</span>}
    </div>
  );
}
