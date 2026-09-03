import React from 'react';

export default function SeverityBadge({ severity, className = '' }) {
  const sev = (severity || 'medium').toLowerCase();
  
  const styles = {
    critical: 'bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-sm shadow-rose-950',
    high: 'bg-orange-500/20 text-orange-300 border-orange-500/40 shadow-sm shadow-orange-950',
    medium: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
    low: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
    info: 'bg-sky-500/20 text-sky-300 border-sky-500/40'
  };

  const dots = {
    critical: 'bg-rose-400 animate-ping',
    high: 'bg-orange-400',
    medium: 'bg-amber-400',
    low: 'bg-emerald-400',
    info: 'bg-sky-400'
  };

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider border ${styles[sev] || styles.medium} ${className}`}>
      <span className="relative flex h-2 w-2">
        {sev === 'critical' && (
          <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${dots[sev]}`}></span>
        )}
        <span className={`relative inline-flex rounded-full h-2 w-2 ${dots[sev] || dots.medium}`}></span>
      </span>
      {sev}
    </span>
  );
}
