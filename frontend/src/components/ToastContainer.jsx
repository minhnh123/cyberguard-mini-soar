import React from 'react';
import { 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  Info, 
  X, 
  Unlock, 
  ExternalLink,
  Volume2,
  VolumeX
} from 'lucide-react';

/**
 * Phát âm thanh radar / cyber chime trực tiếp bằng Web Audio API
 * mà không cần tải bất kỳ file audio ngoài nào.
 */
export const playAudioCue = (type = 'alert') => {
  try {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (!AudioContext) return;
    const ctx = new AudioContext();
    if (ctx.state === 'suspended') {
      ctx.resume();
    }
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    const now = ctx.currentTime;
    if (type === 'critical' || type === 'high') {
      // 2 xung âm thanh cảnh báo dồn dập (Dual high-pitch chirp)
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(750, now);
      osc.frequency.exponentialRampToValueAtTime(1100, now + 0.08);
      osc.frequency.setValueAtTime(900, now + 0.12);
      osc.frequency.exponentialRampToValueAtTime(1300, now + 0.24);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.005, now + 0.28);
      osc.start(now);
      osc.stop(now + 0.28);
    } else {
      // Âm thanh sonar cyber nhẹ nhàng (Gentle tech chime)
      osc.type = 'sine';
      osc.frequency.setValueAtTime(523.25, now); // C5
      osc.frequency.exponentialRampToValueAtTime(783.99, now + 0.18); // G5
      gain.gain.setValueAtTime(0.08, now);
      gain.gain.exponentialRampToValueAtTime(0.005, now + 0.22);
      osc.start(now);
      osc.stop(now + 0.22);
    }
  } catch (e) {
    // Trình duyệt có thể chặn autoplay trước khi có tương tác người dùng
  }
};

export default function ToastContainer({ 
  toasts = [], 
  onDismiss, 
  onSelectIncident, 
  onGoApprovals,
  soundEnabled = true,
  onToggleSound 
}) {
  if (toasts.length === 0) return null;

  const getToastIcon = (type, severity) => {
    if (type === 'TARGET_UNBLOCKED') {
      return <Unlock className="w-4 h-4 text-cyan-400 shrink-0" />;
    }
    if (type === 'APPROVAL_RESOLVED') {
      return <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />;
    }
    if (severity === 'critical' || severity === 'high') {
      return <ShieldAlert className="w-4 h-4 text-rose-400 animate-pulse shrink-0" />;
    }
    if (severity === 'medium') {
      return <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />;
    }
    return <Info className="w-4 h-4 text-cyan-400 shrink-0" />;
  };

  const getBorderColor = (severity) => {
    switch (severity) {
      case 'critical': return 'border-rose-500/60 shadow-rose-950/60';
      case 'high': return 'border-orange-500/60 shadow-orange-950/60';
      case 'medium': return 'border-amber-500/50 shadow-amber-950/50';
      default: return 'border-cyan-500/50 shadow-cyan-950/50';
    }
  };

  return (
    <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2.5 max-w-md w-full pointer-events-none px-3">
      {/* Sound Mute Toggle Button */}
      <div className="self-end pointer-events-auto">
        <button
          onClick={onToggleSound}
          className="p-1.5 rounded-lg bg-slate-900/90 border border-slate-700/80 text-slate-400 hover:text-cyan-300 hover:border-cyan-500/50 text-[10px] font-mono flex items-center gap-1.5 shadow-lg backdrop-blur transition"
          title={soundEnabled ? "Mute SOC Audio Alerts" : "Enable SOC Audio Alerts"}
        >
          {soundEnabled ? <Volume2 className="w-3.5 h-3.5 text-cyan-400" /> : <VolumeX className="w-3.5 h-3.5 text-slate-500" />}
          <span className="hidden sm:inline">{soundEnabled ? "Sound ON" : "Muted"}</span>
        </button>
      </div>

      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={`pointer-events-auto p-4 rounded-xl bg-slate-950/95 backdrop-blur-md border ${getBorderColor(toast.severity)} shadow-2xl space-y-2 transform transition-all duration-300 ease-out translate-y-0`}
        >
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-2 min-w-0">
              {getToastIcon(toast.type, toast.severity)}
              <span className="text-xs font-bold text-slate-100 truncate">
                {toast.title}
              </span>
            </div>
            <button
              onClick={() => onDismiss(toast.id)}
              className="text-slate-500 hover:text-slate-300 p-0.5 rounded transition"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
            {toast.message}
          </p>

          <div className="flex items-center justify-between pt-1 border-t border-slate-800/80 text-[11px]">
            <span className="text-slate-500 font-mono">
              {toast.time || 'Just now'}
            </span>

            <div className="flex items-center gap-2">
              {toast.incidentId && onSelectIncident && (
                <button
                  onClick={() => {
                    onSelectIncident(toast.incidentId);
                    onDismiss(toast.id);
                  }}
                  className="px-2.5 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 font-semibold flex items-center gap-1 transition"
                >
                  <span>View Incident</span>
                  <ExternalLink className="w-3 h-3" />
                </button>
              )}
              {toast.isApproval && onGoApprovals && (
                <button
                  onClick={() => {
                    onGoApprovals();
                    onDismiss(toast.id);
                  }}
                  className="px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 font-semibold flex items-center gap-1 transition"
                >
                  <span>Review Approval</span>
                  <ExternalLink className="w-3 h-3" />
                </button>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
