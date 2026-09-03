import React, { useState } from 'react';
import { 
  Search, 
  Globe, 
  ShieldCheck, 
  ShieldAlert, 
  FileCode, 
  Activity, 
  Server, 
  MapPin, 
  ExternalLink,
  Zap
} from 'lucide-react';
import { ThreatIntelAPI } from '../services/api';

export default function ThreatIntelPage() {
  const [iocType, setIocType] = useState('ip');
  const [iocValue, setIocValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleLookup = async (e) => {
    if (e) e.preventDefault();
    if (!iocValue.trim()) return;

    try {
      setLoading(true);
      setError('');
      setResult(null);
      const data = await ThreatIntelAPI.lookup(iocType, iocValue.trim());
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Lookup failed');
    } finally {
      setLoading(false);
    }
  };

  const sampleLookups = [
    { type: 'ip', value: '185.220.101.45', label: 'Tor Exit Node / Brute Force IP' },
    { type: 'ip', value: '8.8.8.8', label: 'Google Public DNS' },
    { type: 'ip', value: '192.168.1.1', label: 'Internal LAN Gateway' },
    { type: 'hash', value: '44d88612fea8a8f36de82e1278abb02f', label: 'EICAR Test Antivirus Hash' }
  ];

  const vtData = result?.enrichment?.virustotal || result?.enrichment?.virustotal_file;
  const geoData = result?.enrichment?.ip_geo;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header Banner */}
      <div className="p-5 rounded-xl bg-gradient-to-r from-cyan-950/40 via-slate-900 to-slate-900 border border-cyan-500/30 flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-cyan-200 flex items-center gap-2">
            <Search className="w-5 h-5 text-cyan-400" />
            Threat Intelligence & IOC Scanner
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Enrich IP addresses, domain names, and file hashes in real-time with Geolocation, ASN, and VirusTotal reputation.
          </p>
        </div>

        {/* Quick Sample Buttons */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-[11px] text-slate-400 font-mono">Samples:</span>
          {sampleLookups.map((s, idx) => (
            <button
              key={idx}
              onClick={() => {
                setIocType(s.type);
                setIocValue(s.value);
              }}
              className="text-[11px] px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition font-mono"
            >
              {s.value}
            </button>
          ))}
        </div>
      </div>

      {/* Search Input Bar */}
      <form onSubmit={handleLookup} className="glass-panel p-4 rounded-xl border border-slate-800 flex flex-col sm:flex-row items-center gap-3">
        <select
          value={iocType}
          onChange={(e) => setIocType(e.target.value)}
          className="w-full sm:w-40 px-3 py-2.5 rounded-lg bg-slate-900 border border-slate-700 text-xs font-semibold text-slate-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="ip">IP Address</option>
          <option value="domain">Domain Name</option>
          <option value="hash">File Hash (MD5/SHA256)</option>
        </select>

        <input
          type="text"
          placeholder={
            iocType === 'ip' ? 'Enter IP address e.g. 185.220.101.45...' :
            iocType === 'domain' ? 'Enter domain e.g. malicious-c2-domain.com...' :
            'Enter MD5, SHA1, or SHA256 file hash...'
          }
          value={iocValue}
          onChange={(e) => setIocValue(e.target.value)}
          className="flex-1 w-full px-4 py-2.5 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
        />

        <button
          type="submit"
          disabled={loading}
          className="w-full sm:w-auto px-6 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 transition shrink-0"
        >
          <Search className="w-4 h-4" />
          <span>{loading ? 'Scanning...' : 'Scan IOC'}</span>
        </button>
      </form>

      {/* Error display */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Results Display */}
      {result && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 animate-in fade-in zoom-in-95">
          {/* Card 1: Geolocation & Network Infrastructure */}
          {geoData && (
            <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <MapPin className="w-4 h-4 text-cyan-400" />
                  IP Geolocation & ISP
                </h3>
                {geoData.is_private ? (
                  <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    Private Subnet
                  </span>
                ) : (
                  <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold">
                    {geoData.countryCode || 'GLOBAL'}
                  </span>
                )}
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-[11px] text-slate-400">Country:</div>
                  <div className="font-semibold text-slate-200 mt-0.5">{geoData.country || 'N/A'}</div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-[11px] text-slate-400">City / Region:</div>
                  <div className="font-semibold text-slate-200 mt-0.5">{geoData.city || geoData.regionName || 'N/A'}</div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-[11px] text-slate-400">ISP / Carrier:</div>
                  <div className="font-semibold text-slate-200 mt-0.5 truncate">{geoData.isp || 'N/A'}</div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-[11px] text-slate-400">Autonomous System:</div>
                  <div className="font-semibold text-slate-200 mt-0.5 truncate">{geoData.as || 'N/A'}</div>
                </div>
              </div>
            </div>
          )}

          {/* Card 2: VirusTotal Reputation & Malicious Engine Breakdown */}
          {vtData && (
            <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-rose-400" />
                  VirusTotal Antivirus Engine Matrix
                </h3>
                <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded border font-bold ${
                  vtData.reputation === 'malicious'
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse'
                    : vtData.reputation === 'clean'
                    ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                    : 'bg-slate-800 text-slate-400 border-slate-700'
                }`}>
                  {vtData.reputation}
                </span>
              </div>

              {vtData.stats ? (
                <div className="grid grid-cols-3 gap-3 text-center">
                  <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30">
                    <div className="text-xl font-bold font-mono text-rose-400">{vtData.stats.malicious || 0}</div>
                    <div className="text-[11px] text-rose-300">Malicious Detections</div>
                  </div>

                  <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30">
                    <div className="text-xl font-bold font-mono text-amber-400">{vtData.stats.suspicious || 0}</div>
                    <div className="text-[11px] text-amber-300">Suspicious</div>
                  </div>

                  <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
                    <div className="text-xl font-bold font-mono text-emerald-400">{vtData.stats.harmless || 0}</div>
                    <div className="text-[11px] text-emerald-300">Clean Engines</div>
                  </div>
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-400">
                  {vtData.message || 'No VirusTotal detection records or API key not set.'}
                </div>
              )}

              {vtData.tags && vtData.tags.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap pt-2">
                  <span className="text-[11px] text-slate-400">Threat Tags:</span>
                  {vtData.tags.map((tag, i) => (
                    <span key={i} className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono border border-slate-700">
                      #{tag}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
