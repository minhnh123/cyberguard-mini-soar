import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Navbar from './components/Navbar';
import ToastContainer, { playAudioCue } from './components/ToastContainer';
import DashboardPage from './pages/DashboardPage';
import IncidentsPage from './pages/IncidentsPage';
import ApprovalsPage from './pages/ApprovalsPage';
import PlaybooksPage from './pages/PlaybooksPage';
import ThreatIntelPage from './pages/ThreatIntelPage';
import SimulatorPage from './pages/SimulatorPage';
import SettingsPage from './pages/SettingsPage';
import { StatsAPI } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [stats, setStats] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // WebSocket & Toast Notifications State
  const [toasts, setToasts] = useState([]);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const [lastWsEvent, setLastWsEvent] = useState(null);

  const addToast = (toast) => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev.slice(-4), { ...toast, id }]);
    if (soundEnabled) {
      playAudioCue(toast.severity || 'info');
    }
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 8000);
  };

  const removeToast = (id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const fetchStats = async () => {
    try {
      setIsRefreshing(true);
      const data = await StatsAPI.getDashboard();
      setStats(data);
    } catch (err) {
      console.error('Failed to fetch stats', err);
    } finally {
      setIsRefreshing(false);
    }
  };

  // WebSocket Real-time Connection
  useEffect(() => {
    let ws = null;
    let reconnectTimeout = null;

    const connectWebSocket = () => {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host;
      const wsUrl = `${protocol}//${host}/api/v1/ws/events`;

      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            const { event: evtType, data } = msg;

            setLastWsEvent({ type: evtType, data, timestamp: Date.now() });
            fetchStats();

            if (evtType === 'NEW_ALERT') {
              addToast({
                type: 'NEW_ALERT',
                title: data.is_correlated
                  ? `⚡ Correlated Alert (${data.alert_count}x)`
                  : `🚨 New Alert [${(data.severity || 'medium').toUpperCase()}]`,
                message: `${data.title} ${data.source_ip ? `(${data.source_ip})` : ''}`,
                severity: data.severity,
                incidentId: data.incident_id,
                time: new Date().toLocaleTimeString()
              });
            } else if (evtType === 'PENDING_APPROVAL') {
              addToast({
                type: 'PENDING_APPROVAL',
                title: `⚠️ Action Pending Approval`,
                message: `Action '${data.action_type}' for target '${data.target}' (${data.connector})`,
                severity: 'high',
                isApproval: true,
                incidentId: data.incident_id,
                time: new Date().toLocaleTimeString()
              });
            } else if (evtType === 'APPROVAL_RESOLVED') {
              addToast({
                type: 'APPROVAL_RESOLVED',
                title: `Action ${data.decision === 'approve' ? 'Approved' : 'Rejected'}`,
                message: `Target ${data.target} on ${data.connector}`,
                severity: data.status === 'executed' ? 'low' : 'medium',
                incidentId: data.incident_id,
                time: new Date().toLocaleTimeString()
              });
            } else if (evtType === 'TARGET_UNBLOCKED') {
              addToast({
                type: 'TARGET_UNBLOCKED',
                title: `🔓 Firewall Rule Reverted`,
                message: `Target ${data.target} unblocked on ${data.connector}`,
                severity: 'info',
                incidentId: data.incident_id,
                time: new Date().toLocaleTimeString()
              });
            }
          } catch (e) {
            console.error('Error parsing WS event', e);
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimeout = setTimeout(connectWebSocket, 4000);
        };

        ws.onerror = () => {
          ws.close();
        };
      } catch (err) {
        setWsConnected(false);
        reconnectTimeout = setTimeout(connectWebSocket, 4000);
      }
    };

    connectWebSocket();

    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, [soundEnabled]);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleSelectIncident = (id) => {
    setSelectedIncidentId(id);
    setActiveTab('incidents');
  };

  const handleGoApprovals = () => {
    setActiveTab('approvals');
  };

  const handleOpenSimulator = () => {
    setActiveTab('simulator');
  };

  const pendingApprovalsCount = stats?.kpis?.pending_approvals || 0;
  const openIncidentsCount = stats?.kpis?.open_incidents || 0;

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
      {/* Toast Notifications Overlay */}
      <ToastContainer
        toasts={toasts}
        onDismiss={removeToast}
        onSelectIncident={handleSelectIncident}
        onGoApprovals={handleGoApprovals}
        soundEnabled={soundEnabled}
        onToggleSound={() => setSoundEnabled((prev) => !prev)}
      />

      {/* Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={(tab) => {
          setActiveTab(tab);
          if (tab !== 'incidents') setSelectedIncidentId(null);
        }}
        pendingApprovalsCount={pendingApprovalsCount}
        openIncidentsCount={openIncidentsCount}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Navbar
          activeTab={activeTab}
          onRefresh={fetchStats}
          isRefreshing={isRefreshing}
          pendingApprovalsCount={pendingApprovalsCount}
          onOpenSimulator={handleOpenSimulator}
          onGoApprovals={handleGoApprovals}
          wsConnected={wsConnected}
        />

        <main className="flex-1 overflow-y-auto bg-slate-950/80">
          {activeTab === 'dashboard' && (
            <DashboardPage
              lastWsEvent={lastWsEvent}
              onSelectIncident={handleSelectIncident}
              onGoApprovals={handleGoApprovals}
              onOpenSimulator={handleOpenSimulator}
            />
          )}

          {activeTab === 'incidents' && (
            <IncidentsPage
              lastWsEvent={lastWsEvent}
              selectedIncidentId={selectedIncidentId}
              onClearSelectedIncident={() => setSelectedIncidentId(null)}
            />
          )}

          {activeTab === 'approvals' && (
            <ApprovalsPage 
              lastWsEvent={lastWsEvent}
              onSelectIncident={handleSelectIncident} 
            />
          )}

          {activeTab === 'playbooks' && <PlaybooksPage />}

          {activeTab === 'threat-intel' && <ThreatIntelPage />}

          {activeTab === 'simulator' && (
            <SimulatorPage
              onSelectIncident={handleSelectIncident}
              onGoApprovals={handleGoApprovals}
            />
          )}

          {activeTab === 'settings' && <SettingsPage />}
        </main>
      </div>
    </div>
  );
}
