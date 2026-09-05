import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

export const StatsAPI = {
  getDashboard: () => api.get('/stats/dashboard').then(r => r.data),
};

export const AlertsAPI = {
  list: (params) => api.get('/alerts', { params }).then(r => r.data),
  get: (id) => api.get(`/alerts/${id}`).then(r => r.data),
  ingestWebhook: (data) => api.post('/alerts/webhook', data).then(r => r.data),
  simulate: (scenario) => api.post(`/alerts/simulate?scenario=${scenario}`).then(r => r.data),
  launchLiveAttack: (data) => api.post('/alerts/live-attack-vm', data).then(r => r.data),
};

export const IncidentsAPI = {
  list: (params) => api.get('/incidents', { params }).then(r => r.data),
  get: (id) => api.get(`/incidents/${id}`).then(r => r.data),
  update: (id, data) => api.patch(`/incidents/${id}`, data).then(r => r.data),
  reanalyze: (id) => api.post(`/incidents/${id}/reanalyze`).then(r => r.data),
  unblock: (id, data = {}) => api.post(`/incidents/${id}/unblock`, data).then(r => r.data),
  delete: (id) => api.delete(`/incidents/${id}`).then(r => r.data),
};

export const ApprovalsAPI = {
  list: (params) => api.get('/approvals', { params }).then(r => r.data),
  decision: (id, decision, analystNote = '') =>
    api.post(`/approvals/${id}/decision`, { decision, analyst_note: analystNote }).then(r => r.data),
  rollback: (id, analystNote = '') =>
    api.post(`/approvals/${id}/rollback`, { analyst_note: analystNote }).then(r => r.data),
};

export const PlaybooksAPI = {
  list: (params) => api.get('/playbooks', { params }).then(r => r.data),
  get: (id) => api.get(`/playbooks/${id}`).then(r => r.data),
  create: (data) => api.post('/playbooks', data).then(r => r.data),
  update: (id, data) => api.put(`/playbooks/${id}`, data).then(r => r.data),
  delete: (id) => api.delete(`/playbooks/${id}`).then(r => r.data),
  run: (id, incidentId) => api.post(`/playbooks/${id}/run?incident_id=${incidentId}`).then(r => r.data),
};

export const ThreatIntelAPI = {
  lookup: (iocType, iocValue) =>
    api.get(`/threat-intel/lookup`, { params: { ioc_type: iocType, ioc_value: iocValue } }).then(r => r.data),
};

export const ConnectorsAPI = {
  test: (data) => api.post('/connectors/test', data).then(r => r.data),
  getWazuhAgents: () => api.get('/connectors/wazuh/agents').then(r => r.data),
  triggerWazuhScan: (agentId, scanType) =>
    api.post(`/connectors/wazuh/agents/${agentId}/scan`, { scan_type: scanType }).then(r => r.data),
  triggerWazuhAction: (agentId, command) =>
    api.post(`/connectors/wazuh/agents/${agentId}/action`, { command }).then(r => r.data),
  getFirewallRules: (connector = 'linux_ssh') =>
    api.get('/connectors/firewall-rules', { params: { connector } }).then(r => r.data),
  deleteFirewallRule: (connector, target, parameters = {}) =>
    api.post('/connectors/firewall-rules/delete', { connector, target, parameters }).then(r => r.data),
};

export const SettingsAPI = {
  getAll: () => api.get('/settings').then(r => r.data),
  save: (data) => api.post('/settings', data).then(r => r.data),
};

export const MitreAPI = {
  getTechniques: () => api.get('/mitre/techniques').then(r => r.data),
};

export default api;
