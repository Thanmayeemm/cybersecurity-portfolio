const API_BASE = import.meta.env.VITE_API_URL || '';

export async function fetchMetrics() {
  const r = await fetch(`${API_BASE}/api/v1/metrics`);
  if (!r.ok) throw new Error('Failed to fetch metrics');
  return r.json();
}

export async function fetchAlerts(params = {}) {
  const sp = new URLSearchParams(params);
  const r = await fetch(`${API_BASE}/api/v1/alerts?${sp}`);
  if (!r.ok) throw new Error('Failed to fetch alerts');
  return r.json();
}

export function getAlertsWsUrl() {
  const base = import.meta.env.VITE_WS_URL || (typeof location !== 'undefined' ? `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}` : 'ws://localhost:5173');
  return `${base.replace(/\/$/, '')}/api/v1/alerts/ws`;
}
