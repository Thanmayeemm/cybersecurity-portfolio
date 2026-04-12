import { useState, useEffect, useCallback } from 'react'
import { fetchMetrics, fetchAlerts, getAlertsWsUrl } from './api/client'
import AlertsBySeverity from './components/AlertsBySeverity'
import FailedLogins from './components/FailedLogins'
import SuspiciousIPs from './components/SuspiciousIPs'
import MalwareDetection from './components/MalwareDetection'
import RecentAlerts from './components/RecentAlerts'
import EventStream from './components/EventStream'
import './App.css'

function App() {
  const [metrics, setMetrics] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [streamAlerts, setStreamAlerts] = useState([])
  const [filters, setFilters] = useState({ severity: '', alert_type: '' })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [wsConnected, setWsConnected] = useState(false)

  const loadMetrics = useCallback(async () => {
    try {
      const data = await fetchMetrics()
      setMetrics(data)
    } catch (e) {
      setError(e.message)
    }
  }, [])

  const loadAlerts = useCallback(async () => {
    try {
      const params = {}
      if (filters.severity) params.severity = filters.severity
      if (filters.alert_type) params.alert_type = filters.alert_type
      params.limit = 50
      const data = await fetchAlerts(params)
      setAlerts(data)
    } catch (e) {
      setError(e.message)
    }
  }, [filters.severity, filters.alert_type])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    Promise.all([loadMetrics(), loadAlerts()]).finally(() => {
      if (!cancelled) setLoading(false)
    })
    return () => { cancelled = true }
  }, [loadMetrics, loadAlerts])

  useEffect(() => {
    const interval = setInterval(loadMetrics, 10000)
    return () => clearInterval(interval)
  }, [loadMetrics])

  useEffect(() => {
    const wsUrl = getAlertsWsUrl()
    const ws = new WebSocket(wsUrl)
    ws.onopen = () => setWsConnected(true)
    ws.onclose = () => setWsConnected(false)
    ws.onmessage = (ev) => {
      try {
        const alert = JSON.parse(ev.data)
        setStreamAlerts((prev) => [alert, ...prev].slice(0, 50))
        loadMetrics()
        loadAlerts()
      } catch (_) {}
    }
    return () => ws.close()
  }, [loadMetrics, loadAlerts])

  const onFilterChange = (key, value) => {
    setFilters((f) => ({ ...f, [key]: value }))
  }

  useEffect(() => {
    loadAlerts()
  }, [loadAlerts])

  if (error) {
    return (
      <div className="app-error">
        <h1>SOC Dashboard</h1>
        <p>Error: {error}. Is the backend running?</p>
      </div>
    )
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-left">
          <h1>SOC Security Dashboard</h1>
          <span className={`live-badge ${wsConnected ? 'live' : 'off'}`}>
            {wsConnected ? '● LIVE' : '○ OFFLINE'}
          </span>
        </div>
        <div className="header-filters">
          <select
            value={filters.severity}
            onChange={(e) => onFilterChange('severity', e.target.value)}
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select
            value={filters.alert_type}
            onChange={(e) => onFilterChange('alert_type', e.target.value)}
          >
            <option value="">All types</option>
            <option value="failed_login">Failed login</option>
            <option value="malware_detection">Malware</option>
            <option value="phishing">Phishing</option>
            <option value="suspicious_ip">Suspicious IP</option>
            <option value="brute_force">Brute force</option>
          </select>
        </div>
      </header>

      {loading && !metrics ? (
        <div className="loading">Loading dashboard…</div>
      ) : (
        <main className="dashboard">
          <section className="panels-row">
            <AlertsBySeverity data={metrics?.alerts_by_severity} />
            <FailedLogins count={metrics?.failed_logins_count} />
            <MalwareDetection count={metrics?.malware_count} />
          </section>
          <section className="panels-row">
            <SuspiciousIPs data={metrics?.top_suspicious_ips} />
            <div className="panel summary-panel">
              <h3>24h Summary</h3>
              <p className="big-number">{metrics?.total_alerts_24h ?? 0}</p>
              <p className="muted">Total alerts</p>
            </div>
          </section>
          <section className="panels-row full">
            <RecentAlerts alerts={alerts} loading={loading} />
          </section>
          <section className="panels-row full">
            <EventStream alerts={streamAlerts} connected={wsConnected} />
          </section>
        </main>
      )}
    </div>
  )
}

export default App
