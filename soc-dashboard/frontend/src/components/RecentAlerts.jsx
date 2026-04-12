function formatTime(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  return d.toLocaleString()
}

export default function RecentAlerts({ alerts, loading }) {
  return (
    <div className="panel panel-table">
      <h3>Recent Security Alerts</h3>
      {loading ? (
        <p className="muted">Loading…</p>
      ) : !alerts?.length ? (
        <p className="muted">No alerts in the selected period.</p>
      ) : (
        <div className="table-wrap">
          <table className="alerts-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Type</th>
                <th>Source IP</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.id}>
                  <td className="mono">{formatTime(a.timestamp)}</td>
                  <td>
                    <span className={`severity-badge severity-${a.severity}`}>{a.severity}</span>
                  </td>
                  <td>{a.alert_type?.replace(/_/g, ' ')}</td>
                  <td className="mono">{a.source_ip}</td>
                  <td className="desc">{a.description || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
