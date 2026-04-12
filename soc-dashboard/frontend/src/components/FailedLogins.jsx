export default function FailedLogins({ count }) {
  const n = count ?? 0
  const severity = n > 50 ? 'critical' : n > 20 ? 'high' : n > 5 ? 'medium' : 'low'

  return (
    <div className="panel">
      <h3>Failed Login Attempts</h3>
      <p className={`big-number severity-${severity}`}>{n}</p>
      <p className="muted">Last 24 hours</p>
    </div>
  )
}
