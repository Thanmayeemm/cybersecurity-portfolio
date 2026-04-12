function formatTime(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  return d.toLocaleTimeString()
}

export default function EventStream({ alerts, connected }) {
  return (
    <div className="panel panel-stream">
      <h3>
        Real-time Event Stream
        <span className={`stream-status ${connected ? 'live' : 'off'}`}>
          {connected ? '● Live' : '○ Disconnected'}
        </span>
      </h3>
      <div className="stream-list">
        {!alerts?.length ? (
          <p className="muted">
            {connected ? 'Waiting for new alerts…' : 'Connect to backend for live alerts.'}
          </p>
        ) : (
          alerts.map((a, i) => (
            <div key={`${a.id}-${i}`} className={`stream-item severity-${a.severity}`}>
              <span className="stream-time mono">{formatTime(a.timestamp)}</span>
              <span className="stream-severity">{a.severity}</span>
              <span className="stream-type">{a.alert_type?.replace(/_/g, ' ')}</span>
              <span className="stream-ip mono">{a.source_ip}</span>
              <span className="stream-desc">{a.description || '—'}</span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
