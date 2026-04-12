import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts'

export default function SuspiciousIPs({ data }) {
  const chartData = (data || []).slice(0, 8).map(({ ip, count }) => ({ ip: ip.slice(-12), count }))

  return (
    <div className="panel panel-chart">
      <h3>Top Suspicious IPs</h3>
      <div className="chart-wrap">
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={chartData} layout="vertical" margin={{ left: 20, right: 20 }}>
            <XAxis type="number" stroke="var(--text-muted)" fontSize={11} />
            <YAxis type="category" dataKey="ip" width={100} stroke="var(--text-muted)" fontSize={11} tick={{ fill: 'var(--text)' }} />
            <Tooltip
              contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)' }}
              formatter={(value) => [value, 'Alerts']}
              labelFormatter={(l) => `IP: ${l}`}
            />
            <Bar dataKey="count" fill="var(--high)" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
