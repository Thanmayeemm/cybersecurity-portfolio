import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts'

const SEVERITY_COLORS = {
  critical: '#f85149',
  high: '#da3633',
  medium: '#d29922',
  low: '#3fb950',
  info: '#58a6ff',
}

export default function AlertsBySeverity({ data }) {
  const chartData = data
    ? Object.entries(data).map(([name, value]) => ({ name, value }))
    : []

  return (
    <div className="panel panel-chart">
      <h3>Alerts by Severity</h3>
      <div className="chart-wrap">
        <ResponsiveContainer width="100%" height={180}>
          <PieChart>
            <Pie
              data={chartData}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={70}
              paddingAngle={2}
              label={({ name, value }) => `${name}: ${value}`}
            >
              {chartData.map((entry, i) => (
                <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || '#8b949e'} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)' }}
              formatter={(value) => [value, 'Alerts']}
            />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
