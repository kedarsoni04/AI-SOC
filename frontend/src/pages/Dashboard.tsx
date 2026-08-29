/**
 * SOC Dashboard Page — main overview with KPIs, charts, and live feed
 */
import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity, AlertTriangle, Siren, Shield, CheckCircle,
  Zap, Play, Square, RefreshCw,
  Eye, BarChart2
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer
} from 'recharts';
import { PageHeader } from '../components/layout/PageHeader';
import { SeverityBadge } from '../components/ui/Badge';
import { useWebSocket } from '../hooks/useWebSocket';
import { get, post } from '../services/api';
import type { DashboardSummary, EventVolumePoint, SecurityEvent, WSMessage } from '../types';
import { formatDistanceToNow } from 'date-fns';



const SCENARIOS = [
  { id: 'normal', label: 'Normal Traffic', color: 'btn-secondary' },
  { id: 'brute_force', label: 'Brute Force', color: 'btn-danger' },
  { id: 'sql_injection', label: 'SQL Injection', color: 'btn-danger' },
  { id: 'port_scan', label: 'Port Scan', color: 'btn-danger' },
  { id: 'account_compromise', label: 'Account Compromise', color: 'btn-danger' },
  { id: 'data_exfiltration', label: 'Data Exfiltration', color: 'btn-danger' },
  { id: 'multi_stage', label: '🔴 Multi-Stage Attack', color: 'btn-danger' },
];

export function Dashboard() {
  const navigate = useNavigate();
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [eventVolume, setEventVolume] = useState<EventVolumePoint[]>([]);
  const [attackTypes, setAttackTypes] = useState<{ attack_type: string; count: number }[]>([]);
  const [topIPs, setTopIPs] = useState<{ ip: string; country: string; count: number }[]>([]);
  const [liveEvents, setLiveEvents] = useState<SecurityEvent[]>([]);
  const [isSimRunning, setIsSimRunning] = useState(false);

  const [lastRefresh, setLastRefresh] = useState(new Date());

  const loadDashboard = useCallback(async () => {
    try {
      const [sum, vol, types, ips] = await Promise.all([
        get<DashboardSummary>('/dashboard/summary'),
        get<EventVolumePoint[]>('/dashboard/event-volume', { hours: 24 }),
        get<{ attack_type: string; count: number }[]>('/dashboard/attack-types'),
        get<{ ip: string; country: string; count: number }[]>('/dashboard/top-source-ips'),
      ]);
      setSummary(sum);
      setEventVolume(vol);
      setAttackTypes(types);
      setTopIPs(ips);
      setIsSimRunning(sum.simulation_status?.is_running ?? false);
      setLastRefresh(new Date());
    } catch (err) {
      console.error('Dashboard load error:', err);
    }
  }, []);

  useEffect(() => {
    loadDashboard();
    const interval = setInterval(loadDashboard, 15000); // refresh every 15s
    return () => clearInterval(interval);
  }, [loadDashboard]);

  // WebSocket for live events
  const handleWsMessage = useCallback((msg: WSMessage) => {
    if (msg.type === 'new_event' && msg.data) {
      const event = msg.data as SecurityEvent;
      setLiveEvents(prev => [event, ...prev].slice(0, 50));
    }
    if (msg.type === 'stats_update' || msg.type === 'incident_update' || msg.type === 'new_alert') {
      loadDashboard();
    }
  }, [loadDashboard]);

  const { isConnected } = useWebSocket({ onMessage: handleWsMessage });

  const handleSimulation = async (scenario: string) => {
    try {
      const action = scenario === 'stop' ? 'stop' : 'start';
      if (action === 'stop') {
        await post('/simulation/stop');
        setIsSimRunning(false);
      } else {
        await post('/simulation/start', { action: 'start', scenario });
        setIsSimRunning(scenario === 'normal');
        // Refresh after scenario
        setTimeout(loadDashboard, 2000);
      }
    } catch (err) {
      console.error('Simulation error:', err);
    }
  };

  const severityPieData = summary ? [
    { name: 'Critical', value: summary.critical_incidents, color: '#ef4444' },
    { name: 'Active', value: summary.active_incidents, color: '#f97316' },
    { name: 'Resolved', value: summary.resolved_incidents, color: '#10b981' },
  ].filter(d => d.value > 0) : [];

  return (
    <div className="flex flex-col h-full">
      <PageHeader
        title="SOC Dashboard"
        subtitle={`Last updated ${formatDistanceToNow(lastRefresh)} ago`}
        badge={{ label: isConnected ? '● LIVE' : '○ OFFLINE', color: isConnected ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400' }}
        actions={
          <button onClick={loadDashboard} className="btn-ghost btn-sm">
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        }
      />

      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* ── KPI Cards ────────────────────────────────────────────── */}
        <div className="grid grid-cols-4 gap-4">
          <KPICard
            title="Total Events"
            value={summary?.total_events ?? 0}
            icon={<Activity className="w-5 h-5 text-soc-primary" />}
            color="primary"
            sub={`${summary?.events_last_hour ?? 0} last hour`}
          />
          <KPICard
            title="Active Incidents"
            value={summary?.active_incidents ?? 0}
            icon={<Siren className="w-5 h-5 text-orange-400" />}
            color="warning"
            sub={`${summary?.critical_incidents ?? 0} critical`}
            alert={summary?.critical_incidents ? summary.critical_incidents > 0 : false}
          />
          <KPICard
            title="High Alerts"
            value={summary?.high_alerts ?? 0}
            icon={<AlertTriangle className="w-5 h-5 text-red-400" />}
            color="danger"
            sub={`${summary?.threats_today ?? 0} today`}
          />
          <KPICard
            title="Resolved"
            value={summary?.resolved_incidents ?? 0}
            icon={<CheckCircle className="w-5 h-5 text-green-400" />}
            color="success"
            sub={`${summary?.blocked_ips ?? 0} IPs blocked`}
          />
        </div>

        {/* ── Simulation Controls ──────────────────────────────────── */}
        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-soc-primary" />
              <h3 className="text-sm font-medium text-soc-text">Simulation Engine</h3>
              {isSimRunning && (
                <span className="flex items-center gap-1 text-xs text-green-400">
                  <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" />
                  Running
                </span>
              )}
            </div>
            {isSimRunning && (
              <button onClick={() => handleSimulation('stop')} className="btn-danger btn-sm">
                <Square className="w-3 h-3" />
                Stop
              </button>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            {SCENARIOS.map(s => (
              <button
                key={s.id}
                onClick={() => handleSimulation(s.id)}
                className={`${s.color} btn btn-sm`}
              >
                <Play className="w-3 h-3" />
                {s.label}
              </button>
            ))}
          </div>
        </div>

        {/* ── Charts Row ───────────────────────────────────────────── */}
        <div className="grid grid-cols-3 gap-4">
          {/* Event Volume */}
          <div className="col-span-2 card">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-soc-text flex items-center gap-2">
                <BarChart2 className="w-4 h-4 text-soc-primary" />
                Event Volume (24h)
              </h3>
            </div>
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={eventVolume}>
                <defs>
                  <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="timestamp" tick={{ fontSize: 10, fill: '#64748b' }} tickFormatter={v => v.slice(11, 16)} />
                <YAxis tick={{ fontSize: 10, fill: '#64748b' }} />
                <Tooltip contentStyle={{ background: '#1a2235', border: '1px solid #1e2d40', borderRadius: '8px', fontSize: '12px' }} />
                <Area type="monotone" dataKey="total" stroke="#00d4ff" fill="url(#colorTotal)" strokeWidth={1.5} name="Total" />
                <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="url(#colorCritical)" strokeWidth={1.5} name="Critical" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Attack Types */}
          <div className="card">
            <h3 className="text-sm font-medium text-soc-text mb-4">Attack Types</h3>
            {attackTypes.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={attackTypes.slice(0, 6)} layout="vertical">
                  <XAxis type="number" tick={{ fontSize: 10, fill: '#64748b' }} />
                  <YAxis dataKey="attack_type" type="category" tick={{ fontSize: 9, fill: '#94a3b8' }} width={90} />
                  <Tooltip contentStyle={{ background: '#1a2235', border: '1px solid #1e2d40', borderRadius: '8px', fontSize: '12px' }} />
                  <Bar dataKey="count" fill="#7c3aed" radius={[0, 3, 3, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-44 flex items-center justify-center text-soc-text-muted text-sm">
                No attack data yet
              </div>
            )}
          </div>
        </div>

        {/* ── Bottom Row ───────────────────────────────────────────── */}
        <div className="grid grid-cols-3 gap-4">
          {/* Top Source IPs */}
          <div className="card">
            <h3 className="text-sm font-medium text-soc-text mb-3 flex items-center gap-2">
              <Shield className="w-4 h-4 text-red-400" />
              Top Source IPs
            </h3>
            <div className="space-y-2">
              {topIPs.slice(0, 8).map((ip, i) => (
                <div key={ip.ip} className="flex items-center gap-2 text-xs">
                  <span className="text-soc-text-muted w-4">{i + 1}</span>
                  <span className="font-mono text-soc-primary flex-1">{ip.ip}</span>
                  <span className="text-soc-text-muted">{ip.country}</span>
                  <span className="text-soc-text font-medium">{ip.count}</span>
                </div>
              ))}
              {topIPs.length === 0 && (
                <p className="text-soc-text-muted text-xs">No data yet — run simulation</p>
              )}
            </div>
          </div>

          {/* Incident Summary Pie */}
          <div className="card">
            <h3 className="text-sm font-medium text-soc-text mb-3">Incident Status</h3>
            {severityPieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={severityPieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={60} label={({ name, value }) => `${name}: ${value}`} labelLine={false}>
                    {severityPieData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#1a2235', border: '1px solid #1e2d40', borderRadius: '8px', fontSize: '12px' }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-40 flex items-center justify-center text-soc-text-muted text-sm">
                No incidents yet
              </div>
            )}
          </div>

          {/* Live Event Feed */}
          <div className="card flex flex-col">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-medium text-soc-text flex items-center gap-2">
                <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
                Live Events
              </h3>
              <button onClick={() => navigate('/events')} className="btn-ghost btn-sm">
                <Eye className="w-3 h-3" />
                View All
              </button>
            </div>
            <div className="flex-1 overflow-y-auto space-y-1 max-h-48">
              {liveEvents.length === 0 ? (
                <p className="text-soc-text-muted text-xs text-center py-8">
                  Events will appear here in real-time
                </p>
              ) : (
                liveEvents.map((event, i) => (
                  <div key={event.id || i} className="event-row">
                    <SeverityBadge severity={event.severity} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium text-soc-text truncate">{event.event_type}</p>
                      <p className="text-xs text-soc-text-muted">{event.source_ip}</p>
                    </div>
                    <span className="text-xs text-soc-text-muted font-mono whitespace-nowrap">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── KPI Card ──────────────────────────────────────────────────────────────────
function KPICard({
  title, value, icon, color, sub, alert = false
}: {
  title: string;
  value: number;
  icon: React.ReactNode;
  color: 'primary' | 'warning' | 'danger' | 'success';
  sub?: string;
  alert?: boolean;
}) {
  const colorMap = {
    primary: 'metric-card-primary',
    warning: 'metric-card-warning',
    danger: 'metric-card-danger',
    success: 'metric-card-success',
  };
  
  return (
    <div className={`metric-card ${colorMap[color]} ${alert ? 'glow-red' : ''}`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-soc-text-muted mb-1">{title}</p>
          <p className="text-3xl font-bold font-mono text-soc-text">{value.toLocaleString()}</p>
          {sub && <p className="text-xs text-soc-text-muted mt-1">{sub}</p>}
        </div>
        <div className="p-2 bg-soc-surface rounded-lg">
          {icon}
        </div>
      </div>
    </div>
  );
}
