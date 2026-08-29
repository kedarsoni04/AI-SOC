/**
 * Alerts Page — List with filtering and management
 */
import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle, Filter, Search, CheckCheck, ExternalLink } from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { SeverityBadge, StatusBadge } from '../components/ui/Badge';
import { get, patch, post } from '../services/api';
import type { Alert, PaginatedResponse } from '../types';
import { formatDistanceToNow } from 'date-fns';

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['', 'new', 'acknowledged', 'investigating', 'resolved', 'false_positive'];

export function AlertsPage() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('new');
  const [search, setSearch] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [selected, setSelected] = useState<string[]>([]);

  const loadAlerts = useCallback(async () => {
    setIsLoading(true);
    try {
      const params: Record<string, unknown> = { page, page_size: 50 };
      if (severity) params.severity = severity;
      if (status) params.status = status;
      
      const data = await get<PaginatedResponse<Alert>>('/alerts', params);
      setAlerts(data.items);
      setTotal(data.total);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  }, [page, severity, status]);

  useEffect(() => { loadAlerts(); }, [loadAlerts]);

  const acknowledge = async (alertId: string) => {
    await patch(`/alerts/${alertId}`, { status: 'acknowledged' });
    loadAlerts();
  };

  const convertToIncident = async (alertId: string) => {
    const result = await post<{ incident_id: string }>(`/alerts/${alertId}/convert-to-incident`);
    navigate(`/incidents/${result.incident_id}`);
  };

  const filtered = alerts.filter(a =>
    !search ||
    a.title.toLowerCase().includes(search.toLowerCase()) ||
    (a.source_ip || '').includes(search) ||
    (a.username || '').toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="flex flex-col h-full">
      <PageHeader
        title="Alerts"
        subtitle={`${total} total alerts`}
        actions={
          <div className="flex items-center gap-2">
            <select className="select text-xs py-1.5 w-32" value={severity} onChange={e => setSeverity(e.target.value)}>
              {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All Severities'}</option>)}
            </select>
            <select className="select text-xs py-1.5 w-36" value={status} onChange={e => setStatus(e.target.value)}>
              {STATUSES.map(s => <option key={s} value={s}>{s || 'All Statuses'}</option>)}
            </select>
          </div>
        }
      />

      <div className="flex-1 overflow-hidden flex flex-col p-6 gap-4">
        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-soc-text-muted" />
          <input
            type="text"
            placeholder="Search alerts by title, IP, user..."
            className="input pl-9"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        {/* Table */}
        <div className="card flex-1 overflow-hidden flex flex-col">
          <div className="overflow-auto flex-1">
            <table className="table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Alert</th>
                  <th>Type</th>
                  <th>Source IP</th>
                  <th>Status</th>
                  <th>Confidence</th>
                  <th>Time</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr><td colSpan={8} className="text-center py-8 text-soc-text-muted">Loading...</td></tr>
                ) : filtered.length === 0 ? (
                  <tr><td colSpan={8} className="text-center py-8 text-soc-text-muted">
                    No alerts found. Run a simulation to generate events.
                  </td></tr>
                ) : filtered.map(alert => (
                  <tr key={alert.id} onClick={() => navigate(`/incidents`)}>
                    <td><SeverityBadge severity={alert.severity} /></td>
                    <td>
                      <p className="text-xs font-medium text-soc-text">{alert.title}</p>
                      {alert.username && <p className="text-xs text-soc-text-muted">User: {alert.username}</p>}
                    </td>
                    <td>
                      {alert.attack_type ? (
                        <span className="text-xs font-mono text-soc-primary">{alert.attack_type}</span>
                      ) : '-'}
                    </td>
                    <td>
                      <span className="font-mono text-xs text-soc-text-dim">{alert.source_ip || '—'}</span>
                    </td>
                    <td><StatusBadge status={alert.status} /></td>
                    <td>
                      <div className="flex items-center gap-1">
                        <div className="flex-1 bg-soc-border rounded-full h-1 w-16">
                          <div className="bg-soc-primary h-1 rounded-full" style={{ width: `${alert.confidence * 100}%` }} />
                        </div>
                        <span className="text-xs text-soc-text-muted">{(alert.confidence * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="text-xs text-soc-text-muted whitespace-nowrap">
                      {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      <div className="flex items-center gap-1">
                        {alert.status === 'new' && (
                          <button
                            onClick={() => acknowledge(alert.id)}
                            className="p-1 rounded hover:bg-soc-border text-soc-text-muted hover:text-soc-primary"
                            title="Acknowledge"
                          >
                            <CheckCheck className="w-3.5 h-3.5" />
                          </button>
                        )}
                        {!alert.incident_id && (
                          <button
                            onClick={() => convertToIncident(alert.id)}
                            className="p-1 rounded hover:bg-soc-border text-soc-text-muted hover:text-yellow-400"
                            title="Convert to Incident"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
