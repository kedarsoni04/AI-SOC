/**
 * Incidents Page — List view
 */
import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Siren, TrendingUp, Eye } from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { SeverityBadge, StatusBadge, RiskScoreBadge } from '../components/ui/Badge';
import { get } from '../services/api';
import type { Incident, PaginatedResponse } from '../types';
import { formatDistanceToNow } from 'date-fns';

const STATUSES = ['', 'new', 'investigating', 'contained', 'resolved', 'false_positive'];
const SEVERITIES = ['', 'critical', 'high', 'medium', 'low'];

export function IncidentsPage() {
  const navigate = useNavigate();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState('');
  const [severity, setSeverity] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const params: Record<string, unknown> = { page, page_size: 20 };
      if (status) params.status = status;
      if (severity) params.severity = severity;
      const data = await get<PaginatedResponse<Incident>>('/incidents', params);
      setIncidents(data.items);
      setTotal(data.total);
    } finally {
      setIsLoading(false);
    }
  }, [page, status, severity]);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="flex flex-col h-full">
      <PageHeader
        title="Incidents"
        subtitle={`${total} total incidents`}
        actions={
          <div className="flex items-center gap-2">
            <select className="select text-xs py-1.5 w-36" value={status} onChange={e => setStatus(e.target.value)}>
              {STATUSES.map(s => <option key={s} value={s}>{s || 'All Statuses'}</option>)}
            </select>
            <select className="select text-xs py-1.5 w-32" value={severity} onChange={e => setSeverity(e.target.value)}>
              {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All Severities'}</option>)}
            </select>
          </div>
        }
      />

      <div className="flex-1 overflow-auto p-6">
        {isLoading ? (
          <div className="card text-center py-12 text-soc-text-muted">Loading incidents...</div>
        ) : incidents.length === 0 ? (
          <div className="card text-center py-12">
            <Siren className="w-12 h-12 text-soc-text-muted mx-auto mb-4" />
            <p className="text-soc-text-muted text-sm">No incidents found.</p>
            <p className="text-soc-text-muted text-xs mt-1">Run a simulation to generate incidents automatically.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {incidents.map(incident => (
              <div
                key={incident.id}
                className="card hover:border-soc-border-light cursor-pointer transition-all"
                onClick={() => navigate(`/incidents/${incident.id}`)}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs text-soc-text-muted font-mono">INC-{String(incident.incident_number).padStart(4, '0')}</span>
                      <SeverityBadge severity={incident.severity} />
                      <StatusBadge status={incident.status} />
                    </div>
                    <h3 className="text-sm font-medium text-soc-text">{incident.title}</h3>
                    {incident.description && (
                      <p className="text-xs text-soc-text-muted mt-0.5 line-clamp-1">{incident.description}</p>
                    )}
                    <div className="flex items-center gap-3 mt-2 text-xs text-soc-text-muted">
                      {incident.source_ip && (
                        <span className="font-mono text-soc-primary">{incident.source_ip}</span>
                      )}
                      {incident.target_user && (
                        <span>User: {incident.target_user}</span>
                      )}
                      {incident.attack_vector && (
                        <span className="text-soc-text-dim">{incident.attack_vector}</span>
                      )}
                      {incident.alert_count !== undefined && (
                        <span>{incident.alert_count} alerts</span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-4 flex-shrink-0">
                    <div className="text-right">
                      <p className="text-xs text-soc-text-muted">Risk Score</p>
                      <RiskScoreBadge score={incident.risk_score} size="sm" />
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-soc-text-muted">Created</p>
                      <p className="text-xs text-soc-text-dim">{formatDistanceToNow(new Date(incident.created_at), { addSuffix: true })}</p>
                    </div>
                    <Eye className="w-4 h-4 text-soc-text-muted" />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
