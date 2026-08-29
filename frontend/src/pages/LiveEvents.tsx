/**
 * Live Events Feed Page
 */
import { useState, useEffect, useCallback, useRef } from 'react';
import { Zap, Pause, Play } from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { SeverityBadge } from '../components/ui/Badge';
import { get } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import type { SecurityEvent, PaginatedResponse, WSMessage } from '../types';
import { format } from 'date-fns';

export function LiveEventsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [isPaused, setIsPaused] = useState(false);
  const [total, setTotal] = useState(0);
  const [severityFilter, setSeverityFilter] = useState('');
  const pendingRef = useRef<SecurityEvent[]>([]);

  const loadEvents = useCallback(async () => {
    const params: Record<string, unknown> = { page: 1, page_size: 100 };
    if (severityFilter) params.severity = severityFilter;
    const data = await get<PaginatedResponse<SecurityEvent>>('/events', params);
    setEvents(data.items);
    setTotal(data.total);
  }, [severityFilter]);

  useEffect(() => { loadEvents(); }, [loadEvents]);

  const handleWs = useCallback((msg: WSMessage) => {
    if (msg.type === 'new_event' && msg.data) {
      const ev = msg.data as SecurityEvent;
      if (!severityFilter || ev.severity === severityFilter) {
        if (isPaused) {
          pendingRef.current = [ev, ...pendingRef.current].slice(0, 100);
        } else {
          setEvents(prev => [ev, ...prev].slice(0, 100));
          setTotal(t => t + 1);
        }
      }
    }
  }, [isPaused, severityFilter]);

  const { isConnected } = useWebSocket({ onMessage: handleWs });

  const resume = () => {
    setIsPaused(false);
    if (pendingRef.current.length > 0) {
      setEvents(prev => [...pendingRef.current, ...prev].slice(0, 200));
      pendingRef.current = [];
    }
  };

  return (
    <div className="flex flex-col h-full">
      <PageHeader
        title="Live Security Events"
        subtitle={`${total.toLocaleString()} total events`}
        badge={{ label: isConnected ? '● LIVE' : '○ OFFLINE', color: isConnected ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400' }}
        actions={
          <div className="flex items-center gap-2">
            <select className="select text-xs py-1.5 w-32" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
              <option value="">All Severities</option>
              {['critical', 'high', 'medium', 'low', 'info'].map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <button
              onClick={() => isPaused ? resume() : setIsPaused(true)}
              className={isPaused ? 'btn-success btn-sm' : 'btn-secondary btn-sm'}
            >
              {isPaused ? <><Play className="w-3 h-3" />Resume ({pendingRef.current.length})</> : <><Pause className="w-3 h-3" />Pause</>}
            </button>
          </div>
        }
      />
      <div className="flex-1 overflow-hidden p-6">
        <div className="card h-full overflow-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Event Type</th>
                <th>Source IP</th>
                <th>Username</th>
                <th>Destination</th>
                <th>Anomaly</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr><td colSpan={8} className="text-center py-12 text-soc-text-muted">
                  <Zap className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  No events yet. Start a simulation.
                </td></tr>
              ) : events.map(ev => (
                <tr key={ev.id}>
                  <td className="font-mono text-xs whitespace-nowrap">
                    {format(new Date(ev.timestamp), 'HH:mm:ss.SSS')}
                  </td>
                  <td><SeverityBadge severity={ev.severity} /></td>
                  <td className="font-mono text-xs text-soc-primary">{ev.event_type}</td>
                  <td className="font-mono text-xs">{ev.source_ip || '—'}</td>
                  <td className="text-xs">{ev.username || '—'}</td>
                  <td className="font-mono text-xs">{ev.destination_ip || '—'}</td>
                  <td>
                    {ev.is_anomaly ? (
                      <span className="badge-critical">ANOMALY</span>
                    ) : (
                      <span className="text-xs text-soc-text-muted">{(ev.anomaly_score || 0).toFixed(2)}</span>
                    )}
                  </td>
                  <td className="text-xs text-soc-text-muted">{ev.source || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
