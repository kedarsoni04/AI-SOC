/**
 * Response Center Page
 */
import { useState, useEffect } from 'react';
import { Terminal, CheckCircle, XCircle } from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { StatusBadge } from '../components/ui/Badge';
import { get, patch } from '../services/api';
import type { ResponseAction, PaginatedResponse } from '../types';
import { format } from 'date-fns';

export function ResponseCenterPage() {
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState('pending');
  const [isLoading, setIsLoading] = useState(true);

  const load = async () => {
    setIsLoading(true);
    const params: Record<string, unknown> = { page: 1, page_size: 50 };
    if (statusFilter) params.status = statusFilter;
    const data = await get<PaginatedResponse<ResponseAction>>('/response', params);
    setActions(data.items);
    setTotal(data.total);
    setIsLoading(false);
  };

  useEffect(() => { load(); }, [statusFilter]);

  const approve = async (id: string) => {
    await patch(`/response/${id}`, { status: 'approved' });
    load();
  };

  const reject = async (id: string) => {
    await patch(`/response/${id}`, { status: 'rejected', rejection_reason: 'Rejected by analyst' });
    load();
  };

  const actionTypeColors: Record<string, string> = {
    block_ip: 'text-red-400',
    disable_account: 'text-orange-400',
    revoke_session: 'text-yellow-400',
    isolate_endpoint: 'text-purple-400',
    reset_credentials: 'text-blue-400',
    create_ticket: 'text-green-400',
  };

  return (
    <div className="flex flex-col h-full">
      <PageHeader
        title="Response Center"
        subtitle={`${total} response actions`}
        actions={
          <select className="select text-xs py-1.5 w-36" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
            <option value="">All Statuses</option>
            {['pending', 'approved', 'executed', 'rejected'].map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        }
      />
      <div className="flex-1 overflow-auto p-6">
        {isLoading ? (
          <div className="card text-center py-12 text-soc-text-muted">Loading...</div>
        ) : actions.length === 0 ? (
          <div className="card text-center py-12">
            <Terminal className="w-12 h-12 text-soc-text-muted mx-auto mb-4" />
            <p className="text-soc-text-muted text-sm">No response actions found.</p>
            <p className="text-xs text-soc-text-muted mt-1">Trigger AI investigation on incidents to generate recommendations.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {actions.map(action => (
              <div key={action.id} className="card">
                <div className="flex items-start gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`text-sm font-medium font-mono ${actionTypeColors[action.action_type] || 'text-soc-text'}`}>
                        {action.action_type.replace(/_/g, ' ').toUpperCase()}
                      </span>
                      <StatusBadge status={action.status} />
                      <span className="text-xs text-soc-text-muted">by {action.recommended_by}</span>
                    </div>
                    {action.target && (
                      <p className="text-xs font-mono text-soc-primary mb-1">Target: {action.target}</p>
                    )}
                    <p className="text-xs text-soc-text-dim">{action.description}</p>
                    <p className="text-xs text-soc-text-muted mt-1">
                      {format(new Date(action.created_at), 'MMM d, HH:mm')}
                      {action.executed_at && ` → Executed ${format(new Date(action.executed_at), 'HH:mm')}`}
                    </p>
                  </div>
                  {action.status === 'pending' && (
                    <div className="flex gap-2">
                      <button onClick={() => approve(action.id)} className="btn-success btn-sm">
                        <CheckCircle className="w-3.5 h-3.5" />Approve
                      </button>
                      <button onClick={() => reject(action.id)} className="btn-danger btn-sm">
                        <XCircle className="w-3.5 h-3.5" />Reject
                      </button>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
