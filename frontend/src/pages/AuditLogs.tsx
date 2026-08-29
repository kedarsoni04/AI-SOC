/**
 * Audit Logs Page
 */
import { useState, useEffect, useCallback } from 'react';
import { FileText } from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { get } from '../services/api';
import type { AuditLog, PaginatedResponse } from '../types';
import { format } from 'date-fns';

export function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const PAGE_SIZE = 50;

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await get<PaginatedResponse<AuditLog>>('/audit-logs', { page, page_size: PAGE_SIZE });
      setLogs(data.items);
      setTotal(data.total);
    } finally {
      setIsLoading(false);
    }
  }, [page]);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="flex flex-col h-full">
      <PageHeader
        title="Audit Logs"
        subtitle={`${total.toLocaleString()} audit entries`}
      />
      <div className="flex-1 overflow-hidden flex flex-col p-6">
        <div className="card flex-1 overflow-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Resource ID</th>
                <th>IP Address</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={6} className="text-center py-12 text-soc-text-muted">Loading...</td></tr>
              ) : logs.length === 0 ? (
                <tr><td colSpan={6} className="text-center py-12">
                  <FileText className="w-8 h-8 text-soc-text-muted mx-auto mb-2 opacity-30" />
                  <p className="text-soc-text-muted text-sm">No audit logs yet</p>
                </td></tr>
              ) : logs.map(log => (
                <tr key={log.id}>
                  <td className="font-mono text-xs whitespace-nowrap">
                    {format(new Date(log.created_at), 'MMM d HH:mm:ss')}
                  </td>
                  <td>
                    <span className={`text-xs font-mono ${
                      log.action.includes('login') ? 'text-soc-primary' :
                      log.action.includes('delete') ? 'text-red-400' :
                      log.action.includes('update') ? 'text-yellow-400' :
                      'text-soc-text-dim'
                    }`}>{log.action}</span>
                  </td>
                  <td className="text-xs text-soc-text-muted">{log.resource_type || '—'}</td>
                  <td className="font-mono text-xs text-soc-text-muted">
                    {log.resource_id ? log.resource_id.slice(0, 8) + '...' : '—'}
                  </td>
                  <td className="font-mono text-xs">{log.ip_address || '—'}</td>
                  <td>
                    {log.success ? (
                      <span className="badge-resolved text-xs">OK</span>
                    ) : (
                      <span className="badge-critical text-xs">FAILED</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {total > PAGE_SIZE && (
          <div className="flex items-center justify-between mt-3">
            <span className="text-xs text-soc-text-muted">
              {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, total)} of {total}
            </span>
            <div className="flex gap-2">
              <button
                className="btn-secondary btn-sm"
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
              >
                Previous
              </button>
              <button
                className="btn-secondary btn-sm"
                onClick={() => setPage(p => p + 1)}
                disabled={page * PAGE_SIZE >= total}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
