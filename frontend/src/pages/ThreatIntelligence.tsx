/**
 * Threat Intelligence Page
 */
import { useState, useEffect, useCallback } from 'react';
import { Search, Plus, X } from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { SeverityBadge } from '../components/ui/Badge';
import { get, post } from '../services/api';
import type { ThreatIndicator, PaginatedResponse } from '../types';
import { format } from 'date-fns';

export function ThreatIntelPage() {
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');

  const [showAdd, setShowAdd] = useState(false);
  const [searchResult, setSearchResult] = useState<{ found: boolean; indicators: ThreatIndicator[] } | null>(null);
  const [newIndicator, setNewIndicator] = useState({
    indicator_type: 'ip', value: '', threat_type: '', severity: 'medium', source: '', description: '', confidence: 0.8
  });

  const load = useCallback(async () => {

    const params: Record<string, unknown> = { page: 1, page_size: 50 };
    if (typeFilter) params.indicator_type = typeFilter;
    if (search) params.search = search;
    const data = await get<PaginatedResponse<ThreatIndicator>>('/threat-intelligence', params);
    setIndicators(data.items);
    setTotal(data.total);
  }, [typeFilter, search]);

  useEffect(() => { load(); }, [load]);

  const doSearch = async () => {
    if (!search) return;
    const result = await post<{ found: boolean; indicators: ThreatIndicator[] }>('/threat-intelligence/search', { query: search });
    setSearchResult(result);
  };

  const addIndicator = async () => {
    await post('/threat-intelligence', newIndicator);
    setShowAdd(false);
    load();
  };

  return (
    <div className="flex flex-col h-full">
      <PageHeader
        title="Threat Intelligence"
        subtitle={`${total} indicators`}
        actions={
          <button onClick={() => setShowAdd(true)} className="btn-primary btn-sm">
            <Plus className="w-3.5 h-3.5" />Add Indicator
          </button>
        }
      />
      <div className="flex-1 overflow-auto p-6 space-y-4">
        {/* Search */}
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-soc-text-muted" />
            <input className="input pl-9" placeholder="Search IPs, domains, hashes..." value={search} onChange={e => setSearch(e.target.value)} onKeyDown={e => e.key === 'Enter' && doSearch()} />
          </div>
          <button onClick={doSearch} className="btn-primary">Search</button>
          <select className="select w-36" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
            <option value="">All Types</option>
            {['ip', 'domain', 'hash', 'url', 'email'].map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>

        {/* Search result banner */}
        {searchResult && (
          <div className={`p-3 rounded-lg border text-sm ${searchResult.found ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-green-500/10 border-green-500/30 text-green-400'}`}>
            {searchResult.found
              ? `⚠️ THREAT FOUND: ${searchResult.indicators.length} match(es) for "${search}"`
              : `✓ No threat intelligence found for "${search}"`}
            <button onClick={() => setSearchResult(null)} className="ml-2 opacity-50 hover:opacity-100"><X className="w-3 h-3" /></button>
          </div>
        )}

        {/* Add form */}
        {showAdd && (
          <div className="card border-soc-primary/30">
            <h3 className="text-sm font-medium text-soc-text mb-3">Add Threat Indicator</h3>
            <div className="grid grid-cols-2 gap-3">
              <select className="select text-xs" value={newIndicator.indicator_type} onChange={e => setNewIndicator({...newIndicator, indicator_type: e.target.value})}>
                {['ip', 'domain', 'hash', 'url', 'email'].map(t => <option key={t} value={t}>{t}</option>)}
              </select>
              <input className="input text-xs" placeholder="Value (IP/domain/hash)" value={newIndicator.value} onChange={e => setNewIndicator({...newIndicator, value: e.target.value})} />
              <input className="input text-xs" placeholder="Threat type" value={newIndicator.threat_type} onChange={e => setNewIndicator({...newIndicator, threat_type: e.target.value})} />
              <select className="select text-xs" value={newIndicator.severity} onChange={e => setNewIndicator({...newIndicator, severity: e.target.value})}>
                {['critical', 'high', 'medium', 'low'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <input className="input text-xs" placeholder="Source" value={newIndicator.source} onChange={e => setNewIndicator({...newIndicator, source: e.target.value})} />
              <input className="input text-xs" placeholder="Description" value={newIndicator.description} onChange={e => setNewIndicator({...newIndicator, description: e.target.value})} />
            </div>
            <div className="flex gap-2 mt-3">
              <button onClick={addIndicator} className="btn-primary btn-sm">Add</button>
              <button onClick={() => setShowAdd(false)} className="btn-secondary btn-sm">Cancel</button>
            </div>
          </div>
        )}

        {/* Table */}
        <div className="card overflow-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Threat Type</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Source</th>
                <th>Hits</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {indicators.map(ind => (
                <tr key={ind.id}>
                  <td><span className="badge bg-soc-border text-soc-text-dim">{ind.indicator_type.toUpperCase()}</span></td>
                  <td className="font-mono text-xs text-soc-primary">{ind.value}</td>
                  <td className="text-xs">{ind.threat_type || '—'}</td>
                  <td><SeverityBadge severity={ind.severity} /></td>
                  <td>
                    <div className="flex items-center gap-1">
                      <div className="w-16 bg-soc-border rounded-full h-1">
                        <div className="bg-soc-primary h-1 rounded-full" style={{ width: `${ind.confidence * 100}%` }} />
                      </div>
                      <span className="text-xs text-soc-text-muted">{(ind.confidence * 100).toFixed(0)}%</span>
                    </div>
                  </td>
                  <td className="text-xs text-soc-text-muted">{ind.source || '—'}</td>
                  <td className="text-xs font-mono">{ind.hit_count}</td>
                  <td className="text-xs text-soc-text-muted">{format(new Date(ind.last_seen), 'MMM d HH:mm')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
