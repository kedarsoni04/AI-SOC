/**
 * Incident Investigation Page — detailed view with AI investigation
 */
import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, Brain, Shield, AlertTriangle, Target,
  CheckCircle, XCircle, ChevronDown, ChevronRight, Bot,
  RefreshCw, Loader2
} from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { SeverityBadge, StatusBadge, RiskScoreBadge } from '../components/ui/Badge';
import { get, post, patch } from '../services/api';
import type { Incident, IncidentTimeline, AIInvestigation, ResponseAction } from '../types';
import { formatDistanceToNow, format } from 'date-fns';

export function IncidentInvestigation() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [timeline, setTimeline] = useState<IncidentTimeline | null>(null);
  const [investigation, setInvestigation] = useState<AIInvestigation | null>(null);
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'timeline' | 'ai' | 'response'>('overview');
  const [notes, setNotes] = useState('');
  const [status, setStatus] = useState('');
  const [expandedEvents, setExpandedEvents] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!id) return;
    const load = async () => {
      setIsLoading(true);
      try {
        const [inc, tl, invs] = await Promise.all([
          get<Incident>(`/incidents/${id}`),
          get<IncidentTimeline>(`/incidents/${id}/timeline`),
          get<AIInvestigation[]>(`/incidents/${id}/investigations`),
        ]);
        setIncident(inc);
        setTimeline(tl);
        setNotes(inc.analyst_notes || '');
        setStatus(inc.status);
        if (invs.length > 0) setInvestigation(invs[0]);
      } catch (err) {
        console.error(err);
      } finally {
        setIsLoading(false);
      }
    };
    load();
  }, [id]);

  const triggerInvestigation = async () => {
    if (!id) return;
    setIsInvestigating(true);
    try {
      const result = await post<AIInvestigation>(`/incidents/${id}/investigate`);
      setInvestigation(result as AIInvestigation);
      setActiveTab('ai');
    } catch (err) {
      console.error(err);
    } finally {
      setIsInvestigating(false);
    }
  };

  const saveNotes = async () => {
    if (!id) return;
    await patch(`/incidents/${id}`, { analyst_notes: notes, status });
    const inc = await get<Incident>(`/incidents/${id}`);
    setIncident(inc);
  };

  const toggleEvent = (eventId: string) => {
    setExpandedEvents(prev => {
      const next = new Set(prev);
      next.has(eventId) ? next.delete(eventId) : next.add(eventId);
      return next;
    });
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="w-8 h-8 text-soc-primary animate-spin" />
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <AlertTriangle className="w-12 h-12 text-red-400" />
        <p className="text-soc-text-muted">Incident not found</p>
        <button onClick={() => navigate('/incidents')} className="btn-secondary btn-sm">
          Back to Incidents
        </button>
      </div>
    );
  }

  const riskBreakdown = incident.risk_breakdown;

  return (
    <div className="flex flex-col h-full">
      <PageHeader
        title={`INC-${String(incident.incident_number).padStart(4, '0')} — ${incident.title}`}
        subtitle={`Created ${formatDistanceToNow(new Date(incident.created_at), { addSuffix: true })}`}
        actions={
          <div className="flex items-center gap-2">
            <button onClick={() => navigate('/incidents')} className="btn-ghost btn-sm">
              <ArrowLeft className="w-3.5 h-3.5" />
              Back
            </button>
            <button
              onClick={triggerInvestigation}
              className="btn-primary btn-sm"
              disabled={isInvestigating}
            >
              {isInvestigating ? (
                <><Loader2 className="w-3.5 h-3.5 animate-spin" />Investigating...</>
              ) : (
                <><Brain className="w-3.5 h-3.5" />AI Investigate</>
              )}
            </button>
          </div>
        }
      />

      <div className="flex-1 overflow-hidden flex">
        {/* Left panel */}
        <div className="flex-1 overflow-y-auto">
          {/* Tabs */}
          <div className="border-b border-soc-border px-6 flex gap-1">
            {(['overview', 'timeline', 'ai', 'response'] as const).map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-4 py-3 text-xs font-medium border-b-2 transition-colors capitalize ${
                  activeTab === tab
                    ? 'border-soc-primary text-soc-primary'
                    : 'border-transparent text-soc-text-muted hover:text-soc-text'
                }`}
              >
                {tab === 'ai' ? '🤖 AI Analysis' : tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </div>

          <div className="p-6">
            {/* ── Overview Tab ─────────────────────────────────── */}
            {activeTab === 'overview' && (
              <div className="space-y-4">
                {/* Risk Score breakdown */}
                {riskBreakdown && (
                  <div className="card">
                    <h3 className="text-sm font-medium text-soc-text mb-4 flex items-center gap-2">
                      <Shield className="w-4 h-4 text-soc-primary" />
                      Risk Assessment
                    </h3>
                    <div className="flex items-start gap-6">
                      <div className="text-center">
                        <RiskScoreBadge score={incident.risk_score} size="lg" />
                        <p className="text-xs text-soc-text-muted mt-1">{riskBreakdown.label}</p>
                      </div>
                      <div className="flex-1 space-y-2">
                        {riskBreakdown.breakdown?.map(item => (
                          <div key={item.factor} className="flex items-center gap-3">
                            <span className="text-xs text-soc-text-muted w-40 truncate">{item.factor}</span>
                            <div className="flex-1 bg-soc-border rounded-full h-1.5">
                              <div
                                className="bg-soc-primary h-1.5 rounded-full"
                                style={{ width: `${(item.score / item.max) * 100}%` }}
                              />
                            </div>
                            <span className="text-xs font-mono text-soc-text">+{item.score}</span>
                          </div>
                        ))}
                        {riskBreakdown.explanation && (
                          <p className="text-xs text-soc-text-muted mt-2 italic">{riskBreakdown.explanation}</p>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* MITRE */}
                {incident.mitre_tactics && incident.mitre_tactics.length > 0 && (
                  <div className="card">
                    <h3 className="text-sm font-medium text-soc-text mb-3 flex items-center gap-2">
                      <Target className="w-4 h-4 text-soc-secondary" />
                      MITRE ATT&CK
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      {incident.mitre_tactics.map(t => (
                        <span key={t} className="text-xs px-2 py-1 bg-soc-secondary/20 text-purple-300 border border-soc-secondary/30 rounded-lg">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Analyst notes */}
                <div className="card">
                  <h3 className="text-sm font-medium text-soc-text mb-3">Analyst Notes</h3>
                  <textarea
                    className="input min-h-[100px] resize-none"
                    placeholder="Add investigation notes..."
                    value={notes}
                    onChange={e => setNotes(e.target.value)}
                  />
                  <div className="flex items-center justify-between mt-3">
                    <select
                      className="select text-xs py-1.5 w-40"
                      value={status}
                      onChange={e => setStatus(e.target.value)}
                    >
                      {['new', 'investigating', 'contained', 'resolved', 'false_positive'].map(s => (
                        <option key={s} value={s}>{s.replace(/_/g, ' ').toUpperCase()}</option>
                      ))}
                    </select>
                    <button onClick={saveNotes} className="btn-primary btn-sm">
                      <CheckCircle className="w-3.5 h-3.5" />
                      Save
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* ── Timeline Tab ──────────────────────────────────── */}
            {activeTab === 'timeline' && (
              <div className="space-y-3">
                {timeline?.timeline.length === 0 ? (
                  <div className="card text-center py-8 text-soc-text-muted">No timeline events</div>
                ) : timeline?.timeline.map((entry, i) => (
                  <div key={i} className="flex gap-4">
                    <div className="flex flex-col items-center">
                      <div className={`w-3 h-3 rounded-full flex-shrink-0 mt-1 ${
                        entry.severity === 'critical' ? 'bg-red-500' :
                        entry.severity === 'high' ? 'bg-orange-500' :
                        entry.severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
                      }`} />
                      {i < (timeline?.timeline.length || 0) - 1 && (
                        <div className="w-0.5 flex-1 bg-soc-border mt-1" />
                      )}
                    </div>
                    <div className="flex-1 pb-4">
                      <button
                        className="w-full text-left card hover:border-soc-border-light transition-all"
                        onClick={() => toggleEvent(String(i))}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <SeverityBadge severity={entry.severity} />
                            <span className="text-xs font-medium text-soc-text">{entry.title}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-soc-text-muted font-mono">
                              {format(new Date(entry.timestamp), 'HH:mm:ss')}
                            </span>
                            {expandedEvents.has(String(i)) ? (
                              <ChevronDown className="w-3.5 h-3.5 text-soc-text-muted" />
                            ) : (
                              <ChevronRight className="w-3.5 h-3.5 text-soc-text-muted" />
                            )}
                          </div>
                        </div>
                        {expandedEvents.has(String(i)) && (
                          <div className="mt-3 pt-3 border-t border-soc-border space-y-2">
                            <p className="text-xs text-soc-text-dim">Rule: {entry.detection_rule}</p>
                            <p className="text-xs text-soc-text-dim">
                              Confidence: {(entry.confidence * 100).toFixed(0)}%
                            </p>
                            {entry.evidence && (
                              <div className="bg-soc-surface rounded p-2">
                                <p className="text-xs text-soc-text-muted mb-1">Evidence:</p>
                                <pre className="text-xs text-soc-text-dim font-mono overflow-x-auto">
                                  {JSON.stringify(entry.evidence, null, 2)}
                                </pre>
                              </div>
                            )}
                            {entry.events.slice(0, 3).map(ev => (
                              <div key={ev.id} className="bg-soc-surface rounded p-2 text-xs">
                                <div className="flex gap-2">
                                  <span className="font-mono text-soc-text-muted">{format(new Date(ev.timestamp), 'HH:mm:ss')}</span>
                                  <span className="text-soc-primary">{ev.event_type}</span>
                                  <span className="text-soc-text-muted">{ev.source_ip}</span>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* ── AI Analysis Tab ───────────────────────────────── */}
            {activeTab === 'ai' && (
              <div className="space-y-4">
                {!investigation ? (
                  <div className="card text-center py-12">
                    <Bot className="w-12 h-12 text-soc-primary mx-auto mb-4 opacity-50" />
                    <p className="text-soc-text-muted text-sm">No AI investigation yet</p>
                    <button onClick={triggerInvestigation} className="btn-primary btn-sm mx-auto mt-4" disabled={isInvestigating}>
                      {isInvestigating ? 'Investigating...' : 'Start AI Investigation'}
                    </button>
                  </div>
                ) : (
                  <>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Bot className="w-4 h-4 text-soc-primary" />
                        <span className="text-sm font-medium text-soc-text">AI Analysis</span>
                        <span className="badge bg-soc-primary/20 text-soc-primary border-soc-primary/30">
                          {investigation.llm_provider?.toUpperCase() || 'RULE-BASED'}
                        </span>
                        <span className="text-xs text-soc-text-muted">
                          Confidence: {((investigation.confidence || 0) * 100).toFixed(0)}%
                        </span>
                      </div>
                      <button onClick={triggerInvestigation} className="btn-ghost btn-sm" disabled={isInvestigating}>
                        <RefreshCw className={`w-3.5 h-3.5 ${isInvestigating ? 'animate-spin' : ''}`} />
                        Re-analyze
                      </button>
                    </div>

                    <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-lg p-3 text-xs text-yellow-400">
                      ⚠️ This is AI-generated analysis based on structured evidence. Always verify before taking action.
                    </div>

                    {investigation.summary && (
                      <div className="card">
                        <h4 className="text-xs font-medium text-soc-text-muted uppercase tracking-wider mb-2">Summary</h4>
                        <p className="text-sm text-soc-text">{investigation.summary}</p>
                      </div>
                    )}

                    {investigation.attack_analysis && (
                      <div className="card">
                        <h4 className="text-xs font-medium text-soc-text-muted uppercase tracking-wider mb-2">Attack Analysis</h4>
                        <p className="text-sm text-soc-text-dim">{investigation.attack_analysis}</p>
                      </div>
                    )}

                    {investigation.mitre_mapping && investigation.mitre_mapping.length > 0 && (
                      <div className="card">
                        <h4 className="text-xs font-medium text-soc-text-muted uppercase tracking-wider mb-3">MITRE ATT&CK Mapping</h4>
                        <div className="space-y-2">
                          {investigation.mitre_mapping.map((m, i) => (
                            <div key={i} className="bg-soc-surface rounded-lg p-3 text-xs">
                              <div className="flex gap-4">
                                <div>
                                  <p className="text-soc-text-muted">Tactic</p>
                                  <p className="text-purple-300 font-medium">{m.tactic}</p>
                                </div>
                                <div>
                                  <p className="text-soc-text-muted">Technique</p>
                                  <p className="text-soc-primary">{m.technique}</p>
                                </div>
                                {m.evidence && (
                                  <div className="flex-1">
                                    <p className="text-soc-text-muted">Evidence</p>
                                    <p className="text-soc-text-dim">{m.evidence}</p>
                                  </div>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {investigation.recommended_response && (
                      <div className="card border-soc-primary/20">
                        <h4 className="text-xs font-medium text-soc-text-muted uppercase tracking-wider mb-2 flex items-center gap-2">
                          <CheckCircle className="w-3.5 h-3.5 text-green-400" />
                          Recommended Response
                        </h4>
                        <div className="text-sm text-soc-text-dim whitespace-pre-line">
                          {investigation.recommended_response}
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* ── Response Tab ──────────────────────────────────── */}
            {activeTab === 'response' && (
              <ResponseTab incidentId={id!} />
            )}
          </div>
        </div>

        {/* Right sidebar */}
        <div className="w-72 border-l border-soc-border overflow-y-auto p-4 space-y-4 flex-shrink-0">
          <div className="space-y-1 text-xs">
            <InfoRow label="Status" value={<StatusBadge status={incident.status} />} />
            <InfoRow label="Severity" value={<SeverityBadge severity={incident.severity} />} />
            <InfoRow label="Source IP" value={<span className="font-mono text-soc-primary">{incident.source_ip || '—'}</span>} />
            <InfoRow label="Target User" value={incident.target_user || '—'} />
            <InfoRow label="Attack Vector" value={incident.attack_vector || '—'} />
            <InfoRow label="Alerts" value={String(incident.alert_count || 0)} />
            <InfoRow label="Created" value={format(new Date(incident.created_at), 'MMM d, HH:mm')} />
          </div>
        </div>
      </div>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between py-1.5 border-b border-soc-border/50 gap-2">
      <span className="text-soc-text-muted">{label}</span>
      <span className="text-soc-text text-right">{value}</span>
    </div>
  );
}

function ResponseTab({ incidentId }: { incidentId: string }) {
  const [actions, setActions] = useState<ResponseAction[]>([]);

  const [newAction, setNewAction] = useState({ action_type: 'block_ip', target: '', description: '' });

  const load = async () => {

    try {
      const data = await get<{ items: ResponseAction[] }>('/response', { incident_id: incidentId });
      setActions(data.items);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => { load(); }, [incidentId]);

  const approve = async (actionId: string) => {
    await patch(`/response/${actionId}`, { status: 'approved' });
    load();
  };

  const reject = async (actionId: string) => {
    await patch(`/response/${actionId}`, { status: 'rejected', rejection_reason: 'Analyst rejected' });
    load();
  };

  const create = async () => {
    if (!newAction.description) return;
    await post('/response', { ...newAction, incident_id: incidentId });
    setNewAction({ action_type: 'block_ip', target: '', description: '' });
    load();
  };

  return (
    <div className="space-y-4">
      {/* Create new action */}
      <div className="card">
        <h4 className="text-sm font-medium text-soc-text mb-3">Add Response Action</h4>
        <div className="space-y-2">
          <select className="select text-xs" value={newAction.action_type} onChange={e => setNewAction({...newAction, action_type: e.target.value})}>
            {['block_ip', 'disable_account', 'revoke_session', 'isolate_endpoint', 'reset_credentials', 'create_ticket'].map(t => (
              <option key={t} value={t}>{t.replace(/_/g, ' ').toUpperCase()}</option>
            ))}
          </select>
          <input className="input text-xs" placeholder="Target (IP/user/endpoint)" value={newAction.target} onChange={e => setNewAction({...newAction, target: e.target.value})} />
          <textarea className="input text-xs resize-none" rows={2} placeholder="Description" value={newAction.description} onChange={e => setNewAction({...newAction, description: e.target.value})} />
          <button onClick={create} className="btn-primary btn-sm w-full justify-center">Create Action</button>
        </div>
      </div>

      {/* Existing actions */}
      <div className="space-y-2">
        {actions.map(action => (
          <div key={action.id} className="card">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-mono text-soc-primary">{action.action_type.replace(/_/g, ' ').toUpperCase()}</span>
                  <StatusBadge status={action.status} />
                </div>
                {action.target && <p className="text-xs text-soc-text-dim">{action.target}</p>}
                <p className="text-xs text-soc-text-muted">{action.description}</p>
              </div>
            </div>
            {action.status === 'pending' && (
              <div className="flex gap-2 mt-2">
                <button onClick={() => approve(action.id)} className="btn-success btn-sm flex-1 justify-center">
                  <CheckCircle className="w-3.5 h-3.5" />Approve
                </button>
                <button onClick={() => reject(action.id)} className="btn-danger btn-sm flex-1 justify-center">
                  <XCircle className="w-3.5 h-3.5" />Reject
                </button>
              </div>
            )}
            {action.status === 'executed' && (
              <p className="text-xs text-green-400 mt-1">✓ Executed</p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
