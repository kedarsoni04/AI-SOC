// ── Core Types ─────────────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AlertStatus = 'new' | 'acknowledged' | 'investigating' | 'resolved' | 'false_positive';
export type IncidentStatus = 'new' | 'investigating' | 'contained' | 'resolved' | 'false_positive';
export type UserRole = 'admin' | 'analyst' | 'viewer';

// ── User ─────────────────────────────────────────────────────────────────────
export interface User {
  id: string;
  email: string;
  username: string;
  full_name?: string;
  role: UserRole;
  is_active: boolean;
  last_login?: string;
  created_at: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  user: User;
}

// ── Security Event ────────────────────────────────────────────────────────────
export interface SecurityEvent {
  id: string;
  timestamp: string;
  source?: string;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  username?: string;
  event_type: string;
  http_method?: string;
  endpoint?: string;
  status_code?: number;
  user_agent?: string;
  severity: Severity;
  bytes_transferred?: number;
  protocol?: string;
  country?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  is_anomaly: boolean;
  anomaly_score?: number;
  raw_log?: string;
  created_at: string;
}

// ── Alert ─────────────────────────────────────────────────────────────────────
export interface Alert {
  id: string;
  title: string;
  description?: string;
  severity: Severity;
  status: AlertStatus;
  detection_rule?: string;
  source_ip?: string;
  destination_ip?: string;
  username?: string;
  attack_type?: string;
  confidence: number;
  evidence?: Record<string, unknown>;
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  incident_id?: string;
  created_at: string;
  updated_at: string;
}

// ── Incident ──────────────────────────────────────────────────────────────────
export interface RiskBreakdownItem {
  factor: string;
  score: number;
  max: number;
  reason: string;
}

export interface RiskBreakdown {
  score: number;
  label: string;
  breakdown: RiskBreakdownItem[];
  explanation: string;
}

export interface Incident {
  id: string;
  incident_number: number;
  title: string;
  description?: string;
  severity: Severity;
  status: IncidentStatus;
  risk_score: number;
  risk_breakdown?: RiskBreakdown;
  source_ip?: string;
  target_user?: string;
  attack_vector?: string;
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  analyst_notes?: string;
  resolution?: string;
  assigned_analyst_id?: string;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
  first_event_at?: string;
  last_event_at?: string;
  alert_count?: number;
}

// ── AI Investigation ──────────────────────────────────────────────────────────
export interface MitreMapping {
  tactic: string;
  technique: string;
  evidence: string;
}

export interface AIInvestigation {
  id: string;
  incident_id: string;
  llm_provider?: string;
  model_used?: string;
  summary?: string;
  attack_analysis?: string;
  evidence_summary?: string;
  mitre_mapping?: MitreMapping[];
  risk_explanation?: string;
  recommended_response?: string;
  confidence: number;
  tokens_used?: number;
  duration_ms?: number;
  created_at: string;
}

// ── Threat Intel ──────────────────────────────────────────────────────────────
export interface ThreatIndicator {
  id: string;
  indicator_type: 'ip' | 'domain' | 'hash' | 'url' | 'email';
  value: string;
  threat_type?: string;
  confidence: number;
  severity: Severity;
  source?: string;
  description?: string;
  tags?: string[];
  is_active: boolean;
  first_seen: string;
  last_seen: string;
  hit_count: number;
  created_at: string;
}

// ── Response Action ────────────────────────────────────────────────────────────
export interface ResponseAction {
  id: string;
  incident_id: string;
  action_type: string;
  target?: string;
  description: string;
  status: 'pending' | 'approved' | 'executed' | 'rejected';
  recommended_by: 'ai' | 'rule' | 'analyst';
  approved_by_id?: string;
  rejection_reason?: string;
  executed_at?: string;
  created_at: string;
}

// ── Audit Log ─────────────────────────────────────────────────────────────────
export interface AuditLog {
  id: string;
  user_id?: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  details?: Record<string, unknown>;
  ip_address?: string;
  success: boolean;
  created_at: string;
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
export interface DashboardSummary {
  total_events: number;
  active_incidents: number;
  critical_incidents: number;
  high_alerts: number;
  resolved_incidents: number;
  blocked_ips: number;
  threats_today: number;
  events_last_hour: number;
  simulation_status: SimulationStatus;
}

export interface EventVolumePoint {
  timestamp: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface GeoAttack {
  ip: string;
  country: string;
  city?: string;
  lat?: number;
  lon?: number;
  count: number;
}

// ── ML ────────────────────────────────────────────────────────────────────────
export interface MLModelMetrics {
  model_name: string;
  model_type: string;
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1_score?: number;
  training_samples?: number;
  feature_names?: string[];
  class_labels?: string[];
  confusion_matrix?: number[][];
  trained_at?: string;
  is_trained: boolean;
  is_loaded: boolean;
  sklearn_available?: boolean;
}

// ── Simulation ────────────────────────────────────────────────────────────────
export interface SimulationStatus {
  is_running: boolean;
  scenario?: string;
  events_generated: number;
  started_at?: string;
}

// ── WebSocket Messages ────────────────────────────────────────────────────────
export type WSMessageType = 
  | 'connected' 
  | 'new_event' 
  | 'new_alert' 
  | 'incident_update' 
  | 'stats_update'
  | 'pong';

export interface WSMessage {
  type: WSMessageType;
  data?: unknown;
  action?: string;
  client_id?: string;
}

// ── Pagination ────────────────────────────────────────────────────────────────
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

// ── Timeline ──────────────────────────────────────────────────────────────────
export interface TimelineEvent {
  type: 'alert';
  timestamp: string;
  title: string;
  severity: Severity;
  attack_type?: string;
  detection_rule?: string;
  confidence: number;
  evidence?: Record<string, unknown>;
  mitre_tactics?: string[];
  events: SecurityEvent[];
}

export interface IncidentTimeline {
  incident_id: string;
  title: string;
  severity: Severity;
  timeline: TimelineEvent[];
  ai_investigations: AIInvestigation[];
}

// ── Search ────────────────────────────────────────────────────────────────────
export interface SearchResult {
  type: 'event' | 'alert' | 'incident' | 'threat_intel';
  id: string;
  title: string;
  severity?: Severity;
  source_ip?: string;
  timestamp?: string;
}
