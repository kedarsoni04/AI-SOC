"""
Pydantic Schemas for request/response validation.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, EmailStr, Field, field_validator
import uuid


# ── Helpers ────────────────────────────────────────────────────────────────────
def gen_id() -> str:
    return str(uuid.uuid4())


# ── Auth ──────────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    email: str
    username: str
    password: str
    full_name: Optional[str] = None
    role: str = "analyst"


class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    last_login: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse


# ── Security Events ────────────────────────────────────────────────────────────
class SecurityEventCreate(BaseModel):
    timestamp: Optional[datetime] = None
    source: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    username: Optional[str] = None
    event_type: Optional[str] = "GENERIC"
    http_method: Optional[str] = None
    endpoint: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    severity: Optional[str] = "info"
    bytes_transferred: Optional[float] = None
    protocol: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None
    raw_log: Optional[str] = None


class SecurityEventResponse(BaseModel):
    id: str
    timestamp: datetime
    source: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    username: Optional[str] = None
    event_type: Optional[str] = None
    http_method: Optional[str] = None
    endpoint: Optional[str] = None
    status_code: Optional[int] = None
    severity: str
    bytes_transferred: Optional[float] = None
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_anomaly: bool = False
    anomaly_score: Optional[float] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Alerts ─────────────────────────────────────────────────────────────────────
class AlertResponse(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    detection_rule: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    attack_type: Optional[str] = None
    confidence: float
    evidence: Optional[Dict[str, Any]] = None
    mitre_tactics: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    incident_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to_id: Optional[str] = None
    false_positive_reason: Optional[str] = None


# ── Incidents ──────────────────────────────────────────────────────────────────
class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    source_ip: Optional[str] = None
    target_user: Optional[str] = None


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    analyst_notes: Optional[str] = None
    resolution: Optional[str] = None
    assigned_analyst_id: Optional[str] = None


class IncidentResponse(BaseModel):
    id: str
    incident_number: int
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    risk_score: float
    risk_breakdown: Optional[Dict[str, Any]] = None
    source_ip: Optional[str] = None
    target_user: Optional[str] = None
    attack_vector: Optional[str] = None
    mitre_tactics: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    analyst_notes: Optional[str] = None
    resolution: Optional[str] = None
    assigned_analyst_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    first_event_at: Optional[datetime] = None
    last_event_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ── AI Investigation ──────────────────────────────────────────────────────────
class AIInvestigationResponse(BaseModel):
    id: str
    incident_id: str
    llm_provider: Optional[str] = None
    model_used: Optional[str] = None
    summary: Optional[str] = None
    attack_analysis: Optional[str] = None
    evidence_summary: Optional[str] = None
    mitre_mapping: Optional[List[Dict[str, Any]]] = None
    risk_explanation: Optional[str] = None
    recommended_response: Optional[str] = None
    confidence: float
    tokens_used: Optional[int] = None
    duration_ms: Optional[int] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Threat Intelligence ────────────────────────────────────────────────────────
class ThreatIndicatorCreate(BaseModel):
    indicator_type: str
    value: str
    threat_type: Optional[str] = None
    confidence: float = 0.8
    severity: str = "medium"
    source: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None


class ThreatIndicatorResponse(BaseModel):
    id: str
    indicator_type: str
    value: str
    threat_type: Optional[str] = None
    confidence: float
    severity: str
    source: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    is_active: bool
    first_seen: datetime
    last_seen: datetime
    hit_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


class ThreatSearchRequest(BaseModel):
    query: str
    indicator_type: Optional[str] = None


class ThreatSearchResponse(BaseModel):
    found: bool
    indicators: List[ThreatIndicatorResponse]
    total: int


# ── Response Actions ──────────────────────────────────────────────────────────
class ResponseActionCreate(BaseModel):
    incident_id: str
    action_type: str
    target: Optional[str] = None
    description: str


class ResponseActionUpdate(BaseModel):
    status: str
    rejection_reason: Optional[str] = None


class ResponseActionResponse(BaseModel):
    id: str
    incident_id: str
    action_type: str
    target: Optional[str] = None
    description: str
    status: str
    recommended_by: str
    approved_by_id: Optional[str] = None
    rejection_reason: Optional[str] = None
    executed_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Audit Logs ────────────────────────────────────────────────────────────────
class AuditLogResponse(BaseModel):
    id: str
    user_id: Optional[str] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    success: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Dashboard ─────────────────────────────────────────────────────────────────
class DashboardSummary(BaseModel):
    total_events: int
    active_incidents: int
    critical_incidents: int
    high_alerts: int
    resolved_incidents: int
    blocked_ips: int
    threats_today: int
    events_last_hour: int
    simulation_status: Dict[str, Any]


# ── Simulation ────────────────────────────────────────────────────────────────
class SimulationControl(BaseModel):
    action: str = "start"  # start, stop
    scenario: Optional[str] = "normal"


class SimulationStatus(BaseModel):
    is_running: bool
    scenario: Optional[str] = None
    events_generated: int
    started_at: Optional[datetime] = None


# ── Pagination ────────────────────────────────────────────────────────────────
class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int
    pages: int
