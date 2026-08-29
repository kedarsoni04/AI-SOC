"""
SQLAlchemy ORM Models — AI-SOC Platform
"""
import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import (
    String, Integer, Float, Boolean, DateTime, Text, JSON,
    ForeignKey, Table, Column, func
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _uuid():
    return str(uuid.uuid4())


# ── Base ───────────────────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


# ── Association Table: Alert ↔ SecurityEvent ───────────────────────────────────
event_alert_association = Table(
    "event_alert_association",
    Base.metadata,
    Column("event_id", String(36), ForeignKey("security_events.id"), primary_key=True),
    Column("alert_id", String(36), ForeignKey("alerts.id"), primary_key=True),
)


# ── User ───────────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(50), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)


# ── SecurityEvent ──────────────────────────────────────────────────────────────
class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)
    source: Mapped[Optional[str]] = mapped_column(String(100))
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45))
    source_port: Mapped[Optional[int]] = mapped_column(Integer)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer)
    username: Mapped[Optional[str]] = mapped_column(String(100), index=True)
    event_type: Mapped[Optional[str]] = mapped_column(String(100), index=True)
    http_method: Mapped[Optional[str]] = mapped_column(String(10))
    endpoint: Mapped[Optional[str]] = mapped_column(Text)
    status_code: Mapped[Optional[int]] = mapped_column(Integer)
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), default="info", index=True)
    bytes_transferred: Mapped[Optional[float]] = mapped_column(Float)
    protocol: Mapped[Optional[str]] = mapped_column(String(20))
    country: Mapped[Optional[str]] = mapped_column(String(100))
    city: Mapped[Optional[str]] = mapped_column(String(100))
    latitude: Mapped[Optional[float]] = mapped_column(Float)
    longitude: Mapped[Optional[float]] = mapped_column(Float)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)
    anomaly_score: Mapped[Optional[float]] = mapped_column(Float)
    raw_log: Mapped[Optional[str]] = mapped_column(Text)
    event_metadata: Mapped[Optional[dict]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    # Relationships
    alerts: Mapped[List["Alert"]] = relationship(
        "Alert", secondary=event_alert_association, back_populates="events"
    )
    ml_predictions: Mapped[List["MLPrediction"]] = relationship(
        "MLPrediction", back_populates="event", cascade="all, delete-orphan"
    )


# ── Alert ──────────────────────────────────────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(50), default="new", index=True)
    detection_rule: Mapped[Optional[str]] = mapped_column(String(100))
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45))
    username: Mapped[Optional[str]] = mapped_column(String(100))
    attack_type: Mapped[Optional[str]] = mapped_column(String(100), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[Optional[dict]] = mapped_column(JSON)
    mitre_tactics: Mapped[Optional[list]] = mapped_column(JSON)
    mitre_techniques: Mapped[Optional[list]] = mapped_column(JSON)
    false_positive_reason: Mapped[Optional[str]] = mapped_column(Text)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    assigned_to_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"))
    incident_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("incidents.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    # Relationships
    events: Mapped[List["SecurityEvent"]] = relationship(
        "SecurityEvent", secondary=event_alert_association, back_populates="alerts"
    )
    incident: Mapped[Optional["Incident"]] = relationship("Incident", back_populates="alerts")
    assigned_to: Mapped[Optional["User"]] = relationship("User", foreign_keys=[assigned_to_id])


# ── Incident ───────────────────────────────────────────────────────────────────
class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_number: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(50), default="new", index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_breakdown: Mapped[Optional[dict]] = mapped_column(JSON)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45))
    target_user: Mapped[Optional[str]] = mapped_column(String(100))
    attack_vector: Mapped[Optional[str]] = mapped_column(String(200))
    mitre_tactics: Mapped[Optional[list]] = mapped_column(JSON)
    mitre_techniques: Mapped[Optional[list]] = mapped_column(JSON)
    analyst_notes: Mapped[Optional[str]] = mapped_column(Text)
    resolution: Mapped[Optional[str]] = mapped_column(Text)
    assigned_analyst_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    first_event_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_event_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Relationships
    alerts: Mapped[List["Alert"]] = relationship("Alert", back_populates="incident")
    ai_investigations: Mapped[List["AIInvestigation"]] = relationship(
        "AIInvestigation", back_populates="incident", cascade="all, delete-orphan"
    )
    response_actions: Mapped[List["ResponseAction"]] = relationship(
        "ResponseAction", back_populates="incident", cascade="all, delete-orphan"
    )
    assigned_analyst: Mapped[Optional["User"]] = relationship("User", foreign_keys=[assigned_analyst_id])


# ── DetectionRule ──────────────────────────────────────────────────────────────
class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    rule_type: Mapped[str] = mapped_column(String(50))  # rule, ml, correlation
    attack_type: Mapped[Optional[str]] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    threshold: Mapped[Optional[float]] = mapped_column(Float)
    time_window_seconds: Mapped[Optional[int]] = mapped_column(Integer)
    conditions: Mapped[Optional[dict]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)


# ── ThreatIndicator ────────────────────────────────────────────────────────────
class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    indicator_type: Mapped[str] = mapped_column(String(50), index=True)  # ip, domain, hash, url, email
    value: Mapped[str] = mapped_column(String(2000), nullable=False, index=True)
    threat_type: Mapped[Optional[str]] = mapped_column(String(100))
    confidence: Mapped[float] = mapped_column(Float, default=0.7)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    source: Mapped[Optional[str]] = mapped_column(String(200))
    description: Mapped[Optional[str]] = mapped_column(Text)
    tags: Mapped[Optional[list]] = mapped_column(JSON)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


# ── ResponseAction ─────────────────────────────────────────────────────────────
class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=False)
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)  # block_ip, disable_account, etc.
    target: Mapped[Optional[str]] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    recommended_by: Mapped[str] = mapped_column(String(50), default="analyst")  # ai, rule, analyst
    approved_by_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"))
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="response_actions")
    approved_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[approved_by_id])


# ── AuditLog ───────────────────────────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String(100))
    resource_id: Mapped[Optional[str]] = mapped_column(String(36))
    details: Mapped[Optional[dict]] = mapped_column(JSON)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)


# ── MLPrediction ───────────────────────────────────────────────────────────────
class MLPrediction(Base):
    __tablename__ = "ml_predictions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    event_id: Mapped[str] = mapped_column(String(36), ForeignKey("security_events.id"), nullable=False)
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    prediction_label: Mapped[str] = mapped_column(String(100))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    anomaly_score: Mapped[Optional[float]] = mapped_column(Float)
    features: Mapped[Optional[dict]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    event: Mapped["SecurityEvent"] = relationship("SecurityEvent", back_populates="ml_predictions")


# ── AIInvestigation ────────────────────────────────────────────────────────────
class AIInvestigation(Base):
    __tablename__ = "ai_investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=False)
    llm_provider: Mapped[Optional[str]] = mapped_column(String(50))
    model_used: Mapped[Optional[str]] = mapped_column(String(100))
    summary: Mapped[Optional[str]] = mapped_column(Text)
    attack_analysis: Mapped[Optional[str]] = mapped_column(Text)
    evidence_summary: Mapped[Optional[str]] = mapped_column(Text)
    mitre_mapping: Mapped[Optional[list]] = mapped_column(JSON)
    risk_explanation: Mapped[Optional[str]] = mapped_column(Text)
    recommended_response: Mapped[Optional[str]] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.7)
    tokens_used: Mapped[Optional[int]] = mapped_column(Integer)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="ai_investigations")


# ── BlockedIP ──────────────────────────────────────────────────────────────────
class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    reason: Mapped[Optional[str]] = mapped_column(Text)
    blocked_by_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"))
    incident_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("incidents.id"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
