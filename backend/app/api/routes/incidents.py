"""
Incidents API Routes
GET   /incidents
POST  /incidents
GET   /incidents/{id}
PATCH /incidents/{id}
POST  /incidents/{id}/investigate  — triggers AI investigation
GET   /incidents/{id}/timeline
"""
import logging
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models import Incident, Alert, AIInvestigation, AuditLog, SecurityEvent
from app.schemas import (
    IncidentCreate, IncidentUpdate, IncidentResponse,
    AIInvestigationResponse, PaginatedResponse
)
from app.api.routes.auth import get_current_user, require_role
from app.services.ai.investigator import ai_investigator
from app.services.risk.scorer import score_incident
from app.websocket.manager import ws_manager

router = APIRouter(prefix="/incidents", tags=["Incidents"])
logger = logging.getLogger(__name__)


@router.get("", response_model=PaginatedResponse)
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source_ip: Optional[str] = None,
    target_user: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    filters = []
    if severity:
        filters.append(Incident.severity == severity)
    if status:
        filters.append(Incident.status == status)
    if source_ip:
        filters.append(Incident.source_ip == source_ip)
    if target_user:
        filters.append(Incident.target_user.ilike(f"%{target_user}%"))
    
    count_q = select(func.count(Incident.id))
    if filters:
        count_q = count_q.where(and_(*filters))
    total = (await db.execute(count_q)).scalar()
    
    q = (
        select(Incident)
        .options(selectinload(Incident.alerts))
        .order_by(desc(Incident.created_at))
    )
    if filters:
        q = q.where(and_(*filters))
    q = q.offset((page - 1) * page_size).limit(page_size)
    
    result = await db.execute(q)
    incidents = result.scalars().all()
    
    items = []
    for inc in incidents:
        d = IncidentResponse.model_validate(inc).model_dump()
        d["alert_count"] = len(inc.alerts)
        items.append(d)
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size if total else 0,
    )


@router.post("", response_model=IncidentResponse, status_code=201)
async def create_incident(
    data: IncidentCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin", "analyst")),
):
    """Manually create an incident."""
    risk = score_incident(
        severity=data.severity,
        attack_types=[],
        alert_count=0,
        target_user=data.target_user,
        anomaly_score=None,
        bytes_exfiltrated=None,
        mitre_tactics=[],
    )
    
    max_num = await db.execute(select(func.max(Incident.incident_number)))
    next_num = (max_num.scalar() or 0) + 1
    
    incident = Incident(
        incident_number=next_num,
        title=data.title,
        description=data.description,
        severity=data.severity,
        source_ip=data.source_ip,
        target_user=data.target_user,
        risk_score=risk["score"],
        risk_breakdown=risk,
    )
    db.add(incident)
    await db.flush()
    
    background_tasks.add_task(
        ws_manager.broadcast_incident,
        {"id": incident.id, "title": incident.title, "severity": incident.severity},
        "created",
    )
    
    return IncidentResponse.model_validate(incident)


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(
        select(Incident)
        .options(selectinload(Incident.alerts))
        .where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    d = IncidentResponse.model_validate(incident).model_dump()
    d["alert_count"] = len(incident.alerts)
    return d


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: str,
    update: IncidentUpdate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin", "analyst")),
):
    result = await db.execute(
        select(Incident).options(selectinload(Incident.alerts)).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    for field, value in update.model_dump(exclude_none=True).items():
        setattr(incident, field, value)
    
    if update.status == "resolved":
        incident.resolved_at = datetime.now(timezone.utc).replace(tzinfo=None)
    
    audit = AuditLog(
        user_id=current_user.id,
        action="incident_updated",
        resource_type="incident",
        resource_id=incident_id,
        details=update.model_dump(exclude_none=True),
    )
    db.add(audit)
    await db.flush()
    
    background_tasks.add_task(
        ws_manager.broadcast_incident,
        {"id": incident.id, "title": incident.title, "status": incident.status},
        "updated",
    )
    
    d = IncidentResponse.model_validate(incident).model_dump()
    d["alert_count"] = len(incident.alerts)
    return d


@router.post("/{incident_id}/investigate")
async def trigger_investigation(
    incident_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin", "analyst")),
):
    """Trigger AI investigation for an incident."""
    result = await db.execute(
        select(Incident)
        .options(selectinload(Incident.alerts))
        .where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Build evidence dict
    incident_data = {
        "title": incident.title,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "risk_label": (incident.risk_breakdown or {}).get("label", "UNKNOWN"),
        "source_ip": incident.source_ip,
        "target_user": incident.target_user,
        "attack_vector": incident.attack_vector,
        "alerts": [
            {
                "title": a.title,
                "severity": a.severity,
                "attack_type": a.attack_type,
                "detection_rule": a.detection_rule,
                "confidence": a.confidence,
                "mitre_tactics": a.mitre_tactics,
                "created_at": a.created_at,
            }
            for a in incident.alerts
        ],
        "risk_breakdown": incident.risk_breakdown,
        "mitre_tactics": incident.mitre_tactics,
        "first_event_at": incident.first_event_at,
        "last_event_at": incident.last_event_at,
    }
    
    # Run AI investigation
    import time
    start = time.time()
    ai_result = await ai_investigator.investigate(incident_data)
    duration_ms = int((time.time() - start) * 1000)
    
    # Store result
    investigation = AIInvestigation(
        incident_id=incident_id,
        llm_provider=ai_result.get("llm_provider"),
        model_used=ai_result.get("model_used"),
        summary=ai_result.get("summary"),
        attack_analysis=ai_result.get("attack_analysis"),
        evidence_summary=ai_result.get("evidence_summary"),
        mitre_mapping=ai_result.get("mitre_mapping"),
        risk_explanation=ai_result.get("risk_explanation"),
        recommended_response=ai_result.get("recommended_response"),
        confidence=ai_result.get("confidence", 0.7),
        duration_ms=duration_ms,
    )
    db.add(investigation)
    
    # Audit
    audit = AuditLog(
        user_id=current_user.id,
        action="ai_investigation_triggered",
        resource_type="incident",
        resource_id=incident_id,
        details={"provider": ai_result.get("llm_provider")},
    )
    db.add(audit)
    await db.flush()
    
    return {
        "investigation_id": investigation.id,
        "provider": ai_result.get("llm_provider"),
        "summary": ai_result.get("summary"),
        "attack_analysis": ai_result.get("attack_analysis"),
        "evidence_summary": ai_result.get("evidence_summary"),
        "mitre_mapping": ai_result.get("mitre_mapping"),
        "risk_explanation": ai_result.get("risk_explanation"),
        "recommended_response": ai_result.get("recommended_response"),
        "confidence": ai_result.get("confidence"),
        "duration_ms": duration_ms,
    }


@router.get("/{incident_id}/timeline")
async def get_timeline(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get the incident timeline — all related alerts sorted by time."""
    result = await db.execute(
        select(Incident)
        .options(selectinload(Incident.alerts).selectinload(Alert.events))
        .where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    timeline = []
    for alert in sorted(incident.alerts, key=lambda a: a.created_at):
        entry = {
            "type": "alert",
            "timestamp": alert.created_at,
            "title": alert.title,
            "severity": alert.severity,
            "attack_type": alert.attack_type,
            "detection_rule": alert.detection_rule,
            "confidence": alert.confidence,
            "evidence": alert.evidence,
            "mitre_tactics": alert.mitre_tactics,
        }
        
        # Add sub-events
        sub_events = []
        for event in sorted(alert.events, key=lambda e: e.timestamp):
            sub_events.append({
                "id": event.id,
                "timestamp": event.timestamp,
                "event_type": event.event_type,
                "source_ip": event.source_ip,
                "username": event.username,
                "severity": event.severity,
                "bytes_transferred": event.bytes_transferred,
            })
        entry["events"] = sub_events
        timeline.append(entry)
    
    return {
        "incident_id": incident_id,
        "title": incident.title,
        "severity": incident.severity,
        "timeline": timeline,
        "ai_investigations": [
            AIInvestigationResponse.model_validate(inv).model_dump()
            for inv in incident.ai_investigations
        ],
    }


@router.get("/{incident_id}/investigations")
async def get_investigations(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get all AI investigations for an incident."""
    result = await db.execute(
        select(AIInvestigation)
        .where(AIInvestigation.incident_id == incident_id)
        .order_by(desc(AIInvestigation.created_at))
    )
    investigations = result.scalars().all()
    return [AIInvestigationResponse.model_validate(inv) for inv in investigations]
