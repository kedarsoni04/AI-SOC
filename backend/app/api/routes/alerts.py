"""
Alerts API Routes
GET   /alerts
GET   /alerts/{id}
PATCH /alerts/{id}
POST  /alerts/{id}/convert-to-incident
"""
import logging
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_, or_
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models import Alert, Incident, User, AuditLog
from app.schemas import AlertResponse, AlertUpdate, PaginatedResponse
from app.api.routes.auth import get_current_user, require_role
from app.services.correlation.correlator import correlation_engine
from app.services.risk.scorer import score_incident
from app.websocket.manager import ws_manager

router = APIRouter(prefix="/alerts", tags=["Alerts"])
logger = logging.getLogger(__name__)


@router.get("", response_model=PaginatedResponse)
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    attack_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """List alerts with filtering and pagination."""
    filters = []
    if severity:
        filters.append(Alert.severity == severity)
    if status:
        filters.append(Alert.status == status)
    if attack_type:
        filters.append(Alert.attack_type == attack_type)
    if source_ip:
        filters.append(Alert.source_ip == source_ip)
    if start_time:
        filters.append(Alert.created_at >= start_time)
    if end_time:
        filters.append(Alert.created_at <= end_time)
    
    count_q = select(func.count(Alert.id))
    if filters:
        count_q = count_q.where(and_(*filters))
    total = (await db.execute(count_q)).scalar()
    
    q = select(Alert).order_by(desc(Alert.created_at))
    if filters:
        q = q.where(and_(*filters))
    q = q.offset((page - 1) * page_size).limit(page_size)
    
    result = await db.execute(q)
    alerts = result.scalars().all()
    
    return PaginatedResponse(
        items=[AlertResponse.model_validate(a) for a in alerts],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size if total else 0,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(
        select(Alert).options(selectinload(Alert.events)).where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertResponse.model_validate(alert)


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: str,
    update: AlertUpdate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Update alert status, assignment, or mark as false positive."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    if update.status:
        alert.status = update.status
        if update.status == "acknowledged":
            alert.acknowledged_at = datetime.now(timezone.utc).replace(tzinfo=None)
    if update.assigned_to_id:
        alert.assigned_to_id = update.assigned_to_id
    if update.false_positive_reason:
        alert.false_positive_reason = update.false_positive_reason
        alert.status = "false_positive"
    
    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        action="alert_updated",
        resource_type="alert",
        resource_id=alert_id,
        details=update.model_dump(exclude_none=True),
    )
    db.add(audit)
    await db.flush()
    
    return AlertResponse.model_validate(alert)


@router.post("/{alert_id}/convert-to-incident")
async def convert_to_incident(
    alert_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin", "analyst")),
):
    """Convert an alert to a standalone incident."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    if alert.incident_id:
        raise HTTPException(status_code=400, detail="Alert already linked to an incident")
    
    # Build incident
    alert_dict = AlertResponse.model_validate(alert).model_dump()
    risk = score_incident(
        severity=alert.severity,
        attack_types=[alert.attack_type] if alert.attack_type else [],
        alert_count=1,
        target_user=alert.username,
        anomaly_score=None,
        bytes_exfiltrated=None,
        mitre_tactics=alert.mitre_tactics,
    )
    
    # Get next incident number
    max_num = await db.execute(select(func.max(Incident.incident_number)))
    next_num = (max_num.scalar() or 0) + 1
    
    incident = Incident(
        incident_number=next_num,
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        risk_score=risk["score"],
        risk_breakdown=risk,
        source_ip=alert.source_ip,
        target_user=alert.username,
        attack_vector=alert.attack_type or "Unknown",
        mitre_tactics=alert.mitre_tactics,
        mitre_techniques=alert.mitre_techniques,
    )
    db.add(incident)
    await db.flush()
    
    alert.incident_id = incident.id
    alert.status = "investigating"
    
    background_tasks.add_task(
        ws_manager.broadcast_incident,
        {"id": incident.id, "title": incident.title, "severity": incident.severity},
        "created",
    )
    
    return {"incident_id": incident.id, "message": "Incident created successfully"}
