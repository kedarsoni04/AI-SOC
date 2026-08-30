"""
Events API Routes
GET  /events
POST /events (ingest new log)
GET  /events/{id}
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_, or_

from app.core.database import get_db
from app.models import SecurityEvent, Alert, MLPrediction
from app.schemas import SecurityEventCreate, SecurityEventResponse, PaginatedResponse
from app.api.routes.auth import get_current_user
from app.services.normalization.normalizer import normalizer
from app.services.detection.rule_engine import rule_engine
from app.services.detection.ml_detector import anomaly_detector
from app.services.detection.classifier import threat_classifier
from app.websocket.manager import ws_manager

router = APIRouter(prefix="/events", tags=["Security Events"])
logger = logging.getLogger(__name__)


@router.get("", response_model=PaginatedResponse)
async def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    is_anomaly: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """List security events with filtering and pagination."""
    filters = []
    
    if severity:
        filters.append(SecurityEvent.severity == severity)
    if event_type:
        filters.append(SecurityEvent.event_type.ilike(f"%{event_type}%"))
    if source_ip:
        filters.append(SecurityEvent.source_ip == source_ip)
    if username:
        filters.append(SecurityEvent.username.ilike(f"%{username}%"))
    if start_time:
        filters.append(SecurityEvent.timestamp >= start_time)
    if end_time:
        filters.append(SecurityEvent.timestamp <= end_time)
    if is_anomaly is not None:
        filters.append(SecurityEvent.is_anomaly == is_anomaly)
    
    # Count
    count_q = select(func.count(SecurityEvent.id))
    if filters:
        count_q = count_q.where(and_(*filters))
    total = (await db.execute(count_q)).scalar()
    
    # Fetch
    q = select(SecurityEvent).order_by(desc(SecurityEvent.timestamp))
    if filters:
        q = q.where(and_(*filters))
    q = q.offset((page - 1) * page_size).limit(page_size)
    
    result = await db.execute(q)
    events = result.scalars().all()
    
    return PaginatedResponse(
        items=[SecurityEventResponse.model_validate(e) for e in events],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size if total else 0,
    )


@router.post("", response_model=SecurityEventResponse, status_code=201)
async def ingest_event(
    raw_log: SecurityEventCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Ingest a raw log entry — normalize, detect, and store."""
    raw_dict = raw_log.model_dump(by_alias=True, exclude_none=True)
    event = await _process_event(raw_dict, db, background_tasks)
    return SecurityEventResponse.model_validate(event)


@router.get("/{event_id}", response_model=SecurityEventResponse)
async def get_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get a specific security event by ID."""
    result = await db.execute(select(SecurityEvent).where(SecurityEvent.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return SecurityEventResponse.model_validate(event)


# ── Core event processing pipeline ────────────────────────────────────────────
async def _process_event(
    raw_log: dict,
    db: AsyncSession,
    background_tasks: Optional[BackgroundTasks] = None,
) -> SecurityEvent:
    """
    Full event processing pipeline:
    1. Normalize
    2. Store
    3. ML Anomaly Detection
    4. Threat Classification
    5. Rule-Based Detection → Alerts
    6. Broadcast via WebSocket
    """
    # 1. Normalize
    normalized = normalizer.normalize(raw_log)
    
    # 2. ML Anomaly Detection
    is_anomaly, anomaly_score = anomaly_detector.predict(normalized)
    normalized["is_anomaly"] = bool(is_anomaly)
    normalized["anomaly_score"] = float(anomaly_score) if anomaly_score is not None else None
    
    # 3. Store event
    event = SecurityEvent(**normalized)
    db.add(event)
    await db.flush()  # Get the ID
    
    # 4. ML Classification (store prediction)
    pred_label, pred_confidence = threat_classifier.predict(normalized)
    # Convert numpy scalars to native Python types (JSON serialization safety)
    pred_label_str = str(pred_label)
    pred_confidence_float = float(pred_confidence)
    is_anomaly_bool = bool(is_anomaly)
    anomaly_score_float = float(anomaly_score) if anomaly_score is not None else None
    if pred_label_str != "unknown":
        ml_pred = MLPrediction(
            event_id=event.id,
            model_name="ThreatClassifier",
            prediction_label=pred_label_str,
            confidence=pred_confidence_float,
            anomaly_score=anomaly_score_float,
            features={"is_anomaly": is_anomaly_bool, "anomaly_score": anomaly_score_float},
        )
        db.add(ml_pred)
    
    # 5. Rule-Based Detection
    detection_alerts = rule_engine.analyze(normalized)
    
    for det_alert in detection_alerts:
        alert = Alert(
            title=det_alert.title,
            description=det_alert.description,
            severity=det_alert.severity,
            detection_rule=det_alert.rule_name,
            source_ip=det_alert.source_ip,
            destination_ip=det_alert.destination_ip,
            username=det_alert.username,
            attack_type=det_alert.attack_type,
            confidence=det_alert.confidence,
            evidence=det_alert.evidence,
            mitre_tactics=det_alert.mitre_tactics,
            mitre_techniques=det_alert.mitre_techniques,
        )
        alert.events = [event]
        db.add(alert)
    
    await db.flush()
    
    # 6. Broadcast
    event_dict = {
        "id": event.id,
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "severity": event.severity,
        "source_ip": event.source_ip,
        "username": event.username,
        "is_anomaly": event.is_anomaly,
        "anomaly_score": event.anomaly_score,
    }
    
    if background_tasks:
        background_tasks.add_task(ws_manager.broadcast_event, event_dict)
        for det_alert in detection_alerts:
            alert_dict = {
                "title": det_alert.title,
                "severity": det_alert.severity,
                "attack_type": det_alert.attack_type,
                "source_ip": det_alert.source_ip,
            }
            background_tasks.add_task(ws_manager.broadcast_alert, alert_dict)
    
    return event
