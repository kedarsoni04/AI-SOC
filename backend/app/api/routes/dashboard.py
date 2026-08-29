"""
Dashboard, Simulation, Threat Intel, ML, Response, Audit, and WebSocket routes.
"""
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_, or_, text

from app.core.database import get_db
from app.models import (
    SecurityEvent, Alert, Incident, ThreatIndicator, ResponseAction,
    AuditLog, BlockedIP, AIInvestigation
)
from app.schemas import (
    DashboardSummary, ThreatIndicatorCreate, ThreatIndicatorResponse,
    ThreatSearchRequest, ThreatSearchResponse, ResponseActionCreate,
    ResponseActionUpdate, ResponseActionResponse, AuditLogResponse,
    SimulationControl, SimulationStatus, PaginatedResponse
)
from app.api.routes.auth import get_current_user, require_role
from app.services.simulation.generator import simulation_engine, SCENARIOS
from app.services.correlation.correlator import correlation_engine
from app.services.risk.scorer import score_incident
from app.websocket.manager import ws_manager

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# Dashboard
# ═══════════════════════════════════════════════════════════════════════════════
dashboard_router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@dashboard_router.get("/summary")
async def get_dashboard_summary(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Real-time dashboard summary statistics."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    last_hour = now - timedelta(hours=1)
    
    # Total events
    total_events = (await db.execute(select(func.count(SecurityEvent.id)))).scalar()
    
    # Active incidents (not resolved/false_positive)
    active_incidents = (await db.execute(
        select(func.count(Incident.id)).where(
            Incident.status.in_(["new", "investigating", "contained"])
        )
    )).scalar()
    
    # Critical incidents
    critical_incidents = (await db.execute(
        select(func.count(Incident.id)).where(
            and_(Incident.severity == "critical", Incident.status != "resolved")
        )
    )).scalar()
    
    # High alerts (active)
    high_alerts = (await db.execute(
        select(func.count(Alert.id)).where(
            and_(Alert.severity.in_(["critical", "high"]), Alert.status == "new")
        )
    )).scalar()
    
    # Resolved incidents
    resolved_incidents = (await db.execute(
        select(func.count(Incident.id)).where(Incident.status == "resolved")
    )).scalar()
    
    # Blocked IPs
    blocked_ips = (await db.execute(
        select(func.count(BlockedIP.id)).where(BlockedIP.is_active == True)
    )).scalar()
    
    # Threats today
    threats_today = (await db.execute(
        select(func.count(Alert.id)).where(Alert.created_at >= today_start)
    )).scalar()
    
    # Events last hour
    events_last_hour = (await db.execute(
        select(func.count(SecurityEvent.id)).where(SecurityEvent.timestamp >= last_hour)
    )).scalar()
    
    return {
        "total_events": total_events,
        "active_incidents": active_incidents,
        "critical_incidents": critical_incidents,
        "high_alerts": high_alerts,
        "resolved_incidents": resolved_incidents,
        "blocked_ips": blocked_ips,
        "threats_today": threats_today,
        "events_last_hour": events_last_hour,
        "simulation_status": simulation_engine.get_status(),
    }


@dashboard_router.get("/event-volume")
async def get_event_volume(
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Event volume over time (by hour)."""
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
    
    result = await db.execute(
        select(SecurityEvent.timestamp, SecurityEvent.severity)
        .where(SecurityEvent.timestamp >= since)
        .order_by(SecurityEvent.timestamp)
    )
    rows = result.fetchall()
    
    # Bucket by hour
    buckets = {}
    for ts, severity in rows:
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        hour_key = ts.strftime("%Y-%m-%dT%H:00:00")
        if hour_key not in buckets:
            buckets[hour_key] = {"timestamp": hour_key, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        buckets[hour_key]["total"] += 1
        if severity in buckets[hour_key]:
            buckets[hour_key][severity] += 1
    
    return sorted(buckets.values(), key=lambda x: x["timestamp"])


@dashboard_router.get("/severity-distribution")
async def get_severity_distribution(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
    )
    rows = result.fetchall()
    return {row[0]: row[1] for row in rows}


@dashboard_router.get("/attack-types")
async def get_attack_types(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(
        select(Alert.attack_type, func.count(Alert.id))
        .where(Alert.attack_type.isnot(None))
        .group_by(Alert.attack_type)
        .order_by(desc(func.count(Alert.id)))
        .limit(10)
    )
    rows = result.fetchall()
    return [{"attack_type": row[0], "count": row[1]} for row in rows]


@dashboard_router.get("/top-source-ips")
async def get_top_source_ips(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(
        select(SecurityEvent.source_ip, SecurityEvent.country, func.count(SecurityEvent.id))
        .where(SecurityEvent.source_ip.isnot(None))
        .group_by(SecurityEvent.source_ip, SecurityEvent.country)
        .order_by(desc(func.count(SecurityEvent.id)))
        .limit(10)
    )
    rows = result.fetchall()
    return [{"ip": row[0], "country": row[1], "count": row[2]} for row in rows]


@dashboard_router.get("/incident-trends")
async def get_incident_trends(
    days: int = Query(7, ge=1, le=30),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Incident count by day for trend chart."""
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    result = await db.execute(
        select(Incident.created_at, Incident.severity, Incident.status)
        .where(Incident.created_at >= since)
    )
    rows = result.fetchall()
    
    buckets = {}
    for ts, severity, status in rows:
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        day_key = ts.strftime("%Y-%m-%d")
        if day_key not in buckets:
            buckets[day_key] = {"date": day_key, "total": 0, "critical": 0, "high": 0, "resolved": 0}
        buckets[day_key]["total"] += 1
        if severity in ("critical",):
            buckets[day_key]["critical"] += 1
        elif severity == "high":
            buckets[day_key]["high"] += 1
        if status == "resolved":
            buckets[day_key]["resolved"] += 1
    
    return sorted(buckets.values(), key=lambda x: x["date"])


@dashboard_router.get("/geo-attacks")
async def get_geo_attacks(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Attack sources by geography for the attack map."""
    result = await db.execute(
        select(
            SecurityEvent.source_ip,
            SecurityEvent.country,
            SecurityEvent.city,
            SecurityEvent.latitude,
            SecurityEvent.longitude,
            func.count(SecurityEvent.id).label("count"),
        )
        .where(
            and_(
                SecurityEvent.country.isnot(None),
                SecurityEvent.country != "Unknown",
                SecurityEvent.latitude.isnot(None),
            )
        )
        .group_by(
            SecurityEvent.source_ip,
            SecurityEvent.country,
            SecurityEvent.city,
            SecurityEvent.latitude,
            SecurityEvent.longitude,
        )
        .order_by(desc("count"))
        .limit(50)
    )
    rows = result.fetchall()
    return [
        {
            "ip": row[0],
            "country": row[1],
            "city": row[2],
            "lat": row[3],
            "lon": row[4],
            "count": row[5],
        }
        for row in rows
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# Simulation
# ═══════════════════════════════════════════════════════════════════════════════
simulation_router = APIRouter(prefix="/simulation", tags=["Simulation"])


async def _ingest_event_internal(event_dict: dict, db: AsyncSession):
    """Internal event ingestion used by the simulation engine."""
    from app.api.routes.events import _process_event
    try:
        async with db:
            await _process_event(event_dict, db)
    except Exception as e:
        logger.error(f"Failed to ingest simulated event: {e}")


@simulation_router.post("/start")
async def start_simulation(
    control: SimulationControl,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin", "analyst")),
):
    """Start the simulation engine."""
    from app.core.database import AsyncSessionLocal
    
    async def process_event(event: dict):
        """Callback: process each generated event."""
        from app.api.routes.events import _process_event
        async with AsyncSessionLocal() as session:
            await _process_event(event, session)
            await session.commit()
    
    simulation_engine.register_callback(process_event)
    
    if control.action == "start":
        scenario = control.scenario or "normal"
        
        if scenario in SCENARIOS and scenario != "normal":
            # One-shot scenario: generate immediately
            events = await simulation_engine.generate_scenario_once(scenario)
            
            # Trigger correlation after batch
            await _run_correlation(db)
            
            return {
                "status": "scenario_executed",
                "scenario": scenario,
                "events_generated": len(events),
            }
        else:
            # Continuous simulation
            await simulation_engine.start(scenario="normal")
            return {"status": "started", "scenario": "normal"}
    
    return {"status": "noop"}


async def _run_correlation(db: AsyncSession):
    """Run correlation on recent unlinked alerts to create incidents."""
    from sqlalchemy.orm import selectinload
    
    recent_cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=2)
    result = await db.execute(
        select(Alert)
        .where(
            and_(Alert.incident_id.is_(None), Alert.created_at >= recent_cutoff)
        )
        .order_by(Alert.created_at)
    )
    unlinked_alerts = result.scalars().all()
    
    if not unlinked_alerts:
        return
    
    alert_dicts = [
        {
            "id": a.id,
            "attack_type": a.attack_type,
            "source_ip": a.source_ip,
            "username": a.username,
            "severity": a.severity,
            "title": a.title,
            "confidence": a.confidence,
            "mitre_tactics": a.mitre_tactics,
            "created_at": a.created_at,
        }
        for a in unlinked_alerts
    ]
    
    proposed_incidents = correlation_engine.correlate(alert_dicts)
    
    max_num_result = await db.execute(select(func.max(Incident.incident_number)))
    next_num = (max_num_result.scalar() or 0) + 1
    
    for inc_data in proposed_incidents:
        alert_ids = [a["id"] for a in inc_data["alerts"]]
        
        # Get actual alerts + their events for anomaly score
        result2 = await db.execute(
            select(Alert).where(Alert.id.in_(alert_ids))
        )
        alerts_obj = result2.scalars().all()
        
        attack_types = list({a.attack_type for a in alerts_obj if a.attack_type})
        target_user = inc_data.get("target_user")
        
        risk = score_incident(
            severity=inc_data["severity"],
            attack_types=attack_types,
            alert_count=len(alerts_obj),
            target_user=target_user,
            anomaly_score=0.6,
            bytes_exfiltrated=None,
            mitre_tactics=inc_data.get("mitre_tactics", []),
        )
        
        incident = Incident(
            incident_number=next_num,
            title=inc_data["title"],
            description=inc_data["description"],
            severity=inc_data["severity"],
            risk_score=risk["score"],
            risk_breakdown=risk,
            source_ip=inc_data.get("source_ip"),
            target_user=target_user,
            attack_vector=inc_data.get("attack_vector"),
            mitre_tactics=inc_data.get("mitre_tactics", []),
            mitre_techniques=inc_data.get("mitre_techniques", []),
            first_event_at=inc_data.get("first_event_at"),
            last_event_at=inc_data.get("last_event_at"),
        )
        db.add(incident)
        await db.flush()
        
        for alert_obj in alerts_obj:
            alert_obj.incident_id = incident.id
            alert_obj.status = "investigating"
        
        next_num += 1
        
        await ws_manager.broadcast_incident(
            {
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "risk_score": incident.risk_score,
            },
            "created",
        )
    
    await db.flush()


@simulation_router.post("/stop")
async def stop_simulation(
    current_user=Depends(require_role("admin", "analyst")),
):
    await simulation_engine.stop()
    return {"status": "stopped", "events_generated": simulation_engine.events_generated}


@simulation_router.get("/status", response_model=SimulationStatus)
async def simulation_status(current_user=Depends(get_current_user)):
    return simulation_engine.get_status()


# ═══════════════════════════════════════════════════════════════════════════════
# Threat Intelligence
# ═══════════════════════════════════════════════════════════════════════════════
ti_router = APIRouter(prefix="/threat-intelligence", tags=["Threat Intelligence"])


@ti_router.get("", response_model=PaginatedResponse)
async def list_indicators(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    indicator_type: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    filters = []
    if indicator_type:
        filters.append(ThreatIndicator.indicator_type == indicator_type)
    if severity:
        filters.append(ThreatIndicator.severity == severity)
    if search:
        filters.append(ThreatIndicator.value.ilike(f"%{search}%"))
    
    count_q = select(func.count(ThreatIndicator.id))
    if filters:
        count_q = count_q.where(and_(*filters))
    total = (await db.execute(count_q)).scalar()
    
    q = select(ThreatIndicator).order_by(desc(ThreatIndicator.last_seen))
    if filters:
        q = q.where(and_(*filters))
    q = q.offset((page - 1) * page_size).limit(page_size)
    
    result = await db.execute(q)
    indicators = result.scalars().all()
    
    return PaginatedResponse(
        items=[ThreatIndicatorResponse.model_validate(i) for i in indicators],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size if total else 0,
    )


@ti_router.post("", response_model=ThreatIndicatorResponse, status_code=201)
async def add_indicator(
    data: ThreatIndicatorCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin", "analyst")),
):
    indicator = ThreatIndicator(**data.model_dump())
    db.add(indicator)
    await db.flush()
    return ThreatIndicatorResponse.model_validate(indicator)


@ti_router.post("/search")
async def search_indicator(
    search: ThreatSearchRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    filters = [ThreatIndicator.value.ilike(f"%{search.query}%")]
    if search.indicator_type:
        filters.append(ThreatIndicator.indicator_type == search.indicator_type)
    
    result = await db.execute(
        select(ThreatIndicator)
        .where(and_(*filters))
        .limit(20)
    )
    indicators = result.scalars().all()
    
    # Update hit counts
    for ind in indicators:
        ind.hit_count += 1
        ind.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
    
    await db.flush()
    
    return {
        "found": len(indicators) > 0,
        "indicators": [ThreatIndicatorResponse.model_validate(i) for i in indicators],
        "total": len(indicators),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ML Analytics
# ═══════════════════════════════════════════════════════════════════════════════
ml_router = APIRouter(prefix="/ml", tags=["ML Analytics"])


@ml_router.get("/performance")
async def get_ml_performance(current_user=Depends(get_current_user)):
    """Return ML model performance metrics."""
    from app.services.detection.ml_detector import anomaly_detector
    from app.services.detection.classifier import threat_classifier
    
    return {
        "anomaly_detector": anomaly_detector.get_info(),
        "threat_classifier": threat_classifier.get_info(),
    }


@ml_router.post("/train")
async def train_models(
    background_tasks: BackgroundTasks,
    current_user=Depends(require_role("admin")),
):
    """Trigger model training in the background."""
    from app.services.detection.ml_detector import anomaly_detector
    from app.services.detection.classifier import threat_classifier
    
    def _train():
        try:
            anomaly_detector.train_on_normal()
        except Exception as e:
            logger.error(f"Anomaly training failed: {e}")
        
        try:
            threat_classifier.train_on_synthetic()
        except Exception as e:
            logger.error(f"Classifier training failed: {e}")
    
    background_tasks.add_task(_train)
    return {"status": "training_started", "message": "Model training running in background"}


# ═══════════════════════════════════════════════════════════════════════════════
# Response Actions
# ═══════════════════════════════════════════════════════════════════════════════
response_router = APIRouter(prefix="/response", tags=["Response"])


@response_router.get("", response_model=PaginatedResponse)
async def list_response_actions(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: Optional[str] = None,
    incident_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    filters = []
    if status:
        filters.append(ResponseAction.status == status)
    if incident_id:
        filters.append(ResponseAction.incident_id == incident_id)
    
    count_q = select(func.count(ResponseAction.id))
    if filters:
        count_q = count_q.where(and_(*filters))
    total = (await db.execute(count_q)).scalar()
    
    q = select(ResponseAction).order_by(desc(ResponseAction.created_at))
    if filters:
        q = q.where(and_(*filters))
    q = q.offset((page - 1) * page_size).limit(page_size)
    
    result = await db.execute(q)
    actions = result.scalars().all()
    
    return PaginatedResponse(
        items=[ResponseActionResponse.model_validate(a) for a in actions],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size if total else 0,
    )


@response_router.post("", response_model=ResponseActionResponse, status_code=201)
async def create_response_action(
    data: ResponseActionCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin", "analyst")),
):
    action = ResponseAction(**data.model_dump(), recommended_by="analyst")
    db.add(action)
    await db.flush()
    return ResponseActionResponse.model_validate(action)


@response_router.patch("/{action_id}", response_model=ResponseActionResponse)
async def update_response_action(
    action_id: str,
    update: ResponseActionUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin", "analyst")),
):
    """Approve or reject a response action."""
    result = await db.execute(select(ResponseAction).where(ResponseAction.id == action_id))
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Response action not found")
    
    action.status = update.status
    
    if update.status == "approved":
        action.approved_by_id = current_user.id
        action.status = "executed"
        action.executed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        
        # Handle block_ip response action
        if action.action_type == "block_ip" and action.target:
            existing = await db.execute(
                select(BlockedIP).where(BlockedIP.ip_address == action.target)
            )
            if not existing.scalar_one_or_none():
                blocked = BlockedIP(
                    ip_address=action.target,
                    reason=f"Blocked via incident response action {action_id}",
                    blocked_by_id=current_user.id,
                    incident_id=action.incident_id,
                )
                db.add(blocked)
    
    elif update.status == "rejected":
        action.rejection_reason = update.rejection_reason
    
    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        action=f"response_action_{update.status}",
        resource_type="response_action",
        resource_id=action_id,
        details={
            "action_type": action.action_type,
            "target": action.target,
            "status": update.status,
        },
    )
    db.add(audit)
    await db.flush()
    
    return ResponseActionResponse.model_validate(action)


# ═══════════════════════════════════════════════════════════════════════════════
# Audit Logs
# ═══════════════════════════════════════════════════════════════════════════════
audit_router = APIRouter(prefix="/audit-logs", tags=["Audit"])


@audit_router.get("", response_model=PaginatedResponse)
async def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: Optional[str] = None,
    user_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin")),
):
    filters = []
    if action:
        filters.append(AuditLog.action.ilike(f"%{action}%"))
    if user_id:
        filters.append(AuditLog.user_id == user_id)
    if start_time:
        filters.append(AuditLog.created_at >= start_time)
    
    count_q = select(func.count(AuditLog.id))
    if filters:
        count_q = count_q.where(and_(*filters))
    total = (await db.execute(count_q)).scalar()
    
    q = select(AuditLog).order_by(desc(AuditLog.created_at))
    if filters:
        q = q.where(and_(*filters))
    q = q.offset((page - 1) * page_size).limit(page_size)
    
    result = await db.execute(q)
    logs = result.scalars().all()
    
    return PaginatedResponse(
        items=[AuditLogResponse.model_validate(l) for l in logs],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size if total else 0,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Global Search
# ═══════════════════════════════════════════════════════════════════════════════
search_router = APIRouter(prefix="/search", tags=["Search"])


@search_router.get("")
async def global_search(
    q: str = Query(..., min_length=2),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Global search across events, alerts, incidents, IPs, and threat intel."""
    results = []
    
    # Events
    ev_result = await db.execute(
        select(SecurityEvent)
        .where(or_(
            SecurityEvent.source_ip.ilike(f"%{q}%"),
            SecurityEvent.username.ilike(f"%{q}%"),
            SecurityEvent.event_type.ilike(f"%{q}%"),
        ))
        .limit(5)
    )
    for e in ev_result.scalars():
        results.append({"type": "event", "id": e.id, "title": e.event_type, "source_ip": e.source_ip, "timestamp": e.timestamp})
    
    # Alerts
    al_result = await db.execute(
        select(Alert)
        .where(or_(
            Alert.title.ilike(f"%{q}%"),
            Alert.source_ip.ilike(f"%{q}%"),
            Alert.username.ilike(f"%{q}%"),
        ))
        .limit(5)
    )
    for a in al_result.scalars():
        results.append({"type": "alert", "id": a.id, "title": a.title, "severity": a.severity, "timestamp": a.created_at})
    
    # Incidents
    in_result = await db.execute(
        select(Incident)
        .where(or_(
            Incident.title.ilike(f"%{q}%"),
            Incident.source_ip.ilike(f"%{q}%"),
            Incident.target_user.ilike(f"%{q}%"),
        ))
        .limit(5)
    )
    for i in in_result.scalars():
        results.append({"type": "incident", "id": i.id, "title": i.title, "severity": i.severity, "timestamp": i.created_at})
    
    # Threat Intel
    ti_result = await db.execute(
        select(ThreatIndicator)
        .where(ThreatIndicator.value.ilike(f"%{q}%"))
        .limit(5)
    )
    for t in ti_result.scalars():
        results.append({"type": "threat_intel", "id": t.id, "title": t.value, "severity": t.severity, "timestamp": t.created_at})
    
    return {"query": q, "results": results, "total": len(results)}


# ═══════════════════════════════════════════════════════════════════════════════
# WebSocket
# ═══════════════════════════════════════════════════════════════════════════════
ws_router = APIRouter(tags=["WebSocket"])


@ws_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time WebSocket endpoint for live event streaming."""
    client_id = str(uuid.uuid4())
    
    try:
        await ws_manager.connect(websocket, client_id, rooms=["global"])
        
        while True:
            try:
                # Keep alive — wait for client messages
                data = await websocket.receive_text()
                # Handle ping/pong
                if data == "ping":
                    await websocket.send_text('{"type":"pong"}')
            except WebSocketDisconnect:
                break
    
    except Exception as e:
        logger.error(f"WebSocket error for {client_id}: {e}")
    finally:
        await ws_manager.disconnect(client_id)


# Collect all routers for easy import
all_routers = [
    dashboard_router,
    simulation_router,
    ti_router,
    ml_router,
    response_router,
    audit_router,
    search_router,
    ws_router,
]
