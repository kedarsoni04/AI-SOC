"""
AI-SOC Backend — Main Application Entry Point
"""
import logging
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.core.config import settings
from app.core.database import create_tables, AsyncSessionLocal
from app.models import User, DetectionRule, ThreatIndicator
from app.core.security import hash_password

# Import all route modules
from app.api.routes.auth import router as auth_router
from app.api.routes.events import router as events_router
from app.api.routes.alerts import router as alerts_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.dashboard import all_routers as dashboard_routers

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

# ── Rate Limiter ───────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)


# ── Startup / Shutdown ────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    logger.info(f"Starting AI-SOC Platform v{settings.app_version}")
    
    # Create database tables
    await create_tables()
    logger.info("Database tables created/verified")
    
    # Seed database with defaults
    await seed_database()
    
    # Initialize ML models (lazy — train if not found)
    await init_ml_models()
    
    yield
    
    logger.info("AI-SOC Platform shutting down")


# ── Application ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="AI-SOC Platform API",
    description=(
        "AI-Powered Security Operations Center — Final Year B.Tech Project.\n\n"
        "Provides real-time threat detection, ML-based anomaly detection, "
        "event correlation, AI investigation, and incident management."
    ),
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Middleware ─────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error" if not settings.debug else str(exc)},
    )


# ── Health Check ───────────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "version": settings.app_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": settings.app_env,
    }


# ── Register Routers ───────────────────────────────────────────────────────────
app.include_router(auth_router, prefix="/api/v1")
app.include_router(events_router, prefix="/api/v1")
app.include_router(alerts_router, prefix="/api/v1")
app.include_router(incidents_router, prefix="/api/v1")

for router in dashboard_routers:
    if hasattr(router, 'prefix') and router.prefix:
        app.include_router(router, prefix="/api/v1")
    else:
        app.include_router(router)  # WebSocket router has no prefix


# ── Seed Functions ─────────────────────────────────────────────────────────────
async def seed_database():
    """Create default users, detection rules, and threat intel if not present."""
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        
        # Default users
        default_users = [
            {"email": "admin@soc.local", "username": "admin", "password": "Admin@123", "role": "admin", "full_name": "SOC Administrator", "is_superuser": True},
            {"email": "analyst@soc.local", "username": "analyst", "password": "Analyst@123", "role": "analyst", "full_name": "SOC Analyst"},
            {"email": "viewer@soc.local", "username": "viewer", "password": "Viewer@123", "role": "viewer", "full_name": "SOC Viewer"},
        ]
        
        for u in default_users:
            result = await db.execute(select(User).where(User.username == u["username"]))
            if not result.scalar_one_or_none():
                user = User(
                    email=u["email"],
                    username=u["username"],
                    hashed_password=hash_password(u["password"]),
                    full_name=u.get("full_name"),
                    role=u["role"],
                    is_superuser=u.get("is_superuser", False),
                )
                db.add(user)
                logger.info(f"Created default user: {u['username']}")
        
        # Default detection rules metadata
        default_rules = [
            {"name": "BRUTE_FORCE_IP", "description": ">10 login failures from same IP in 5 min", "rule_type": "rule", "attack_type": "brute_force", "severity": "high"},
            {"name": "BRUTE_FORCE_USER", "description": ">15 failures targeting same user", "rule_type": "rule", "attack_type": "brute_force", "severity": "high"},
            {"name": "SQL_INJECTION", "description": "SQL injection patterns in request", "rule_type": "rule", "attack_type": "sql_injection", "severity": "critical"},
            {"name": "PORT_SCAN", "description": ">20 unique ports from same IP", "rule_type": "rule", "attack_type": "port_scan", "severity": "high"},
            {"name": "PRIVILEGE_ESCALATION", "description": "Privilege change detected", "rule_type": "rule", "attack_type": "privilege_escalation", "severity": "critical"},
            {"name": "DATA_EXFILTRATION", "description": "Transfer > 50MB outbound", "rule_type": "rule", "attack_type": "data_exfiltration", "severity": "critical"},
            {"name": "SUSPICIOUS_LOGIN", "description": "Login success after multiple failures", "rule_type": "rule", "attack_type": "suspicious_login", "severity": "high"},
            {"name": "IMPOSSIBLE_TRAVEL", "description": "Login from geographically impossible locations", "rule_type": "rule", "attack_type": "impossible_travel", "severity": "critical"},
            {"name": "ISOLATION_FOREST", "description": "ML anomaly detection", "rule_type": "ml", "attack_type": "anomaly", "severity": "medium"},
            {"name": "THREAT_CLASSIFIER", "description": "ML threat classification", "rule_type": "ml", "attack_type": "ml_classification", "severity": "medium"},
        ]
        
        for r in default_rules:
            result = await db.execute(select(DetectionRule).where(DetectionRule.name == r["name"]))
            if not result.scalar_one_or_none():
                rule = DetectionRule(**r)
                db.add(rule)
        
        # Sample threat indicators
        sample_ti = [
            {"indicator_type": "ip", "value": "185.220.101.45", "threat_type": "tor_exit_node", "confidence": 0.95, "severity": "high", "source": "Tor Project", "description": "Known Tor exit node"},
            {"indicator_type": "ip", "value": "91.108.4.244", "threat_type": "c2_server", "confidence": 0.85, "severity": "critical", "source": "Internal TI", "description": "Command & Control server"},
            {"indicator_type": "ip", "value": "195.24.155.100", "threat_type": "scanner", "confidence": 0.75, "severity": "high", "source": "AbuseIPDB", "description": "Known port scanner"},
            {"indicator_type": "domain", "value": "malware-c2.evil.com", "threat_type": "malware", "confidence": 0.90, "severity": "critical", "source": "VirusTotal"},
            {"indicator_type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e", "threat_type": "malware_sample", "confidence": 0.80, "severity": "critical", "source": "Internal"},
        ]
        
        for ti in sample_ti:
            result = await db.execute(select(ThreatIndicator).where(ThreatIndicator.value == ti["value"]))
            if not result.scalar_one_or_none():
                indicator = ThreatIndicator(**ti)
                db.add(indicator)
        
        await db.commit()
        logger.info("Database seeding complete")


async def init_ml_models():
    """Initialize ML models — train if no saved model found."""
    from app.services.detection.ml_detector import anomaly_detector
    from app.services.detection.classifier import threat_classifier
    
    if not anomaly_detector.is_trained:
        logger.info("No anomaly model found — training on synthetic data...")
        try:
            result = anomaly_detector.train_on_normal()
            logger.info(f"Anomaly model trained: {result}")
        except Exception as e:
            logger.warning(f"Anomaly model training failed: {e}")
    
    if not threat_classifier.is_trained:
        logger.info("No classifier model found — training on synthetic data...")
        try:
            result = threat_classifier.train_on_synthetic()
            logger.info(f"Classifier trained: accuracy={result.get('accuracy', 'N/A')}")
        except Exception as e:
            logger.warning(f"Classifier training failed: {e}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level="debug" if settings.debug else "info",
    )
