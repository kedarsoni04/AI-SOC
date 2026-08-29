from app.api.routes.auth import router as auth_router
from app.api.routes.events import router as events_router
from app.api.routes.alerts import router as alerts_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.dashboard import all_routers

__all__ = ["auth_router", "events_router", "alerts_router", "incidents_router", "all_routers"]
