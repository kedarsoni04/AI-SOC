"""
Attack Simulation Engine
Generates realistic security events for demonstration and testing.
"""
import random
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Callable
import uuid

logger = logging.getLogger(__name__)

# ── Sample Data ────────────────────────────────────────────────────────────────
EXTERNAL_IPS = [
    "185.220.101.45", "185.220.101.72", "45.33.32.156",
    "91.108.4.244", "195.24.155.100", "5.39.216.100",
    "82.102.16.200", "80.249.145.55", "203.0.113.10",
    "198.51.100.42", "223.25.247.15",
]

INTERNAL_IPS = [
    "10.0.0.5", "10.0.0.10", "10.0.1.20", "10.0.1.50",
    "192.168.1.100", "192.168.1.200", "172.16.0.50",
]

USERNAMES = [
    "admin", "john.doe", "jane.smith", "bob.wilson",
    "alice.brown", "svc_account", "postgres", "root",
    "deploy_user", "api_service",
]

HTTP_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "python-requests/2.28.0",
    "sqlmap/1.7 (https://sqlmap.org)",  # Scanner
    "Nikto/2.1.6",  # Scanner
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

ENDPOINTS = [
    "/api/login", "/api/users", "/api/data", "/admin/config",
    "/api/reports", "/api/export", "/db/query", "/api/auth",
    "/api/files", "/admin/users", "/api/logs",
]

SQL_INJECTION_PAYLOADS = [
    "/api/search?q=' OR 1=1--",
    "/api/users?id=1 UNION SELECT username,password FROM users--",
    "/api/data?filter='; DROP TABLE users;--",
    "/login?user=admin'--&pass=anything",
    "/api/products?id=1; EXEC xp_cmdshell('whoami')--",
]

PORTS = [22, 23, 25, 80, 443, 3306, 5432, 8080, 8443, 3389, 445, 21, 6379, 27017]


def _ts(offset_seconds: float = 0) -> datetime:
    return (datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)).replace(tzinfo=None)


def _rip() -> str:
    """Random external IP."""
    return random.choice(EXTERNAL_IPS)


def _user() -> str:
    return random.choice(USERNAMES)


# ── Normal Traffic Events ──────────────────────────────────────────────────────
def generate_normal_events(n: int = 100) -> List[Dict[str, Any]]:
    """Generate n normal security events for ML training."""
    events = []
    base_time = datetime.now(timezone.utc)
    
    for i in range(n):
        ts = base_time - timedelta(seconds=random.randint(0, 86400))
        hour = ts.hour
        
        event_types = ["LOGIN_SUCCESS", "LOGOUT", "API_CALL", "FILE_ACCESS"] * 4 + ["LOGIN_FAILED"]
        et = random.choice(event_types)
        
        events.append({
            "timestamp": ts.replace(tzinfo=None),
            "source": "authentication_server",
            "source_ip": random.choice(INTERNAL_IPS),
            "destination_ip": random.choice(INTERNAL_IPS),
            "username": _user(),
            "event_type": et,
            "http_method": random.choice(["GET", "POST", "GET", "GET"]),
            "endpoint": random.choice(ENDPOINTS[:5]),
            "status_code": random.choice([200, 200, 200, 301, 404]),
            "user_agent": HTTP_AGENTS[0],
            "severity": "info" if et not in ["LOGIN_FAILED"] else "low",
            "bytes_transferred": random.randint(100, 50000),
            "destination_port": random.choice([80, 443]),
        })
    
    return events


# ── Scenario Generators ────────────────────────────────────────────────────────
def scenario_normal_traffic(n: int = 5) -> List[Dict[str, Any]]:
    return [random.choice([
        _login_success_event(),
        _api_call_event(),
        _file_access_event(),
    ]) for _ in range(n)]


def _login_success_event() -> Dict[str, Any]:
    return {
        "timestamp": _ts(),
        "source": "authentication_server",
        "source_ip": random.choice(INTERNAL_IPS),
        "destination_ip": "10.0.0.5",
        "username": _user(),
        "event_type": "LOGIN_SUCCESS",
        "http_method": "POST",
        "endpoint": "/api/login",
        "status_code": 200,
        "user_agent": HTTP_AGENTS[0],
        "severity": "info",
        "bytes_transferred": random.randint(500, 5000),
        "destination_port": 443,
    }


def _api_call_event() -> Dict[str, Any]:
    return {
        "timestamp": _ts(),
        "source": "api_gateway",
        "source_ip": random.choice(INTERNAL_IPS),
        "destination_ip": "10.0.0.10",
        "username": _user(),
        "event_type": "API_CALL",
        "http_method": random.choice(["GET", "POST"]),
        "endpoint": random.choice(ENDPOINTS),
        "status_code": 200,
        "user_agent": HTTP_AGENTS[0],
        "severity": "info",
        "bytes_transferred": random.randint(1000, 20000),
        "destination_port": 8080,
    }


def _file_access_event() -> Dict[str, Any]:
    return {
        "timestamp": _ts(),
        "source": "file_server",
        "source_ip": random.choice(INTERNAL_IPS),
        "destination_ip": "10.0.1.20",
        "username": _user(),
        "event_type": "FILE_ACCESS",
        "severity": "info",
        "bytes_transferred": random.randint(1000, 100000),
    }


def scenario_brute_force(target_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    """Generate brute-force attack events."""
    attacker_ip = target_ip or _rip()
    target_user = random.choice(["admin", "administrator", "root"])
    events = []
    
    # 15 failed logins
    for i in range(15):
        events.append({
            "timestamp": _ts(offset_seconds=random.uniform(0, 60)),
            "source": "authentication_server",
            "source_ip": attacker_ip,
            "destination_ip": "10.0.0.5",
            "username": target_user,
            "event_type": "LOGIN_FAILED",
            "http_method": "POST",
            "endpoint": "/api/login",
            "status_code": 401,
            "user_agent": "python-requests/2.28.0",
            "severity": "medium",
            "bytes_transferred": 200,
            "destination_port": 443,
        })
    
    return events


def scenario_sql_injection(source_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    """Generate SQL injection attempt events."""
    attacker_ip = source_ip or _rip()
    events = []
    
    for payload in SQL_INJECTION_PAYLOADS:
        events.append({
            "timestamp": _ts(offset_seconds=random.uniform(0, 30)),
            "source": "web_application_firewall",
            "source_ip": attacker_ip,
            "destination_ip": "10.0.0.10",
            "username": None,
            "event_type": "SQL_INJECTION_ATTEMPT",
            "http_method": "GET",
            "endpoint": payload,
            "status_code": 400,
            "user_agent": "sqlmap/1.7 (https://sqlmap.org)",
            "severity": "high",
            "bytes_transferred": 500,
            "destination_port": 80,
        })
    
    return events


def scenario_port_scan(source_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    """Generate port scanning events."""
    attacker_ip = source_ip or _rip()
    events = []
    target_ip = random.choice(INTERNAL_IPS)
    
    for port in random.sample(range(1, 65536), 30):
        events.append({
            "timestamp": _ts(offset_seconds=random.uniform(0, 10)),
            "source": "network_monitor",
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "event_type": "PORT_SCAN_DETECTED",
            "destination_port": port,
            "protocol": "TCP",
            "status_code": None,
            "severity": "high",
            "bytes_transferred": 40,
        })
    
    return events


def scenario_account_compromise(source_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    """Generate account compromise: brute force → success → privilege escalation."""
    attacker_ip = source_ip or _rip()
    target_user = "john.doe"
    events = []
    
    # Brute force
    for i in range(12):
        events.append({
            "timestamp": _ts(offset_seconds=random.uniform(60, 120)),
            "source": "authentication_server",
            "source_ip": attacker_ip,
            "destination_ip": "10.0.0.5",
            "username": target_user,
            "event_type": "LOGIN_FAILED",
            "status_code": 401,
            "severity": "medium",
            "bytes_transferred": 200,
        })
    
    # Successful login
    events.append({
        "timestamp": _ts(offset_seconds=30),
        "source": "authentication_server",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.5",
        "username": target_user,
        "event_type": "LOGIN_SUCCESS",
        "status_code": 200,
        "severity": "high",
        "bytes_transferred": 1500,
    })
    
    # Privilege escalation
    events.append({
        "timestamp": _ts(offset_seconds=20),
        "source": "access_control",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.5",
        "username": target_user,
        "event_type": "PRIVILEGE_ESCALATION",
        "severity": "critical",
        "bytes_transferred": 500,
        "metadata": {"old_role": "user", "new_role": "admin"},
    })
    
    return events


def scenario_data_exfiltration(source_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    """Generate data exfiltration events."""
    attacker_ip = source_ip or _rip()
    username = "admin"
    events = []
    
    # Database access
    events.append({
        "timestamp": _ts(offset_seconds=60),
        "source": "database_monitor",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.20",
        "username": username,
        "event_type": "DATABASE_BULK_ACCESS",
        "endpoint": "/db/query?table=users&limit=100000",
        "status_code": 200,
        "severity": "high",
        "bytes_transferred": 5 * 1024 * 1024,  # 5 MB
        "destination_port": 5432,
    })
    
    # Large outbound transfer
    events.append({
        "timestamp": _ts(offset_seconds=30),
        "source": "network_monitor",
        "source_ip": attacker_ip,
        "destination_ip": "185.220.101.45",
        "username": username,
        "event_type": "UNUSUAL_OUTBOUND",
        "protocol": "HTTPS",
        "severity": "critical",
        "bytes_transferred": 75 * 1024 * 1024,  # 75 MB — above threshold
        "destination_port": 443,
    })
    
    return events


def scenario_multi_stage(source_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Full multi-stage attack:
    Port scan → Brute force → Successful login → Privilege escalation → DB access → Data exfiltration
    """
    attacker_ip = source_ip or _rip()
    target_user = "admin"
    events = []
    
    # Stage 1: Reconnaissance — Port Scan
    for port in random.sample(PORTS + list(range(8000, 8100)), 25):
        events.append({
            "timestamp": _ts(offset_seconds=random.uniform(200, 300)),
            "source": "network_monitor",
            "source_ip": attacker_ip,
            "destination_ip": "10.0.0.5",
            "event_type": "PORT_SCAN_DETECTED",
            "destination_port": port,
            "protocol": "TCP",
            "severity": "high",
            "bytes_transferred": 40,
        })
    
    # Stage 2: Brute Force
    for i in range(18):
        events.append({
            "timestamp": _ts(offset_seconds=random.uniform(100, 180)),
            "source": "authentication_server",
            "source_ip": attacker_ip,
            "destination_ip": "10.0.0.5",
            "username": target_user,
            "event_type": "LOGIN_FAILED",
            "status_code": 401,
            "severity": "medium",
            "user_agent": "python-requests/2.28.0",
            "bytes_transferred": 200,
        })
    
    # Stage 3: Successful Login
    events.append({
        "timestamp": _ts(offset_seconds=80),
        "source": "authentication_server",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.5",
        "username": target_user,
        "event_type": "LOGIN_SUCCESS",
        "status_code": 200,
        "severity": "high",
        "user_agent": "python-requests/2.28.0",
        "bytes_transferred": 1500,
        "country": "Russia",
    })
    
    # Stage 4: Privilege Escalation
    events.append({
        "timestamp": _ts(offset_seconds=60),
        "source": "access_control",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.5",
        "username": target_user,
        "event_type": "PRIVILEGE_ESCALATION",
        "severity": "critical",
        "bytes_transferred": 500,
        "metadata": {"old_role": "user", "new_role": "superadmin"},
    })
    
    # Stage 5: Database Access
    events.append({
        "timestamp": _ts(offset_seconds=40),
        "source": "database_monitor",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.20",
        "username": target_user,
        "event_type": "DATABASE_BULK_ACCESS",
        "endpoint": "/db/query?table=users,payments&limit=unlimited",
        "status_code": 200,
        "severity": "critical",
        "bytes_transferred": 10 * 1024 * 1024,
        "destination_port": 5432,
    })
    
    # Stage 6: Data Exfiltration
    events.append({
        "timestamp": _ts(offset_seconds=10),
        "source": "network_monitor",
        "source_ip": attacker_ip,
        "destination_ip": "185.220.101.45",
        "username": target_user,
        "event_type": "DATA_EXFILTRATION",
        "protocol": "HTTPS",
        "severity": "critical",
        "bytes_transferred": 100 * 1024 * 1024,  # 100 MB
        "destination_port": 443,
    })
    
    return events


SCENARIOS = {
    "normal": scenario_normal_traffic,
    "brute_force": scenario_brute_force,
    "sql_injection": scenario_sql_injection,
    "port_scan": scenario_port_scan,
    "account_compromise": scenario_account_compromise,
    "data_exfiltration": scenario_data_exfiltration,
    "multi_stage": scenario_multi_stage,
}


# ── Simulation Engine ──────────────────────────────────────────────────────────
class SimulationEngine:
    """Manages continuous background event generation."""
    
    def __init__(self):
        self.is_running = False
        self.current_scenario = "normal"
        self.events_generated = 0
        self.started_at: Optional[datetime] = None
        self._task: Optional[asyncio.Task] = None
        self._event_callbacks: List[Callable] = []
    
    def register_callback(self, callback: Callable):
        """Register a callback to receive generated events."""
        self._event_callbacks.append(callback)
    
    async def start(self, scenario: str = "normal"):
        """Start the simulation engine."""
        if self.is_running:
            await self.stop()
        
        self.is_running = True
        self.current_scenario = scenario
        self.events_generated = 0
        self.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
        self._task = asyncio.create_task(self._run_loop())
        logger.info(f"Simulation started: scenario={scenario}")
    
    async def stop(self):
        """Stop the simulation engine."""
        self.is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info(f"Simulation stopped. Events generated: {self.events_generated}")
    
    async def generate_scenario_once(self, scenario: str) -> List[Dict[str, Any]]:
        """Generate a single batch of events for a scenario (non-continuous)."""
        gen = SCENARIOS.get(scenario, scenario_normal_traffic)
        events = gen()
        for cb in self._event_callbacks:
            for event in events:
                await cb(event)
        self.events_generated += len(events)
        return events
    
    async def _run_loop(self):
        """Background loop that continuously generates events."""
        from app.core.config import settings
        
        interval = 1.0 / settings.simulation_events_per_second
        
        while self.is_running:
            try:
                scenario = self.current_scenario
                gen = SCENARIOS.get(scenario, scenario_normal_traffic)
                
                if scenario == "normal":
                    # Generate 1-3 normal events
                    events = gen(n=random.randint(1, 3))
                else:
                    events = gen()
                    # After attack scenario, switch back to normal
                    if scenario != "multi_stage":
                        self.current_scenario = "normal"
                
                for event in events:
                    for cb in self._event_callbacks:
                        try:
                            await cb(event)
                        except Exception as e:
                            logger.error(f"Event callback error: {e}")
                    self.events_generated += 1
                
                await asyncio.sleep(interval)
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Simulation loop error: {e}")
                await asyncio.sleep(1)
    
    def get_status(self) -> Dict[str, Any]:
        return {
            "is_running": self.is_running,
            "scenario": self.current_scenario,
            "events_generated": self.events_generated,
            "started_at": self.started_at,
        }


# Module-level singleton
simulation_engine = SimulationEngine()
