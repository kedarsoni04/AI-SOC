"""
Rule-Based Threat Detection Engine
Implements deterministic security detection rules.
"""
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any
import asyncio
import logging

logger = logging.getLogger(__name__)


# ── MITRE ATT&CK Mappings ──────────────────────────────────────────────────────
MITRE_MAPPINGS = {
    "brute_force": {
        "tactics": ["TA0006 - Credential Access"],
        "techniques": ["T1110 - Brute Force", "T1110.001 - Password Guessing"],
    },
    "sql_injection": {
        "tactics": ["TA0001 - Initial Access", "TA0009 - Collection"],
        "techniques": ["T1190 - Exploit Public-Facing Application"],
    },
    "port_scan": {
        "tactics": ["TA0007 - Discovery"],
        "techniques": ["T1046 - Network Service Scanning"],
    },
    "privilege_escalation": {
        "tactics": ["TA0004 - Privilege Escalation"],
        "techniques": ["T1068 - Exploitation for Privilege Escalation", "T1548 - Abuse Elevation Control Mechanism"],
    },
    "data_exfiltration": {
        "tactics": ["TA0010 - Exfiltration"],
        "techniques": ["T1041 - Exfiltration Over C2 Channel", "T1048 - Exfiltration Over Alternative Protocol"],
    },
    "suspicious_login": {
        "tactics": ["TA0001 - Initial Access"],
        "techniques": ["T1078 - Valid Accounts", "T1078.003 - Local Accounts"],
    },
    "impossible_travel": {
        "tactics": ["TA0001 - Initial Access"],
        "techniques": ["T1078 - Valid Accounts"],
    },
    "account_compromise": {
        "tactics": ["TA0001 - Initial Access", "TA0003 - Persistence"],
        "techniques": ["T1078 - Valid Accounts"],
    },
}


# ── In-memory state for sliding window tracking ────────────────────────────────
class SlidingWindowTracker:
    """Thread-safe sliding window event counter."""
    
    def __init__(self, window_seconds: int = 300):
        self.window = timedelta(seconds=window_seconds)
        self._store: Dict[str, List[datetime]] = defaultdict(list)
    
    def add(self, key: str, ts: Optional[datetime] = None) -> int:
        """Add event for key, return count in window."""
        now = ts or datetime.now(timezone.utc).replace(tzinfo=None)
        self._store[key].append(now)
        # Prune old events
        cutoff = now - self.window
        self._store[key] = [t for t in self._store[key] if t > cutoff]
        return len(self._store[key])
    
    def count(self, key: str) -> int:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        cutoff = now - self.window
        self._store[key] = [t for t in self._store[key] if t > cutoff]
        return len(self._store[key])
    
    def get_events(self, key: str) -> List[datetime]:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        cutoff = now - self.window
        self._store[key] = [t for t in self._store[key] if t > cutoff]
        return list(self._store[key])


# ── SQLi Patterns ──────────────────────────────────────────────────────────────
SQLI_PATTERNS = [
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"or\s+1\s*=\s*1", re.IGNORECASE),
    re.compile(r"and\s+1\s*=\s*1", re.IGNORECASE),
    re.compile(r"'\s*;\s*(drop|delete|insert|update)\s", re.IGNORECASE),
    re.compile(r"--\s*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"/\*.*?\*/", re.IGNORECASE | re.DOTALL),
    re.compile(r"exec\s*\(", re.IGNORECASE),
    re.compile(r"xp_cmdshell", re.IGNORECASE),
    re.compile(r"information_schema", re.IGNORECASE),
    re.compile(r"sleep\s*\(\s*\d+\s*\)", re.IGNORECASE),
    re.compile(r"benchmark\s*\(", re.IGNORECASE),
    re.compile(r"char\s*\(\s*\d+\s*\)", re.IGNORECASE),
    re.compile(r"0x[0-9a-fA-F]+", re.IGNORECASE),
]

PRIV_ESC_EVENTS = {
    "PRIVILEGE_CHANGE", "SUDO_COMMAND", "SETUID_EXEC",
    "ROLE_ASSIGNMENT", "ADMIN_GRANT", "PRIVILEGE_ESCALATION",
    "ROOT_ACCESS", "SUDO_FAILED",
}

SUSPICIOUS_LOGIN_EVENTS = {
    "LOGIN_AFTER_HOURS", "LOGIN_NEW_LOCATION", "LOGIN_UNUSUAL_AGENT",
    "LOGIN_SUCCESS",  # after many failures
}

EXFIL_THRESHOLD_BYTES = 50 * 1024 * 1024  # 50 MB


class DetectionAlert:
    """A detected threat alert from a rule."""
    
    def __init__(
        self,
        rule_name: str,
        attack_type: str,
        title: str,
        description: str,
        severity: str,
        confidence: float,
        evidence: Dict[str, Any],
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        username: Optional[str] = None,
        mitre_mapping: Optional[Dict] = None,
    ):
        self.rule_name = rule_name
        self.attack_type = attack_type
        self.title = title
        self.description = description
        self.severity = severity
        self.confidence = confidence
        self.evidence = evidence
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.username = username
        self.mitre_tactics = (mitre_mapping or {}).get("tactics", [])
        self.mitre_techniques = (mitre_mapping or {}).get("techniques", [])
        self.timestamp = datetime.now(timezone.utc).replace(tzinfo=None)


class RuleEngine:
    """
    Deterministic rule-based threat detection engine.
    Processes normalized security events and generates DetectionAlerts.
    """
    
    def __init__(self):
        # Sliding window trackers
        self.failed_logins = SlidingWindowTracker(window_seconds=300)   # 5 min
        self.port_connections = SlidingWindowTracker(window_seconds=60)  # 1 min
        self.data_transfers = SlidingWindowTracker(window_seconds=300)   # 5 min
        self.api_calls = SlidingWindowTracker(window_seconds=60)          # 1 min
        
        # State tracking
        self.recent_successful_logins: Dict[str, List[datetime]] = defaultdict(list)
        self.destination_ports: Dict[str, set] = defaultdict(set)
        self.bytes_per_ip: Dict[str, int] = defaultdict(int)
        self.user_login_history: Dict[str, List[Tuple[str, datetime]]] = defaultdict(list)
        # user → [(country, timestamp), ...]
        
    def analyze(self, event: Dict[str, Any]) -> List[DetectionAlert]:
        """
        Run all rules against a normalized event.
        Returns a list of zero or more DetectionAlerts.
        """
        alerts = []
        
        event_type = (event.get("event_type") or "UNKNOWN").upper()
        source_ip = event.get("source_ip")
        username = event.get("username")
        timestamp = event.get("timestamp") or datetime.now(timezone.utc).replace(tzinfo=None)
        endpoint = event.get("endpoint") or ""
        user_agent = event.get("user_agent") or ""
        bytes_tx = event.get("bytes_transferred") or 0
        dst_port = event.get("destination_port")
        country = event.get("country")
        
        # 1. Brute Force
        if event_type in {"LOGIN_FAILED", "AUTH_FAILURE"}:
            ip_key = f"login_fail:{source_ip}"
            user_key = f"login_fail_user:{username}"
            
            ip_count = self.failed_logins.add(ip_key, timestamp)
            user_count = self.failed_logins.add(user_key, timestamp) if username else 0
            
            if ip_count >= 10:
                alerts.append(DetectionAlert(
                    rule_name="BRUTE_FORCE_IP",
                    attack_type="brute_force",
                    title=f"Brute Force Attack from {source_ip}",
                    description=f"{ip_count} failed login attempts from {source_ip} within 5 minutes.",
                    severity="high",
                    confidence=min(0.95, 0.6 + (ip_count - 10) * 0.02),
                    evidence={"failed_count": ip_count, "window_minutes": 5, "source_ip": source_ip},
                    source_ip=source_ip,
                    username=username,
                    mitre_mapping=MITRE_MAPPINGS["brute_force"],
                ))
            
            if user_count >= 15 and username:
                alerts.append(DetectionAlert(
                    rule_name="BRUTE_FORCE_USER",
                    attack_type="brute_force",
                    title=f"Account Brute Force — {username}",
                    description=f"{user_count} failed attempts targeting account '{username}'.",
                    severity="high",
                    confidence=min(0.98, 0.7 + (user_count - 15) * 0.01),
                    evidence={"failed_count": user_count, "target_user": username},
                    source_ip=source_ip,
                    username=username,
                    mitre_mapping=MITRE_MAPPINGS["brute_force"],
                ))
        
        # 2. SQL Injection
        search_text = f"{endpoint} {user_agent} {event.get('raw_log', '')}"
        matched_patterns = [p.pattern for p in SQLI_PATTERNS if p.search(search_text)]
        if matched_patterns:
            confidence = min(0.95, 0.5 + len(matched_patterns) * 0.1)
            alerts.append(DetectionAlert(
                rule_name="SQL_INJECTION",
                attack_type="sql_injection",
                title=f"SQL Injection Attempt from {source_ip}",
                description=f"SQL injection patterns detected in request from {source_ip}.",
                severity="critical" if len(matched_patterns) > 2 else "high",
                confidence=confidence,
                evidence={
                    "matched_patterns": matched_patterns[:5],
                    "endpoint": endpoint[:200],
                    "pattern_count": len(matched_patterns),
                },
                source_ip=source_ip,
                destination_ip=event.get("destination_ip"),
                username=username,
                mitre_mapping=MITRE_MAPPINGS["sql_injection"],
            ))
        
        # 3. Port Scanning
        if dst_port and source_ip:
            self.destination_ports[source_ip].add(dst_port)
            port_count = len(self.destination_ports[source_ip])
            
            # Also track via sliding window
            scan_key = f"portscan:{source_ip}"
            scan_count = self.port_connections.add(scan_key, timestamp)
            
            if port_count >= 20 or scan_count >= 50:
                alerts.append(DetectionAlert(
                    rule_name="PORT_SCAN",
                    attack_type="port_scan",
                    title=f"Port Scan Detected from {source_ip}",
                    description=f"Source {source_ip} contacted {port_count} unique ports.",
                    severity="high",
                    confidence=min(0.90, 0.5 + port_count * 0.02),
                    evidence={
                        "unique_ports": port_count,
                        "recent_connections": scan_count,
                        "sample_ports": list(self.destination_ports[source_ip])[:10],
                    },
                    source_ip=source_ip,
                    mitre_mapping=MITRE_MAPPINGS["port_scan"],
                ))
                # Reset to avoid spam
                self.destination_ports[source_ip] = set()
        
        # 4. Privilege Escalation
        if event_type in PRIV_ESC_EVENTS:
            alerts.append(DetectionAlert(
                rule_name="PRIVILEGE_ESCALATION",
                attack_type="privilege_escalation",
                title=f"Privilege Escalation — {username or 'Unknown User'}",
                description=f"Event type '{event_type}' detected for user '{username}'.",
                severity="critical",
                confidence=0.80,
                evidence={"event_type": event_type, "username": username, "source_ip": source_ip},
                source_ip=source_ip,
                username=username,
                mitre_mapping=MITRE_MAPPINGS["privilege_escalation"],
            ))
        
        # 5. Suspicious Login (login success after previous failures)
        if event_type == "LOGIN_SUCCESS" and source_ip:
            fail_key = f"login_fail:{source_ip}"
            recent_failures = self.failed_logins.count(fail_key)
            
            if recent_failures >= 5:
                alerts.append(DetectionAlert(
                    rule_name="SUSPICIOUS_LOGIN",
                    attack_type="suspicious_login",
                    title=f"Suspicious Login Success after {recent_failures} Failures",
                    description=f"Login succeeded from {source_ip} after {recent_failures} recent failures — possible credential stuffing.",
                    severity="high",
                    confidence=min(0.90, 0.6 + recent_failures * 0.02),
                    evidence={"prior_failures": recent_failures, "source_ip": source_ip, "username": username},
                    source_ip=source_ip,
                    username=username,
                    mitre_mapping=MITRE_MAPPINGS["suspicious_login"],
                ))
            
            # Track user login for impossible travel
            if username and country:
                self.user_login_history[username].append((country, timestamp))
                # Keep last 10
                self.user_login_history[username] = self.user_login_history[username][-10:]
        
        # 6. Data Exfiltration
        if bytes_tx >= EXFIL_THRESHOLD_BYTES:
            ip_key = f"exfil:{source_ip}"
            self.bytes_per_ip[source_ip] = self.bytes_per_ip.get(source_ip, 0) + bytes_tx
            alerts.append(DetectionAlert(
                rule_name="DATA_EXFILTRATION",
                attack_type="data_exfiltration",
                title=f"Possible Data Exfiltration from {source_ip}",
                description=f"Unusually large data transfer: {bytes_tx / (1024*1024):.1f} MB outbound.",
                severity="critical",
                confidence=0.75,
                evidence={
                    "bytes_transferred": bytes_tx,
                    "mb_transferred": round(bytes_tx / (1024 * 1024), 2),
                    "source_ip": source_ip,
                    "username": username,
                },
                source_ip=source_ip,
                destination_ip=event.get("destination_ip"),
                username=username,
                mitre_mapping=MITRE_MAPPINGS["data_exfiltration"],
            ))
        
        # 7. Impossible Travel
        if event_type == "LOGIN_SUCCESS" and username:
            history = self.user_login_history.get(username, [])
            if len(history) >= 2:
                last_country, last_ts = history[-2]
                current_country = country
                if (
                    current_country
                    and last_country
                    and current_country != last_country
                    and current_country not in ("Unknown", "")
                    and last_country not in ("Unknown", "")
                ):
                    time_diff = abs((timestamp - last_ts).total_seconds() / 60)
                    if time_diff < 60:  # Less than 1 hour between logins from different countries
                        alerts.append(DetectionAlert(
                            rule_name="IMPOSSIBLE_TRAVEL",
                            attack_type="impossible_travel",
                            title=f"Impossible Travel — {username}",
                            description=(
                                f"User '{username}' logged in from {last_country} and then "
                                f"{current_country} within {time_diff:.0f} minutes — geographically impossible."
                            ),
                            severity="critical",
                            confidence=0.85,
                            evidence={
                                "last_country": last_country,
                                "current_country": current_country,
                                "time_difference_minutes": round(time_diff, 1),
                                "username": username,
                            },
                            source_ip=source_ip,
                            username=username,
                            mitre_mapping=MITRE_MAPPINGS["impossible_travel"],
                        ))
        
        return alerts


# Module-level singleton
rule_engine = RuleEngine()
