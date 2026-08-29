"""
Event Correlation Engine
Groups related alerts into incidents based on time window, IP, user, and event type.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict

logger = logging.getLogger(__name__)

# Multi-stage attack correlation patterns
CORRELATION_RULES = [
    {
        "name": "Account Compromise and Data Exfiltration",
        "description": "Brute force followed by successful login, privilege escalation, and data exfiltration",
        "required_types": ["brute_force", "suspicious_login", "privilege_escalation", "data_exfiltration"],
        "optional_types": ["port_scan", "sql_injection"],
        "time_window_minutes": 60,
        "min_types_required": 3,
        "severity": "critical",
        "mitre_tactics": ["TA0006 - Credential Access", "TA0004 - Privilege Escalation", "TA0010 - Exfiltration"],
    },
    {
        "name": "Brute Force Attack Campaign",
        "description": "Multiple brute force attempts targeting same user or IP",
        "required_types": ["brute_force"],
        "optional_types": ["suspicious_login"],
        "time_window_minutes": 30,
        "min_types_required": 1,
        "severity": "high",
        "mitre_tactics": ["TA0006 - Credential Access"],
    },
    {
        "name": "Network Reconnaissance",
        "description": "Port scanning followed by targeted attacks",
        "required_types": ["port_scan"],
        "optional_types": ["sql_injection", "brute_force"],
        "time_window_minutes": 45,
        "min_types_required": 1,
        "severity": "high",
        "mitre_tactics": ["TA0007 - Discovery"],
    },
    {
        "name": "Web Application Attack",
        "description": "SQL injection attempts against web application",
        "required_types": ["sql_injection"],
        "optional_types": [],
        "time_window_minutes": 30,
        "min_types_required": 1,
        "severity": "critical",
        "mitre_tactics": ["TA0001 - Initial Access"],
    },
    {
        "name": "Insider Threat — Data Exfiltration",
        "description": "Privilege escalation followed by bulk data transfer",
        "required_types": ["privilege_escalation", "data_exfiltration"],
        "optional_types": ["suspicious_login"],
        "time_window_minutes": 120,
        "min_types_required": 2,
        "severity": "critical",
        "mitre_tactics": ["TA0004 - Privilege Escalation", "TA0010 - Exfiltration"],
    },
    {
        "name": "Impossible Travel — Account Takeover",
        "description": "Login from geographically impossible locations",
        "required_types": ["impossible_travel"],
        "optional_types": ["suspicious_login", "privilege_escalation"],
        "time_window_minutes": 120,
        "min_types_required": 1,
        "severity": "critical",
        "mitre_tactics": ["TA0001 - Initial Access"],
    },
]


class AlertGroup:
    """A candidate group of related alerts for correlation."""
    
    def __init__(self, key: str):
        self.key = key  # Correlation key (ip:user or ip or user)
        self.alerts: List[Dict[str, Any]] = []
        self.attack_types: set = set()
        self.source_ips: set = set()
        self.usernames: set = set()
        self.first_seen: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None
    
    def add_alert(self, alert: Dict[str, Any]):
        self.alerts.append(alert)
        if alert.get("attack_type"):
            self.attack_types.add(alert["attack_type"])
        if alert.get("source_ip"):
            self.source_ips.add(alert["source_ip"])
        if alert.get("username"):
            self.usernames.add(alert["username"])
        
        ts = alert.get("created_at") or alert.get("timestamp")
        if ts:
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except Exception:
                    ts = datetime.now()
            if self.first_seen is None or ts < self.first_seen:
                self.first_seen = ts
            if self.last_seen is None or ts > self.last_seen:
                self.last_seen = ts
    
    @property
    def duration_minutes(self) -> float:
        if self.first_seen and self.last_seen:
            return (self.last_seen - self.first_seen).total_seconds() / 60
        return 0.0


class CorrelationEngine:
    """
    Correlates related alerts into incidents.
    Uses time windows, shared IP/user context, and attack sequence patterns.
    """
    
    def __init__(self, default_window_minutes: int = 60):
        self.default_window = default_window_minutes
    
    def correlate(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Takes a list of alert dicts and returns a list of proposed incidents.
        Each incident contains the correlated alerts and metadata.
        """
        if not alerts:
            return []
        
        # Group alerts by correlation key
        groups: Dict[str, AlertGroup] = defaultdict(AlertGroup)
        
        for alert in alerts:
            keys = self._get_correlation_keys(alert)
            for key in keys:
                if key not in groups:
                    groups[key] = AlertGroup(key)
                groups[key].add_alert(alert)
        
        # Match groups to correlation rules
        proposed_incidents = []
        processed_alert_ids = set()
        
        for key, group in groups.items():
            if len(group.alerts) < 1:
                continue
            
            # Try each correlation rule
            for rule in CORRELATION_RULES:
                incident = self._try_correlate(group, rule)
                if incident:
                    # Avoid duplicating alerts already in an incident
                    alert_ids = {a["id"] for a in incident["alerts"]}
                    if not alert_ids.issubset(processed_alert_ids):
                        processed_alert_ids.update(alert_ids)
                        proposed_incidents.append(incident)
                        break  # Best match wins for this group
            else:
                # No rule matched — create a basic incident if enough alerts
                if len(group.alerts) >= 2:
                    alert_ids = {a["id"] for a in group.alerts}
                    if not alert_ids.issubset(processed_alert_ids):
                        processed_alert_ids.update(alert_ids)
                        proposed_incidents.append(
                            self._create_generic_incident(group)
                        )
        
        return proposed_incidents
    
    def _get_correlation_keys(self, alert: Dict[str, Any]) -> List[str]:
        """Generate correlation keys for an alert."""
        keys = []
        source_ip = alert.get("source_ip")
        username = alert.get("username")
        
        if source_ip and username:
            keys.append(f"ip:{source_ip}|user:{username}")
        if source_ip:
            keys.append(f"ip:{source_ip}")
        if username:
            keys.append(f"user:{username}")
        
        if not keys:
            keys.append(f"ungrouped:{alert.get('id', 'unknown')}")
        
        return keys
    
    def _try_correlate(self, group: AlertGroup, rule: Dict) -> Optional[Dict[str, Any]]:
        """Attempt to match a group to a correlation rule. Returns incident dict or None."""
        required_types = set(rule["required_types"])
        time_window = rule["time_window_minutes"]
        min_required = rule.get("min_types_required", len(required_types))
        
        # Check required attack types are present
        matching_required = required_types & group.attack_types
        if len(matching_required) < min_required:
            return None
        
        # Check time window
        if group.duration_minutes > time_window:
            return None
        
        # Build incident
        primary_ip = next(iter(group.source_ips), None)
        primary_user = next(iter(group.usernames), None)
        severity = rule["severity"]
        
        attack_vector = " → ".join(
            t.replace("_", " ").title()
            for t in rule["required_types"]
            if t in group.attack_types
        )
        
        return {
            "title": rule["name"],
            "description": (
                f"{rule['description']}. "
                f"Detected {len(group.alerts)} related alerts over {group.duration_minutes:.0f} minutes. "
                f"Attack types: {', '.join(group.attack_types)}."
            ),
            "severity": severity,
            "source_ip": primary_ip,
            "target_user": primary_user,
            "attack_vector": attack_vector,
            "mitre_tactics": rule.get("mitre_tactics", []),
            "mitre_techniques": [],
            "alerts": group.alerts,
            "first_event_at": group.first_seen,
            "last_event_at": group.last_seen,
            "correlation_rule": rule["name"],
        }
    
    def _create_generic_incident(self, group: AlertGroup) -> Dict[str, Any]:
        """Create a generic incident for uncorrelated groups."""
        primary_ip = next(iter(group.source_ips), None)
        primary_user = next(iter(group.usernames), None)
        attack_types = list(group.attack_types)
        
        # Determine severity from worst alert
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_severity = max(
            (a.get("severity", "medium") for a in group.alerts),
            key=lambda s: severity_order.get(s, 0),
            default="medium",
        )
        
        return {
            "title": f"Security Incident — {primary_ip or primary_user or 'Unknown Source'}",
            "description": (
                f"Multiple related security alerts detected. "
                f"Attack types: {', '.join(attack_types) if attack_types else 'Unknown'}. "
                f"{len(group.alerts)} alerts over {group.duration_minutes:.0f} minutes."
            ),
            "severity": max_severity,
            "source_ip": primary_ip,
            "target_user": primary_user,
            "attack_vector": " → ".join(attack_types),
            "mitre_tactics": [],
            "mitre_techniques": [],
            "alerts": group.alerts,
            "first_event_at": group.first_seen,
            "last_event_at": group.last_seen,
            "correlation_rule": "generic_grouping",
        }


# Module-level singleton
correlation_engine = CorrelationEngine()
