"""
Log Normalization Service
Converts raw log entries from various sources into a common schema.
"""
import re
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
import ipaddress

# Simulated geo-IP data for development (private ranges omitted)
SIMULATED_GEO = {
    "185.220.101": ("Russia", "Moscow", 55.75, 37.62),
    "45.33.32": ("United States", "Fremont", 37.54, -121.96),
    "104.28.30": ("United States", "San Francisco", 37.77, -122.42),
    "223.25.247": ("China", "Beijing", 39.92, 116.38),
    "91.108.4": ("Germany", "Frankfurt", 50.11, 8.68),
    "195.24.155": ("Ukraine", "Kyiv", 50.45, 30.52),
    "5.39.216": ("France", "Paris", 48.87, 2.33),
    "82.102.16": ("Netherlands", "Amsterdam", 52.37, 4.89),
    "80.249.145": ("United Kingdom", "London", 51.51, -0.13),
    "203.0.113": ("Japan", "Tokyo", 35.68, 139.69),
    "198.51.100": ("Brazil", "São Paulo", -23.54, -46.63),
    "192.0.2": ("India", "Mumbai", 19.08, 72.88),
}

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


def get_geo(ip: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[float], Optional[float]]:
    """Returns (country, city, lat, lon) for a given IP."""
    if not ip or is_private_ip(ip):
        return None, None, None, None
    
    prefix_3 = ".".join(ip.split(".")[:3])
    prefix_2 = ".".join(ip.split(".")[:2])
    
    if prefix_3 in SIMULATED_GEO:
        return SIMULATED_GEO[prefix_3]
    if prefix_2 in SIMULATED_GEO:
        return SIMULATED_GEO[prefix_2]
    
    # Default unknown external IPs to generic location
    return "Unknown", "Unknown", None, None


def infer_severity(event_type: str, status_code: Optional[int] = None) -> str:
    """Infer severity from event type."""
    critical_events = {
        "DATA_EXFILTRATION", "PRIVILEGE_ESCALATION", "RANSOMWARE_ACTIVITY",
        "ROOT_ACCESS", "SQL_INJECTION_SUCCESS", "MALWARE_DETECTED",
    }
    high_events = {
        "BRUTE_FORCE_DETECTED", "SQL_INJECTION_ATTEMPT", "PORT_SCAN_DETECTED",
        "ACCOUNT_COMPROMISE", "UNAUTHORIZED_ACCESS", "PRIVILEGE_CHANGE",
        "BULK_DELETE", "CONFIG_CHANGE", "FIREWALL_BYPASS",
    }
    medium_events = {
        "LOGIN_FAILED", "SUSPICIOUS_PROCESS", "UNUSUAL_OUTBOUND",
        "API_ABUSE", "RATE_LIMIT_EXCEEDED", "AUTH_FAILURE",
        "SUSPICIOUS_DOWNLOAD", "CLOUD_CONFIG_CHANGE",
    }
    low_events = {
        "LOGIN_SUCCESS", "LOGOUT", "PASSWORD_CHANGE",
        "FILE_ACCESS", "API_CALL", "SERVICE_START",
    }

    event_upper = event_type.upper()
    if event_upper in critical_events:
        return "critical"
    if event_upper in high_events:
        return "high"
    if event_upper in medium_events:
        return "medium"
    if event_upper in low_events:
        return "low"
    
    # HTTP status code inference
    if status_code:
        if status_code >= 500:
            return "medium"
        if status_code == 403:
            return "medium"
    
    return "info"


class LogNormalizer:
    """
    Converts raw log dicts from any source into the common SecurityEvent schema.
    """

    def normalize(self, raw_log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main normalization entrypoint.
        Returns a dict ready to insert into SecurityEvent model.
        """
        # Parse timestamp
        timestamp = self._parse_timestamp(raw_log.get("timestamp"))
        
        # Basic field extraction with aliases
        source_ip = (
            raw_log.get("source_ip")
            or raw_log.get("src_ip")
            or raw_log.get("client_ip")
            or raw_log.get("remote_addr")
        )
        destination_ip = (
            raw_log.get("destination_ip")
            or raw_log.get("dst_ip")
            or raw_log.get("dest_ip")
            or raw_log.get("server_ip")
        )
        username = (
            raw_log.get("username")
            or raw_log.get("user")
            or raw_log.get("user_id")
            or raw_log.get("account")
        )
        event_type = (
            raw_log.get("event_type")
            or raw_log.get("type")
            or raw_log.get("action")
            or "UNKNOWN"
        ).upper()

        severity = raw_log.get("severity") or infer_severity(
            event_type, raw_log.get("status_code")
        )

        # Geo-IP enrichment
        country, city, lat, lon = get_geo(source_ip)

        # Build metadata from leftover fields
        known_keys = {
            "timestamp", "source_ip", "src_ip", "client_ip", "remote_addr",
            "destination_ip", "dst_ip", "dest_ip", "server_ip",
            "username", "user", "user_id", "account",
            "event_type", "type", "action", "severity",
            "source", "http_method", "endpoint", "status_code",
            "user_agent", "bytes_transferred", "protocol",
            "source_port", "destination_port", "raw_log",
        }
        metadata = {k: v for k, v in raw_log.items() if k not in known_keys and v is not None}

        return {
            "timestamp": timestamp,
            "source": raw_log.get("source") or "unknown",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": raw_log.get("source_port"),
            "destination_port": raw_log.get("destination_port"),
            "username": username,
            "event_type": event_type,
            "http_method": raw_log.get("http_method"),
            "endpoint": raw_log.get("endpoint"),
            "status_code": raw_log.get("status_code"),
            "user_agent": raw_log.get("user_agent"),
            "severity": severity,
            "bytes_transferred": raw_log.get("bytes_transferred"),
            "protocol": raw_log.get("protocol"),
            "country": country,
            "city": city,
            "latitude": lat,
            "longitude": lon,
            "raw_log": json.dumps(raw_log, default=str),
            "event_metadata": metadata or None,
        }

    def _parse_timestamp(self, ts_value: Any) -> datetime:
        if ts_value is None:
            return datetime.now(timezone.utc).replace(tzinfo=None)
        if isinstance(ts_value, datetime):
            return ts_value.replace(tzinfo=None)
        if isinstance(ts_value, (int, float)):
            return datetime.fromtimestamp(ts_value, tz=timezone.utc).replace(tzinfo=None)
        if isinstance(ts_value, str):
            formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(ts_value, fmt)
                except ValueError:
                    continue
        return datetime.now(timezone.utc).replace(tzinfo=None)


# Module-level singleton
normalizer = LogNormalizer()
