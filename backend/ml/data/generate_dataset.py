"""
Synthetic dataset generator for ML threat classifier training.
Generates labeled events for all threat classes.
"""
import numpy as np
import random
from typing import Tuple, List
from datetime import datetime, timedelta


THREAT_CLASSES = [
    "normal",
    "brute_force",
    "sql_injection",
    "port_scan",
    "privilege_escalation",
    "data_exfiltration",
    "account_compromise",
    "malware_activity",
]


def _make_feature_vector(threat_class: str, seed_offset: int = 0) -> np.ndarray:
    """Generate a realistic feature vector for a given threat class."""
    r = random.Random(seed_offset + hash(threat_class) % 10000)
    
    if threat_class == "normal":
        hour = r.randint(8, 18)      # Business hours
        dow = r.randint(0, 4)        # Weekday
        is_night = 0.0
        is_weekend = 0.0
        failed_login = 0.0
        bytes_mb = r.uniform(0, 5)
        dst_port = r.choice([80, 443, 8080])
        sc_norm = 0.0
        ext_ip = 0.0
        et_risk = r.uniform(0.0, 0.2)
        has_sql = 0.0
        has_unusual_agent = 0.0
        port_scan_ind = 0.0
        priv_event = 0.0
    
    elif threat_class == "brute_force":
        hour = r.randint(0, 23)
        dow = r.randint(0, 6)
        is_night = 1.0 if (hour < 6 or hour > 22) else 0.0
        is_weekend = 1.0 if dow >= 5 else 0.0
        failed_login = 1.0
        bytes_mb = 0.1
        dst_port = r.choice([22, 443, 3389, 21])
        sc_norm = 0.5                # 401 responses
        ext_ip = 1.0
        et_risk = 0.7
        has_sql = 0.0
        has_unusual_agent = r.uniform(0.3, 1.0)
        port_scan_ind = 0.0
        priv_event = 0.0
    
    elif threat_class == "sql_injection":
        hour = r.randint(0, 23)
        dow = r.randint(0, 6)
        is_night = r.uniform(0, 1)
        is_weekend = r.uniform(0, 1)
        failed_login = 0.0
        bytes_mb = r.uniform(0, 1)
        dst_port = r.choice([80, 443, 8080])
        sc_norm = r.choice([0.3, 0.5, 0.8])
        ext_ip = 1.0
        et_risk = 0.95
        has_sql = 1.0
        has_unusual_agent = r.uniform(0.5, 1.0)
        port_scan_ind = 0.0
        priv_event = 0.0
    
    elif threat_class == "port_scan":
        hour = r.randint(0, 23)
        dow = r.randint(0, 6)
        is_night = r.uniform(0, 1)
        is_weekend = r.uniform(0, 1)
        failed_login = 0.0
        bytes_mb = 0.01
        dst_port = r.randint(1, 65535) / 65535.0  # Random port
        sc_norm = 0.0
        ext_ip = 1.0
        et_risk = 0.9
        has_sql = 0.0
        has_unusual_agent = r.uniform(0.5, 1.0)
        port_scan_ind = 1.0
        priv_event = 0.0
    
    elif threat_class == "privilege_escalation":
        hour = r.randint(0, 23)
        dow = r.randint(0, 6)
        is_night = r.uniform(0, 1)
        is_weekend = r.uniform(0, 1)
        failed_login = 0.0
        bytes_mb = r.uniform(0, 2)
        dst_port = r.choice([22, 5432, 3306])
        sc_norm = 0.0
        ext_ip = r.uniform(0, 1)
        et_risk = 1.0
        has_sql = 0.0
        has_unusual_agent = 0.0
        port_scan_ind = 0.0
        priv_event = 1.0
    
    elif threat_class == "data_exfiltration":
        hour = r.randint(0, 6)      # Off-hours
        dow = r.randint(0, 6)
        is_night = 1.0
        is_weekend = r.uniform(0, 1)
        failed_login = 0.0
        bytes_mb = r.uniform(50, 1000)    # Large transfer
        dst_port = r.choice([443, 80, 22])
        sc_norm = 0.0
        ext_ip = 1.0
        et_risk = 1.0
        has_sql = 0.0
        has_unusual_agent = 0.0
        port_scan_ind = 0.0
        priv_event = 0.0
    
    elif threat_class == "account_compromise":
        hour = r.randint(0, 23)
        dow = r.randint(0, 6)
        is_night = r.uniform(0, 1)
        is_weekend = r.uniform(0, 1)
        failed_login = r.uniform(0.5, 1.0)    # Mix of failed/success
        bytes_mb = r.uniform(0, 10)
        dst_port = r.choice([443, 80])
        sc_norm = r.choice([0.0, 0.5])
        ext_ip = 1.0
        et_risk = 0.7
        has_sql = 0.0
        has_unusual_agent = r.uniform(0.3, 0.8)
        port_scan_ind = 0.0
        priv_event = r.uniform(0, 0.5)
    
    elif threat_class == "malware_activity":
        hour = r.randint(0, 23)
        dow = r.randint(0, 6)
        is_night = r.uniform(0.3, 1.0)
        is_weekend = r.uniform(0, 1)
        failed_login = 0.0
        bytes_mb = r.uniform(0, 100)
        dst_port = r.choice([4444, 1337, 8888, 6666])   # Common malware ports
        sc_norm = 0.0
        ext_ip = 1.0
        et_risk = 1.0
        has_sql = r.uniform(0, 0.3)
        has_unusual_agent = r.uniform(0.3, 1.0)
        port_scan_ind = 0.0
        priv_event = r.uniform(0, 0.5)
    
    else:
        raise ValueError(f"Unknown class: {threat_class}")
    
    # Normalize
    return np.array([
        hour / 23.0,
        dow / 6.0,
        is_night,
        is_weekend,
        failed_login,
        min(bytes_mb / 100.0, 1.0),
        dst_port if isinstance(dst_port, float) else min(dst_port / 65535.0, 1.0),
        sc_norm,
        ext_ip,
        et_risk,
        has_sql,
        has_unusual_agent,
        port_scan_ind,
        priv_event,
    ], dtype=np.float32)


def generate_labeled_dataset(n_per_class: int = 500) -> Tuple[np.ndarray, List[str]]:
    """
    Generate a labeled dataset for classifier training.
    Returns (X, y) where X has shape (n_classes * n_per_class, 14).
    """
    X_parts = []
    y_parts = []
    
    for threat_class in THREAT_CLASSES:
        for i in range(n_per_class):
            vec = _make_feature_vector(threat_class, seed_offset=i * 100)
            # Add some noise
            noise = np.random.normal(0, 0.05, size=vec.shape)
            vec = np.clip(vec + noise, 0, 1)
            X_parts.append(vec)
            y_parts.append(threat_class)
    
    X = np.array(X_parts)
    y = y_parts
    
    # Shuffle
    indices = np.random.permutation(len(y))
    return X[indices], [y[i] for i in indices]


if __name__ == "__main__":
    import sys
    sys.path.insert(0, "../../../backend")
    
    X, y = generate_labeled_dataset(n_per_class=500)
    print(f"Dataset generated: {X.shape[0]} samples, {X.shape[1]} features")
    
    from collections import Counter
    print("Class distribution:", Counter(y))
