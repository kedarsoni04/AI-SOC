"""
ML-based Anomaly Detection using Isolation Forest.
Detects anomalous security events based on behavioral features.
"""
import os
import json
import logging
import numpy as np
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import joblib
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available — ML anomaly detection disabled")


# Feature names for the anomaly model
ANOMALY_FEATURES = [
    "hour_of_day",
    "day_of_week",
    "is_night",
    "failed_login_score",
    "bytes_transferred_mb",
    "destination_port_norm",
    "status_code_norm",
    "is_external_ip",
    "event_type_encoded",
]


def encode_event_type(event_type: str) -> float:
    """Map event types to numeric risk scores."""
    risk_map = {
        "LOGIN_FAILED": 0.7,
        "AUTH_FAILURE": 0.7,
        "LOGIN_SUCCESS": 0.1,
        "LOGOUT": 0.0,
        "API_CALL": 0.2,
        "FILE_ACCESS": 0.2,
        "PRIVILEGE_CHANGE": 0.9,
        "PRIVILEGE_ESCALATION": 1.0,
        "DATA_EXFILTRATION": 1.0,
        "PORT_SCAN_DETECTED": 0.9,
        "SQL_INJECTION_ATTEMPT": 0.95,
        "CONFIG_CHANGE": 0.6,
        "CLOUD_CONFIG_CHANGE": 0.65,
        "SUDO_COMMAND": 0.7,
        "BULK_DELETE": 0.85,
        "SUSPICIOUS_DOWNLOAD": 0.75,
        "UNUSUAL_OUTBOUND": 0.8,
        "UNKNOWN": 0.5,
    }
    return risk_map.get(event_type.upper(), 0.4)


def is_external_ip(ip: Optional[str]) -> float:
    """Returns 1.0 if external IP, 0.0 if private/internal."""
    if not ip:
        return 0.0
    import ipaddress
    import re
    try:
        addr = ipaddress.ip_address(ip)
        private_ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
        ]
        return 0.0 if any(addr in net for net in private_ranges) else 1.0
    except ValueError:
        return 0.5


def extract_features(event: Dict[str, Any]) -> np.ndarray:
    """Extract feature vector from a normalized security event."""
    timestamp = event.get("timestamp")
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except Exception:
            timestamp = datetime.now()
    if not isinstance(timestamp, datetime):
        timestamp = datetime.now()
    
    hour = timestamp.hour
    dow = timestamp.weekday()
    is_night = 1.0 if (hour < 6 or hour > 22) else 0.0
    
    # Failed login heuristic: mark based on event type
    event_type = (event.get("event_type") or "UNKNOWN").upper()
    failed_login_score = 1.0 if event_type in {"LOGIN_FAILED", "AUTH_FAILURE"} else 0.0
    
    bytes_tx = event.get("bytes_transferred") or 0
    bytes_mb = min(bytes_tx / (1024 * 1024), 1000.0)  # cap at 1GB
    
    dst_port = event.get("destination_port") or 0
    port_norm = min(dst_port / 65535.0, 1.0)
    
    status_code = event.get("status_code") or 200
    # Normalize: 200=0, 400=0.5, 500=0.8, 403=0.6
    if status_code >= 500:
        sc_norm = 0.8
    elif status_code == 403:
        sc_norm = 0.6
    elif status_code == 401:
        sc_norm = 0.5
    elif status_code >= 400:
        sc_norm = 0.4
    else:
        sc_norm = 0.0
    
    ext_ip = is_external_ip(event.get("source_ip"))
    et_enc = encode_event_type(event_type)
    
    return np.array([
        hour / 23.0,
        dow / 6.0,
        is_night,
        failed_login_score,
        min(bytes_mb / 100.0, 1.0),
        port_norm,
        sc_norm,
        ext_ip,
        et_enc,
    ], dtype=np.float32)


class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector.
    Trains on normal behavior, flags outliers.
    """
    
    MODEL_FILENAME = "anomaly_detector.pkl"
    SCALER_FILENAME = "anomaly_scaler.pkl"
    META_FILENAME = "anomaly_meta.json"
    
    def __init__(self, model_path: str = "./ml/models"):
        self.model_path = Path(model_path)
        self.model: Optional[Any] = None
        self.scaler: Optional[Any] = None
        self.is_trained = False
        self.training_samples = 0
        self.contamination = 0.05  # 5% expected anomaly rate
        self._load_model()
    
    def _load_model(self):
        """Try to load a pre-trained model from disk."""
        if not SKLEARN_AVAILABLE:
            return
        
        model_file = self.model_path / self.MODEL_FILENAME
        scaler_file = self.model_path / self.SCALER_FILENAME
        meta_file = self.model_path / self.META_FILENAME
        
        if model_file.exists() and scaler_file.exists():
            try:
                self.model = joblib.load(model_file)
                self.scaler = joblib.load(scaler_file)
                if meta_file.exists():
                    with open(meta_file) as f:
                        meta = json.load(f)
                        self.training_samples = meta.get("training_samples", 0)
                self.is_trained = True
                logger.info(f"Anomaly model loaded from {model_file}")
            except Exception as e:
                logger.error(f"Failed to load anomaly model: {e}")
    
    def train(self, events: List[Dict[str, Any]], contamination: float = 0.05) -> Dict[str, Any]:
        """Train the Isolation Forest on a list of events."""
        if not SKLEARN_AVAILABLE:
            return {"error": "scikit-learn not available"}
        
        self.contamination = contamination
        features = np.array([extract_features(e) for e in events])
        
        self.scaler = StandardScaler()
        features_scaled = self.scaler.fit_transform(features)
        
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(features_scaled)
        self.is_trained = True
        self.training_samples = len(events)
        
        # Save to disk
        self.model_path.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path / self.MODEL_FILENAME)
        joblib.dump(self.scaler, self.model_path / self.SCALER_FILENAME)
        with open(self.model_path / self.META_FILENAME, "w") as f:
            json.dump({
                "training_samples": self.training_samples,
                "contamination": contamination,
                "feature_names": ANOMALY_FEATURES,
                "trained_at": datetime.now().isoformat(),
            }, f)
        
        logger.info(f"Anomaly model trained on {len(events)} samples")
        return {"status": "trained", "samples": len(events), "contamination": contamination}
    
    def predict(self, event: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Returns (is_anomaly, anomaly_score).
        Score is in [0, 1] where 1 = most anomalous.
        """
        if not self.is_trained or not SKLEARN_AVAILABLE:
            return False, 0.0
        
        features = extract_features(event).reshape(1, -1)
        features_scaled = self.scaler.transform(features)
        
        # IsolationForest: -1 = anomaly, 1 = normal
        prediction = self.model.predict(features_scaled)[0]
        # decision_function: more negative = more anomalous
        score = self.model.decision_function(features_scaled)[0]
        
        # Normalize score to [0, 1] (flip sign, scale)
        normalized_score = max(0.0, min(1.0, -score * 0.5 + 0.5))
        is_anomaly = prediction == -1
        
        return is_anomaly, float(normalized_score)
    
    def train_on_normal(self) -> Dict[str, Any]:
        """Generate synthetic normal behavior and train."""
        from app.services.simulation.generator import generate_normal_events
        
        logger.info("Generating synthetic normal events for anomaly model training...")
        normal_events = generate_normal_events(n=2000)
        return self.train(normal_events, contamination=0.05)
    
    def get_info(self) -> Dict[str, Any]:
        return {
            "model_type": "Isolation Forest",
            "is_trained": self.is_trained,
            "training_samples": self.training_samples,
            "contamination": self.contamination,
            "feature_names": ANOMALY_FEATURES,
            "sklearn_available": SKLEARN_AVAILABLE,
        }


# Module-level singleton
_model_path = os.environ.get("ML_MODEL_PATH", "./ml/models")
anomaly_detector = AnomalyDetector(model_path=_model_path)
