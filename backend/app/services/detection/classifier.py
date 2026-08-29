"""
Threat Classification using Random Forest / XGBoost.
Classifies security events into attack categories.
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
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder, StandardScaler
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, classification_report
    )
    from sklearn.model_selection import train_test_split
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# Try XGBoost, fall back to RF
try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

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

# Feature vector size
CLASSIFIER_FEATURES = [
    "hour_of_day",
    "day_of_week",
    "is_night",
    "is_weekend",
    "failed_login_score",
    "bytes_transferred_mb",
    "destination_port_norm",
    "status_code_norm",
    "is_external_ip",
    "event_type_risk",
    "has_sql_pattern",
    "has_unusual_agent",
    "port_scan_indicator",
    "privilege_event",
]


def encode_event_for_classifier(event: Dict[str, Any]) -> np.ndarray:
    """Extract 14-feature vector for the classifier."""
    from app.services.detection.ml_detector import extract_features, is_external_ip
    import re
    
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
    is_weekend = 1.0 if dow >= 5 else 0.0
    
    event_type = (event.get("event_type") or "UNKNOWN").upper()
    failed_login = 1.0 if event_type in {"LOGIN_FAILED", "AUTH_FAILURE"} else 0.0
    
    bytes_tx = event.get("bytes_transferred") or 0
    bytes_mb = min(bytes_tx / (1024 * 1024), 1000.0)
    
    dst_port = event.get("destination_port") or 0
    port_norm = min(dst_port / 65535.0, 1.0)
    
    status_code = event.get("status_code") or 200
    if status_code >= 500:
        sc_norm = 0.8
    elif status_code in (403, 401):
        sc_norm = 0.5
    elif status_code >= 400:
        sc_norm = 0.3
    else:
        sc_norm = 0.0
    
    ext_ip = is_external_ip(event.get("source_ip"))
    
    # Event type risk
    risk_map = {
        "LOGIN_FAILED": 0.7, "AUTH_FAILURE": 0.7,
        "LOGIN_SUCCESS": 0.1, "LOGOUT": 0.0,
        "PRIVILEGE_CHANGE": 0.9, "PRIVILEGE_ESCALATION": 1.0,
        "DATA_EXFILTRATION": 1.0, "PORT_SCAN_DETECTED": 0.9,
        "SQL_INJECTION_ATTEMPT": 0.95, "CONFIG_CHANGE": 0.6,
    }
    et_risk = risk_map.get(event_type, 0.4)
    
    # SQL pattern indicator
    raw = str(event.get("raw_log", "") or event.get("endpoint", ""))
    sql_indicators = ["union select", "or 1=1", "drop table", "xp_cmdshell", "information_schema"]
    has_sql = 1.0 if any(p in raw.lower() for p in sql_indicators) else 0.0
    
    # Unusual agent
    agent = (event.get("user_agent") or "").lower()
    unusual_agents = ["sqlmap", "nikto", "nmap", "masscan", "dirbuster", "hydra", "medusa"]
    has_unusual_agent = 1.0 if any(ua in agent for ua in unusual_agents) else 0.0
    
    # Port scan indicator
    port_scan_event = 1.0 if event_type == "PORT_SCAN_DETECTED" else 0.0
    
    # Privilege event
    priv_events = {"PRIVILEGE_CHANGE", "PRIVILEGE_ESCALATION", "SUDO_COMMAND", "ROOT_ACCESS"}
    is_priv = 1.0 if event_type in priv_events else 0.0
    
    return np.array([
        hour / 23.0, dow / 6.0, is_night, is_weekend,
        failed_login, min(bytes_mb / 100.0, 1.0), port_norm,
        sc_norm, ext_ip, et_risk, has_sql, has_unusual_agent,
        port_scan_event, is_priv,
    ], dtype=np.float32)


class ThreatClassifier:
    """
    Random Forest / XGBoost threat classifier.
    Classifies events into THREAT_CLASSES.
    """
    
    MODEL_FILENAME = "threat_classifier.pkl"
    SCALER_FILENAME = "classifier_scaler.pkl"
    ENCODER_FILENAME = "label_encoder.pkl"
    META_FILENAME = "classifier_meta.json"
    
    def __init__(self, model_path: str = "./ml/models"):
        self.model_path = Path(model_path)
        self.model = None
        self.scaler = None
        self.encoder = None
        self.is_trained = False
        self.metrics: Dict[str, Any] = {}
        self.training_samples = 0
        self._load_model()
    
    def _load_model(self):
        if not SKLEARN_AVAILABLE:
            return
        
        model_file = self.model_path / self.MODEL_FILENAME
        scaler_file = self.model_path / self.SCALER_FILENAME
        encoder_file = self.model_path / self.ENCODER_FILENAME
        meta_file = self.model_path / self.META_FILENAME
        
        if model_file.exists() and scaler_file.exists() and encoder_file.exists():
            try:
                self.model = joblib.load(model_file)
                self.scaler = joblib.load(scaler_file)
                self.encoder = joblib.load(encoder_file)
                if meta_file.exists():
                    with open(meta_file) as f:
                        meta = json.load(f)
                        self.metrics = meta.get("metrics", {})
                        self.training_samples = meta.get("training_samples", 0)
                self.is_trained = True
                logger.info(f"Classifier loaded from {model_file}")
            except Exception as e:
                logger.error(f"Failed to load classifier: {e}")
    
    def train(self, X: np.ndarray, y: List[str]) -> Dict[str, Any]:
        """Train the classifier on feature matrix and labels."""
        if not SKLEARN_AVAILABLE:
            return {"error": "scikit-learn not available"}
        
        self.encoder = LabelEncoder()
        y_enc = self.encoder.fit_transform(y)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
        )
        
        self.scaler = StandardScaler()
        X_train_sc = self.scaler.fit_transform(X_train)
        X_test_sc = self.scaler.transform(X_test)
        
        # Use XGBoost if available, else Random Forest
        if XGBOOST_AVAILABLE:
            self.model = XGBClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                eval_metric="mlogloss",
            )
        else:
            self.model = RandomForestClassifier(
                n_estimators=200,
                max_depth=10,
                random_state=42,
                n_jobs=-1,
            )
        
        self.model.fit(X_train_sc, y_train)
        self.is_trained = True
        self.training_samples = len(X)
        
        # Evaluate
        y_pred = self.model.predict(X_test_sc)
        
        self.metrics = {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "precision": float(precision_score(y_test, y_pred, average="weighted", zero_division=0)),
            "recall": float(recall_score(y_test, y_pred, average="weighted", zero_division=0)),
            "f1_score": float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
            "class_labels": list(self.encoder.classes_),
        }
        
        # Save
        self.model_path.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path / self.MODEL_FILENAME)
        joblib.dump(self.scaler, self.model_path / self.SCALER_FILENAME)
        joblib.dump(self.encoder, self.model_path / self.ENCODER_FILENAME)
        with open(self.model_path / self.META_FILENAME, "w") as f:
            json.dump({
                "training_samples": self.training_samples,
                "metrics": self.metrics,
                "feature_names": CLASSIFIER_FEATURES,
                "class_labels": list(self.encoder.classes_),
                "model_type": "XGBoost" if XGBOOST_AVAILABLE else "RandomForest",
                "trained_at": datetime.now().isoformat(),
            }, f)
        
        logger.info(f"Classifier trained: accuracy={self.metrics['accuracy']:.3f}")
        return {"status": "trained", **self.metrics}
    
    def predict(self, event: Dict[str, Any]) -> Tuple[str, float]:
        """Returns (predicted_class, confidence)."""
        if not self.is_trained or not SKLEARN_AVAILABLE:
            return "unknown", 0.0
        
        features = encode_event_for_classifier(event).reshape(1, -1)
        features_scaled = self.scaler.transform(features)
        
        pred_enc = self.model.predict(features_scaled)[0]
        pred_label = self.encoder.inverse_transform([pred_enc])[0]
        
        proba = self.model.predict_proba(features_scaled)[0]
        confidence = float(np.max(proba))
        
        return pred_label, confidence
    
    def train_on_synthetic(self) -> Dict[str, Any]:
        """Generate synthetic labeled data and train."""
        from ml.data.generate_dataset import generate_labeled_dataset
        
        logger.info("Generating synthetic labeled dataset for classifier training...")
        X, y = generate_labeled_dataset(n_per_class=500)
        return self.train(X, y)
    
    def get_info(self) -> Dict[str, Any]:
        meta_file = self.model_path / self.META_FILENAME
        meta = {}
        if meta_file.exists():
            with open(meta_file) as f:
                meta = json.load(f)
        
        return {
            "model_name": "Threat Classifier",
            "model_type": meta.get("model_type", "XGBoost" if XGBOOST_AVAILABLE else "RandomForest"),
            "is_trained": self.is_trained,
            "training_samples": self.training_samples,
            "feature_names": CLASSIFIER_FEATURES,
            "class_labels": meta.get("class_labels", THREAT_CLASSES),
            "trained_at": meta.get("trained_at"),
            **self.metrics,
        }


# Module-level singleton
_model_path = os.environ.get("ML_MODEL_PATH", "./ml/models")
threat_classifier = ThreatClassifier(model_path=_model_path)
