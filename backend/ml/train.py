"""
Standalone ML training script — can be run independently.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from pathlib import Path
MODEL_PATH = Path(__file__).parent / "models"
MODEL_PATH.mkdir(exist_ok=True)

os.environ["ML_MODEL_PATH"] = str(MODEL_PATH)


def train_anomaly_detector():
    from app.services.detection.ml_detector import anomaly_detector
    from app.services.simulation.generator import generate_normal_events
    
    logger.info("Generating normal training data...")
    normal_events = generate_normal_events(n=3000)
    
    logger.info(f"Training Isolation Forest on {len(normal_events)} events...")
    result = anomaly_detector.train(normal_events, contamination=0.05)
    logger.info(f"Anomaly detector training result: {result}")
    return result


def train_classifier():
    from app.services.detection.classifier import threat_classifier
    from ml.data.generate_dataset import generate_labeled_dataset
    
    logger.info("Generating labeled training dataset...")
    X, y = generate_labeled_dataset(n_per_class=1000)
    logger.info(f"Dataset shape: {X.shape}, classes: {set(y)}")
    
    logger.info("Training threat classifier...")
    result = threat_classifier.train(X, y)
    logger.info(f"Classifier metrics:")
    logger.info(f"  Accuracy:  {result.get('accuracy', 'N/A'):.4f}")
    logger.info(f"  Precision: {result.get('precision', 'N/A'):.4f}")
    logger.info(f"  Recall:    {result.get('recall', 'N/A'):.4f}")
    logger.info(f"  F1-Score:  {result.get('f1_score', 'N/A'):.4f}")
    return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train AI-SOC ML models")
    parser.add_argument("--model", choices=["anomaly", "classifier", "all"], default="all")
    args = parser.parse_args()
    
    if args.model in ("anomaly", "all"):
        train_anomaly_detector()
    
    if args.model in ("classifier", "all"):
        train_classifier()
    
    logger.info("Training complete! Models saved to: " + str(MODEL_PATH))
