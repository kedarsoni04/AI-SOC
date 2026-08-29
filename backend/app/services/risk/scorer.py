"""
Risk Scoring Engine — Transparent 0-100 scoring system.
Every factor is calculated deterministically and explained.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime


SEVERITY_SCORES = {
    "critical": 25,
    "high": 18,
    "medium": 10,
    "low": 4,
    "info": 1,
}

ATTACK_TYPE_SCORES = {
    "data_exfiltration": 20,
    "privilege_escalation": 18,
    "account_compromise": 16,
    "impossible_travel": 15,
    "sql_injection": 14,
    "brute_force": 12,
    "port_scan": 8,
    "suspicious_login": 8,
    "malware_activity": 20,
    "unknown": 5,
}

PRIVILEGED_USERS = {
    "admin", "administrator", "root", "sa", "postgres",
    "system", "oracle", "superuser", "sysadmin",
}


def score_incident(
    severity: str,
    attack_types: List[str],
    alert_count: int,
    target_user: Optional[str],
    anomaly_score: Optional[float],
    bytes_exfiltrated: Optional[int],
    mitre_tactics: Optional[List[str]],
    evidence_strength: float = 0.7,
) -> Dict[str, Any]:
    """
    Calculate a 0-100 risk score with full breakdown.
    
    Returns:
        {
            "score": 85,
            "label": "CRITICAL",
            "breakdown": [...],
            "explanation": "..."
        }
    """
    breakdown = []
    total = 0

    # 1. Threat Severity (0-25)
    sev_score = SEVERITY_SCORES.get(severity.lower(), 10)
    breakdown.append({
        "factor": "Threat Severity",
        "score": sev_score,
        "max": 25,
        "reason": f"Incident classified as '{severity}' severity",
    })
    total += sev_score

    # 2. Attack Type Risk (0-20)
    attack_max = 0
    for at in attack_types:
        attack_max = max(attack_max, ATTACK_TYPE_SCORES.get(at.lower(), 5))
    breakdown.append({
        "factor": "Attack Type Risk",
        "score": attack_max,
        "max": 20,
        "reason": f"Most dangerous attack type: {', '.join(attack_types) or 'Unknown'}",
    })
    total += attack_max

    # 3. Attack Frequency (0-15)
    freq_score = min(15, alert_count * 1.5)
    breakdown.append({
        "factor": "Attack Frequency",
        "score": round(freq_score, 1),
        "max": 15,
        "reason": f"{alert_count} related alerts detected",
    })
    total += freq_score

    # 4. User Privilege Level (0-15)
    is_privileged = bool(target_user and target_user.lower() in PRIVILEGED_USERS)
    user_score = 15 if is_privileged else (8 if target_user else 3)
    breakdown.append({
        "factor": "Target User Privilege",
        "score": user_score,
        "max": 15,
        "reason": (
            f"Target '{target_user}' is a privileged system account" if is_privileged
            else f"Target '{target_user}' is a standard user" if target_user
            else "No specific target user identified"
        ),
    })
    total += user_score

    # 5. ML Anomaly Score (0-10)
    ml_score = round((anomaly_score or 0) * 10, 1)
    breakdown.append({
        "factor": "ML Anomaly Score",
        "score": ml_score,
        "max": 10,
        "reason": f"Machine learning anomaly score: {(anomaly_score or 0):.2f}",
    })
    total += ml_score

    # 6. Data Exfiltration Indicator (0-10)
    exfil_score = 0
    if bytes_exfiltrated and bytes_exfiltrated > 0:
        mb = bytes_exfiltrated / (1024 * 1024)
        exfil_score = min(10, round(mb / 10, 1))
    if "data_exfiltration" in attack_types:
        exfil_score = max(exfil_score, 8)
    breakdown.append({
        "factor": "Data Exfiltration Risk",
        "score": exfil_score,
        "max": 10,
        "reason": (
            f"{bytes_exfiltrated / (1024*1024):.1f} MB transferred" if bytes_exfiltrated
            else "No data exfiltration evidence"
        ),
    })
    total += exfil_score

    # 7. MITRE Coverage (0-5)
    mitre_score = min(5, len(mitre_tactics or []))
    breakdown.append({
        "factor": "MITRE ATT&CK Tactics",
        "score": mitre_score,
        "max": 5,
        "reason": f"{len(mitre_tactics or [])} MITRE tactics identified",
    })
    total += mitre_score

    # Cap at 100
    final_score = min(100, round(total, 1))

    # Label
    if final_score >= 80:
        label = "CRITICAL"
    elif final_score >= 60:
        label = "HIGH"
    elif final_score >= 40:
        label = "MEDIUM"
    elif final_score >= 20:
        label = "LOW"
    else:
        label = "INFO"

    # Build explanation
    top_factors = sorted(breakdown, key=lambda x: x["score"], reverse=True)[:3]
    explanation = (
        f"Risk score {final_score}/100 ({label}). "
        f"Primary risk drivers: "
        + "; ".join(f"{f['factor']} (+{f['score']})" for f in top_factors)
        + "."
    )

    return {
        "score": final_score,
        "label": label,
        "breakdown": breakdown,
        "explanation": explanation,
        "raw_total": total,
    }
