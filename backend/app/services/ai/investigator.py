"""
AI Investigation Engine — LLM abstraction layer.
The LLM analyzes structured evidence assembled by the deterministic system.
It does NOT make detection decisions — it explains, summarizes, and recommends.
"""
import logging
import time
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional
from app.core.config import settings

logger = logging.getLogger(__name__)

# Timeout for all LLM API calls (seconds)
LLM_TIMEOUT_SECONDS = 60


INVESTIGATION_PROMPT_TEMPLATE = """
You are an expert cybersecurity analyst in a Security Operations Center (SOC).
You have been provided with structured evidence from an automated security detection system.
Your role is to ANALYZE the evidence, EXPLAIN the incident, and RECOMMEND response actions.

IMPORTANT CONSTRAINTS:
- You are NOT making the detection decision — the deterministic system has already done that.
- Base your analysis ONLY on the provided evidence.
- Do NOT fabricate details not present in the evidence.
- Clearly indicate your confidence level.
- If evidence is insufficient, say so explicitly.

---

## Incident Evidence

**Incident Title:** {title}
**Severity:** {severity}
**Risk Score:** {risk_score}/100 ({risk_label})
**Source IP:** {source_ip}
**Target User:** {target_user}
**Attack Vector:** {attack_vector}

**Alert Summary ({alert_count} alerts):**
{alert_summary}

**Risk Score Breakdown:**
{risk_breakdown}

**MITRE ATT&CK Tactics Identified:**
{mitre_tactics}

**Timeline:** {first_event} -> {last_event} ({duration_minutes:.0f} minutes)

---

Please provide a structured analysis in the following JSON format:

{{
  "summary": "2-3 sentence plain English summary of what happened",
  "attack_analysis": "Detailed explanation of the attack sequence and methodology (4-6 sentences)",
  "key_evidence": ["strongest evidence item 1", "strongest evidence item 2", "strongest evidence item 3"],
  "mitre_mapping": [
    {{"tactic": "tactic name", "technique": "T1234 - Technique Name", "evidence": "what triggered this"}}
  ],
  "risk_explanation": "Why this incident is dangerous and what assets are at risk (3-4 sentences)",
  "recommended_response": {{
    "immediate": ["immediate action 1", "immediate action 2"],
    "investigation": ["investigation step 1", "investigation step 2"],
    "containment": ["containment step 1", "containment step 2"],
    "recovery": ["recovery step 1"]
  }},
  "confidence": 0.85,
  "analyst_notes": "Any caveats, uncertainties, or additional context"
}}
"""


class AIInvestigator:
    """
    LLM-powered investigation engine.
    Supports Gemini (google-genai SDK), OpenAI, Anthropic,
    or graceful degradation when no key is set.
    """

    def __init__(self):
        self.provider = settings.llm_provider
        self._client = None
        self._init_client()

    def _init_client(self):
        """Initialize the appropriate LLM client based on settings."""
        if self.provider == "gemini" and settings.gemini_api_key:
            try:
                from google import genai  # new google-genai SDK (not deprecated)
                self._client = genai.Client(api_key=settings.gemini_api_key)
                logger.info(
                    f"AI Investigator: Gemini ({settings.gemini_model}) "
                    f"initialized via google-genai SDK"
                )
            except Exception as e:
                logger.error(f"Gemini init failed: {e}")
                self.provider = "none"

        elif self.provider == "openai" and settings.openai_api_key:
            try:
                from openai import AsyncOpenAI  # type: ignore
                self._client = AsyncOpenAI(api_key=settings.openai_api_key)
                logger.info(f"AI Investigator: OpenAI ({settings.openai_model}) initialized")
            except Exception as e:
                logger.error(f"OpenAI init failed: {e}")
                self.provider = "none"

        elif self.provider == "anthropic" and settings.anthropic_api_key:
            try:
                import anthropic  # type: ignore
                self._client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
                logger.info(f"AI Investigator: Anthropic ({settings.anthropic_model}) initialized")
            except Exception as e:
                logger.error(f"Anthropic init failed: {e}")
                self.provider = "none"

        else:
            if self.provider != "none":
                logger.warning(
                    f"AI provider '{self.provider}' configured but no API key found "
                    f"-- using rule-based fallback"
                )
            self.provider = "none"

    async def investigate(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main investigation function.
        Returns structured AI analysis of the incident.
        """
        start_time = time.time()

        # Dynamically initialize or refresh client if key was provided
        if self._client is None or self.provider == "none":
            self.provider = settings.llm_provider
            self._init_client()

        prompt = self._build_prompt(incident_data)

        if self.provider == "none" or self._client is None:
            result = self._rule_based_analysis(incident_data)
            result["llm_provider"] = "none"
            result["model_used"] = "rule_based_fallback"
            return result

        try:
            if self.provider == "gemini":
                raw_response = await asyncio.wait_for(
                    self._call_gemini(prompt),
                    timeout=LLM_TIMEOUT_SECONDS,
                )
            elif self.provider == "openai":
                raw_response = await asyncio.wait_for(
                    self._call_openai(prompt),
                    timeout=LLM_TIMEOUT_SECONDS,
                )
            elif self.provider == "anthropic":
                raw_response = await asyncio.wait_for(
                    self._call_anthropic(prompt),
                    timeout=LLM_TIMEOUT_SECONDS,
                )
            else:
                raw_response = None

            if raw_response:
                parsed = self._parse_response(raw_response)
                parsed["llm_provider"] = self.provider
                parsed["model_used"] = self._get_model_name()
                parsed["raw_response"] = raw_response
                parsed["duration_ms"] = int((time.time() - start_time) * 1000)
                return parsed

        except asyncio.TimeoutError:
            logger.error(f"LLM investigation timed out after {LLM_TIMEOUT_SECONDS}s")
        except Exception as e:
            logger.error(f"LLM investigation failed: {e}")

        # Fallback to rule-based
        result = self._rule_based_analysis(incident_data)
        result["llm_provider"] = "none"
        result["model_used"] = "rule_based_fallback"
        return result

    def _build_prompt(self, incident: Dict[str, Any]) -> str:
        alerts = incident.get("alerts", [])
        alert_summary = "\n".join([
            f"- [{a.get('severity', 'unknown').upper()}] {a.get('title', 'Alert')} "
            f"(rule: {a.get('detection_rule', 'N/A')}, confidence: {a.get('confidence', 0):.0%})"
            for a in alerts[:10]  # Limit to 10 alerts
        ]) or "No alerts"

        risk_breakdown = incident.get("risk_breakdown") or {}
        rb_text = "\n".join([
            f"  - {item['factor']}: +{item['score']}/{item['max']} ({item['reason']})"
            for item in (risk_breakdown.get("breakdown") or [])
        ]) or "Not available"

        first_event = incident.get("first_event_at")
        last_event = incident.get("last_event_at")
        if isinstance(first_event, datetime):
            first_event = first_event.strftime("%H:%M:%S")
        if isinstance(last_event, datetime):
            last_event = last_event.strftime("%H:%M:%S")

        duration = 0.0
        if incident.get("first_event_at") and incident.get("last_event_at"):
            try:
                fe = incident["first_event_at"]
                le = incident["last_event_at"]
                if isinstance(fe, str):
                    fe = datetime.fromisoformat(fe)
                if isinstance(le, str):
                    le = datetime.fromisoformat(le)
                duration = (le - fe).total_seconds() / 60
            except Exception:
                pass

        return INVESTIGATION_PROMPT_TEMPLATE.format(
            title=incident.get("title", "Security Incident"),
            severity=incident.get("severity", "unknown").upper(),
            risk_score=incident.get("risk_score", 0),
            risk_label=incident.get("risk_label", "UNKNOWN"),
            source_ip=incident.get("source_ip") or "Unknown",
            target_user=incident.get("target_user") or "Unknown",
            attack_vector=incident.get("attack_vector") or "Unknown",
            alert_count=len(alerts),
            alert_summary=alert_summary,
            risk_breakdown=rb_text,
            mitre_tactics=", ".join(incident.get("mitre_tactics") or []) or "None identified",
            first_event=first_event or "Unknown",
            last_event=last_event or "Unknown",
            duration_minutes=duration,
        )

    async def _call_gemini(self, prompt: str) -> Optional[str]:
        """Call Gemini using the new google-genai SDK (natively async)."""
        from google.genai import types as genai_types  # type: ignore[import]

        response = await self._client.aio.models.generate_content(
            model=settings.gemini_model,
            contents=prompt,
            config=genai_types.GenerateContentConfig(
                max_output_tokens=2048,
                temperature=0.2,
                automatic_function_calling=genai_types.AutomaticFunctionCallingConfig(
                    disable=True
                ),
            ),
        )
        if response.text:
            return response.text
        # Fallback: walk candidates
        if response.candidates:
            candidate = response.candidates[0]
            if candidate.content and candidate.content.parts:
                return "".join(
                    part.text for part in candidate.content.parts
                    if hasattr(part, "text") and part.text
                )
        return None

    async def _call_openai(self, prompt: str) -> Optional[str]:
        response = await self._client.chat.completions.create(
            model=settings.openai_model,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            max_tokens=2000,
        )
        return response.choices[0].message.content

    async def _call_anthropic(self, prompt: str) -> Optional[str]:
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._client.messages.create(
                model=settings.anthropic_model,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}],
            )
        )
        return response.content[0].text

    def _parse_response(self, raw: str) -> Dict[str, Any]:
        """Parse JSON from LLM response."""
        import json
        import re

        # Extract JSON block if wrapped in markdown
        json_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
        json_str = json_match.group(1).strip() if json_match else raw.strip()

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            # Try to extract partial JSON
            try:
                start = json_str.find("{")
                end = json_str.rfind("}") + 1
                if start != -1 and end > start:
                    data = json.loads(json_str[start:end])
                else:
                    raise ValueError("No valid JSON found")
            except Exception:
                return {
                    "summary": raw[:500],
                    "attack_analysis": "Parsed from LLM response.",
                    "evidence_summary": "See raw response.",
                    "mitre_mapping": [],
                    "risk_explanation": "",
                    "recommended_response": raw[:200],
                    "confidence": 0.75,
                }

        # Flatten recommended_response dict -> markdown string
        rec = data.get("recommended_response", "")
        if isinstance(rec, dict):
            parts = []
            for phase, actions in rec.items():
                if actions:
                    if isinstance(actions, list):
                        parts.append(f"**{phase.title()}**: " + "; ".join(actions))
                    else:
                        parts.append(f"**{phase.title()}**: {actions}")
            rec = "\n".join(parts)

        key_ev = data.get("key_evidence", [])
        evidence_str = "; ".join(key_ev) if isinstance(key_ev, list) else str(key_ev)

        return {
            "summary": data.get("summary", ""),
            "attack_analysis": data.get("attack_analysis", ""),
            "evidence_summary": evidence_str,
            "mitre_mapping": data.get("mitre_mapping", []),
            "risk_explanation": data.get("risk_explanation", ""),
            "recommended_response": rec,
            "confidence": float(data.get("confidence", 0.85)),
            "analyst_notes": data.get("analyst_notes", ""),
        }

    def _rule_based_analysis(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fallback analysis when no LLM is available.
        Generates structured response using deterministic rules.
        """
        title = incident.get("title", "Security Incident")
        severity = incident.get("severity", "medium")
        source_ip = incident.get("source_ip") or "unknown source"
        target_user = incident.get("target_user") or "unknown user"
        attack_vector = incident.get("attack_vector") or "unknown"
        alerts = incident.get("alerts", [])
        attack_types = list({a.get("attack_type", "") for a in alerts if a.get("attack_type")})
        risk_score = incident.get("risk_score", 0)

        summary = (
            f"A {severity}-severity security incident '{title}' was detected from {source_ip} "
            f"targeting {target_user}. {len(alerts)} related alerts were generated over the "
            f"investigation period. The attack involved: {attack_vector}."
        )

        attack_analysis = (
            f"The automated detection system identified a multi-step attack pattern. "
            f"Attack types detected: {', '.join(attack_types) or 'Unknown'}. "
            f"The source IP {source_ip} was involved in {len(alerts)} security events. "
            f"The risk score of {risk_score}/100 indicates a {severity} threat level requiring "
            f"immediate investigation by SOC analysts."
        )

        recommendations = {
            "brute_force": "**Immediate**: Block source IP; **Investigation**: Review authentication logs; **Containment**: Enable account lockout policy",
            "sql_injection": "**Immediate**: Block malicious requests at WAF; **Investigation**: Check database query logs; **Containment**: Patch vulnerable endpoint",
            "data_exfiltration": "**Immediate**: Block outbound connection; **Investigation**: Identify all transferred data; **Containment**: Revoke compromised credentials",
            "privilege_escalation": "**Immediate**: Disable elevated session; **Investigation**: Audit privilege assignments; **Containment**: Reset compromised account",
            "port_scan": "**Immediate**: Block scanning IP at firewall; **Investigation**: Check for subsequent targeted attacks; **Containment**: Review exposed services",
        }

        rec = next(
            (recommendations[at] for at in attack_types if at in recommendations),
            "**Immediate**: Contain the threat; **Investigation**: Review related logs; **Containment**: Isolate affected systems",
        )

        mitre_mapping: List[Dict[str, Any]] = []
        for a in alerts[:5]:
            for tactic in (a.get("mitre_tactics") or []):
                if tactic not in [m.get("tactic") for m in mitre_mapping]:
                    mitre_mapping.append({
                        "tactic": tactic,
                        "technique": "See alert details",
                        "evidence": a.get("title", ""),
                    })

        return {
            "summary": summary,
            "attack_analysis": attack_analysis,
            "evidence_summary": "; ".join(a.get("title", "") for a in alerts[:5]),
            "mitre_mapping": mitre_mapping,
            "risk_explanation": (
                f"This incident scores {risk_score}/100 due to its {severity} severity, "
                f"{len(alerts)} correlated alerts, and involvement of {attack_vector}."
            ),
            "recommended_response": rec,
            "confidence": 0.65,
        }

    def _get_model_name(self) -> str:
        if self.provider == "gemini":
            return settings.gemini_model
        if self.provider == "openai":
            return settings.openai_model
        if self.provider == "anthropic":
            return settings.anthropic_model
        return "none"

    def is_available(self) -> bool:
        return self.provider != "none"


# Module-level singleton
ai_investigator = AIInvestigator()
