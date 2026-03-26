# reflection.py — T17 Layer 3
# Verifies ai_brain output, adds confidence score, maps to MITRE ATT&CK
# Replaces the incorrect memory.py code that was here before

import json
import re
from datetime import datetime

# ── CONFIDENCE SCORING RULES ─────────────────────────────────
CONFIDENCE_BOOSTERS = {
    "critical":    +20,
    "high":        +15,
    "medium":      +5,
    "malicious":   +15,
    "suspicious":  +10,
    "attack":      +10,
    "exploit":     +10,
    "detected":    +5,
    "confirmed":   +15,
}

CONFIDENCE_REDUCERS = {
    "low":         -10,
    "unlikely":    -15,
    "unclear":     -10,
    "uncertain":   -15,
    "possibly":    -5,
    "might":       -5,
    "normal":      -20,
    "legitimate":  -20,
    "no threat":   -25,
}

# ── SEVERITY EXTRACTOR ───────────────────────────────────────
def extract_severity(text: str) -> str:
    """Pull severity level out of LLM response text."""
    text_lower = text.lower()
    if "critical" in text_lower:
        return "critical"
    elif "high" in text_lower:
        return "high"
    elif "medium" in text_lower:
        return "medium"
    elif "low" in text_lower:
        return "low"
    return "unknown"

# ── CONFIDENCE CALCULATOR ────────────────────────────────────
def calculate_confidence(raw_response: str, curiosity_score: int) -> int:
    """
    Calculate a 0-100 confidence score based on:
    - Words in the LLM response (boosters and reducers)
    - The original curiosity score (higher score = more confident)
    """
    # Base confidence from curiosity score (0-10 → 0-50 range)
    base = curiosity_score * 5

    # Adjust based on LLM response language
    text_lower = raw_response.lower()
    adjustment = 0
    for word, boost in CONFIDENCE_BOOSTERS.items():
        if word in text_lower:
            adjustment += boost
    for word, reduction in CONFIDENCE_REDUCERS.items():
        if word in text_lower:
            adjustment += reduction

    # Clamp between 0 and 100
    confidence = max(0, min(100, base + adjustment))
    return confidence

# ── HALLUCINATION CHECK ──────────────────────────────────────
def check_for_hallucination(raw_response: str) -> dict:
    """
    Basic check for signs the LLM may have hallucinated or been vague.
    Returns a warning if detected.
    """
    warning_phrases = [
        "i cannot",
        "i don't know",
        "i'm not sure",
        "as an ai",
        "i am unable",
        "no information",
        "cannot determine",
        "insufficient data",
    ]
    text_lower = raw_response.lower()
    for phrase in warning_phrases:
        if phrase in text_lower:
            return {
                "hallucination_risk": True,
                "warning": f"LLM expressed uncertainty: '{phrase}' detected in response"
            }
    return {"hallucination_risk": False, "warning": None}

# ── MAIN REFLECT FUNCTION ────────────────────────────────────
def reflect(brain_output: dict) -> dict:
    """
    Takes the output from ai_brain.analyse() and:
    1. Checks for hallucination
    2. Calculates confidence score
    3. Extracts severity
    4. Builds final structured JSON threat report

    Args:
        brain_output: dict from AIBrain.analyse()

    Returns:
        Final verified threat report as a dict
    """
    # If brain discarded the input (score too low) — pass through
    if brain_output.get("status") == "discarded":
        return {
            "status":        "discarded",
            "reason":        brain_output.get("reason"),
            "curiosity_score": brain_output.get("score"),
            "timestamp":     datetime.now().isoformat()
        }

    raw        = brain_output.get("raw", "")
    score      = brain_output.get("score", 5)
    mitre      = brain_output.get("mitre", {})
    model_used = brain_output.get("model_used", "unknown")

    # Run checks
    confidence   = calculate_confidence(raw, score)
    severity     = extract_severity(raw)
    hallucination = check_for_hallucination(raw)

    # Build final report
    report = {
        "status":          "threat_report",
        "timestamp":       datetime.now().isoformat(),
        "model_used":      model_used,
        "curiosity_score": score,
        "severity":        severity,
        "confidence":      confidence,
        "mitre": {
            "id":     mitre.get("id",     "T0000"),
            "name":   mitre.get("name",   "Unclassified"),
            "tactic": mitre.get("tactic", "Unknown"),
        },
        "hallucination_check": hallucination,
        "reasoning":       raw,
        "verdict":         _build_verdict(severity, confidence, hallucination)
    }

    return report

# ── VERDICT BUILDER ──────────────────────────────────────────
def _build_verdict(severity: str, confidence: int, hallucination: dict) -> str:
    """Generate a plain-English one-line verdict."""
    if hallucination["hallucination_risk"]:
        return "⚠️  Low confidence — LLM response was uncertain. Manual review recommended."
    if confidence >= 75 and severity in ("high", "critical"):
        return "🔴  High confidence threat detected. Immediate action recommended."
    elif confidence >= 50 and severity == "medium":
        return "🟡  Medium confidence threat. Investigate further."
    elif confidence >= 40:
        return "🟠  Possible threat detected. Low-medium confidence."
    else:
        return "🟢  No significant threat detected. Monitoring continues."

# ── PRETTY PRINT HELPER ──────────────────────────────────────
def print_report(report: dict):
    """Print the threat report cleanly to terminal."""
    print("\n" + "="*55)
    print("  T17 THREAT REPORT")
    print("="*55)
    print(f"  Status:       {report.get('status')}")
    print(f"  Timestamp:    {report.get('timestamp')}")
    print(f"  Model used:   {report.get('model_used')}")
    print(f"  Severity:     {report.get('severity', '').upper()}")
    print(f"  Confidence:   {report.get('confidence')}/100")
    mitre = report.get("mitre", {})
    print(f"  MITRE ID:     {mitre.get('id')} — {mitre.get('name')}")
    print(f"  Tactic:       {mitre.get('tactic')}")
    print(f"  Verdict:      {report.get('verdict')}")
    if report.get("hallucination_check", {}).get("hallucination_risk"):
        print(f"  ⚠️  Warning:  {report['hallucination_check']['warning']}")
    print("-"*55)
    print(f"  Reasoning:\n  {report.get('reasoning', '')[:300]}...")
    print("="*55 + "\n")