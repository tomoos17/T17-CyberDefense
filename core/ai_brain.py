# ai_brain.py — T17 upgraded with tiered inference
# Models: Phi-3 Mini (fast) → Mistral 7B (deep) → LLaMA 3 (legacy/fallback)

import json
import requests
import os

# ── TIERED MODEL CONFIG ──────────────────────────────────────
MODELS = {
    "fast":    "phi3",     # curiosity score 4–6 — quick
    "deep":    "mistral",  # curiosity score 7–10 — deep
    "legacy":  "llama3"    # fallback testing only
}

OLLAMA_URL = "http://localhost:11434/api/generate"

# ── MITRE ATT&CK QUICK LOOKUP ────────────────────────────────
MITRE_MAP = {
    "powershell":          {"id": "T1059.001", "name": "PowerShell",               "tactic": "Execution"},
    "-enc":                {"id": "T1059.001", "name": "PowerShell Encoded",        "tactic": "Execution"},
    "base64":              {"id": "T1027",     "name": "Obfuscated Files",          "tactic": "Defence Evasion"},
    "certutil":            {"id": "T1105",     "name": "Ingress Tool Transfer",     "tactic": "Command & Control"},
    "wget":                {"id": "T1105",     "name": "Ingress Tool Transfer",     "tactic": "Command & Control"},
    "curl":                {"id": "T1105",     "name": "Ingress Tool Transfer",     "tactic": "Command & Control"},
    "port scan":           {"id": "T1046",     "name": "Network Service Scanning",  "tactic": "Discovery"},
    "nmap":                {"id": "T1046",     "name": "Network Service Scanning",  "tactic": "Discovery"},
    "dns tunnel":          {"id": "T1071.004", "name": "DNS C2",                   "tactic": "Command & Control"},
    "exfiltrat":           {"id": "T1041",     "name": "Exfiltration Over C2",      "tactic": "Exfiltration"},
    "brute force":         {"id": "T1110",     "name": "Brute Force",               "tactic": "Credential Access"},
    "failed login":        {"id": "T1110",     "name": "Brute Force",               "tactic": "Credential Access"},
    "lateral":             {"id": "T1021",     "name": "Remote Services",           "tactic": "Lateral Movement"},
    "syn flood":           {"id": "T1499",     "name": "Endpoint Denial of Service","tactic": "Impact"},
    "privilege escalat":   {"id": "T1068",     "name": "Exploitation for Priv Esc", "tactic": "Privilege Escalation"},
    "invoke-webrequest":   {"id": "T1059.001", "name": "PowerShell Web Request",    "tactic": "Execution"},
    "scheduled task":      {"id": "T1053",     "name": "Scheduled Task",            "tactic": "Persistence"},
    "registry":            {"id": "T1112",     "name": "Modify Registry",           "tactic": "Defence Evasion"},
}

def map_to_mitre(text: str) -> dict:
    text_lower = text.lower()
    for keyword, mapping in MITRE_MAP.items():
        if keyword in text_lower:
            return mapping
    return {"id": "T0000", "name": "Unclassified", "tactic": "Unknown"}


# ── LEGACY FUNCTION (kept for backward compatibility) ────────
def analyze_log(log_entry, score=5):
    """
    Legacy function — still works, now uses tiered model selection.
    score: curiosity score 0-10 (default 5 = medium)
    """
    model = MODELS["deep"] if score >= 7 else MODELS["fast"] if score >= 4 else None
    if model is None:
        return "[Discarded] Score below threshold — not suspicious enough."

    payload = {
        "model": model,
        "prompt": f"Analyse this security log and identify any threats: {log_entry}",
        "stream": False
    }
    try:
        response = requests.post(OLLAMA_URL, json=payload, stream=False)
        result = response.json()
        return result.get("response", "[No response from model]")
    except Exception as e:
        return f"[Error contacting {model}] {str(e)}"


# ── MAIN CLASS ───────────────────────────────────────────────
class AIBrain:
    def __init__(self, prompt_file="configs/prompt_templates.json"):
        self.prompts = self.load_prompts(prompt_file)

    def load_prompts(self, path):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        root_dir = os.path.join(base_dir, "..")
        full_path = os.path.normpath(os.path.join(root_dir, path))
        with open(full_path, 'r') as f:
            return json.load(f)

    def generate_prompt(self, intent, **kwargs):
        template = self.prompts.get(intent, "")
        if not template:
            return "[Error] Unknown prompt type"
        return template.format(**kwargs)

    def select_model(self, score: int) -> str:
        """Pick model tier based on curiosity score."""
        if score >= 7:
            return MODELS["deep"]    # Mistral 7B
        elif score >= 4:
            return MODELS["fast"]    # Phi-3 Mini
        else:
            return None              # below threshold — discard

    def analyse(self, text: str, score: int = 5) -> dict:
        """
        Main analysis method — tiered model selection + MITRE mapping.
        Returns a structured dict (ready for reflection.py to verify).
        """
        model = self.select_model(score)

        # Below threshold — don't waste LLM call
        if model is None:
            return {
                "status":     "discarded",
                "reason":     "Curiosity score below threshold",
                "score":      score,
                "mitre":      None,
                "model_used": None
            }

        # Build structured prompt — forces JSON-style thinking
        prompt = (
            f"You are T17, an AI cybersecurity analyst.\n"
            f"Analyse the following input and respond with:\n"
            f"1. threat_type: what kind of attack or event is this?\n"
            f"2. severity: low / medium / high / critical\n"
            f"3. reasoning: brief explanation (2-3 sentences)\n"
            f"4. recommended_action: what should be done?\n\n"
            f"Input: {text}\n\n"
            f"Respond in plain structured text."
        )

        try:
            response = requests.post(
                OLLAMA_URL,
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=60
            )
            raw_response = response.json().get("response", "[No response]")
        except Exception as e:
            raw_response = f"[Error] {str(e)}"

        # Map to MITRE ATT&CK
        mitre = map_to_mitre(text + " " + raw_response)

        return {
            "status":     "analysed",
            "model_used": model,
            "score":      score,
            "raw":        raw_response,
            "mitre":      mitre
        }

    def process(self, intent, llm_handler, **kwargs):
        """Legacy method — kept for backward compatibility."""
        prompt = self.generate_prompt(intent, **kwargs)
        return llm_handler(prompt)