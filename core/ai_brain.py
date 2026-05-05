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
# ── MITRE ATT&CK QUICK LOOKUP ────────────────────────────────
MITRE_MAP = {

    # ── EXECUTION ─────────────────────────────────────────────
    "powershell":          {"id": "T1059.001", "name": "PowerShell",                "tactic": "Execution"},
    "-enc":                {"id": "T1059.001", "name": "PowerShell Encoded",         "tactic": "Execution"},
    "-encodedcommand":     {"id": "T1059.001", "name": "PowerShell Encoded",         "tactic": "Execution"},
    "invoke-expression":   {"id": "T1059.001", "name": "PowerShell IEX",             "tactic": "Execution"},
    "iex":                 {"id": "T1059.001", "name": "PowerShell IEX",             "tactic": "Execution"},
    "invoke-webrequest":   {"id": "T1059.001", "name": "PowerShell Web Request",     "tactic": "Execution"},
    "downloadstring":      {"id": "T1059.001", "name": "PowerShell Download",        "tactic": "Execution"},
    "wscript":             {"id": "T1059.005", "name": "Visual Basic Script",        "tactic": "Execution"},
    "cscript":             {"id": "T1059.005", "name": "Visual Basic Script",        "tactic": "Execution"},
    "mshta":               {"id": "T1059.003", "name": "Windows Command Shell",      "tactic": "Execution"},
    "bash -i":             {"id": "T1059.004", "name": "Unix Shell",                 "tactic": "Execution"},
    "bash -c":             {"id": "T1059.004", "name": "Unix Shell",                 "tactic": "Execution"},
    "python -c":           {"id": "T1059.006", "name": "Python Execution",           "tactic": "Execution"},
    "perl -e":             {"id": "T1059.006", "name": "Script Interpreter",         "tactic": "Execution"},
    "shellcode":           {"id": "T1059",     "name": "Command and Scripting",      "tactic": "Execution"},
    "4688":                {"id": "T1059",     "name": "Process Created",            "tactic": "Execution"},

    # ── DEFENCE EVASION ───────────────────────────────────────
    "base64":              {"id": "T1027",     "name": "Obfuscated Files",           "tactic": "Defence Evasion"},
    "frombase64string":    {"id": "T1027",     "name": "Obfuscated Files",           "tactic": "Defence Evasion"},
    "xor":                 {"id": "T1027",     "name": "Obfuscated Files",           "tactic": "Defence Evasion"},
    "registry":            {"id": "T1112",     "name": "Modify Registry",            "tactic": "Defence Evasion"},
    "amsi":                {"id": "T1562.001", "name": "Disable Security Tools",     "tactic": "Defence Evasion"},
    "amsibypass":          {"id": "T1562.001", "name": "Disable Security Tools",     "tactic": "Defence Evasion"},
    "set-mppreference":    {"id": "T1562.001", "name": "Disable AV",                 "tactic": "Defence Evasion"},
    "clear-eventlog":      {"id": "T1070.001", "name": "Clear Windows Event Logs",   "tactic": "Defence Evasion"},
    "wevtutil cl":         {"id": "T1070.001", "name": "Clear Windows Event Logs",   "tactic": "Defence Evasion"},
    "1102":                {"id": "T1070.001", "name": "Audit Log Cleared",          "tactic": "Defence Evasion"},
    "timestomp":           {"id": "T1070.006", "name": "Timestomp",                  "tactic": "Defence Evasion"},
    "regsvr32":            {"id": "T1218.010", "name": "Regsvr32",                   "tactic": "Defence Evasion"},
    "rundll32":            {"id": "T1218.011", "name": "Rundll32",                   "tactic": "Defence Evasion"},
    "msiexec":             {"id": "T1218.007", "name": "Msiexec",                    "tactic": "Defence Evasion"},
    "dll injection":       {"id": "T1055.001", "name": "DLL Injection",              "tactic": "Defence Evasion"},
    "process hollowing":   {"id": "T1055.012", "name": "Process Hollowing",          "tactic": "Defence Evasion"},
    "virtualalloc":        {"id": "T1055",     "name": "Process Injection",          "tactic": "Defence Evasion"},
    "writeprocessmemory":  {"id": "T1055",     "name": "Process Injection",          "tactic": "Defence Evasion"},

    # ── CREDENTIAL ACCESS ─────────────────────────────────────
    "mimikatz":            {"id": "T1003.001", "name": "LSASS Memory Dump",          "tactic": "Credential Access"},
    "sekurlsa":            {"id": "T1003.001", "name": "LSASS Memory Dump",          "tactic": "Credential Access"},
    "lsass":               {"id": "T1003.001", "name": "LSASS Memory Dump",          "tactic": "Credential Access"},
    "hashdump":            {"id": "T1003.002", "name": "SAM Database Dump",          "tactic": "Credential Access"},
    "ntds.dit":            {"id": "T1003.003", "name": "NTDS Credential Dump",       "tactic": "Credential Access"},
    "wdigest":             {"id": "T1003.001", "name": "Credential Dump",            "tactic": "Credential Access"},
    "brute force":         {"id": "T1110",     "name": "Brute Force",                "tactic": "Credential Access"},
    "bruteforce":          {"id": "T1110",     "name": "Brute Force",                "tactic": "Credential Access"},
    "password spray":      {"id": "T1110.003", "name": "Password Spraying",          "tactic": "Credential Access"},
    "credential stuffing": {"id": "T1110.004", "name": "Credential Stuffing",        "tactic": "Credential Access"},
    "failed login":        {"id": "T1110",     "name": "Brute Force",                "tactic": "Credential Access"},
    "authentication failure": {"id": "T1110", "name": "Brute Force",                "tactic": "Credential Access"},
    "4625":                {"id": "T1110",     "name": "Brute Force — Failed Logon", "tactic": "Credential Access"},
    "/etc/shadow":         {"id": "T1003.008", "name": "Shadow File Credential Dump","tactic": "Credential Access"},

    # ── PRIVILEGE ESCALATION ──────────────────────────────────
    "sudo":                {"id": "T1068",     "name": "Exploitation for Priv Esc",  "tactic": "Privilege Escalation"},
    "root":                {"id": "T1068",     "name": "Exploitation for Priv Esc",  "tactic": "Privilege Escalation"},
    "privilege escalat":   {"id": "T1068",     "name": "Exploitation for Priv Esc",  "tactic": "Privilege Escalation"},
    "bypassuac":           {"id": "T1548.002", "name": "Bypass UAC",                 "tactic": "Privilege Escalation"},
    "uac bypass":          {"id": "T1548.002", "name": "Bypass UAC",                 "tactic": "Privilege Escalation"},
    "token":               {"id": "T1134",     "name": "Access Token Manipulation",  "tactic": "Privilege Escalation"},
    "impersonat":          {"id": "T1134.001", "name": "Token Impersonation",        "tactic": "Privilege Escalation"},
    "4672":                {"id": "T1068",     "name": "Special Privileges Assigned","tactic": "Privilege Escalation"},

    # ── DISCOVERY ─────────────────────────────────────────────
    "nmap":                {"id": "T1046",     "name": "Network Service Scanning",   "tactic": "Discovery"},
    "port scan":           {"id": "T1046",     "name": "Network Service Scanning",   "tactic": "Discovery"},
    "masscan":             {"id": "T1046",     "name": "Network Service Scanning",   "tactic": "Discovery"},
    "arp scan":            {"id": "T1018",     "name": "Remote System Discovery",    "tactic": "Discovery"},
    "ping sweep":          {"id": "T1018",     "name": "Remote System Discovery",    "tactic": "Discovery"},
    "whoami":              {"id": "T1033",     "name": "System Owner Discovery",     "tactic": "Discovery"},
    "net user":            {"id": "T1087",     "name": "Account Discovery",          "tactic": "Discovery"},

    # ── LATERAL MOVEMENT ──────────────────────────────────────
    "lateral":             {"id": "T1021",     "name": "Remote Services",            "tactic": "Lateral Movement"},
    "psexec":              {"id": "T1021.002", "name": "SMB Windows Admin Shares",   "tactic": "Lateral Movement"},
    "wmiexec":             {"id": "T1021.003", "name": "Distributed COM",            "tactic": "Lateral Movement"},
    "pass the hash":       {"id": "T1550.002", "name": "Pass the Hash",              "tactic": "Lateral Movement"},
    "pass the ticket":     {"id": "T1550.003", "name": "Pass the Ticket",            "tactic": "Lateral Movement"},
    "rdp":                 {"id": "T1021.001", "name": "Remote Desktop Protocol",    "tactic": "Lateral Movement"},
    "winrm":               {"id": "T1021.006", "name": "Windows Remote Management",  "tactic": "Lateral Movement"},
    "evil-winrm":          {"id": "T1021.006", "name": "Windows Remote Management",  "tactic": "Lateral Movement"},
    "ssh tunnel":          {"id": "T1021.004", "name": "SSH Lateral Movement",       "tactic": "Lateral Movement"},
    "4648":                {"id": "T1021",     "name": "Explicit Credential Logon",  "tactic": "Lateral Movement"},
    "5140":                {"id": "T1021",     "name": "Network Share Accessed",     "tactic": "Lateral Movement"},

    # ── PERSISTENCE ───────────────────────────────────────────
    "scheduled task":      {"id": "T1053.005", "name": "Scheduled Task",             "tactic": "Persistence"},
    "schtasks":            {"id": "T1053.005", "name": "Scheduled Task",             "tactic": "Persistence"},
    "crontab":             {"id": "T1053.003", "name": "Cron Job",                   "tactic": "Persistence"},
    "cron":                {"id": "T1053.003", "name": "Cron Job",                   "tactic": "Persistence"},
    "registry run":        {"id": "T1547.001", "name": "Registry Run Keys",          "tactic": "Persistence"},
    "currentversion\\run": {"id": "T1547.001", "name": "Registry Run Keys",          "tactic": "Persistence"},
    "startup folder":      {"id": "T1547.001", "name": "Startup Folder",             "tactic": "Persistence"},
    "sc create":           {"id": "T1543.003", "name": "Windows Service",            "tactic": "Persistence"},
    "backdoor":            {"id": "T1505",     "name": "Server Software Component",  "tactic": "Persistence"},
    "webshell":            {"id": "T1505.003", "name": "Web Shell",                  "tactic": "Persistence"},
    "web shell":           {"id": "T1505.003", "name": "Web Shell",                  "tactic": "Persistence"},
    "4698":                {"id": "T1053.005", "name": "Scheduled Task Created",     "tactic": "Persistence"},
    "4720":                {"id": "T1136.001", "name": "Local Account Created",      "tactic": "Persistence"},

    # ── COMMAND AND CONTROL ───────────────────────────────────
    "beacon":              {"id": "T1071",     "name": "Application Layer Protocol", "tactic": "Command & Control"},
    "c2":                  {"id": "T1071",     "name": "C2 Communication",           "tactic": "Command & Control"},
    "reverse shell":       {"id": "T1059",     "name": "Reverse Shell",              "tactic": "Command & Control"},
    "netcat":              {"id": "T1059",     "name": "Netcat Shell",               "tactic": "Command & Control"},
    "dns tunnel":          {"id": "T1071.004", "name": "DNS C2",                     "tactic": "Command & Control"},
    "dnscat":              {"id": "T1071.004", "name": "DNS C2",                     "tactic": "Command & Control"},
    "certutil":            {"id": "T1105",     "name": "Ingress Tool Transfer",      "tactic": "Command & Control"},
    "bitsadmin":           {"id": "T1197",     "name": "BITS Jobs",                  "tactic": "Command & Control"},
    "wget":                {"id": "T1105",     "name": "Ingress Tool Transfer",      "tactic": "Command & Control"},
    "curl":                {"id": "T1105",     "name": "Ingress Tool Transfer",      "tactic": "Command & Control"},
    "downloadfile":        {"id": "T1105",     "name": "Ingress Tool Transfer",      "tactic": "Command & Control"},

    # ── EXFILTRATION ──────────────────────────────────────────
    "exfiltrat":           {"id": "T1041",     "name": "Exfiltration Over C2",       "tactic": "Exfiltration"},
    "data theft":          {"id": "T1041",     "name": "Exfiltration Over C2",       "tactic": "Exfiltration"},
    "icmp tunnel":         {"id": "T1048",     "name": "Exfiltration Over Alt Protocol","tactic": "Exfiltration"},
    "compress-archive":    {"id": "T1560",     "name": "Archive Collected Data",     "tactic": "Exfiltration"},

    # ── IMPACT ────────────────────────────────────────────────
    "ransomware":          {"id": "T1486",     "name": "Data Encrypted for Impact",  "tactic": "Impact"},
    "syn flood":           {"id": "T1499",     "name": "Network Denial of Service",  "tactic": "Impact"},
    "ddos":                {"id": "T1499",     "name": "Endpoint Denial of Service", "tactic": "Impact"},
    "wipe":                {"id": "T1485",     "name": "Data Destruction",           "tactic": "Impact"},
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