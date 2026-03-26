# core/log_parser.py — T17 data layer
# Parses raw log strings into structured dictionaries

import re

def parse_log(log_entry):
    """
    Parses a single log entry and extracts:
    - IP address
    - Event type
    - Protocol
    - Raw original string
    """
    result = {
        "ip":       None,
        "event":    "Unknown Event",
        "protocol": "Unknown",
        "raw":      log_entry
    }

    # ── IP EXTRACTION ─────────────────────────────────────
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_entry)
    if ip_match:
        result["ip"] = ip_match.group()

    # ── EVENT CLASSIFICATION ──────────────────────────────
    log_lower = log_entry.lower()

    if "failed login" in log_lower or "authentication failure" in log_lower:
        result["event"] = "Login Failure"
    elif "accepted" in log_lower or "successful login" in log_lower:
        result["event"] = "Login Success"
    elif "powershell" in log_lower or "-enc" in log_lower:
        result["event"] = "PowerShell Execution"
    elif "sudo" in log_lower or "root" in log_lower:
        result["event"] = "Privilege Escalation"
    elif "port scan" in log_lower or "nmap" in log_lower:
        result["event"] = "Port Scan"
    elif "dns" in log_lower:
        result["event"] = "DNS Activity"
    elif "wget" in log_lower or "curl" in log_lower or "certutil" in log_lower:
        result["event"] = "File Download Attempt"

    # ── PROTOCOL DETECTION ────────────────────────────────
    if "ssh" in log_lower:
        result["protocol"] = "SSH"
    elif "http" in log_lower:
        result["protocol"] = "HTTP"
    elif "ftp" in log_lower:
        result["protocol"] = "FTP"
    elif "dns" in log_lower:
        result["protocol"] = "DNS"
    elif "powershell" in log_lower:
        result["protocol"] = "PowerShell"

    return result

def parse_logs(log_entries):
    """
    Takes a list of raw log strings.
    Returns a list of parsed dictionaries.
    """
    return [parse_log(entry) for entry in log_entries]