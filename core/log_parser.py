# core/log_parser.py — T17 data layer
# Handles both simple logs AND real Windows Event Log format

import re

# ── WINDOWS EVENT ID MAPPING ─────────────────────────────────
WINDOWS_EVENT_MAP = {
    "4625": "Login Failure",           # Failed logon
    "4624": "Login Success",           # Successful logon
    "4648": "Login Attempt",           # Logon with explicit credentials
    "4720": "Account Created",         # User account created
    "4726": "Account Deleted",         # User account deleted
    "4728": "Group Member Added",      # Member added to security group
    "4732": "Group Member Added",      # Member added to local group
    "4756": "Group Member Added",      # Member added to universal group
    "4740": "Account Locked",          # Account locked out
    "4767": "Account Unlocked",        # Account unlocked
    "4688": "Process Created",         # New process created
    "4689": "Process Terminated",      # Process terminated
    "4698": "Scheduled Task Created",  # Scheduled task created
    "4702": "Scheduled Task Modified", # Scheduled task modified
    "4657": "Registry Modified",       # Registry value modified
    "4663": "File Accessed",           # File accessed
    "4670": "Permission Changed",      # Permissions changed
    "4907": "Audit Policy Change",     # Audit settings changed
    "4719": "Audit Policy Change",     # System audit policy changed
    "4776": "Credential Validation",   # Credential validation attempt
    "4771": "Kerberos Failure",        # Kerberos pre-auth failed
    "4769": "Kerberos Ticket",         # Kerberos service ticket requested
    "5140": "Network Share Access",    # Network share accessed
    "5145": "Network Share Check",     # Network share access check
    "4946": "Firewall Rule Added",     # Firewall rule added
    "4947": "Firewall Rule Modified",  # Firewall rule modified
    "1102": "Audit Log Cleared",       # Audit log was cleared
    "4616": "System Time Changed",     # System time changed
    "4672": "Privilege Assigned",      # Special privileges assigned
    "4673": "Privilege Used",          # Privileged service called
    "4674": "Privilege Used",          # Operation on privileged object
}

# Event IDs that are suspicious and worth scoring higher
SUSPICIOUS_EVENT_IDS = {
    "4625",  # Failed logon — brute force
    "4648",  # Explicit credential logon — lateral movement
    "4720",  # Account created — persistence
    "4726",  # Account deleted — covering tracks
    "4728",  # Added to security group — privilege escalation
    "4732",  # Added to local group — privilege escalation
    "4740",  # Account locked — brute force
    "4688",  # Process created — execution
    "4698",  # Scheduled task — persistence
    "4702",  # Scheduled task modified — persistence
    "4657",  # Registry modified — persistence/evasion
    "4719",  # Audit policy changed — covering tracks
    "1102",  # Audit log cleared — covering tracks
    "4672",  # Special privileges — privilege escalation
    "4776",  # Credential validation — credential access
    "4771",  # Kerberos failure — brute force
    "5140",  # Network share — lateral movement
}

def parse_windows_event(block: str) -> dict:
    """
    Parse a single Windows Event Log block into a structured dict.
    Handles the wevtutil /f:text format.
    """
    result = {
        "ip":        None,
        "event":     "Unknown Event",
        "protocol":  "Windows Event",
        "raw":       block.strip(),
        "event_id":  None,
        "level":     None,
        "task":      None,
        "computer":  None,
        "user":      None,
        "is_windows": True
    }

    # Extract Event ID
    eid_match = re.search(r'Event ID:\s*(\d+)', block)
    if eid_match:
        eid = eid_match.group(1)
        result["event_id"] = eid
        result["event"] = WINDOWS_EVENT_MAP.get(eid, f"Event {eid}")

    # Extract Level
    level_match = re.search(r'Level:\s*(.+)', block)
    if level_match:
        result["level"] = level_match.group(1).strip()

    # Extract Task
    task_match = re.search(r'Task:\s*(.+)', block)
    if task_match:
        result["task"] = task_match.group(1).strip()

    # Extract Computer
    comp_match = re.search(r'Computer:\s*(.+)', block)
    if comp_match:
        result["computer"] = comp_match.group(1).strip()

    # Extract Account Name
    user_match = re.search(r'Account Name:\s*(.+)', block)
    if user_match:
        result["user"] = user_match.group(1).strip()

    # Extract IP address
    ip_match = re.search(r'(?:Source Network Address|Network Address|Workstation Name):\s*([\d\.]+)', block)
    if ip_match:
        ip = ip_match.group(1).strip()
        if ip not in ("-", "::1", "127.0.0.1"):
            result["ip"] = ip

    # Extract Process Name for process creation events
    proc_match = re.search(r'Process Name:\s*(.+)', block)
    if proc_match:
        proc = proc_match.group(1).strip()
        # Flag suspicious processes
        suspicious_procs = ["powershell", "cmd.exe", "wscript", "cscript",
                           "mshta", "regsvr32", "rundll32", "certutil", "wmic"]
        for sp in suspicious_procs:
            if sp.lower() in proc.lower():
                result["event"] = f"Suspicious Process: {sp}"
                result["protocol"] = "Process Execution"
                break

    return result

def split_windows_events(content: str) -> list:
    """Split wevtutil text output into individual event blocks."""
    blocks = re.split(r'\nEvent\[\d+\]\n', content)
    return [b.strip() for b in blocks if b.strip()]

def parse_log(log_entry: str) -> dict:
    """
    Parse a single log entry — handles both simple and Windows formats.
    """
    result = {
        "ip":       None,
        "event":    "Unknown Event",
        "protocol": "Unknown",
        "raw":      log_entry.strip()
    }

    log_lower = log_entry.lower()

    # ── SIMPLE LOG FORMAT ────────────────────────────────────
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
    elif "base64" in log_lower or "b64" in log_lower:
        result["event"] = "Encoded Payload"
    else:
        result["event"] = "Unknown Event"

    # Protocol
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

    # IP
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_entry)
    if ip_match:
        result["ip"] = ip_match.group()

    return result

def parse_logs(log_entries: list) -> list:
    """
    Parse a list of raw log strings.
    Auto-detects Windows Event Log format vs simple logs.
    """
    if not log_entries:
        return []

    # Join to check if it's Windows Event Log format
    combined = "\n".join(str(e) for e in log_entries)

    # Detect Windows Event Log format
    if "Event ID:" in combined and "Log Name:" in combined:
        return parse_windows_log_file(combined)

    # Simple log format
    return [parse_log(str(entry)) for entry in log_entries if str(entry).strip()]

def parse_windows_log_file(content: str) -> list:
    """
    Parse a full Windows Event Log file exported by wevtutil.
    Only returns events worth analysing — filters out noise.
    """
    blocks = split_windows_events(content)
    results = []

    for block in blocks:
        if not block:
            continue

        parsed = parse_windows_event(block)

        # Only keep events worth analysing
        eid = parsed.get("event_id", "")
        if eid in SUSPICIOUS_EVENT_IDS:
            results.append(parsed)
        elif parsed.get("event") != "Unknown Event":
            # Keep known events but they'll likely score low
            results.append(parsed)

    return results