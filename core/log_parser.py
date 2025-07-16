import re

def parse_log(log_entry):
    """
    Parses a single log entry and extracts key components like:
    - IP address
    - Event type
    - Protocol
    """
    result = {
        "ip": None,
        "event": None,
        "protocol": None,
        "raw": log_entry
    }

    # Try to extract IP address
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_entry)
    if ip_match:
        result["ip"] = ip_match.group()

    # Event classification
    if "Failed login" in log_entry or "authentication failure" in log_entry:
        result["event"] = "Login Failure"
    elif "Accepted" in log_entry or "Successful login" in log_entry:
        result["event"] = "Login Success"
    
    # Protocol detection
    if "SSH" in log_entry.upper():
        result["protocol"] = "SSH"
    elif "HTTP" in log_entry.upper():
        result["protocol"] = "HTTP"
    elif "FTP" in log_entry.upper():
        result["protocol"] = "FTP"

    return result

def parse_logs(log_entries):
    """
    Takes a list of log strings and returns a list of parsed dictionaries.
    """
    return [parse_log(entry) for entry in log_entries]
