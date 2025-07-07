# core/threat_engine.py

THRESHOLD = 2  # max allowed failures per IP

# Temporary in-memory tracker
ip_failure_count = {}

# A mock blacklist
blacklisted_ips = {"10.0.0.99", "192.168.100.200"}

def detect_threats(parsed_logs):
    threats = []

    for log in parsed_logs:
        ip = log.get("ip")
        event = log.get("event")
        protocol = log.get("protocol")
        
        # Brute-force detection
        if event == "Login Failure":
            ip_failure_count[ip] = ip_failure_count.get(ip, 0) + 1
            if ip_failure_count[ip] >= THRESHOLD:
                threats.append({
                    "type": "Brute Force Attempt",
                    "ip": ip,
                    "count": ip_failure_count[ip],
                    "raw": log["raw"]
                })

        # Blacklist detection
        if ip in blacklisted_ips:
            threats.append({
                "type": "Blacklisted IP",
                "ip": ip,
                "protocol": protocol,
                "raw": log["raw"]
            })

    return threats
