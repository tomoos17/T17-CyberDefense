from threat_engine import detect_threats

sample_logs = [
    {"ip": "192.168.0.10", "event": "Login Failure", "protocol": "SSH", "raw": "Failed login from 192.168.0.10 via SSH"},
    {"ip": "192.168.0.10", "event": "Login Failure", "protocol": "SSH", "raw": "Failed login from 192.168.0.10 via SSH"},
    {"ip": "192.168.0.10", "event": "Login Failure", "protocol": "SSH", "raw": "Failed login from 192.168.0.10 via SSH"},
    {"ip": "10.0.0.99", "event": "Login Success", "protocol": "FTP", "raw": "Accepted login from 10.0.0.99"},
]

threats = detect_threats(sample_logs)

print("=== Detected Threats ===")
for threat in threats:
    print(threat)
