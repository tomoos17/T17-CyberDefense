# core/test_curiosity.py

from curiosity import analyze_novelty, keyword_score, frequency_score

# Simulate past memory logs
memory_logs = [
    {"event": "Login Failure", "ip": "10.0.0.1", "protocol": "SSH"},
    {"event": "Login Failure", "ip": "10.0.0.2", "protocol": "SSH"}
]

# Simulated log entry
log_entry = {
    "event": "Login Failure",
    "ip": "192.168.0.77",
    "protocol": "SSH",
    "raw": "Failed login attempt using sudo on SSH from 192.168.0.77"
}

# Test curiosity scores
novelty_result = analyze_novelty(log_entry)
keyword_count = keyword_score(log_entry["raw"])
frequency = frequency_score(log_entry["event"], memory_logs)

# Display results
print("📊 Novelty Analysis:", novelty_result)
print("⚠️  Keyword Threat Count:", keyword_count)
print("🔁 Memory Frequency Score:", frequency)
