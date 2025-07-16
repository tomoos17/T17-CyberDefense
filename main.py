# main.py

from core.log_parser import parse_logs
from core.threat_engine import detect_threats
from core.curiosity import analyze_novelty
from core.memory import save_to_memory, search_memory
from core.reflection import reflect_on_threat
from core.feedback_loop import ask_for_feedback

# Simulated raw log entries (in real scenario, these come from log files)
raw_logs = [
    "Failed login from 192.168.0.10 via SSH",
    "Accepted login from 10.0.0.22 over HTTP",
    "Failed login from 192.168.0.10 via SSH",
    "Failed login from 192.168.0.10 via SSH",
    "Accepted login from 10.0.0.99",
    "User root attempted sudo access from 172.16.0.5 via SSH"
]

# Step 1: Parse logs
structured_logs = parse_logs(raw_logs)

# Step 2: Detect threats
detected_threats = detect_threats(structured_logs)

# Step 3: Analyze each for novelty + memory
for threat in detected_threats:
    print("\n🔍 Potential Threat Detected:")
    print(threat)

    # Find the matching structured log for this threat
matching_log = next((log for log in structured_logs if log["raw"] == threat["raw"]), None)

if matching_log:
    novelty = analyze_novelty(matching_log)
    print(f"🧠 Novelty Score: {novelty['score']} | Level: {novelty['novelty_level']}")
else:
    print("⚠️  Could not analyze novelty — original log not found.")


    # Step 3B: Reflection
    reflection = reflect_on_threat(threat)
    if reflection["status"] == "known_threat":
        print("📂 Previously Seen Threat:", reflection["matched_entry"])
    else:
        print("🆕 New Threat! Logging...")

    # Step 3C: Save to memory if new
    save_to_memory(threat)

    # Step 3D: Ask user for feedback
    ask_for_feedback(threat)
